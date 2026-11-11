require_relative 'spec_helper'
require 'open3'
require 'rbconfig'

class TestPipelineSend < Minitest::Test
  # Every scenario gets its own selector tables and method hooks. This also
  # prevents the suite's real singleton from consuming fixture-owned events.
  FIXTURE = <<~'RUBY'
    require 'dnsruby'
    require 'timeout'
    Dnsruby.log.level = Logger::FATAL
    K = Dnsruby::SelectThread
    {
      mutex: Mutex.new, query_hash: {}, socket_hash: {}, timeouts: {}, sockets: Set.new,
      tcp_buffers: {}, socket_is_persistent: {}, socket_remaining_queries: {},
      queued_exceptions: [], queued_responses: [], queued_validation_responses: [],
      observers: {}, tick_observers: [], select_thread: nil
    }.each { |name, value| K.class_variable_set("@@#{name}", value) }
    SELECTOR = K.send(:allocate)
    SELECTOR.define_singleton_method(:check_select_thread_synchronized) {}
    SELECTOR.define_singleton_method(:wake_up_select_thread) {}
    SELECTOR.define_singleton_method(:notify_queue_observers) { |*| }
    K.define_singleton_method(:instance) { SELECTOR }

    class FrameSocket
      attr_accessor :on_write, :limit, :incoming
      attr_reader :written
      def initialize
        @closed = false
        @written = ''.b
        @incoming = ''.b
      end
      def closed?; @closed; end
      def close; @closed = true; end
      def getsockopt(*)
        raise IOError, 'closed stream' if closed?
        Struct.new(:data).new([Socket::SOCK_STREAM].pack('i'))
      end
      def write_nonblock(bytes)
        raise IOError, 'closed stream' if closed?
        count = @limit ? [@limit, bytes.bytesize].min : bytes.bytesize
        @written << bytes.byteslice(0, count)
        @on_write.call(bytes, count) if @on_write
        count
      end
      # Old implementations use send twice; retaining it makes the fast-reply
      # regression fail for the actual original ordering, not a missing method.
      def send(bytes, _flags); write_nonblock(bytes); end
      def recv_nonblock(length)
        raise IOError, 'closed stream' if closed?
        raise IO::EAGAINWaitReadable if @incoming.empty?
        @incoming.slice!(0, length)
      end
    end

    def query(name = 'pipeline.example.')
      q = Dnsruby::Message.new(name)
      q.do_validation = q.do_caching = false
      q
    end
    def sender(socket, max = :infinite)
      result = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: true,
        tcp_pipelining_max_queries: max, packet_timeout: 1)
      result.define_singleton_method(:tcp_pipeline_socket) { |_| [socket, false] }
      result
    end
    def settings(socket, id, q = query, resolver = sender(socket), max = :infinite)
      s = K::QuerySettings.new(q.encode, q, false, Queue.new, id, socket,
        '127.0.0.1', 53, Time.now + 1, 512, resolver)
      s.is_persistent_socket = true
      s.tcp_pipelining_max_queries = max
      s
    end
    def drain_errors
      SELECTOR.send_queued_exceptions
    end
    def assert_clean(socket)
      [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
        raise "retained #{name}" if K.class_variable_get("@@#{name}").key?(socket)
      end
      raise 'retained socket' if K.class_variable_get(:@@sockets).include?(socket)
    end
  RUBY

  def test_valid_response_is_delivered_before_native_write_returns
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      writer = sender(socket)
      old = settings(socket, :old, query('older.example.'), writer)
      SELECTOR.add_to_select(old) # The reused socket is already being selected.
      q, queue = query('immediate.example.'), Queue.new
      response = q.clone
      response.header.qr = true
      wire = response.encode
      delivered = Queue.new
      reader = nil
      socket.on_write = ->(_bytes, _count) do
        next unless socket.written.bytesize >= q.encode.bytesize + 2
        socket.incoming = [wire.bytesize].pack('n') + wire
        reader = Thread.new do
          incoming = SELECTOR.get_incoming_data(socket, 0)
          SELECTOR.process_message(*incoming, socket) if incoming
          SELECTOR.send_queued_validation_responses
          delivered << true
        end
        delivered.pop # The response is processed while the writer is paused.
        raise 'fast answer was lost before registration' unless queue.length == 2
      end
      writer.send_dnsruby(q.encode, q, :immediate, queue, true)
      reader.join
      events = 2.times.map { queue.pop(true) }
      raise 'wrong delivery order' unless events.map { |e| e[1] } ==
        [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED]
      raise 'unexpected error' unless events.all? { |e| e.last.nil? }
      raise 'duplicate answer' unless queue.empty?
      raise 'answer still registered' if SELECTOR.query_settings_for_id(:immediate)
      raise 'other query removed' unless SELECTOR.query_settings_for_id(:old).equal?(old)
    RUBY
  end

  def test_partial_writes_complete_frames_and_ordinary_callers_wait_for_the_writer
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      socket.limit = 3
      writer = sender(socket)
      entered, release, returned = Queue.new, Queue.new, Queue.new
      first_write = true
      socket.on_write = ->(*) do
        if first_write
          first_write = false
          entered << true
          release.pop
        end
      end
      a, b = query('first.example.'), query('second.example.')
      t1 = Thread.new { writer.send_dnsruby(a.encode, a, :first, Queue.new, true) }
      entered.pop
      t2 = Thread.new do
        writer.send_dnsruby(b.encode, b, :second, Queue.new, true)
        returned << true
      end
      Thread.pass until t2.status == 'sleep'
      raise 'ordinary caller returned before sending' unless returned.empty?
      release << true
      t1.value
      t2.value
      expected = [a, b].map { |q| [q.encode.bytesize].pack('n') + q.encode }.join
      raise 'interleaved or truncated frames' unless socket.written == expected
    RUBY
  end

  def test_selector_retry_defers_when_another_writer_owns_the_pipeline
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      writer = sender(socket)
      entered, release = Queue.new, Queue.new
      first_write = true
      socket.on_write = ->(*) do
        if first_write
          first_write = false
          entered << true
          release.pop
        end
      end
      first = query('first.example.')
      sending = Thread.new { writer.send_dnsruby(first.encode, first, :first, Queue.new, true) }
      entered.pop
      K.class_variable_set(:@@select_thread, Thread.current)
      retry_query = query('retry.example.')
      old = settings(FrameSocket.new, :retry, retry_query, writer)
      old.is_persistent_socket = false # UDP-to-TCP retry replaces a one-use socket.
      SELECTOR.add_to_select(old)
      worker = writer.send_dnsruby(retry_query.encode, retry_query, :retry, old.client_queue, true)
      raise 'selector send did not defer' unless worker.is_a?(Thread)
      raise 'new writer entered before old frame ended' unless socket.written.bytesize == first.encode.bytesize + 2
      release << true
      sending.value
      worker.value
      replacement = SELECTOR.query_settings_for_id(:retry)
      raise 'retry lost' unless replacement && !replacement.equal?(old) && replacement.socket == socket
      assert_clean(old.socket)
    RUBY
  end

  def test_deferred_retry_cannot_resurrect_an_expired_or_replaced_query
    run_scenario(<<~'RUBY')
      [:expired, :replaced].each do |kind|
        socket = FrameSocket.new
        writer = sender(socket)
        lock = Mutex.new
        writer.instance_variable_set(:@pipeline_mutex, lock)
        lock.lock
        K.class_variable_set(:@@select_thread, Thread.current)
        old = settings(FrameSocket.new, kind, query("#{kind}.example."), writer)
        SELECTOR.add_to_select(old)
        worker = writer.send_dnsruby(old.query_bytes, old.query, kind, old.client_queue, true)
        if kind == :expired
          old.endtime = Time.now - 1
          K.class_variable_get(:@@timeouts)[kind] = old.endtime
          SELECTOR.process_timeouts
        else
          replacement = settings(FrameSocket.new, kind)
          SELECTOR.add_to_select(replacement)
        end
        lock.unlock
        worker.value
        drain_errors
        raise 'stale retry wrote bytes' unless socket.written.empty?
        if kind == :expired
          raise 'wrong timeout cardinality' unless old.client_queue.length == 1
          raise 'expired retry resurrected' if SELECTOR.query_settings_for_id(kind)
        else
          raise 'replacement lost' unless SELECTOR.query_settings_for_id(kind).equal?(replacement)
          raise 'obsolete retry reported an error' unless old.client_queue.empty?
        end
      end
    RUBY
  end

  def test_failure_retires_the_stream_and_reports_each_query_once
    run_scenario(<<~'RUBY')
      [:infinite, 3].each do |max|
        [:raise, :zero].each do |failure|
          socket = FrameSocket.new
          writer = sender(socket, max)
          old = settings(socket, :old, query('older.example.'), writer, max)
          SELECTOR.add_to_select(old)
          if failure == :zero
            socket.define_singleton_method(:write_nonblock) { |_| 0 }
          else
            socket.limit = 2
            calls = 0
            socket.on_write = ->(*) { calls += 1; raise IOError, 'write failure' if calls == 2 }
          end
          q, queue = query, Queue.new
          writer.send_dnsruby(q.encode, q, :new, queue, true)
          drain_errors
          [old.client_queue, queue].each do |events|
            raise 'missing or duplicate error' unless events.length == 1
            raise 'wrong error' unless events.pop.last.is_a?(Dnsruby::SocketEofResolvError)
          end
          raise 'failed stream left open' unless socket.closed?
          assert_clean(socket)
          raise 'query retained' if SELECTOR.query_settings_for_id(:old) || SELECTOR.query_settings_for_id(:new)
        end
      end
    RUBY
  end

  def test_closed_registration_does_not_attempt_a_write_or_report_twice
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      socket.close
      writer = sender(socket)
      q, queue = query, Queue.new
      writer.send_dnsruby(q.encode, q, :closed, queue, true)
      drain_errors
      raise 'wrote closed socket' unless socket.written.empty?
      raise 'missing or duplicate error' unless queue.length == 1
      raise 'wrong error' unless queue.pop.last.is_a?(Dnsruby::SocketEofResolvError)
      assert_clean(socket)
    RUBY
  end

  def test_retry_expiring_during_connect_releases_only_the_unused_socket
    run_scenario(<<~'RUBY')
      [true, false].each do |new_socket|
        socket = FrameSocket.new
        writer = sender(socket)
        old = settings(FrameSocket.new, :retry, query, writer)
        SELECTOR.add_to_select(old)
        other = settings(socket, :other, query('other.example.'), writer)
        SELECTOR.add_to_select(other) unless new_socket
        writer.define_singleton_method(:tcp_pipeline_socket) do |_|
          old.endtime = Time.now - 1
          K.class_variable_get(:@@timeouts)[:retry] = old.endtime
          SELECTOR.process_timeouts # The original attempt completes during connect.
          @use_counts[socket] = 1
          [socket, new_socket]
        end
        writer.send_dnsruby(old.query_bytes, old.query, :retry, old.client_queue, true)
        drain_errors
        raise 'expired retry wrote bytes' unless socket.written.empty?
        raise 'missing timeout' unless old.client_queue.length == 1 && old.client_queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
        raise 'expired retry retained' if SELECTOR.query_settings_for_id(:retry)
        if new_socket
          raise 'unused socket leaked' unless socket.closed?
          assert_clean(socket)
        else
          raise 'other pending query damaged' if socket.closed? || !SELECTOR.query_settings_for_id(:other).equal?(other)
          SELECTOR.fail_tcp_send(other, Dnsruby::SocketEofResolvError.new)
          drain_errors
        end
      end
    RUBY
  end

  def test_configuration_marshal_and_first_send_from_a_stored_sender
    run_scenario(<<~'RUBY')
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: true)
      raise 'configuration gained a mutex' if writer.instance_variable_defined?(:@pipeline_mutex)
      stored = Marshal.load(Marshal.dump(writer))
      socket = FrameSocket.new
      stored.define_singleton_method(:tcp_pipeline_socket) { |_| [socket, false] }
      q = query
      stored.send_dnsruby(q.encode, q, :stored, Queue.new, true)
      raise 'stored sender cannot send' unless socket.written == [q.encode.bytesize].pack('n') + q.encode
      raise 'stored sender not registered' unless SELECTOR.query_settings_for_id(:stored)
    RUBY
  end

  def test_blocked_write_and_selector_writer_wait_have_bounded_timeouts
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      writer = sender(socket)
      socket.define_singleton_method(:write_nonblock) { |_| raise IO::EAGAINWaitWritable }
      original_select = IO.method(:select)
      IO.define_singleton_method(:select) { |*| nil }
      q, queue = query, Queue.new
      begin
        writer.send_dnsruby(q.encode, q, :blocked, queue, true)
      ensure
        IO.define_singleton_method(:select, original_select)
      end
      drain_errors
      raise 'wrong write timeout' unless queue.length == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'blocked stream not closed' unless socket.closed?
      assert_clean(socket)

      waiting_socket = FrameSocket.new
      waiting = sender(waiting_socket)
      waiting.packet_timeout = 0.02
      lock = Mutex.new
      waiting.instance_variable_set(:@pipeline_mutex, lock)
      lock.lock
      K.class_variable_set(:@@select_thread, Thread.current)
      queue = Queue.new
      worker = waiting.send_dnsruby(q.encode, q, :waiting, queue, true)
      worker.value # Must finish while the other writer still owns the mutex.
      drain_errors
      raise 'wrong writer-wait timeout' unless queue.length == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'timed-out sender wrote' unless waiting_socket.written.empty?
      lock.unlock
    RUBY
  end

  def test_tcp_write_timeout_preserves_the_resolvers_remaining_retries
    run_scenario(<<~'RUBY')
      original_tcp, original_select = Socket.method(:tcp), IO.method(:select)
      begin
        [false, true].each do |pipeline|
          socket = FrameSocket.new
          socket.define_singleton_method(:write_nonblock) { |_| raise IO::EAGAINWaitWritable }
          Socket.define_singleton_method(:tcp) { |*args, **options| socket }
          IO.define_singleton_method(:select) { |*| nil }
          writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true,
            tcp_pipelining: pipeline, dnssec: false, packet_timeout: 0.05)
          q, queue = query, Queue.new
          writer.send_async(q, queue, :write_timeout)
          drain_errors
          raise 'missing or duplicate timeout' unless queue.length == 1
          error = queue.pop(true).last
          raise 'write timeout became a connection failure' unless error.is_a?(Dnsruby::ResolvTimeout)
          raise 'stalled socket left open' unless socket.closed?
          assert_clean(socket)

          # A timeout keeps the next attempt scheduled; a connection error would
          # remove this server and finish the client query prematurely.
          parent = Struct.new(:single_resolvers, :single_res_mutex).new([writer], Mutex.new)
          engine = Dnsruby::ResolverRuby.new(parent)
          client_queue, select_queue = Queue.new, Queue.new
          attempt = [writer, q, :client, 0]
          engine.instance_variable_get(:@query_list)[:client] = [q, client_queue, select_queue, []]
          scheduled = {Time.now + 60 => [writer, 1]}
          engine.instance_variable_get(:@timeouts)[:client] = [Time.now + 120, scheduled]
          SELECTOR.add_observer(select_queue, engine)
          engine.handle_error_response(select_queue, attempt, error, nil)
          raise 'remaining retry removed' unless scheduled.size == 1
          raise 'client query stopped early' unless engine.instance_variable_get(:@query_list).key?(:client)
          raise 'premature client error' unless client_queue.empty?
          engine.stop_querying(:client)
        end
      ensure
        Socket.define_singleton_method(:tcp, original_tcp)
        IO.define_singleton_method(:select, original_select)
      end
    RUBY
  end

  def test_selector_worker_creation_failure_reports_the_original_attempt_once
    run_scenario(<<~'RUBY')
      socket = FrameSocket.new
      writer = sender(socket)
      lock = Mutex.new
      writer.instance_variable_set(:@pipeline_mutex, lock)
      lock.lock
      K.class_variable_set(:@@select_thread, Thread.current)
      old = settings(FrameSocket.new, :retry, query, writer)
      SELECTOR.add_to_select(old)
      factory = Thread.method(:new)
      Thread.define_singleton_method(:new) { |*| raise ThreadError, 'cannot start worker' }
      begin
        writer.send_dnsruby(old.query_bytes, old.query, :retry, old.client_queue, true)
      ensure
        Thread.define_singleton_method(:new, factory)
        lock.unlock
      end
      drain_errors
      raise 'missing worker error' unless old.client_queue.length == 1 && old.client_queue.pop.last.is_a?(ThreadError)
      raise 'failed worker retained query' if SELECTOR.query_settings_for_id(:retry)
      raise 'failed worker wrote' unless socket.written.empty?
    RUBY
  end

  private

  def run_scenario(script)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', "#{FIXTURE}\nTimeout.timeout(10) do\n#{script}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
