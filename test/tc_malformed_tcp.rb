require_relative 'spec_helper'
require 'minitest/mock'
require 'timeout'
require 'socket'
require 'open3'
require 'rbconfig'

class TestMalformedTcp < Minitest::Test
  # Keep selector fixtures off IO.select: a live resolver in another test may
  # share these tables. Only the dedicated allocated receiver uses the fakes.
  class SocketBuffer
    attr_reader :closed
    alias closed? closed
    attr_accessor :udp_response

    def initialize(bytes = ''.b)
      @bytes = bytes.dup
      @closed = false
    end

    def recv_nonblock(length)
      @bytes.slice!(0, [length, 1].min) # Fragment prefix and body alike.
    end

    def close
      @closed = true
    end

    def recvfrom(_length)
      @udp_response
    end
  end

  def setup
    @selector_class = Dnsruby::SelectThread
    @temporary_variables = []
    { :@@mutex => Mutex.new, :@@query_hash => {}, :@@socket_hash => {},
      :@@timeouts => {}, :@@sockets => Set.new, :@@tcp_buffers => {},
      :@@socket_is_persistent => {}, :@@socket_remaining_queries => {}, :@@queued_exceptions => [] }.each do |name, value|
      next if @selector_class.class_variable_defined?(name)
      @selector_class.class_variable_set(name, value)
      @temporary_variables << name
    end
    @selector = @selector_class.send(:allocate)
    @selector.define_singleton_method(:tcp?) { |_| true }
    @selector.define_singleton_method(:notify_queue_observers) { |*| }
    @registered = []
  end

  def teardown
    table(:mutex).synchronize do
      @registered.each do |settings|
        table(:query_hash).delete(settings.client_query_id)
        table(:timeouts).delete(settings.client_query_id)
        [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
          table(name).delete(settings.socket)
        end
      end
    end
    @temporary_variables.each { |name| @selector_class.remove_class_variable(name) }
  end

  def test_short_matching_frames_report_only_the_matching_pipeline_query
    [2, 4, 11].each do |length|
      socket = SocketBuffer.new
      first = register(socket, 12_345)
      second = register(socket, 12_346)
      packet = [12_346, 0x8000, 0, 0, 0, 0].pack('n6')[0, length]
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      event = second.client_queue.pop(true)
      assert_equal(second.client_query_id, event[0])
      assert_kind_of(Dnsruby::DecodeError, event.last)
      assert(first.client_queue.empty?)
      assert_same(first, table(:query_hash)[first.client_query_id])
      refute(socket.closed)
    end
  end

  def test_unknown_and_unidentifiable_pipeline_frames_leave_queries_active
    socket = SocketBuffer.new
    first = register(socket, 12_350)
    second = register(socket, 12_351)
    packets = ['', 'x', [12_352].pack('n'),
      [12_352, 0x8000, 1, 0, 0, 0].pack('n6'),
      [12_352, 0x8000, 0, 0, 0, 0].pack('n6')]
    packets.each do |packet|
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      [first, second].each do |settings|
        assert(settings.client_queue.empty?)
        assert_same(settings, table(:query_hash)[settings.client_query_id])
      end
    end
    refute(socket.closed)
  end

  def test_unidentifiable_frame_on_single_query_reports_decode_error
    ['', 'x'].each do |packet|
      settings = register(SocketBuffer.new, 12_355)
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(settings.socket, 0)) }
      assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
    end
  end

  def test_duplicate_ids_on_one_pipeline_socket_are_ambiguous
    socket = SocketBuffer.new
    first = register(socket, 12_356)
    second = register(socket, 12_356)
    [2, 12].each do |length|
      packet = [12_356, 0x8000, 1, 0, 0, 0].pack('n6')[0, length]
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      [first, second].each do |settings|
        assert(settings.client_queue.empty?)
        assert_same(settings, table(:query_hash)[settings.client_query_id])
      end
    end
  end

  def test_valid_in_order_replies_with_duplicate_ids_keep_existing_behavior
    socket = SocketBuffer.new
    first = register(socket, 12_357)
    second = register(socket, 12_357)
    second.query = Dnsruby::Message.new('second.example.')
    second.query.header.id = 12_357
    delivered = []
    @selector.stub(:push_to_client, ->(*args) { delivered << args }) do
      [first, second].each do |settings|
        settings.single_resolver = Dnsruby::PacketSender.allocate
        response = settings.query.clone
        response.header.qr = true
        @selector.stub(:tcp_read, response.encode) do
          decoded, bytes = @selector.get_incoming_data(socket, 0)
          @selector.send_response_to_client(decoded, bytes, socket)
        end
      end
    end
    assert_equal([first.client_query_id, second.client_query_id], delivered.map(&:first))
    assert(delivered.all? { |args| args[3].nil? })
    assert_equal([], table(:socket_hash)[socket])
    refute(socket.closed)
  end

  def test_matching_ids_on_other_sockets_do_not_supply_tcp_peer_metadata
    first = register(SocketBuffer.new, 12_360, '192.0.2.1', 53)
    second = register(SocketBuffer.new, 12_360, '192.0.2.2', 54)
    response = second.query.clone
    response.header.qr = true
    wire = response.encode
    @selector.stub(:tcp_read, wire) do
      decoded, bytes = @selector.get_incoming_data(second.socket, 0)
      assert_equal('192.0.2.2', decoded.answerip)
      assert_equal(wire, bytes)
    end
    # The same ID on another socket does not make an unsolicited frame ours.
    second.query.header.id = 12_361
    @selector.stub(:tcp_read, wire) { assert_nil(@selector.get_incoming_data(second.socket, 0)) }
    assert(first.client_queue.empty?)
    assert(second.client_queue.empty?)
  end

  def test_malformed_udp_requires_matching_id_address_and_port
    socket = SocketBuffer.new
    settings = register(socket, 12_370, '192.0.2.1', 53)
    [
      [12_371, '192.0.2.1', 53],
      [12_370, '192.0.2.2', 53],
      [12_370, '192.0.2.1', 54],
    ].each do |id, source, port|
      socket.udp_response = [[id, 0x8000, 1, 0, 0, 0].pack('n6'), ['AF_INET', port, source, source]]
      @selector.stub(:tcp?, false) { assert_nil(@selector.get_incoming_data(socket, 512)) }
      assert(settings.client_queue.empty?)
      assert_same(settings, table(:query_hash)[settings.client_query_id])
    end
  end

  def test_malformed_truncated_tcp_response_is_terminal_without_retrying
    settings = register(SocketBuffer.new, 12_372)
    sender = Object.new
    sender.define_singleton_method(:send_async) { |*| raise 'Unexpected TCP retry' }
    settings.single_resolver = sender
    packet = [settings.query.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
    @selector.stub(:tcp_read, packet) do
      assert_nil(@selector.get_incoming_data(settings.socket, 0))
      # A second buffered frame after terminal delivery cannot start a retry.
      assert_nil(@selector.get_incoming_data(settings.socket, 0))
    end
    assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
    assert(settings.client_queue.empty?)
    refute(table(:query_hash).key?(settings.client_query_id))
  end

  def test_malformed_truncated_udp_respects_transport_options
    [[true, false], [false, true], [true, true]].each do |no_tcp, ignore_truncation|
      socket = SocketBuffer.new
      settings = register(socket, 12_373)
      settings.ignore_truncation = ignore_truncation
      sender = Object.new
      sender.define_singleton_method(:no_tcp) { no_tcp }
      sender.define_singleton_method(:send_async) { |*| raise 'Unexpected UDP fallback' }
      settings.single_resolver = sender
      packet = [settings.query.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
      socket.udp_response = [packet, ['AF_INET', 53, '127.0.0.1', '127.0.0.1']]
      @selector.stub(:tcp?, false) { assert_nil(@selector.get_incoming_data(socket, 512)) }
      assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
      refute(table(:query_hash).key?(settings.client_query_id))
    end
  end

  def test_fragmented_zero_one_and_two_byte_frames_do_not_consume_next_frame
    [0, 1, 2].each do |length|
      short = 'x' * length
      valid = Dnsruby::Message.new('following.example.').encode
      socket = SocketBuffer.new([short.bytesize].pack('n') + short + [valid.bytesize].pack('n') + valid)
      # Register only for fixture cleanup; tcp_read itself does not decode.
      register(socket, 12_380 + length)
      frames = []
      (short.bytesize + valid.bytesize + 8).times do
        frame = @selector.tcp_read(socket)
        frames << frame if frame
        break if frames.length == 2
      end
      assert_equal([short, valid], frames)
      refute(socket.closed)
      refute(table(:tcp_buffers).key?(socket))
    end
  end

  def test_error_for_removed_query_is_harmless
    socket = SocketBuffer.new
    assert_nil(@selector.send_exception_to_client(Dnsruby::DecodeError.new, socket, Object.new))
    @selector.stub(:tcp_read, Dnsruby::Message.new.encode) do
      assert_nil(@selector.get_incoming_data(socket, 0))
    end
  end

  def test_eof_after_fragment_fails_all_pending_queries_and_clears_framing
    socket = SocketBuffer.new("\x00".b)
    first = register(socket, 12_390)
    second = register(socket, 12_391)
    assert_equal(false, @selector.tcp_read(socket))
    assert_equal(false, @selector.tcp_read(socket))
    [first, second].each do |settings|
      assert_kind_of(Dnsruby::SocketEofResolvError, settings.client_queue.pop(true).last)
      refute(table(:query_hash).key?(settings.client_query_id))
    end
    assert(socket.closed)
    [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
      refute(table(name).key?(socket))
    end
  end

  def test_idle_selector_drains_deliveries_registered_at_shutdown_boundary
    # The singleton tables and IO.select stub must be isolated from any real
    # resolver running elsewhere in the suite. No network sockets are needed.
    script = <<~'RUBY'
      require 'dnsruby'
      require 'timeout'
      klass = Dnsruby::SelectThread
      [:closed_query, :response, :validation].each do |kind|
        selector = klass.send(:allocate)
        wakeup = Object.new
        wakeup.define_singleton_method(:closed?) { false }
        socket = Object.new
        socket.define_singleton_method(:closed?) { true }
        query = Dnsruby::Message.new('late.example.')
        query.do_validation = query.do_caching = false
        response = query.clone
        response.header.qr = true
        queue = Queue.new
        settings = Dnsruby::SelectThread::QuerySettings.new
        settings.query, settings.client_query_id = query, :late
        settings.client_queue, settings.socket = queue, socket
        settings.endtime = Time.now + 60
        {
          mutex: Mutex.new, sockets: Set.new([wakeup]), timeouts: {}, query_hash: {},
          socket_hash: {}, socket_is_persistent: {}, socket_remaining_queries: {},
          tcp_buffers: {}, select_thread: Thread.current, observers: {},
          queued_exceptions: [], queued_responses: [], queued_validation_responses: [],
          tick_observers: [], wakeup_sockets: [wakeup, wakeup]
        }.each { |name, value| klass.class_variable_set("@@#{name}", value) }
        selector.define_singleton_method(:wake_up_select_thread) {}
        selector.define_singleton_method(:send_tick_to_observers) {}
        selector.define_singleton_method(:notify_queue_observers) { |*| }
        iterations = 0
        selector.define_singleton_method(:process_timeouts) do
          # IO.select has returned on the last otherwise-idle iteration. A
          # producer gets the GVL here, just before the shutdown mutex is taken.
          if iterations == 11
            case kind
            when :closed_query then add_to_select(settings)
            when :response then push_response_to_select(:late, queue, response, query, nil)
            when :validation then push_validation_response_to_select(:late, queue, response, nil, query, nil)
            end
          end
        end
        original_select = IO.method(:select)
        IO.define_singleton_method(:select) { |*| iterations += 1; nil }
        begin
          Timeout.timeout(2) { selector.do_select }
        ensure
          IO.define_singleton_method(:select, original_select)
        end
        expected = kind == :response ? 2 : 1
        raise "#{kind}: stranded delivery" unless queue.length == expected
        if kind == :closed_query
          raise 'wrong error' unless queue.pop.last.is_a?(Dnsruby::SocketEofResolvError)
        end
        [:queued_exceptions, :queued_responses, :queued_validation_responses].each do |name|
          raise "#{kind}: pending #{name}" unless klass.class_variable_get("@@#{name}").empty?
        end
        # Publish the stop decision under the mutex, before the Ruby thread exits.
        raise 'stopping selector still advertised as running' if selector.select_thread_alive?
      end
    RUBY
    assert_selector_subprocess(script)
  end

  def test_simultaneous_delivery_producers_start_only_one_selector
    assert_selector_subprocess(<<~'RUBY')
      klass = Dnsruby::SelectThread
      selector = klass.send(:allocate)
      original_new = Thread.method(:new)
      dead_worker = original_new.call {}.tap(&:join)
      {
        mutex: Mutex.new, select_thread: dead_worker, queued_exceptions: [],
        queued_responses: [], queued_validation_responses: []
      }.each { |name, value| klass.class_variable_set("@@#{name}", value) }
      selector.define_singleton_method(:wake_up_select_thread) {}
      factory_entered, release_factory = Queue.new, Queue.new
      workers, release_workers = Queue.new, Queue.new
      selector.define_singleton_method(:do_select) do
        workers << Thread.current
        release_workers.pop
      end
      Thread.define_singleton_method(:new) do |*args, &block|
        if Thread.current[:selector_producer]
          factory_entered << true
          release_factory.pop
        end
        original_new.call(*args, &block)
      end
      producers = []
      started = Queue.new
      begin
        [:exception, :response, :validation].each do |kind|
          producers << original_new.call do
            Thread.current[:selector_producer] = true
            query = Dnsruby::Message.new('parallel.example.')
            started << kind
            case kind
            when :exception
              selector.push_exception_to_select(kind, Queue.new, Dnsruby::OtherResolvError.new, nil)
            when :response
              selector.push_response_to_select(kind, Queue.new, query, query, nil)
            when :validation
              selector.push_validation_response_to_select(kind, Queue.new, query, nil, query, nil)
            end
          end
          # Hold the first producer inside Thread.new before starting its peers.
          factory_entered.pop if kind == :exception
        end
        3.times { started.pop }
        # Each producer is now blocked either at the selector mutex or at the
        # intercepted thread factory. No timing delay determines the outcome.
        Thread.pass until producers.all? { |thread| thread.status == 'sleep' }
        factories = 1 + factory_entered.length
        3.times { release_factory << true }
        producers.each(&:value)
        # Every created worker must enter do_select before checking its count.
        active_workers = factories.times.map { workers.pop }
        raise "started #{factories} selector workers" unless factories == 1
        counts = [:queued_exceptions, :queued_responses, :queued_validation_responses].map do |name|
          klass.class_variable_get("@@#{name}").length
        end
        raise "lost producer work: #{counts.inspect}" unless counts == [1, 1, 1]
        active_workers.each { release_workers << true }
        active_workers.each(&:value)
      ensure
        Thread.define_singleton_method(:new, original_new)
        producers.each { |thread| thread.kill if thread.alive? }
        worker = klass.class_variable_get(:@@select_thread)
        worker.kill if worker && worker.alive?
        until workers.empty?
          thread = workers.pop(true)
          thread.kill if thread.alive?
        end
        Array(active_workers).each { |thread| thread.kill if thread.alive? }
      end
    RUBY
  end

  def test_stopped_selector_restarts_before_the_old_ruby_thread_exits
    assert_selector_subprocess(<<~'RUBY')
      klass = Dnsruby::SelectThread
      original_select = IO.method(:select)
      IO.define_singleton_method(:select) { |*| nil }
      begin
        [:exception, :response, :validation, :closed_registration].each do |kind|
          selector = klass.send(:allocate)
          wakeup = Object.new
          wakeup.define_singleton_method(:closed?) { false }
          {
            mutex: Mutex.new, sockets: Set.new([wakeup]), timeouts: {}, query_hash: {},
            socket_hash: {}, socket_is_persistent: {}, socket_remaining_queries: {},
            tcp_buffers: {}, select_thread: nil, observers: {}, tick_observers: [],
            queued_exceptions: [], queued_responses: [], queued_validation_responses: [],
            wakeup_sockets: [wakeup, wakeup]
          }.each { |name, value| klass.class_variable_set("@@#{name}", value) }
          selector.define_singleton_method(:wake_up_select_thread) {}
          selector.define_singleton_method(:send_tick_to_observers) {}
          selector.define_singleton_method(:notify_queue_observers) { |*| }
          stopped, release_old, start_old, replacements = Queue.new, Queue.new, Queue.new, Queue.new
          implementation = selector.method(:do_select)
          old_worker = nil
          replacement = nil
          selector.define_singleton_method(:do_select) do
            implementation.call
            if Thread.current.equal?(old_worker)
              stopped << true
              release_old.pop
            else
              replacements << Thread.current
            end
          end
          begin
            old_worker = Thread.new { start_old.pop; selector.do_select }
            klass.class_variable_set(:@@select_thread, old_worker)
            start_old << true
            stopped.pop
            raise 'old worker exited before publication' unless old_worker.alive?
            query = Dnsruby::Message.new('late.example.')
            query.do_validation = query.do_caching = false
            response = query.clone
            response.header.qr = true
            queue = Queue.new
            error = Dnsruby::OtherResolvError.new('late error')
            case kind
            when :exception
              selector.push_exception_to_select(:late, queue, error, nil)
            when :response
              selector.push_response_to_select(:late, queue, response, query, nil)
            when :validation
              selector.push_validation_response_to_select(:late, queue, response, nil, query, nil)
            when :closed_registration
              closed_socket = Object.new
              closed_socket.define_singleton_method(:closed?) { true }
              settings = klass::QuerySettings.new(query.encode, query, false, queue, :late,
                closed_socket, '127.0.0.1', 53, Time.now + 60, 512, nil)
              selector.add_to_select(settings)
            end
            expected_types = case kind
            when :exception, :closed_registration then [Dnsruby::Resolver::EventType::ERROR]
            when :response then [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED]
            when :validation then [Dnsruby::Resolver::EventType::VALIDATED]
            end
            events = Timeout.timeout(2, Timeout::Error, "#{kind}: stranded delivery while old worker is alive") do
              expected_types.map { queue.pop }
            end
            replacement = Timeout.timeout(2, Timeout::Error, "#{kind}: replacement did not stop") { replacements.pop }
            replacement.value
            raise "#{kind}: old worker already exited" unless old_worker.alive?
            raise "#{kind}: wrong delivery types" unless events.map { |event| event[1] } == expected_types
            raise "#{kind}: wrong client ID" unless events.all? { |event| event[0] == :late }
            raise "#{kind}: duplicate delivery" unless queue.empty?
            case kind
            when :exception
              raise 'wrong exception' unless events.first.last.equal?(error)
            when :closed_registration
              raise 'wrong EOF error' unless events.first.last.is_a?(Dnsruby::SocketEofResolvError)
              raise 'closed registration retained' unless klass.class_variable_get(:@@query_hash).empty? &&
                klass.class_variable_get(:@@timeouts).empty? &&
                !klass.class_variable_get(:@@sockets).include?(closed_socket)
            else
              raise "#{kind}: wrong response" unless events.all? { |event| event[2].equal?(response) && event.last.nil? }
            end
            [:queued_exceptions, :queued_responses, :queued_validation_responses].each do |name|
              raise "#{kind}: pending #{name}" unless klass.class_variable_get("@@#{name}").empty?
            end
          ensure
            release_old << true
            old_worker.kill if old_worker && old_worker.alive?
            old_worker.join if old_worker
            worker = klass.class_variable_get(:@@select_thread)
            worker.kill if worker && worker.alive?
            replacement.kill if replacement && replacement.alive?
          end
        end
      ensure
        IO.define_singleton_method(:select, original_select)
      end
    RUBY
  end

  def test_send_failure_on_reused_pipeline_reports_the_registered_query
    sender = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: true)
    socket = Object.new
    socket.define_singleton_method(:write_nonblock) { |*| raise IOError, 'closed during send' }
    queue = Queue.new
    query = Dnsruby::Message.new('late.example.')
    errors = []
    selector = Object.new
    current = nil
    selector.define_singleton_method(:query_settings_for_id) { |_| current }
    selector.define_singleton_method(:register_query_if_current) { |settings, _| current = settings; true }
    selector.define_singleton_method(:fail_tcp_send) do |settings, error|
      errors << [settings.client_query_id, settings.client_queue, error, nil]
    end
    Dnsruby::SelectThread.stub(:instance, selector) do
      sender.stub(:tcp_pipeline_socket, [socket, false]) do
        sender.send_dnsruby(query.encode, query, :late_send, queue, true)
      end
    end
    assert_equal(1, errors.length)
    assert_equal([:late_send, queue], errors.first[0, 2])
    assert_kind_of(Dnsruby::SocketEofResolvError, errors.first[2])
    assert_nil(errors.first[3])
  end

  def test_eof_callback_registration_gets_error_without_retaining_closed_socket
    # add_to_select queues the second EOF in a class variable. Run the complete
    # callback scenario in a child so a live singleton cannot steal its queue.
    assert_selector_subprocess(<<~'RUBY')
      klass = Dnsruby::SelectThread
      {
        mutex: Mutex.new, query_hash: {}, socket_hash: {}, timeouts: {}, sockets: Set.new,
        tcp_buffers: {}, socket_is_persistent: {}, socket_remaining_queries: {}, queued_exceptions: []
      }.each { |name, value| klass.class_variable_set("@@#{name}", value) }
      selector = klass.send(:allocate)
      selector.define_singleton_method(:check_select_thread_synchronized) {}
      selector.define_singleton_method(:wake_up_select_thread) {}
      closed = false
      socket = Object.new
      socket.define_singleton_method(:closed?) { closed }
      socket.define_singleton_method(:close) { closed = true }
      socket.define_singleton_method(:recv_nonblock) { |_| ''.b }
      first, second = [:first, :second].map do |id|
        settings = klass::QuerySettings.new
        settings.query = Dnsruby::Message.new("#{id}.example.")
        settings.client_query_id = [Object.new, settings.query]
        settings.client_queue, settings.socket = Queue.new, socket
        settings.endtime = Time.now + 60
        settings.is_persistent_socket = true
        settings.tcp_pipelining_max_queries = :infinite
        settings
      end
      selector.add_to_select(first)
      notifications = []
      selector.define_singleton_method(:notify_queue_observers) do |_queue, id|
        raise 'callback under selector mutex' if klass.class_variable_get(:@@mutex).owned?
        notifications << id
        # A sender resumes registration during an earlier query's EOF callback.
        add_to_select(second) if id == first.client_query_id
      end
      raise 'unexpected EOF result' unless selector.tcp_read(socket) == false
      selector.send_queued_exceptions
      [first, second].each do |settings|
        event = settings.client_queue.pop(true)
        raise 'wrong EOF error' unless event.last.is_a?(Dnsruby::SocketEofResolvError)
        raise 'duplicate EOF' unless settings.client_queue.empty?
        [:query_hash, :timeouts].each do |name|
          raise "retained #{name}" if klass.class_variable_get("@@#{name}").key?(settings.client_query_id)
        end
      end
      raise 'missing callback' unless notifications == [first.client_query_id, second.client_query_id]
      [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
        raise "retained #{name}" if klass.class_variable_get("@@#{name}").key?(socket)
      end
      raise 'retained socket' if klass.class_variable_get(:@@sockets).include?(socket)
      raise 'undelivered EOF' unless klass.class_variable_get(:@@queued_exceptions).empty?
    RUBY
  end

  private

  def assert_selector_subprocess(script)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    # A child-side deadline also bounds broken synchronization regressions;
    # capture3 otherwise waits forever for a child blocked at a test gate.
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-r', 'dnsruby', '-r', 'timeout',
      '-e', "Timeout.timeout(10) do\n#{script}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end

  def table(name)
    @selector_class.class_variable_get("@@#{name}")
  end

  def register(socket, id, destination = '127.0.0.1', port = 53)
    settings = Dnsruby::SelectThread::QuerySettings.new
    settings.query = Dnsruby::Message.new('malformed.example.')
    settings.query.header.id = id
    settings.client_query_id = [Object.new, settings.query]
    settings.client_queue = Queue.new
    settings.socket = socket
    settings.dest_server = destination
    settings.dest_port = port
    table(:mutex).synchronize do
      table(:query_hash)[settings.client_query_id] = settings
      (table(:socket_hash)[socket] ||= []) << settings.client_query_id
      table(:socket_is_persistent)[socket] = true
    end
    @registered << settings
    settings
  end
end

class TestMalformedTcpTransport < Minitest::Test
  def test_malformed_query_does_not_block_an_unrelated_query_or_its_timeout
    [:two_bytes, :four_bytes, :truncated, :unknown_id].each do |kind|
      listener = TCPServer.new('127.0.0.1', 0)
      connections = []
      exchanges = []
      release = Queue.new
      server = Thread.new do
        begin
          # Both queries must already be outstanding when the malformed reply
          # arrives; resolver retry scheduling is separate from selector liveness.
          requests = 2.times.map do
            connection = listener.accept
            connections << connection
            length = connection.read(2).unpack('n').first
            [connection, Dnsruby::Message.decode(connection.read(length))]
          end
          requests.each do |connection, response|
            if response.question.first.qname.to_s == 'broken.example'
              wire = case kind
              when :two_bytes
                [response.header.id].pack('n')
              when :four_bytes
                [response.header.id, 0x8000].pack('n2')
              when :truncated
                [response.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
              when :unknown_id
                [(response.header.id + 1) % 65_536, 0x8000, 0, 0, 0, 0].pack('n6')
              end
            else
              response.header.qr = true
              response.add_answer(Dnsruby::RR.create('healthy.example. 60 IN A 192.0.2.25'))
              wire = response.encode
            end
            exchanges << [response.question.first.qname.to_s, wire.bytesize]
            connection.write([wire.bytesize].pack('n') + wire)
          end
          release.pop # The unanswered query must time out while its peer stays open.
        rescue StandardError => error
          error
        end
      end
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', port: listener.addr[1],
        use_tcp: true, tcp_pipelining: false, do_caching: false, dnssec: false, retry_times: 1,
        # The second async query is sent on the next resolver tick (up to 0.5s).
        packet_timeout: 1, query_timeout: 2)
      queue = Queue.new
      [:broken, :healthy].each do |id|
        query = Dnsruby::Message.new("#{id}.example.")
        query.do_caching = false
        query.do_validation = false
        resolver.send_async(query, queue, id)
      end
      results = Timeout.timeout(5) { 2.times.map { queue.pop } }
      broken = results.find { |item| item.first == :broken }
      healthy = results.find { |item| item.first == :healthy }
      assert_kind_of(kind == :unknown_id ? Dnsruby::ResolvTimeout : Dnsruby::DecodeError, broken.last)
      assert_nil(healthy.last, "#{kind}: #{exchanges.inspect}, server status: #{server.status.inspect}")
      assert_equal(['192.0.2.25'], healthy[1].answer.map { |rr| rr.address.to_s })
      assert(Dnsruby::SelectThread.instance.select_thread_alive?)
      release << true
      server_result = Timeout.timeout(5) { server.value }
      raise server_result if server_result.is_a?(StandardError)
    ensure
      resolver.close if resolver
      server.kill.join if server
      connections.each { |connection| connection.close unless connection.closed? } if connections
      listener.close if listener && !listener.closed?
    end
  end
end
