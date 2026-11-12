require_relative 'spec_helper'
require 'open3'
require 'rbconfig'

class TestPipelineRetirement < Minitest::Test
  # Selector tables are class variables. Every scenario owns a subprocess so
  # neither its fake sockets nor its queued events can reach a live singleton.
  SUBPROCESS_SETUP = <<~'RUBY'
    require 'dnsruby'
    require 'timeout'

    class RetirementFixture
      attr_reader :selector

      def initialize
        @klass = Dnsruby::SelectThread
        {
          mutex: Mutex.new, sockets: Set.new, query_hash: {}, queries_by_queue: {}.compare_by_identity, socket_hash: {}, timeouts: {},
          socket_is_persistent: {}, socket_remaining_queries: {}, tcp_buffers: {},
          queued_exceptions: [], queued_responses: [], queued_validation_responses: [],
          observers: {}, observer_queue_counts: {}.compare_by_identity, tick_observers: [], select_thread: Thread.current
        }.each { |name, value| @klass.class_variable_set("@@#{name}", value) }
        @selector = @klass.send(:allocate)
        @selector.define_singleton_method(:wake_up_select_thread) {}
        @selector.define_singleton_method(:check_select_thread_synchronized) {}
        @selector.define_singleton_method(:notify_queue_observers) { |*| }
      end

      def table(name)
        @klass.class_variable_get("@@#{name}")
      end

      def socket
        closed = false
        socket = Object.new
        socket.define_singleton_method(:closed?) { closed }
        socket.define_singleton_method(:close) { closed = true }
        type = Struct.new(:data).new([Socket::SOCK_STREAM].pack('i'))
        socket.define_singleton_method(:getsockopt) { |*| type }
        socket
      end

      def settings(socket, id: :query, persistent: true, endtime: Dnsruby::TransportClock.now + 60, register: true)
        query = Dnsruby::Message.new('retirement.example.')
        query.do_validation = query.do_caching = false
        settings = @klass::QuerySettings.new(query.encode, query, false, Queue.new, id,
          socket, '127.0.0.1', 53, endtime, 512, Dnsruby::PacketSender.allocate)
        settings.is_persistent_socket = persistent
        settings.tcp_pipelining_max_queries = :infinite
        @selector.add_to_select(settings) if register
        settings
      end

      def response(settings)
        settings.query.clone.tap { |message| message.header.qr = true }
      end

      def events(settings)
        @selector.send_queued_exceptions
        @selector.send_queued_validation_responses
        events = []
        events << settings.client_queue.pop(true) until settings.client_queue.empty?
        events
      end

      def assert_retired(socket)
        raise 'socket still open' unless socket.closed?
        raise 'retained socket' if table(:sockets).include?(socket)
        [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
          raise "retained #{name}" if table(name).key?(socket)
        end
        raise 'retained socket registration' if table(:query_hash).values.any? { |settings| settings.socket == socket }
      end

      def assert_send_error(settings, error)
        actual = events(settings)
        expected = [[settings.client_query_id, Dnsruby::Resolver::EventType::ERROR, nil, error]]
        raise "unexpected send failure deliveries: #{actual.inspect}" unless actual == expected
        raise 'retained query' if table(:query_hash)[settings.client_query_id].equal?(settings)
        raise 'retained timeout' if table(:timeouts).key?(settings.client_query_id)
        assert_retired(settings.socket)
      end

      def assert_response(settings, response)
        actual = events(settings)
        expected = [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED].map do |type|
          [settings.client_query_id, type, response, nil]
        end
        raise "unexpected response deliveries: #{actual.inspect}" unless actual == expected
        raise 'retained response registration' if table(:query_hash)[settings.client_query_id].equal?(settings)
        raise 'retained response timeout' if table(:timeouts).key?(settings.client_query_id)
      end
    end
  RUBY

  def test_closed_descriptor_during_select_keeps_the_same_worker_processing_queries
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      selector = fixture.selector
      klass = Dnsruby::SelectThread
      broken = fixture.settings(fixture.socket, id: :broken)
      healthy = fixture.settings(fixture.socket, id: :healthy, persistent: false)
      response = fixture.response(healthy)
      bytes = response.encode
      incoming = [bytes.bytesize].pack('n') + bytes
      healthy.socket.define_singleton_method(:recv_nonblock) { |length| incoming.slice!(0, length) }
      wakeup = fixture.socket
      fixture.table(:sockets) << wakeup
      klass.class_variable_set(:@@wakeup_sockets, [wakeup, wakeup])
      notifications = []
      selector.define_singleton_method(:notify_queue_observers) do |_queue, id|
        raise 'callback under selector mutex' if fixture.table(:mutex).owned?
        notifications << [id, Thread.current]
      end
      # Use real startup logic: a missing queued failure must not be rescued by
      # a later producer creating a replacement selector.
      selector.singleton_class.remove_method(:check_select_thread_synchronized)
      entered, release, start = Queue.new, Queue.new, Queue.new
      original_select = IO.method(:select)
      calls = 0
      IO.define_singleton_method(:select) do |readers, *_|
        calls += 1
        if calls == 1
          raise 'query sockets missing from selected snapshot' unless
            readers.include?(broken.socket) && readers.include?(healthy.socket)
          entered << true
          release.pop # The native call is waiting on the snapshotted read set.
          raise 'writer did not retire descriptor' unless broken.socket.closed?
          raise Errno::EBADF, 'descriptor closed while select was waiting'
        elsif calls == 2
          [[healthy.socket], [], []]
        end
      end
      worker = Thread.new { start.pop; selector.do_select }
      worker.report_on_exception = false
      klass.class_variable_set(:@@select_thread, worker)
      begin
        start << true
        entered.pop
        failure = Dnsruby::SocketEofResolvError.new('concurrent writer failed')
        selector.fail_tcp_send(broken, failure)
        raise 'writer replaced active selector' unless fixture.table(:select_thread).equal?(worker)
        release << true
        worker.value
        # Do not call any queue-draining helper: the original worker must have
        # delivered both this failure and the unrelated, already registered reply.
        raise 'failure not delivered once' unless broken.client_queue.length == 1 &&
          broken.client_queue.pop(true) == [:broken, Dnsruby::Resolver::EventType::ERROR, nil, failure]
        expected = [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED]
        actual = 2.times.map { healthy.client_queue.pop(true) }
        raise 'unrelated response lost' unless actual.map { |event| event[1] } == expected &&
          actual.all? { |event| event[0] == :healthy && event.last.nil? }
        raise 'duplicate unrelated response' unless healthy.client_queue.empty?
        raise 'a replacement worker delivered events' unless notifications.length == 3 &&
          notifications.all? { |_id, thread| thread.equal?(worker) }
        fixture.assert_retired(broken.socket)
        raise 'queries retained' unless fixture.table(:query_hash).empty? && fixture.table(:timeouts).empty?
      ensure
        IO.define_singleton_method(:select, original_select)
        worker.kill if worker.alive?
        worker.join
      end
    RUBY
  end

  def test_retirement_during_incoming_socket_classification_is_harmless
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      selector = fixture.selector
      socket = fixture.socket
      settings = fixture.settings(socket)
      error = Dnsruby::SocketEofResolvError.new('write failed during classification')
      classified = false
      socket.define_singleton_method(:getsockopt) do |*|
        classified = true
        selector.fail_tcp_send(settings, error)
        raise IOError, 'closed stream'
      end
      raise 'unexpected incoming data' unless selector.get_incoming_data(socket, 0).nil?
      raise 'classification hook not reached' unless classified
      fixture.assert_send_error(settings, error)
    RUBY
  end

  def test_retirement_after_response_settings_lookup_does_not_duplicate_error
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      selector = fixture.selector
      socket = fixture.socket
      # Nonpersistent settings exercise socket classification after lookup;
      # persistent queries use their recorded TCP type instead.
      settings = fixture.settings(socket, persistent: false)
      response = fixture.response(settings)
      error = Dnsruby::SocketEofResolvError.new('write failed after response lookup')
      classified = false
      socket.define_singleton_method(:getsockopt) do |*|
        classified = true
        selector.fail_tcp_send(settings, error)
        raise IOError, 'closed stream'
      end
      selector.send_response_to_client(response, response.encode, socket)
      raise 'response classification hook not reached' unless classified
      fixture.assert_send_error(settings, error)
    RUBY
  end

  def test_recvfrom_failure_after_socket_retirement_is_harmless
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      settings = fixture.settings(fixture.socket)
      error = Dnsruby::SocketEofResolvError.new('write failed before recvfrom failure')
      fixture.selector.fail_tcp_send(settings, error)
      raise 'socket map was not retired' if fixture.table(:socket_hash).key?(settings.socket)
      fixture.selector.handle_recvfrom_failure(settings.socket, IOError.new('closed stream'))
      fixture.assert_send_error(settings, error)
    RUBY
  end

  def test_tcp_bytes_returning_after_retirement_do_not_restore_framing_buffers
    assert_isolated(<<~'RUBY')
      [:partial_prefix, :complete_prefix, :partial_body].each do |stage|
        fixture = RetirementFixture.new
        selector = fixture.selector
        socket = fixture.socket
        settings = fixture.settings(socket)
        error = Dnsruby::SocketEofResolvError.new("write failed during #{stage}")
        if stage == :partial_body
          # The prefix was already consumed and one body byte was buffered.
          fixture.table(:tcp_buffers)[socket] = [+'a', 4, false]
        end
        read = false
        socket.define_singleton_method(:recv_nonblock) do |_length|
          read = true
          selector.fail_tcp_send(settings, error)
          stage == :complete_prefix ? [4].pack('n') : "\0".b
        end
        raise "#{stage}: unexpected complete frame" unless selector.tcp_read(socket) == false
        raise "#{stage}: read hook not reached" unless read
        fixture.assert_send_error(settings, error)
      end
    RUBY
  end

  def test_response_and_send_failure_have_only_one_terminal_owner
    assert_isolated(<<~'RUBY')
      [:failure_first, :response_first].each do |order|
        fixture = RetirementFixture.new
        selector = fixture.selector
        settings = fixture.settings(fixture.socket)
        response = fixture.response(settings)
        error = Dnsruby::SocketEofResolvError.new("write failed #{order}")
        interrupted = false
        if order == :failure_first
          sender = settings.single_resolver
          check = sender.method(:check_response)
          sender.define_singleton_method(:check_response) do |*args|
            result = check.call(*args)
            interrupted = true
            selector.fail_tcp_send(settings, error)
            result
          end
        else
          push = selector.method(:push_to_client)
          selector.define_singleton_method(:push_to_client) do |*args|
            interrupted = true
            raise 'response had not claimed its settings' if query_settings_for_id(settings.client_query_id).equal?(settings)
            fail_tcp_send(settings, error)
            push.call(*args)
          end
        end
        selector.send_response_to_client(response, response.encode, settings.socket)
        raise "#{order}: ownership hook not reached" unless interrupted
        if order == :failure_first
          fixture.assert_send_error(settings, error)
        else
          fixture.assert_response(settings, response)
          fixture.assert_retired(settings.socket)
        end
      end
    RUBY
  end

  def test_stale_response_cannot_claim_a_replacement_with_the_same_client_id
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      selector = fixture.selector
      original = fixture.settings(fixture.socket)
      replacement = fixture.settings(fixture.socket, register: false)
      response = fixture.response(original)
      sender = original.single_resolver
      check = sender.method(:check_response)
      replaced = false
      sender.define_singleton_method(:check_response) do |*args|
        result = check.call(*args)
        selector.add_to_select(replacement)
        selector.fail_tcp_send(original, Dnsruby::SocketEofResolvError.new('old write failed'))
        replaced = true
        result
      end
      selector.send_response_to_client(response, response.encode, original.socket)
      raise 'replacement hook not reached' unless replaced
      raise 'stale response was delivered' unless fixture.events(original).empty?
      raise 'replacement was consumed' unless selector.query_settings_for_id(:query).equal?(replacement)
      raise 'replacement received stale failure' unless fixture.events(replacement).empty?
      fixture.assert_retired(original.socket)
      response = fixture.response(replacement)
      selector.send_response_to_client(response, response.encode, replacement.socket)
      fixture.assert_response(replacement, response)
    RUBY
  end

  def test_timeout_snapshot_cannot_expire_a_replacement_with_the_same_client_id
    assert_isolated(<<~'RUBY')
      fixture = RetirementFixture.new
      selector = fixture.selector
      deadline = Dnsruby::TransportClock.now - 1
      expired = Object.new
      original = fixture.settings(fixture.socket, endtime: expired)
      replacement = fixture.settings(fixture.socket, register: false)
      replaced = false
      expired.define_singleton_method(:<) do |other|
        # process_timeouts has copied its work and released the selector mutex.
        # Another sender replaces this ID before the expired entry is claimed.
        selector.add_to_select(replacement)
        replaced = true
        deadline < other
      end
      selector.process_timeouts
      raise 'timeout snapshot hook not reached' unless replaced
      raise 'old attempt received timeout' unless fixture.events(original).empty?
      raise 'replacement received old timeout' unless fixture.events(replacement).empty?
      raise 'replacement registration was consumed' unless selector.query_settings_for_id(:query).equal?(replacement)
      raise 'replacement deadline was removed' unless fixture.table(:timeouts)[:query] == replacement.endtime
      # The replacement can still expire on its own deadline.
      fixture.table(:timeouts)[:query] = Dnsruby::TransportClock.now - 1
      selector.process_timeouts
      events = fixture.events(replacement)
      raise 'replacement did not receive one timeout' unless events.length == 1 &&
        events.first[0, 3] == [:query, Dnsruby::Resolver::EventType::ERROR, nil] &&
        events.first.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'timed-out replacement retained' if selector.query_settings_for_id(:query)
    RUBY
  end

  private

  def assert_isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    script = SUBPROCESS_SETUP + "\nTimeout.timeout(10) do\n" + body + "\nend\n"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', script)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
