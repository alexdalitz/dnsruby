require_relative 'spec_helper'
require 'open3'
require 'rbconfig'

class TestPipelineRetry < Minitest::Test
  # Native response checking and sending run unchanged. Fake transport methods
  # inject the competing completion at a known boundary, without real sockets.
  # A child owns all singleton tables, cache hooks, and socket constructors.
  FIXTURE = <<~'RUBY'
    require 'dnsruby'
    require 'timeout'
    Dnsruby.log.level = Logger::FATAL

    class RetrySocket
      attr_accessor :on_send
      attr_reader :writes
      def initialize(tcp)
        @tcp, @closed, @writes = tcp, false, []
      end
      def closed?; @closed; end
      def close; @closed = true; end
      def bind(*); end
      def connect(*); end
      def getsockopt(*)
        raise IOError, 'closed stream' if closed?
        Struct.new(:data).new([@tcp ? Socket::SOCK_STREAM : Socket::SOCK_DGRAM].pack('i'))
      end
      def send(bytes, *)
        raise IOError, 'closed stream' if closed?
        @writes << bytes.dup
        @on_send.call if @on_send
        bytes.bytesize
      end
      def write_nonblock(bytes); send(bytes, 0); end
    end

    class RetryFixture
      attr_reader :selector, :sender, :original, :udp, :tcp, :replacement, :winner_error

      def initialize(kind = :formerr, pipeline: true)
        @klass = Dnsruby::SelectThread
        {
          mutex: Mutex.new, sockets: Set.new, query_hash: {}, socket_hash: {}, timeouts: {},
          socket_is_persistent: {}, socket_remaining_queries: {}, tcp_buffers: {},
          queued_exceptions: [], queued_responses: [], queued_validation_responses: [],
          observers: {}, tick_observers: [], select_thread: Thread.current
        }.each { |name, value| @klass.class_variable_set("@@#{name}", value) }
        @selector = @klass.send(:allocate)
        @selector.define_singleton_method(:wake_up_select_thread) {}
        @selector.define_singleton_method(:check_select_thread_synchronized) {}
        @selector.define_singleton_method(:notify_queue_observers) { |*| }
        @deferred_sends = []
        deferred_sends = @deferred_sends
        defer_send = @selector.method(:defer_send)
        @selector.define_singleton_method(:defer_send) do |*args, &operation|
          defer_send.call(*args, &operation).tap { |task| deferred_sends << task }
        end
        selector = @selector
        @klass.define_singleton_method(:instance) { selector }
        @sender = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: pipeline,
          tcp_pipelining_max_queries: :infinite, packet_timeout: 1, dnssec: false)
        @udp, @tcp = RetrySocket.new(false), RetrySocket.new(true)
        udp, tcp = @udp, @tcp
        UDPSocket.define_singleton_method(:new) { |*| udp }
        Socket.define_singleton_method(:tcp) { |*args, **options| tcp }
        @sender.define_singleton_method(:tcp_pipeline_socket) { |_| [tcp, false] }
        @kind = kind
        @original = settings(RetrySocket.new(kind == :formerr), :retry, @sender)
        @original.is_persistent_socket = pipeline && kind == :formerr
        @original.query.add_additional(Dnsruby::RR::OPT.new(4096)) if kind == :formerr
        @selector.add_to_select(@original)
        Thread.current[:dnsruby_response_query] = nil
      end

      def table(name)
        @klass.class_variable_get("@@#{name}")
      end

      def settings(socket, id, sender = @sender)
        query = Dnsruby::Message.new('retry.example.')
        query.do_validation = query.do_caching = false
        query.header.rd = true
        @klass::QuerySettings.new(query.encode, query, false, Queue.new, id, socket,
          '127.0.0.1', 53, Dnsruby::TransportClock.now + 60, 512, sender)
      end

      def response(settings = @original)
        settings.query.clone.tap do |message|
          message.header.qr = true
          message.header.rcode = Dnsruby::RCode::NOERROR
          message.header.tc = false
        end
      end

      def retry_response
        message = response
        if @kind == :formerr
          message.header.rcode = Dnsruby::RCode::FORMERR
        else
          message.header.tc = true
        end
        message
      end

      def compete(action)
        case action
        when :live
        when :failed
          @winner_error = Dnsruby::SocketEofResolvError.new('original send failed')
          current = @selector.query_settings_for_id(:retry)
          if current && current.socket.nil?
            @selector.fail_query_if_current(:retry, current.client_queue, current, @winner_error)
          else
            @selector.fail_tcp_send(@original, @winner_error)
          end
        when :expired
          table(:timeouts)[:retry] = Dnsruby::TransportClock.now - 1
          @selector.process_timeouts
        when :replaced
          @replacement = settings(RetrySocket.new(true), :retry)
          @selector.add_to_select(@replacement)
        else
          raise "unknown competing action #{action}"
        end
      end

      def check_retry(action = nil, wait: true)
        message = retry_response
        wire = message.encode
        if action
          fixture = self
          if @kind == :formerr
            remove = @original.query.method(:remove_additional)
            @original.query.define_singleton_method(:remove_additional) do
              remove.call
              fixture.compete(action)
            end
          else
            # This getter is reached in the native truncation branch immediately
            # before it calls send_async with use_tcp=true.
            truncated = message.header.method(:tc)
            message.header.define_singleton_method(:tc) do
              fixture.compete(action)
              truncated.call
            end
          end
        end
        @selector.process_message(message, wire, @original.socket)
        raise 'response context leaked' if Thread.current[:dnsruby_response_query]
        @deferred_sends.shift.value until !wait || @deferred_sends.empty?
      end

      def events(settings = @original)
        @selector.send_queued_exceptions
        @selector.send_queued_responses
        @selector.send_queued_validation_responses
        result = []
        result << settings.client_queue.pop(true) until settings.client_queue.empty?
        result
      end

      def assert_stale(action)
        actual = events
        case action
        when :failed, :expired
          error_class = action == :failed ? Dnsruby::SocketEofResolvError : Dnsruby::ResolvTimeout
          raise "#{action}: wrong terminal deliveries #{actual.inspect}" unless actual.length == 1 &&
            actual.first[0, 3] == [:retry, Dnsruby::Resolver::EventType::ERROR, nil] &&
            actual.first.last.is_a?(error_class)
          raise 'wrong failure owner' if action == :failed && !actual.first.last.equal?(@winner_error)
          raise "#{action}: original query resurrected" if @selector.query_settings_for_id(:retry)
          raise "#{action}: stale timeout retained" if table(:timeouts).key?(:retry)
        when :replaced
          raise 'stale attempt published a delivery' unless actual.empty?
          raise 'replacement registration consumed' unless @selector.query_settings_for_id(:retry).equal?(@replacement)
          raise 'replacement received stale delivery' unless events(@replacement).empty?
          raise 'replacement timeout removed' unless table(:timeouts)[:retry] == @replacement.endtime
        end
      end

      def assert_success(settings, message)
        @selector.process_message(message, message.encode, settings.socket)
        expected = [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED].map do |type|
          [settings.client_query_id, type, message, nil]
        end
        actual = events(settings)
        raise "wrong success deliveries: #{actual.inspect}" unless actual == expected
        raise 'completed registration retained' if @selector.query_settings_for_id(settings.client_query_id)
        raise 'completed timeout retained' if table(:timeouts).key?(settings.client_query_id)
      end

      def assert_no_retry_writes
        raise 'stale UDP retry was sent' unless @udp.writes.empty?
        raise 'stale TCP retry was sent' unless @tcp.writes.empty?
      end
    end
  RUBY

  def test_native_formerr_and_truncated_responses_retry_and_complete
    assert_isolated(<<~'RUBY')
      [:formerr, :truncated].each do |kind|
        [true, false].each do |pipeline|
          fixture = RetryFixture.new(kind, pipeline: pipeline)
          fixture.check_retry
          current = fixture.selector.query_settings_for_id(:retry)
          raise "#{kind}: retry missing" unless current && !current.equal?(fixture.original)
          raise 'retry changed the client queue' unless current.client_queue.equal?(fixture.original.client_queue)
          raise 'premature retry delivery' unless fixture.events.empty?
          if kind == :formerr
            raise 'FORMERR did not retry over UDP' unless current.socket.equal?(fixture.udp) && fixture.udp.writes.length == 1
            sent = Dnsruby::Message.decode(fixture.udp.writes.first)
            raise 'FORMERR retry retained EDNS' unless sent.header.arcount == 0
          else
            raise 'truncated UDP did not retry over TCP' unless current.socket.equal?(fixture.tcp) && !fixture.tcp.writes.empty?
            frame = fixture.tcp.writes.join
            raise 'invalid retry frame' unless frame.unpack1('n') == frame.bytesize - 2
            sent = Dnsruby::Message.decode(frame.byteslice(2..))
          end
          raise 'retry changed DNS transaction ID' unless sent.header.id == fixture.original.query.header.id
          fixture.assert_success(current, fixture.response(current))
        end
      end
    RUBY
  end

  def test_native_protocol_retries_get_a_fresh_packet_deadline
    assert_isolated(<<~'RUBY')
      [:formerr, :truncated].each do |kind|
        [true, false].each do |pipeline|
          fixture = RetryFixture.new(kind, pipeline: pipeline)
          crossed = false
          cross_old_deadline = -> do
            crossed = true
            fixture.original.endtime = Dnsruby::TransportClock.now - 1
            fixture.table(:timeouts)[:retry] = fixture.original.endtime
            # No timeout has claimed this attempt: its response is already
            # being processed, and its protocol retry has its own deadline.
          end
          fixture.udp.define_singleton_method(:connect) { |*| cross_old_deadline.call }
          Socket.define_singleton_method(:tcp) do |*args, **options|
            cross_old_deadline.call
            fixture.tcp
          end
          fixture.sender.define_singleton_method(:tcp_pipeline_socket) do |_|
            cross_old_deadline.call
            [fixture.tcp, false]
          end
          fixture.check_retry
          raise 'connection boundary not exercised' unless crossed
          current = fixture.selector.query_settings_for_id(:retry)
          raise 'live protocol retry discarded' unless current && !current.equal?(fixture.original)
          raise 'retry inherited old deadline' unless current.endtime > Dnsruby::TransportClock.now
          raise 'premature retry event' unless fixture.events.empty?
          transport = kind == :formerr ? fixture.udp : fixture.tcp
          raise 'retry was not sent' if transport.writes.empty?
          fixture.assert_success(current, fixture.response(current))
        end
      end
    RUBY
  end

  def test_deferred_protocol_retry_uses_its_own_packet_deadline
    assert_isolated(<<~'RUBY')
      fixture = RetryFixture.new(:truncated)
      lock = Mutex.new
      fixture.sender.instance_variable_set(:@pipeline_mutex, lock)
      lock.lock
      send_query = fixture.sender.method(:send_dnsruby)
      worker = nil
      fixture.sender.define_singleton_method(:send_dnsruby) { |*args| worker = send_query.call(*args) }
      begin
        fixture.check_retry(wait: false)
        raise 'selector retry was not deferred' unless worker.respond_to?(:value)
        fixture.original.endtime = Dnsruby::TransportClock.now - 1
        fixture.table(:timeouts)[:retry] = fixture.original.endtime
        lock.unlock
        worker.value
        current = fixture.selector.query_settings_for_id(:retry)
        raise 'unclaimed retry discarded after writer wait' unless current && !current.equal?(fixture.original)
        raise 'deferred retry inherited old deadline' unless current.endtime > Dnsruby::TransportClock.now
        raise 'premature retry event' unless fixture.events.empty?
        raise 'deferred retry not sent' if fixture.tcp.writes.empty?
        fixture.assert_success(current, fixture.response(current))
      ensure
        lock.unlock if lock.owned?
        worker.join if worker.is_a?(Thread)
      end
    RUBY
  end

  def test_native_retries_cannot_resurrect_failed_expired_or_replaced_settings
    assert_isolated(<<~'RUBY')
      [:formerr, :truncated].each do |kind|
        [:failed, :expired, :replaced].each do |action|
          fixture = RetryFixture.new(kind)
          fixture.check_retry(action)
          fixture.assert_stale(action)
          fixture.assert_no_retry_writes
          if action == :replaced
            fixture.assert_success(fixture.replacement, fixture.response(fixture.replacement))
          else
            fixture.selector.process_timeouts
            raise 'second terminal delivery' unless fixture.events.empty?
          end
        end
      end
    RUBY
  end

  def test_retry_encode_and_oversized_udp_errors_claim_only_the_original_attempt
    assert_isolated(<<~'RUBY')
      [:encode, :oversized_udp].each do |failure|
        [:live, :failed, :expired, :replaced].each do |action|
          fixture = RetryFixture.new
          fixture.sender.no_tcp = true if failure == :oversized_udp
          reached = false
          fixture.sender.define_singleton_method(:make_query_packet) do |*|
            reached = true
            fixture.compete(action)
            if failure == :encode
              raise Dnsruby::EncodeError, 'retry encoding failed'
            else
              'x' * 65_536
            end
          end
          fixture.check_retry
          raise 'early-error hook not reached' unless reached
          if action == :live
            expected = failure == :encode ? Dnsruby::EncodeError : IOError
            events = fixture.events
            raise "#{failure}: wrong early error" unless events.length == 1 &&
              events.first[1] == Dnsruby::Resolver::EventType::ERROR && events.first.last.is_a?(expected)
            raise 'early error retained original registration' if fixture.selector.query_settings_for_id(:retry)
            fixture.selector.process_timeouts
            raise 'early error delivered twice' unless fixture.events.empty?
          else
            fixture.assert_stale(action)
          end
          fixture.assert_no_retry_writes
        end
      end
    RUBY
  end

  def test_retry_cache_hit_claims_only_the_original_attempt
    assert_isolated(<<~'RUBY')
      [:live, :failed, :expired, :replaced].each do |action|
        fixture = RetryFixture.new
        fixture.original.query.do_caching = true
        cached = fixture.response
        cached.cached = true
        reached = false
        cache = Dnsruby::PacketSender.class_variable_get(:@@recursive_cache)
        cache.define_singleton_method(:find) do |*|
          reached = true
          fixture.compete(action)
          cached
        end
        fixture.check_retry
        raise 'cache lookup hook not reached' unless reached
        if action == :live
          expected = [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED].map do |type|
            [:retry, type, cached, nil]
          end
          raise 'cache hit delivered incorrectly' unless fixture.events == expected
          raise 'cached retry retained original registration' if fixture.selector.query_settings_for_id(:retry)
          raise 'cached retry retained timeout' if fixture.table(:timeouts).key?(:retry)
        else
          fixture.assert_stale(action)
        end
        fixture.assert_no_retry_writes
      end
    RUBY
  end

  def test_nonpipeline_retry_write_error_does_not_report_after_another_completion
    assert_isolated(<<~'RUBY')
      [:live, :failed, :expired, :replaced].each do |action|
        fixture = RetryFixture.new(:formerr, pipeline: false)
        reached = false
        fixture.udp.on_send = -> do
          reached = true
          fixture.compete(action)
          raise IOError, 'UDP retry send failed'
        end
        fixture.check_retry
        raise 'nonpipeline send hook not reached' unless reached
        raise 'failed retry socket retained' unless fixture.udp.closed?
        if action == :live
          events = fixture.events
          raise 'live retry error not delivered once' unless events.length == 1 &&
            events.first[1] == Dnsruby::Resolver::EventType::ERROR && events.first.last.is_a?(IOError)
          raise 'failed retry registration retained' if fixture.selector.query_settings_for_id(:retry)
        else
          fixture.assert_stale(action)
        end
      end
    RUBY
  end

  def test_nested_response_checks_restore_context_on_success_and_exception
    assert_isolated(<<~'RUBY')
      [:success, :exception].each do |mode|
        fixture = RetryFixture.new
        selector = fixture.selector
        outer = fixture.original
        inner_sender = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
        inner = fixture.settings(RetrySocket.new(true), :inner, inner_sender)
        selector.add_to_select(inner)
        outer_response, inner_response = fixture.response(outer), fixture.response(inner)
        sentinel = Object.new
        Thread.current[:dnsruby_response_query] = sentinel
        original_outer_check = fixture.sender.method(:check_response)
        original_inner_check = inner_sender.method(:check_response)
        inner_sender.define_singleton_method(:check_response) do |*args|
          raise 'inner context missing' unless response_query_settings(:inner).equal?(inner)
          raise 'wrong ID inherited context' if response_query_settings(:retry)
          raise 'wrong sender inherited context' if fixture.sender.response_query_settings(:inner)
          raise IOError, 'nested response failure' if mode == :exception
          original_inner_check.call(*args)
        end
        fixture.sender.define_singleton_method(:check_response) do |*args|
          raise 'outer context missing' unless response_query_settings(:retry).equal?(outer)
          begin
            selector.process_message(inner_response, inner_response.encode, inner.socket)
          ensure
            raise 'inner check lost outer context' unless Thread.current[:dnsruby_response_query].equal?(outer)
          end
          original_outer_check.call(*args)
        end
        begin
          selector.process_message(outer_response, outer_response.encode, outer.socket)
          raise 'nested exception was swallowed' if mode == :exception
          raise 'inner response missing' unless fixture.events(inner).length == 2
          raise 'outer response missing' unless fixture.events(outer).length == 2
        rescue IOError => error
          raise unless mode == :exception && error.message == 'nested response failure'
          raise 'failed check published a response' unless fixture.events(inner).empty? && fixture.events(outer).empty?
        ensure
          raise 'caller context not restored' unless Thread.current[:dnsruby_response_query].equal?(sentinel)
          Thread.current[:dnsruby_response_query] = nil
        end
      end
    RUBY
  end

  private

  def assert_isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    script = FIXTURE + "\nTimeout.timeout(10) do\n" + body + "\nend\n"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', script)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
