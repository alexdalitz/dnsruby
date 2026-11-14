require_relative 'tc_pipeline_send'
require_relative 'tc_review_transport_native'

class TestReleaseTransportFixes < Minitest::Test
  def isolated(source)
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-Ilib', '-e',
      TestPipelineSend::FIXTURE + "\nTimeout.timeout(5) do\n" + source + "\nend\n",
      chdir: File.expand_path('..', __dir__))
    assert(status.success?, "#{stdout}\n#{stderr}")
  end

  def test_published_configuration_serves_queries_during_nameserver_construction
    isolated(<<~'RUBY')
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      sent = Queue.new
      resolver.single_resolvers.first.define_singleton_method(:send_async) { |*| sent << true }
      original = Dnsruby::PacketSender.method(:new)
      entered, release = Queue.new, Queue.new
      Dnsruby::PacketSender.define_singleton_method(:new) do |*args|
        entered << true
        release.pop
        original.call(*args)
      end
      [:add_server, :nameserver=].each do |operation|
        configuring = Thread.new { resolver.public_send(operation, '127.0.0.2') }
        entered.pop
        begin
          caller = Thread.new { resolver.send_async(query, Queue.new) }
          raise 'query waited for replacement configuration' unless caller.join(1)
          caller.value
          raise 'published sender was not used' unless sent.pop(true)
        ensure
          release << true
          configuring.value
          caller&.join
        end
      end
      resolver.close
    RUBY
  end

  def test_failed_initial_configuration_waits_for_recovery_publication
    isolated(<<~'RUBY')
      resolver = Dnsruby::Resolver.new(nameserver: [], dnssec: false)
      raise 'expected failed initialization' unless resolver.instance_variable_get(:@configuration_error)
      original = Dnsruby::PacketSender.method(:new)
      entered, release, sent = Queue.new, Queue.new, Queue.new
      Dnsruby::PacketSender.define_singleton_method(:new) do |*args|
        entered << true
        release.pop
        writer = original.call(*args)
        writer.define_singleton_method(:send_async) { |*| sent << true }
        writer
      end
      configuring = Thread.new { resolver.nameserver = '127.0.0.1' }
      entered.pop
      caller = Thread.new { resolver.send_async(query, Queue.new) }
      begin
        raise 'query admitted before recovered senders were published' if caller.join(0.05)
      ensure
        release << true
        configuring.value
      end
      caller.value
      raise 'recovered sender was not used' unless sent.pop(true)
      raise 'configuration error survived publication' if resolver.instance_variable_get(:@configuration_error)
      resolver.close
    RUBY
  end

  def test_single_resolver_timeout_setters_update_the_existing_sender
    isolated(<<~'RUBY')
      resolver = Dnsruby::SingleResolver.new(server: '127.0.0.1', packet_timeout: 2)
      writer = resolver.single_resolvers.first
      [:packet_timeout=, :query_timeout=].zip([3, 4]).each do |setter, timeout|
        resolver.public_send(setter, timeout)
        raise 'sender was replaced' unless resolver.single_resolvers.first.equal?(writer)
        raise 'stale packet timeout' unless writer.packet_timeout == timeout &&
          resolver.packet_timeout == timeout && resolver.query_timeout == timeout
      end
      resolver.close
    RUBY
  end

  def test_selector_waits_for_an_empty_resolvers_exact_query_deadline
    isolated(<<~'RUBY')
      now = 100.0
      Dnsruby::TransportClock.define_singleton_method(:now) { now }
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new
      resolver.single_resolvers = []
      resolver.query_timeout = 0.05
      results = Queue.new
      resolver.send_async(query, results, :deadline)
      wakeup = FrameSocket.new
      K.class_variable_set(:@@wakeup_sockets, [wakeup, wakeup])
      K.class_variable_get(:@@sockets) << wakeup
      waits = []
      IO.define_singleton_method(:select) do |_read, _write, _errors, timeout|
        waits << timeout
        now += timeout
        nil
      end
      SELECTOR.do_select
      raise 'deadline was rounded to a polling interval' unless (waits.first - 0.05).abs < 0.000001
      result = results.pop(true)
      raise 'wrong completion' unless result.first == :deadline && result.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'duplicate completion' unless results.empty?
    RUBY
  end

  def test_selector_schedules_retries_at_their_exact_deadline
    isolated(<<~'RUBY')
      now = 100.0
      Dnsruby::TransportClock.define_singleton_method(:now) { now }
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
        retry_times: 2, retry_delay: 0.025, query_timeout: 0.2)
      sent = []
      resolver.single_resolvers.first.define_singleton_method(:send_async) { |*| sent << now }
      results = Queue.new
      resolver.send_async(query, results, :retries)
      wakeup = FrameSocket.new
      K.class_variable_set(:@@wakeup_sockets, [wakeup, wakeup])
      K.class_variable_get(:@@sockets) << wakeup
      IO.define_singleton_method(:select) do |_read, _write, _errors, timeout|
        now += timeout
        nil
      end
      SELECTOR.do_select
      raise 'missing or duplicate attempt' unless sent.length == 2
      raise 'retry missed its deadline' unless (sent.last - 100.05).abs < 0.000001
      raise 'query did not finish' unless results.pop(true).last.is_a?(Dnsruby::ResolvTimeout)
      raise 'duplicate completion' unless results.empty?
    RUBY
  end

  def test_idle_expiration_never_closes_a_pipeline_with_an_outstanding_query
    isolated(<<~'RUBY')
      now = 100.0
      Dnsruby::TransportClock.define_singleton_method(:now) { now }
      socket = FrameSocket.new
      writer = sender(socket)
      writer.tcp_idle_timeout = 2
      first = settings(socket, :first, query, writer)
      SELECTOR.add_to_select(first)
      SELECTOR.claim_query(first, true)
      now = 101.0
      SELECTOR.send(:expire_idle_sockets)
      raise 'closed before idle deadline' if socket.closed?
      second = settings(socket, :second, query, writer)
      SELECTOR.add_to_select(second)
      now = 110.0
      SELECTOR.send(:expire_idle_sockets)
      raise 'closed an active pipeline' if socket.closed?
      SELECTOR.claim_query(second, true)
      now = 112.0
      SELECTOR.send(:expire_idle_sockets)
      raise 'idle connection retained' unless socket.closed?
      assert_clean(socket)
      raise 'idle timer retained' unless K.class_variable_get(:@@socket_idle_deadlines).empty?
    RUBY
  end
end

class ReviewTransportNativeTest < Minitest::Test
  def test_total_query_timeout_is_not_rounded_to_half_a_second
    port, = udp_server { |_| [] }
    resolver = resolver_for(port, packet_timeout: 2, query_timeout: 0.05, do_caching: false)
    started = Dnsruby::TransportClock.now
    assert_raises(Dnsruby::ResolvTimeout) { query(resolver) }
    assert_operator(Dnsruby::TransportClock.now - started, :<, 0.3)
  end

  def test_idle_pipeline_closes_and_the_next_query_reconnects
    server = TCPServer.new('127.0.0.1', 0)
    @sockets << server
    clients = Queue.new
    worker do
      loop do
        client = server.accept
        @sockets << client
        clients << client
        request = read_frame(client)
        write_frame(client, response(request, 'connected'))
      end
    end
    resolver = resolver_for(server.addr[1], use_tcp: true, tcp_pipelining: true,
      tcp_pipelining_max_queries: :infinite, tcp_idle_timeout: 0.05, do_caching: false)
    assert_equal(['connected'], query(resolver).answer.first.strings)
    first = clients.pop
    assert_nil(Timeout.timeout(1) { first.read(1) }, 'client should close the idle stream')
    assert_equal(['connected'], query(resolver).answer.first.strings)
    refute_same(first, clients.pop)
  end
end
