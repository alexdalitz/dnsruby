require_relative 'tc_pipeline_send'

class QueryControlTest < Minitest::Test
  def test_cancelled_lookup_leaves_unrelated_queries_running
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
        do_caching: false, retry_times: 1, query_timeout: 60)
      submitted, finished = Queue.new, Queue.new
      resolver.single_resolvers.each do |sender|
        sender.define_singleton_method(:send_async) { |*| }
      end
      send_async = resolver.method(:send_async)
      resolver.define_singleton_method(:send_async) do |*args|
        id = send_async.call(*args)
        submitted << true
        id
      end
      unrelated = Queue.new
      resolver.send_async(query('unrelated.example.'), unrelated, :unrelated)
      submitted.pop
      control = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + 30)
      waiter = Thread.new do
        begin
          Dnsruby::QueryControl.with(control) do
            resolver.query_no_validation_or_recursion('cancelled.example.', 'A')
          end
          finished << :unexpected_response
        rescue Dnsruby::QueryControl::Cancelled => error
          finished << [error, Dnsruby::QueryControl.current]
        end
      end
      Timeout.timeout(3) { submitted.pop }
      control.cancel
      result = Timeout.timeout(3) { finished.pop }
      waiter.join
      raise 'wrong cancellation result' unless result.first.instance_of?(Dnsruby::QueryControl::Cancelled)
      raise 'query control leaked into later work' unless result.last.nil?
      engine = resolver.instance_variable_get(:@resolver_ruby)
      raise 'cancelled another query or retained cancelled work' unless engine.instance_variable_get(:@query_list).keys == [:unrelated]
      raise 'unrelated query completed' unless unrelated.empty?
      resolver.close
      raise 'lookup observer retained after close' unless K.class_variable_get(:@@observers).empty?
    RUBY
  end

  def test_root_hint_address_lookups_obey_deadlines_and_cancellation
    isolated(<<~'RUBY')
      [:cancel, :timeout].each do |reason|
        control = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + (reason == :timeout ? 0.02 : 30))
        packet = Dnsruby::Message.new('.', 'NS')
        packet.add_answer(Dnsruby::RR.create('. 300 IN NS ns.example.'))
        resolver = Object.new
        [:nameservers=, :recurse=].each { |name| resolver.define_singleton_method(name) { |*| } }
        resolver.define_singleton_method(:single_resolvers) { [Object.new] }
        resolver.define_singleton_method(:query_no_validation_or_recursion) { |*| packet }
        sent, cancelled = [], []
        engine = Object.new
        engine.define_singleton_method(:cancel_query) { |id, queue| cancelled << [id, queue] }
        resolver.instance_variable_set(:@resolver_ruby, engine)
        resolver.define_singleton_method(:send_async) do |_message, queue|
          id = sent.length
          sent << [id, queue]
          control.cancel if reason == :cancel && sent.length == 2
          id
        end
        expected = reason == :cancel ? Dnsruby::QueryControl::Cancelled : Dnsruby::QueryControl::DeadlineExceeded
        begin
          Dnsruby::QueryControl.with(control) do
            Dnsruby::Recursor.set_hints(['127.0.0.1'], resolver)
          end
          raise 'unfinished hint lookups returned successfully'
        rescue expected
        end
        raise 'both A and AAAA lookups should have started' unless sent.length == 2
        raise 'hint lookups were not cancelled' unless cancelled == sent
        raise 'query control leaked after hint lookup failure' unless Dnsruby::QueryControl.current.nil?
      end
    RUBY
  end

  private

  def isolated(code)
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__),
      '-e', TestPipelineSend::FIXTURE + code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
