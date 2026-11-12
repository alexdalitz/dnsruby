require_relative 'tc_pipeline_send'

class TestResolverConcurrency < Minitest::Test
  def test_concurrent_first_use_publishes_one_complete_configuration_and_engine
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      Dnsruby::Config.define_singleton_method(:default_config_hash) { { nameserver: ['127.0.0.1'] } }
      original = Dnsruby::PacketSender.method(:new)
      entered, release = Queue.new, Queue.new
      creations = 0
      Dnsruby::PacketSender.define_singleton_method(:new) do |*args|
        creations += 1
        entered << true
        release.pop
        original.call(*args).tap do |sender|
          sender.define_singleton_method(:send_async) do |message, queue, id|
            answer = message.clone
            answer.header.qr = true
            SELECTOR.push_response_to_select(id, queue, answer, message, self)
          end
        end
      end
      resolver = Dnsruby::Resolver.new
      resolver.dnssec = false
      queues = [Queue.new, Queue.new]
      first = Thread.new { resolver.send_async(query('first.example.'), queues[0], :first) }
      entered.pop
      second = Thread.new { resolver.send_async(query('second.example.'), queues[1], :second) }
      Thread.pass until second.status == 'sleep'
      raise 'partial configuration published' if resolver.instance_variable_get(:@configured)
      release << true
      first.value
      second.value
      SELECTOR.send_tick_to_observers
      SELECTOR.send_queued_responses
      raise 'initialized more than once' unless creations == 1 && resolver.single_resolvers.length == 1
      queues.each do |queue|
        raise 'missing or duplicate completion' unless queue.size == 1
        raise 'cold query failed' unless queue.pop.last.nil?
      end
      resolver.close
    RUBY
  end

  def test_initialization_failure_is_shared_and_an_explicit_reconfiguration_recovers
    isolated(<<~'RUBY')
      Thread.report_on_exception = false
      Dnsruby::Config.define_singleton_method(:default_config_hash) { { nameserver: ['127.0.0.1'] } }
      original = Dnsruby::PacketSender.method(:new)
      entered, release = Queue.new, Queue.new
      creations = 0
      Dnsruby::PacketSender.define_singleton_method(:new) do |*|
        creations += 1
        entered << true
        release.pop
        raise ArgumentError, 'unusable nameserver'
      end
      resolver = Dnsruby::Resolver.new
      resolver.query_timeout = 0.02
      queues = [Queue.new, Queue.new]
      first = Thread.new { resolver.send_async(query, queues[0], :first) }
      entered.pop
      second = Thread.new { resolver.send_async(query, queues[1], :second) }
      Thread.pass until second.status == 'sleep'
      release << true
      first.value
      second.value
      raise 'failed initialization repeated' unless creations == 1
      sleep 0.03
      SELECTOR.send_tick_to_observers
      queues.each do |queue|
        raise 'failed configuration changed async completion' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      end
      SELECTOR.send_tick_to_observers
      raise 'initialization failure completed twice' unless queues.all?(&:empty?)
      Dnsruby::PacketSender.define_singleton_method(:new, original)
      resolver.nameserver = '127.0.0.1'
      raise 'explicit reconfiguration failed' unless resolver.single_resolvers.length == 1
      raise 'failure retained' if resolver.instance_variable_get(:@configuration_error)
    RUBY
  end

  def test_an_explicitly_empty_resolver_completes_each_query_once_without_a_timer_thread
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new
      resolver.single_resolvers = []
      resolver.query_timeout = 0.02
      queue = Queue.new
      resolver.send_async(query, queue, :empty)
      sleep 0.03
      SELECTOR.send_tick_to_observers
      raise 'empty resolver did not time out once' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      SELECTOR.send_tick_to_observers
      raise 'empty resolver completed twice' unless queue.empty?
      resolver.close
    RUBY
  end

  def test_hostname_reconfiguration_does_not_hold_the_selector_callback_lock
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      parent = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      parent.single_resolvers.first.define_singleton_method(:send_async) { |*| }
      parent.send_async(query('pending.example.'), Queue.new, :pending)
      bootstrap = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      queued = Queue.new
      bootstrap.single_resolvers.first.define_singleton_method(:send_async) do |message, queue, id|
        answer = message.clone
        answer.header.qr = true
        answer.add_answer(Dnsruby::RR.create(name: message.question.first.qname, type: 'A', address: '127.0.0.2'))
        SELECTOR.push_response_to_select(id, queue, answer, message, self)
        queued << true
      end
      Dnsruby::Config.define_singleton_method(:nameserver_resolver) { bootstrap }
      reconfigure = Thread.new { parent.nameserver = 'resolver.example.' }
      queued.pop
      # A selector loop ticks observers before dispatching the bootstrap answer.
      # Holding the parent query mutex while joining the constructor deadlocks.
      SELECTOR.send_tick_to_observers
      SELECTOR.send_queued_responses
      reconfigure.value
      raise 'hostname was not configured' unless parent.single_resolvers.first.server == '127.0.0.2'
      parent.close
      bootstrap.close
    RUBY
  end

  def test_every_configuration_entry_point_recovers_an_initially_empty_resolver
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [:add_server, :single_resolvers=, :nameserver=].each do |entry|
        resolver = Dnsruby::Resolver.new(nameserver: [], dnssec: false)
        raise 'fixture did not record empty configuration' unless resolver.instance_variable_get(:@configuration_error)
        value = entry == :single_resolvers= ? [Dnsruby::PacketSender.new(server: '127.0.0.1')] : '127.0.0.1'
        resolver.public_send(entry, value)
        resolver.add_config_nameservers
        raise 'failed initialization retained after recovery' if resolver.instance_variable_get(:@configuration_error)
        raise 'server missing after recovery' unless resolver.single_resolvers.size == 1
        resolver.single_resolvers.first.define_singleton_method(:send_async) do |message, queue, id|
          answer = message.clone
          answer.header.qr = true
          SELECTOR.push_response_to_select(id, queue, answer, message, self)
        end
        queue = Queue.new
        resolver.send_async(query, queue, :recovered)
        SELECTOR.send_queued_responses
        raise 'recovered query failed' unless queue.size == 1 && queue.pop.last.nil?
        resolver.close
      end
    RUBY
  end

  def test_close_cannot_observe_a_query_before_its_selector_observer_exists
    isolated(<<~'RUBY')
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      resolver.single_resolvers.first.define_singleton_method(:send_async) { |*| }
      entered, release, errors = Queue.new, Queue.new, Queue.new
      add_observer = SELECTOR.method(:add_observer)
      SELECTOR.define_singleton_method(:add_observer) do |*args|
        entered << true
        release.pop
        add_observer.call(*args)
      end
      queue = Queue.new
      sending = Thread.new { resolver.send_async(query, queue, :closing) }
      entered.pop
      closing = Thread.new do
        resolver.close
      rescue StandardError => error
        errors << error
      end
      Thread.pass until !closing.alive? || closing.status == 'sleep'
      raise 'close saw an unpublished observer' unless closing.alive? && errors.empty?
      release << true
      sending.value
      closing.value
      raise 'concurrent close raised' unless errors.empty?
      raise 'query did not complete once' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::OtherResolvError)
      raise 'observer retained after close' unless K.class_variable_get(:@@observers).empty?
    RUBY
  end

  private

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
