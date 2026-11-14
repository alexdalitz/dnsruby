require_relative 'tc_pipeline_send'

class TestResolverConcurrency < Minitest::Test
  def test_busy_resolver_dispatches_a_new_query_without_waiting_for_a_tick
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      writer = resolver.single_resolvers.first
      sent = []
      writer.define_singleton_method(:send_async) { |_message, _queue, id| sent << id }
      slow_results, fast_results = Queue.new, Queue.new
      resolver.send_async(query('pending.example.'), slow_results, :pending)
      raise 'first query not dispatched' unless sent.size == 1
      resolver.query_timeout = 0.1
      resolver.send_async(query('fast.example.'), fast_results, :fast)
      raise 'busy resolver left new query waiting for a tick' unless sent.size == 2
      fast = SELECTOR.query_settings_for_id(sent.last)
      answer = fast.query.clone
      answer.header.qr = true
      SELECTOR.push_response_for_query(fast, answer, fast.query, writer)
      SELECTOR.send_queued_responses
      raise 'fast query did not finish independently' unless fast_results.size == 1 &&
        fast_results.pop.last.nil? && slow_results.empty?
      SELECTOR.send_tick_to_observers
      raise 'selector tick resent initial attempt' unless sent.size == 2
      resolver.close
    RUBY
  end

  def test_concurrent_admission_and_selector_ticks_dispatch_each_attempt_once
    isolated(<<~'RUBY')
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      counts, lock = Hash.new(0), Mutex.new
      resolver.single_resolvers.first.define_singleton_method(:send_async) do |_message, _queue, id|
        lock.synchronize { counts[id[2]] += 1 }
        Thread.pass
      end
      gate = Queue.new
      callers = 20.times.map do |index|
        Thread.new { gate.pop; resolver.send_async(query("parallel#{index}.example."), Queue.new, index) }
      end
      ticking = Thread.new { 100.times { SELECTOR.send_tick_to_observers; Thread.pass } }
      callers.length.times { gate << true }
      callers.each(&:value)
      ticking.value
      raise 'lost or duplicate initial attempts' unless counts.size == callers.size && counts.values.all? { |count| count == 1 }
      resolver.close
    RUBY
  end

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

  def test_close_and_id_reuse_ignore_an_old_received_response
    assert_stale_query_event_is_ignored(:RECEIVED)
  end

  def test_close_and_id_reuse_ignore_an_old_received_error
    assert_stale_query_event_is_ignored(:RECEIVED, :ServFail)
  end

  def test_close_and_id_reuse_ignore_an_old_transport_error
    assert_stale_query_event_is_ignored(:ERROR, :ServFail)
  end

  def test_close_and_id_reuse_ignore_an_old_validated_response
    assert_stale_query_event_is_ignored(:VALIDATED)
  end

  def test_close_and_id_reuse_ignore_an_old_validation_error
    assert_stale_query_event_is_ignored(:VALIDATED, :ServFail)
  end

  private

  def assert_stale_query_event_is_ignored(event_type, error_type = nil)
    isolated(<<~RUBY + <<~'RUBY')
      stale_event_type = Dnsruby::Resolver::EventType::#{event_type}
      stale_error = #{error_type ? "Dnsruby::#{error_type}.new" : 'nil'}
    RUBY
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      Thread.report_on_exception = false
      options = { nameserver: '127.0.0.1', dnssec: false, do_caching: false,
        packet_timeout: 60, query_timeout: 60 }
      resolver = Dnsruby::Resolver.new(options)
      unrelated = Dnsruby::Resolver.new(options)
      sends = Queue.new
      [resolver, unrelated].each do |parent|
        parent.single_resolvers.first.define_singleton_method(:send_async) do |message, queue, id|
          sends << [message, queue, id, self]
        end
      end
      queue, keeper_queue, unrelated_queue = Queue.new, Queue.new, Queue.new
      resolver.send_async(query('old.example.'), queue, :reused)
      old_message, old_queue, old_id, = sends.pop
      response = old_message.clone
      response.header.qr = true
      response.header.rcode = Dnsruby::RCode::SERVFAIL if stale_error
      old_queue << [old_id, stale_event_type, response, stale_error]

      engine = resolver.instance_variable_get(:@resolver_ruby)
      original = engine.method(:handle_queue_event)
      entered, release = Queue.new, Queue.new
      engine.define_singleton_method(:handle_queue_event) do |*args|
        if args.first.equal?(old_queue)
          entered << true
          release.pop
        end
        original.call(*args)
      end
      callback = Thread.new do
        # Exercise the real observer lookup, then pause the callback before it
        # can acquire the resolver lock. close cannot retract that lookup.
        SELECTOR.notify_queue_observers(old_queue, old_id)
        raise 'stale event completed the replacement query' unless queue.empty?
        pending = engine.instance_variable_get(:@timeouts)[:reused]
        replacement = engine.instance_variable_get(:@query_list)[:reused]
        raise 'stale event stopped the replacement send' unless pending && replacement &&
          replacement[3].size == 1 && SELECTOR.query_settings_for_id(replacement[3].first)

        # The same selector dispatch must still serve the replacement and a
        # different Resolver. No sockets or timing-dependent timeout is needed.
        SELECTOR.send_tick_to_observers
        until sends.empty?
          message, select_queue, id, sender = sends.pop
          answer = message.clone
          answer.header.qr = true
          SELECTOR.push_response_to_select(id, select_queue, answer, message, sender)
        end
        SELECTOR.send_queued_responses
      end
      entered.pop
      resolver.close
      raise 'close did not complete the old query once' unless
        queue.size == 1 && queue.pop.last.is_a?(Dnsruby::OtherResolvError)

      # Both new queries dispatch immediately, even while the old observer's
      # callback is paused. That stale callback must preserve their attempts.
      resolver.send_async(query('keeper.example.'), keeper_queue, :keeper)
      resolver.send_async(query('new.example.'), queue, :reused)
      unrelated.send_async(query('unrelated.example.'), unrelated_queue, :unrelated)
      release << true
      callback.value
      [[queue, :reused, 'new.example'], [keeper_queue, :keeper, 'keeper.example'],
        [unrelated_queue, :unrelated, 'unrelated.example']].each do |results, expected_id, name|
        raise 'query did not complete exactly once' unless results.size == 1
        id, answer, error = results.pop
        raise 'wrong query completion' unless id == expected_id && error.nil? &&
          answer.question.first.qname.to_s == name
      end
      raise 'completed queries retained selector ownership' unless K.class_variable_get(:@@query_hash).empty?
      resolver.close
      unrelated.close
    RUBY
  end

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
