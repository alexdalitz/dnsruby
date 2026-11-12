require_relative 'tc_pipeline_send'

class TestResolverValidation < Minitest::Test
  FIXTURE = <<~'RUBY'
    SELECTOR.singleton_class.remove_method(:notify_queue_observers)
    clock = 1000.0
    # Advance slightly on reads so an immediately scheduled send is due on
    # the next tick, without sleeps or dependence on the host's clock.
    Dnsruby::TransportClock.define_singleton_method(:now) { clock += 0.0001 }
    validators = []
    Dnsruby::ValidatorThread.define_method(:run) { validators << self }
    Dnsruby::Dnssec.define_singleton_method(:validate_with_query) do |_query, answer|
      answer.security_level = Dnsruby::Message::SecurityLevel::SECURE
    end
    resolver = Dnsruby::Resolver.new(nameserver: ['127.0.0.1', '127.0.0.2'],
      dnssec: true, do_validation: true, do_caching: false,
      retry_times: 2, retry_delay: 1, query_timeout: 10)
    resolver.single_resolvers.each { |writer| writer.define_singleton_method(:send_async) { |*| } }
    results = Queue.new

    def start_query(resolver, results, name = 'validation.example.')
      request = query(name)
      request.do_validation = true
      resolver.send_async(request, results, :client)
      SELECTOR.send_tick_to_observers
      request
    end

    def accept_answer(settings, rcode = Dnsruby::RCode::NOERROR)
      answer = settings.query.clone
      answer.header.qr = true
      answer.header.rcode = rcode
      SELECTOR.push_response_for_query(settings, answer, settings.query, settings.single_resolver)
      SELECTOR.send_queued_responses
      answer
    end

    def attempts
      K.class_variable_get(:@@query_hash).values
    end

    def expect_completion(results, error_class = nil, name = 'validation.example')
      raise 'missing or duplicate completion' unless results.size == 1
      id, answer, error = results.pop
      raise 'wrong completion id' unless id == :client
      if error_class
        raise "wrong error: #{error.inspect}" unless error.is_a?(error_class)
      else
        raise "unexpected error: #{error.inspect}" if error
        raise 'wrong answer' unless answer.question.first.qname.to_s == name
      end
    end

    def expect_clean(resolver)
      engine = resolver.instance_variable_get(:@resolver_ruby)
      tables = [:@query_list, :@timeouts]
      tables << :@validation_queries if engine.instance_variable_defined?(:@validation_queries)
      tables.each do |table|
        raise "retained #{table}" unless engine.instance_variable_get(table).empty?
      end
      raise 'retained attempts' unless attempts.empty?
      raise 'retained observer' unless K.class_variable_get(:@@observers).empty?
    end
  RUBY

  def test_total_deadline_applies_during_positive_and_nxdomain_validation
    [0, 3].each do |rcode|
      isolated("rcode = #{rcode}\n" + <<~'RUBY')
        start_query(resolver, results)
        accept_answer(attempts.first, rcode)
        raise 'validation not pending' unless validators.size == 1 && results.empty?
        clock += 11
        SELECTOR.send_tick_to_observers
        expect_completion(results, Dnsruby::ResolvTimeout)
        validators.shift.do_validate
        SELECTOR.send_queued_validation_responses
        raise 'late validation completed twice' unless results.empty?
        expect_clean(resolver)
      RUBY
    end
  end

  def test_validation_finishing_after_deadline_times_out_even_before_next_tick
    isolated(<<~'RUBY')
      start_query(resolver, results)
      accept_answer(attempts.first)
      clock += 11
      validators.shift.do_validate
      SELECTOR.send_queued_validation_responses
      expect_completion(results, Dnsruby::ResolvTimeout)
      expect_clean(resolver)
    RUBY
  end

  def test_competing_error_or_answer_cannot_replace_the_accepted_validator
    [:servfail, :socket_error, :positive, :nxdomain, :validation_error].each do |event|
      isolated("competing = :#{event}\n" + <<~'RUBY')
        start_query(resolver, results)
        clock += 0.6
        SELECTOR.send_tick_to_observers
        first, second = attempts
        raise 'second server was not queried' unless first && second
        accept_answer(first)
        raise 'competing sends not canceled' unless attempts.empty?
        clock += 3
        SELECTOR.send_tick_to_observers
        raise 'retry continued during validation' unless attempts.empty?

        # A reply/error may already have been claimed and queued when the first
        # answer wins. Exercise those callbacks even though its send is canceled.
        response = second.query.clone
        response.header.qr = true
        kind = Dnsruby::Resolver::EventType::RECEIVED
        error = case competing
        when :servfail then Dnsruby::ServFail.new
        when :socket_error
          kind = Dnsruby::Resolver::EventType::ERROR
          Dnsruby::OtherResolvError.new('peer closed')
        when :nxdomain
          response.header.rcode = Dnsruby::RCode::NXDOMAIN
          Dnsruby::NXDomain.new
        when :validation_error
          kind = Dnsruby::Resolver::EventType::VALIDATED
          Dnsruby::VerifyError.new('other answer failed')
        end
        second.client_queue << [second.client_query_id, kind, response, error]
        SELECTOR.notify_queue_observers(second.client_queue, second.client_query_id)
        if competing == :positive || competing == :nxdomain
          SELECTOR.push_validation_response_to_select(second.client_query_id,
            second.client_queue, response, nil, second.query, second.single_resolver)
          SELECTOR.send_queued_validation_responses
        end
        raise 'competing event completed query' unless results.empty?
        validators.shift.do_validate
        SELECTOR.send_queued_validation_responses
        expect_completion(results)
        expect_clean(resolver)
      RUBY
    end
  end

  def test_accepted_nxdomain_and_validation_failure_keep_their_error_semantics
    [:nxdomain, :bogus].each do |outcome|
      isolated("outcome = :#{outcome}\n" + <<~'RUBY')
        start_query(resolver, results)
        accept_answer(attempts.first, outcome == :nxdomain ? 3 : 0)
        if outcome == :bogus
          Dnsruby::Dnssec.define_singleton_method(:validate_with_query) { |*| raise Dnsruby::VerifyError, 'bad signature' }
        end
        validators.shift.do_validate
        SELECTOR.send_queued_validation_responses
        expect_completion(results, outcome == :nxdomain ? Dnsruby::NXDomain : Dnsruby::VerifyError)
        expect_clean(resolver)
      RUBY
    end
  end

  def test_timeout_or_close_and_id_reuse_ignore_the_old_validator
    [:timeout, :close].each do |finish|
      isolated("finish = :#{finish}\n" + <<~'RUBY')
        start_query(resolver, results)
        accept_answer(attempts.first)
        old_validator = validators.shift
        if finish == :timeout
          clock += 11
          SELECTOR.send_tick_to_observers
        else
          resolver.close
        end
        expect_completion(results, finish == :timeout ? Dnsruby::ResolvTimeout : Dnsruby::OtherResolvError)
        expect_clean(resolver)

        start_query(resolver, results, 'replacement.example.')
        old_validator.do_validate
        SELECTOR.send_queued_validation_responses
        raise 'old validator completed reused id' unless results.empty?
        accept_answer(attempts.first)
        validators.shift.do_validate
        SELECTOR.send_queued_validation_responses
        expect_completion(results, nil, 'replacement.example')
        expect_clean(resolver)
      RUBY
    end
  end

  private

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e',
      "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(10) do\n#{FIXTURE}\n#{body}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
