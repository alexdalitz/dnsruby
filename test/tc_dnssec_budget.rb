require_relative 'tc_key_cache_identity'
require_relative 'tc_pipeline_send'
require_relative 'tc_resolver_validation'

class KeyCacheIdentityTest
  def test_expiration_alone_revokes_learned_keys_and_preserves_other_anchors
    @verifier.add_trust_anchor_with_expiration(@a, @now.to_i + 1)
    @verifier.add_trust_anchor_with_expiration(@b, @now.to_i + 120)
    assert(@verifier.verify(signed(@a, @a, 0)))
    Time.stub(:now, @now + 2) do
      # Do not read trust_anchors first: verification must notice expiry itself.
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(signed(@record, @a, 0)) }
      assert_empty(@verifier.trusted_keys)
      assert(@verifier.verify(signed(@record, @b, 1)))
      assert_equal([@b], @verifier.trust_anchors)
    end
  end

  def test_expiration_during_verification_blocks_publication_without_an_anchor_read
    @verifier.add_trust_anchor_with_expiration(@a, @now.to_i + 1)
    clock = @now
    Time.stub(:now, -> { clock }) do
      pause_after_verification(-> { clock = @now + 2 }) do
        assert(@verifier.verify(signed(@a, @a, 0)))
      end
      assert_empty(@verifier.instance_variable_get(:@trusted_keys).keys)
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(signed(@record, @a, 0)) }
    end
  end

  def test_matching_signatures_reuse_canonical_rdata_and_try_different_metadata
    valid = signed(@record, @a, 0).sigs.first
    invalid = 20.times.map do |i|
      valid.clone.tap do |sig|
        sig.original_ttl = 500 if i.odd?
        sig.signature = [i].pack('n') + "\0" * 62
      end
    end
    records = Dnsruby::RRSet.new([@record] + invalid + [valid])
    record = records.rrs.first
    encode = record.method(:encode_rdata)
    encodings = 0
    record.define_singleton_method(:encode_rdata) do |*args|
      encodings += 1
      encode.call(*args)
    end
    assert(@verifier.verify_rrset(records, [@b, @a]))
    assert_equal(1, encodings)
    assert_equal(300, record.ttl)
  end

  def test_wildcard_signature_and_invalid_label_count
    wildcard = Dnsruby::RR.create('*.collision.invalid. 300 IN A 192.0.2.1')
    signature = signed(wildcard, @a, 0).sigs.first
    signature.labels = 2
    bytes = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(wildcard, true) }.to_s
    der = @private_keys.first.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + bytes))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    signature.name = @record.name
    records = Dnsruby::RRSet.new([@record, signature])
    assert(@verifier.verify_rrset(records, @a))
    records.sigs.first.labels = 4
    assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, @a) }
  end

  def test_signature_limit_is_shared_across_nested_operations_and_can_be_configured
    limits = Dnsruby::Dnssec.validation_limits.merge(max_signature_verifications: 2)
    records = signed(@record, @a, 0)
    budget = Dnsruby::ValidationBudget.new(limits: limits)
    error = assert_raises(Dnsruby::ValidationLimitError) do
      Dnsruby::ValidationBudget.with(budget) do
        assert(@verifier.verify_rrset(records, @a))
        assert(@verifier.verify_rrset(records, @a))
        begin
          @verifier.verify_rrset(records, @a)
        rescue Dnsruby::VerifyError
          flunk('A nested limit must bypass ordinary verification fallbacks')
        end
      end
    end
    assert_nil(Dnsruby::ValidationBudget.current)
    assert_equal(error.backtrace, error.cause.backtrace)
    assert_raises(Dnsruby::ValidationLimitError) { budget.check! }
    assert_raises(Dnsruby::ValidationLimitError) do
      Dnsruby::ValidationBudget.with(budget) { flunk('An exhausted budget was reused') }
    end
    assert(@verifier.verify_rrset(records, @a))
  end

  def test_direct_verifier_limit_stops_colliding_key_fallback
    limits = Dnsruby::Dnssec.validation_limits.merge(max_signature_verifications: 1)
    records = signed(@record, @a, 0)
    Dnsruby::Dnssec.stub(:validation_limits, limits) do
      assert_raises(Dnsruby::ValidationLimitError) do
        @verifier.verify_rrset(records, [@b, @a])
      end
      assert_nil(Dnsruby::ValidationBudget.current)
      assert(@verifier.verify_rrset(records, @a))
    end
  end

  def test_dnssec_rrset_entry_point_keeps_the_verifiers_limit
    limits = Dnsruby::Dnssec.validation_limits.merge(max_signature_verifications: 1)
    records = signed(@record, @a, 0)
    Dnsruby::Dnssec.stub(:validation_limits, limits) do
      Dnsruby::Dnssec.anchor_verifier.stub(:verify_rrset, @verifier.method(:verify_rrset)) do
        assert_raises(Dnsruby::ValidationLimitError) do
          Dnsruby::Dnssec.verify_rrset(records, [@b, @a])
        end
      end
    end
    assert_nil(Dnsruby::ValidationBudget.current)
    assert_nil(Dnsruby::QueryControl.current)
  end

  def test_direct_verifier_checks_cancellation_after_an_early_success_return
    records = signed(@record, @a, 0)
    verify = ->(*) { Dnsruby::ValidationBudget.current.cancel; true }
    @verifier.stub(:verify_rrset_with_key, verify) do
      assert_raises(Dnsruby::ValidationCancelled) { @verifier.verify_rrset(records, @a) }
    end
    assert_nil(Dnsruby::ValidationBudget.current)
  end

  def test_discovery_exhaustion_does_not_become_an_insecure_delegation
    @verifier.add_trust_anchor(@a)
    key_response = Dnsruby::Message.new(@a.name, 'DNSKEY')
    signed(@a, @a, 0).each { |rr| key_response.add_answer(rr) }
    message = Dnsruby::Message.new(@record.name, 'A')
    queries = []
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
      queries << [name, type]
      if type == Dnsruby::Types.DS
        Dnsruby::ValidationBudget.current.check!(100_001)
      end
      key_response
    end

    Dnsruby::Dnssec.stub(:do_validation_with_recursor?, false) do
      Dnsruby::Dnssec.stub(:default_resolver, resolver) do
        @verifier.stub(:get_nameservers_for, resolver) do
          @verifier.stub(:get_nameservers_from_message, resolver) do
            assert_raises(Dnsruby::ValidationLimitError) do
              @verifier.try_to_follow_from_anchor(@a, message, @record.name)
            end
          end
        end
      end
    end
    assert_equal([Dnsruby::Types.DNSKEY, Dnsruby::Types.DS], queries.map(&:last))
    refute_equal(Dnsruby::Message::SecurityLevel.INSECURE, message.security_level)
    assert_nil(Dnsruby::ValidationBudget.current)
  end

  def test_work_limit_bounds_nsec3_hash_iterations
    budget = Dnsruby::ValidationBudget.new(limits: Dnsruby::Dnssec.validation_limits.merge(max_work: 100))
    assert_raises(Dnsruby::ValidationLimitError) do
      Dnsruby::ValidationBudget.with(budget) do
        Dnsruby::RR::NSEC3.calculate_hash('example.', 1000, ''.b, Dnsruby::Nsec3HashAlgorithms.SHA_1)
      end
    end
  end

  def test_cancellation_after_crypto_prevents_success_or_learned_key_publication
    records = signed(@a, @a, 0)
    @verifier.add_trust_anchor(@a)
    budget = Dnsruby::ValidationBudget.new
    key = @a.public_key
    verify = key.method(:dsa_verify_asn1)
    key.define_singleton_method(:dsa_verify_asn1) do |*args|
      result = verify.call(*args)
      budget.cancel
      result
    end
    assert_raises(Dnsruby::ValidationCancelled) do
      Dnsruby::ValidationBudget.with(budget) { @verifier.verify(records) }
    end
    assert_empty(@verifier.trusted_keys)
  end
end

class DnssecBudgetTest < Minitest::Test
  def test_lookup_stops_cross_validation_fallbacks_and_become_public_errors
    [Dnsruby::QueryControl::Cancelled, Dnsruby::QueryControl::DeadlineExceeded].each do |stop_class|
      public_class = stop_class == Dnsruby::QueryControl::Cancelled ?
        Dnsruby::ValidationCancelled : Dnsruby::ValidationLimitError
      error = assert_raises(public_class) do
        Dnsruby::ValidationBudget.with do |budget|
          assert_same(budget.control, Dnsruby::QueryControl.current)
          begin
            Dnsruby::ValidationBudget.with do
              if stop_class == Dnsruby::QueryControl::Cancelled
                budget.control.cancel
                Dnsruby::QueryControl.current.check!
              else
                Dnsruby::TransportClock.stub(:now, budget.deadline) do
                  Dnsruby::QueryControl.current.check!
                end
              end
            end
          rescue Dnsruby::VerifyError, Dnsruby::ResolvError
            flunk('A stopped lookup must bypass validation and lookup fallbacks')
          end
        end
      end
      assert_instance_of(stop_class, error.cause)
      assert_equal(error.cause.backtrace, error.backtrace)
      assert_nil(Dnsruby::ValidationBudget.current)
      assert_nil(Dnsruby::QueryControl.current)
    end
  end

  def test_validation_obeys_and_restores_an_enclosing_lookup_control
    parent = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + 1)
    assert_raises(Dnsruby::QueryControl::Cancelled) do
      Dnsruby::QueryControl.with(parent) do
        error = assert_raises(Dnsruby::ValidationCancelled) do
          Dnsruby::ValidationBudget.with do |budget|
            assert_equal(parent.deadline, budget.deadline)
            parent.cancel
            budget.check!
          end
        end
        assert_instance_of(Dnsruby::QueryControl::Cancelled, error.cause)
        assert_same(parent, Dnsruby::QueryControl.current)
        assert_nil(Dnsruby::ValidationBudget.current)
      end
    end
    assert_nil(Dnsruby::QueryControl.current)
  end

  def test_lookup_deadline_limits_validation_even_when_its_own_timeout_is_longer
    parent = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + 1)
    Dnsruby::QueryControl.with(parent) do
      error = assert_raises(Dnsruby::ValidationLimitError) do
        Dnsruby::ValidationBudget.with do |budget|
          Dnsruby::TransportClock.stub(:now, parent.deadline) { budget.check! }
        end
      end
      assert_instance_of(Dnsruby::QueryControl::DeadlineExceeded, error.cause)
      assert_same(parent, Dnsruby::QueryControl.current)
    end
    assert_nil(Dnsruby::QueryControl.current)
  end

  def test_lookup_waits_do_not_consume_dnssec_work_allowance
    limits = Dnsruby::Dnssec.validation_limits.merge(max_work: 1)
    budget = Dnsruby::ValidationBudget.new(limits: limits)
    replies = Queue.new
    3.times { replies << :reply }
    Dnsruby::ValidationBudget.with(budget) do
      budget.check!(1)
      3.times { assert_equal(:reply, Dnsruby::QueryControl.current.pop(replies)) }
    end
    assert_raises(Dnsruby::ValidationLimitError) { budget.check!(1) }
  end

  def test_exhaustion_stays_terminal_when_a_callback_swallows_the_abort
    budget = Dnsruby::ValidationBudget.new(limits: Dnsruby::Dnssec.validation_limits.merge(max_work: 1))
    rescued = false
    assert_raises(Dnsruby::ValidationLimitError) do
      Dnsruby::ValidationBudget.with(budget) do
        begin
          budget.check!(2)
        rescue StandardError
          rescued = true
        end
        true
      end
    end
    assert(rescued)
    assert_nil(Dnsruby::ValidationBudget.current)
  end

  def test_direct_validation_callback_does_not_swallow_cancellation
    level = Dnsruby::Message::SecurityLevel.BOGUS
    callback = ->(*) do
      Dnsruby::ValidationBudget.with do |budget|
        budget.cancel
        budget.check!
      end
    end
    assert_raises(Dnsruby::ValidationCancelled) do
      Dnsruby::Dnssec.try_validation(level, '', level, callback, Dnsruby::Message.new, nil)
    end
    assert_nil(Dnsruby::ValidationBudget.current)
  end

  def test_anchor_fallbacks_share_limits_and_stop_at_exhaustion
    limits = Dnsruby::Dnssec.validation_limits.merge(max_signature_verifications: 1)
    calls = []
    anchor = ->(*) do
      calls << :anchor
      Dnsruby::ValidationBudget.current.signature!
      raise Dnsruby::VerifyError, 'Try another anchor'
    end
    root = ->(*) do
      calls << :root
      Dnsruby::ValidationBudget.current.signature!
      raise Dnsruby::VerifyError, 'Try DLV'
    end
    dlv = ->(*) { flunk('Exhaustion must not try the DLV fallback') }
    Dnsruby::Dnssec.stub(:validation_limits, limits) do
      Dnsruby::Dnssec.anchor_verifier.stub(:verify_result, anchor) do
        Dnsruby::Dnssec.root_verifier.stub(:verify_result, root) do
          Dnsruby::Dnssec.dlv_verifier.stub(:verify_result, dlv) do
            assert_raises(Dnsruby::ValidationLimitError) do
              Dnsruby::Dnssec.verify(Dnsruby::Message.new('example.', 'A'))
            end
          end
        end
      end
    end
    assert_equal([:anchor, :root], calls)
    assert_nil(Dnsruby::ValidationBudget.current)
  end

  def test_worker_delivers_one_public_terminal_error_and_unregisters
    [Dnsruby::ValidationLimitError, Dnsruby::ValidationCancelled].each do |error_class|
      completions, registrations, removals = [], [], []
      selector = Object.new
      selector.define_singleton_method(:register_validation) { |*args| registrations << args; true }
      selector.define_singleton_method(:unregister_validation) { |*args| removals << args }
      selector.define_singleton_method(:push_validation_response_to_select) { |*args| completions << args }
      resolver = Object.new
      resolver.define_singleton_method(:dnssec) { true }
      query = Dnsruby::Message.new('example.', 'A')
      query.do_validation = true
      response = query.clone
      response.header.qr = true
      validator = Dnsruby::ValidatorThread.new(:client, Queue.new, response, nil, query, selector, resolver)
      validate = ->(*) do
        budget = Dnsruby::ValidationBudget.current
        budget.cancel if error_class == Dnsruby::ValidationCancelled
        budget.check!(100_001)
      end
      Dnsruby::Dnssec.stub(:validate_with_query, validate) do
        Dnsruby::PacketSender.stub(:cache, ->(*) { flunk('An aborted response was cached') }) do
          validator.do_validate
        end
      end
      assert_equal(1, completions.length)
      assert_instance_of(error_class, completions.first[3])
      assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, response.security_level)
      assert_equal(1, registrations.length)
      assert_instance_of(Dnsruby::QueryControl, registrations.first.last)
      assert_equal(registrations, removals)
      assert_nil(Dnsruby::ValidationBudget.current)
      assert_nil(Dnsruby::QueryControl.current)
    end
  end

  def test_deadline_and_configuration_validation
    budget = Dnsruby::ValidationBudget.new(deadline: Dnsruby::TransportClock.now - 1)
    assert_raises(Dnsruby::ValidationLimitError) { budget.check! }
    budget = Dnsruby::ValidationBudget.new
    budget.cancel
    assert_raises(Dnsruby::ValidationCancelled) { budget.check! }
    [:timeout, :max_work, :max_signature_verifications].each do |option|
      [0, -1, nil, '100'].each do |bad|
        assert_raises(ArgumentError) { Dnsruby::Dnssec.validation_limits = { option => bad } }
      end
    end
    assert_raises(ArgumentError) { Dnsruby::Dnssec.validation_limits = { unknown: 3 } }
  end

  def test_async_validation_admission_bounds_workers_and_queue
    code = <<~'RUBY'
      require 'dnsruby'
      require 'timeout'
      entered, release = Queue.new, Queue.new
      job = Object.new
      job.define_singleton_method(:do_validate) { entered << true; release.pop }
      4.times { raise 'worker rejected' unless Dnsruby::ValidatorThread.enqueue(job) }
      Timeout.timeout(3) { 4.times { entered.pop } }
      64.times { raise 'queue rejected' unless Dnsruby::ValidatorThread.enqueue(job) }
      raise 'unbounded admission' if Dnsruby::ValidatorThread.enqueue(job)
      raise 'too many workers' unless entered.empty?
      68.times { release << true }
      Timeout.timeout(3) { 64.times { entered.pop } }
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end

  def test_validation_pool_recovers_after_fork_and_worker_exit
    skip 'fork unavailable' unless Process.respond_to?(:fork)
    code = <<~'RUBY'
      require 'dnsruby'
      require 'timeout'
      completed = Queue.new
      job = Object.new
      job.define_singleton_method(:do_validate) { completed << true }
      raise 'initial admission failed' unless Dnsruby::ValidatorThread.enqueue(job)
      Timeout.timeout(3) { completed.pop }
      pid = fork do
        raise 'child rejected' unless Dnsruby::ValidatorThread.enqueue(job)
        Timeout.timeout(3) { completed.pop }
        exit! 0
      end
      Process.wait(pid)
      raise 'child worker did not run' unless $?.success?
      # Emulate external termination of otherwise idle workers.
      Dnsruby::ValidatorThread.instance_variable_get(:@workers).each { |worker| worker.kill; worker.join }
      raise 'replacement rejected' unless Dnsruby::ValidatorThread.enqueue(job)
      Timeout.timeout(3) { completed.pop }
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end

  def test_partial_worker_creation_failure_keeps_pool_bounded_and_recoverable
    code = <<~'RUBY'
      require 'dnsruby'
      require 'timeout'
      original = Thread.method(:new)
      Thread.define_singleton_method(:new) { |*| raise ThreadError, 'no worker available' }
      raise 'work accepted with no workers' if Dnsruby::ValidatorThread.enqueue(Object.new)
      started = 0
      Thread.define_singleton_method(:new) do |*args, &block|
        raise ThreadError, 'worker unavailable' if started == 1
        started += 1
        original.call(*args, &block)
      end
      completed = Queue.new
      job = Object.new
      job.define_singleton_method(:do_validate) { completed << true }
      raise 'partial pool rejected work' unless Dnsruby::ValidatorThread.enqueue(job)
      Thread.define_singleton_method(:new, original)
      Timeout.timeout(3) { completed.pop }
      raise 'partial workers untracked' unless Dnsruby::ValidatorThread.instance_variable_get(:@workers).count(&:alive?) == 1
      raise 'restored admission failed' unless Dnsruby::ValidatorThread.enqueue(job)
      Timeout.timeout(3) { completed.pop }
      raise 'pool not replenished' unless Dnsruby::ValidatorThread.instance_variable_get(:@workers).count(&:alive?) == 4
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end

  def test_nested_discovery_timeout_cancels_only_its_own_query
    code = TestPipelineSend::FIXTURE + <<~'RUBY'
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', do_caching: false,
        retry_times: 1, query_timeout: 60)
      resolver.single_resolvers.each { |sender| sender.define_singleton_method(:send_async) { |*| } }
      unrelated = Queue.new
      resolver.send_async(query('unrelated.example.'), unrelated, :unrelated)
      budget = Dnsruby::ValidationBudget.new(limits: Dnsruby::Dnssec.validation_limits.merge(timeout: 0.02))
      begin
        Dnsruby::ValidationBudget.with(budget) { resolver.query_no_validation_or_recursion('nested.example.', 'DNSKEY') }
        raise 'discovery did not time out'
      rescue Dnsruby::ValidationLimitError
      end
      engine = resolver.instance_variable_get(:@resolver_ruby)
      raise 'nested query retained or unrelated cancelled' unless engine.instance_variable_get(:@query_list).keys == [:unrelated]
      resolver.close
      raise 'nested observer retained' unless K.class_variable_get(:@@observers).empty?
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end

class TestResolverValidation
  def test_validation_handoff_is_not_duplicated_if_delivery_crosses_deadline
    isolated(<<~'RUBY')
      start_query(resolver, results)
      accept_answer(attempts.first)
      push = SELECTOR.method(:push_validation_response_to_select)
      SELECTOR.define_singleton_method(:push_validation_response_to_select) do |*args|
        push.call(*args)
        clock += 11
      end
      validators.shift.do_validate
      raise 'validation delivered twice' unless K.class_variable_get(:@@queued_validation_responses).length == 1
      SELECTOR.send_queued_validation_responses
      expect_completion(results, Dnsruby::ResolvTimeout)
      expect_clean(resolver)
    RUBY
  end
end
