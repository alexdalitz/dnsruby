require_relative 'spec_helper'
require 'minitest/mock'
require 'ostruct'

# Decision-level tests use metadata doubles and mock cryptographic verification;
# ordinary published root fixtures exercise DS identity without generating keys.
class ReleaseDnssecFixesTest < Minitest::Test
  def setup
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    @zone = Dnsruby::Name.create('example.')
    @child = Dnsruby::Name.create('child.example.')
    @anchor = OpenStruct.new(name: @zone, klass: Dnsruby::Classes.IN, type: Dnsruby::Types.DNSKEY)
    @saved_recursor = Dnsruby::Dnssec.do_validation_with_recursor?
    Dnsruby::Dnssec.do_validation_with_recursor(false)
  end

  def teardown
    Dnsruby::Dnssec.do_validation_with_recursor(@saved_recursor)
  end

  def test_signature_metadata_requires_zone_authority_and_apex_dnskeys
    [[@child, 'A', @zone, true], [@zone, 'DNSKEY', @zone, true],
      [@child, 'DNSKEY', @zone, false], [@child, 'DS', @zone, true],
      [@child, 'DS', @child, false], [@zone, 'A', @child, false]].each do |owner, type, signer, valid|
      rrset = OpenStruct.new(name: owner, klass: Dnsruby::Classes.IN, type: Dnsruby::Types.new(type))
      signature = OpenStruct.new(name: owner, klass: rrset.klass, type_covered: rrset.type,
        signers_name: signer, labels: owner.labels.length, inception: Time.now.to_i - 60,
        expiration: Time.now.to_i + 60)
      if valid
        @verifier.check_rr_data(rrset, signature)
      else
        assert_raises(Dnsruby::VerifyError) { @verifier.check_rr_data(rrset, signature) }
      end
    end
  end

  def test_zone_key_flag_is_required_without_sep
    key = Object.new
    def key.zone_key?; false; end
    error = assert_raises(Dnsruby::VerifyError) { @verifier.send(:verify_rrset_with_key, nil, key, nil) }
    assert_match(/Zone Key flag/, error.message)
  end

  def test_dsa_algorithms_are_rejected_before_crypto
    key = Object.new
    def key.zone_key?; true; end
    [3, 6].each do |algorithm|
      signature = OpenStruct.new(algorithm: Dnsruby::Algorithms.new(algorithm))
      error = assert_raises(Dnsruby::VerifyError) do
        @verifier.send(:verify_rrset_with_key, nil, key, signature)
      end
      assert_match(/prohibited/, error.message)
    end
  end

  def test_ds_binds_owner_and_class_while_dlv_keeps_lookaside_owner_semantics
    fixture = File.join(__dir__, 'fixtures', 'root-dnskey-2026-11-05.zone')
    key = Dnsruby::RR.create(File.readlines(fixture).find { |line| line.include?(' IN DNSKEY ') })
    ds = Dnsruby::RR::DS.from_key(key, 2)
    assert(ds.check_key(key))
    ds.name = 'example.'
    refute(ds.check_key(key))
    ds.name = key.name
    ds.klass = Dnsruby::Classes.CH
    refute(ds.check_key(key))
    dlv = Dnsruby::RR.create(Dnsruby::RR::DS.from_key(key, 2).to_s.sub(/\bDS\b/, 'DLV'))
    dlv.name = 'example.dlv.invalid.'
    assert(dlv.check_key(key))
    dlv.klass = Dnsruby::Classes.CH
    refute(dlv.check_key(key))
  end

  def test_worker_rejects_false_or_bogus_without_an_exception
    [[false, Dnsruby::Message::SecurityLevel.INSECURE],
      [true, Dnsruby::Message::SecurityLevel.BOGUS]].each do |result, level|
      worker = Dnsruby::ValidatorThread.allocate
      worker.define_singleton_method(:should_validate) { true }
      response = Dnsruby::Message.new('example.')
      response.security_level = level
      Dnsruby::Dnssec.stub(:validate_with_query, result) do
        refute(worker.validate(Dnsruby::Message.new('example.'), response, nil))
      end
      assert_instance_of(Dnsruby::VerifyError, response.security_error)
      assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, response.security_level)
    end
  end

  def test_policy_fallback_cannot_erase_failure_with_insecure_result
    previous = Dnsruby::Dnssec.validation_policy
    query = Dnsruby::Message.new('example.')
    query.header.cd = true
    insecure = ->(message, _) { message.security_level = Dnsruby::Message::SecurityLevel.INSECURE; true }
    failure = ->(*) { raise Dnsruby::VerifyError, 'missing authenticated delegation' }
    secure = ->(message, _) { message.security_level = Dnsruby::Message::SecurityLevel.SECURE; true }
    [Dnsruby::Dnssec::ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT,
      Dnsruby::Dnssec::ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS].each do |policy|
      Dnsruby::Dnssec.validation_policy = policy
      Dnsruby::Dnssec.stub(:validate_with_anchors, insecure) do
        Dnsruby::Dnssec.stub(:validate_with_root, failure) do
          Dnsruby::Dnssec.stub(:validate_with_dlv, insecure) do
            response = Dnsruby::Message.new('example.')
            assert_raises(Dnsruby::VerifyError) { Dnsruby::Dnssec.validate_with_query(query, response) }
            assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, response.security_level)
          end
        end
      end
    end
    Dnsruby::Dnssec.validation_policy = Dnsruby::Dnssec::ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS
    Dnsruby::Dnssec.stub(:validate_with_root, failure) do
      Dnsruby::Dnssec.stub(:validate_with_anchors, secure) do
        response = Dnsruby::Message.new('example.')
        assert(Dnsruby::Dnssec.validate_with_query(query, response))
        assert_equal(Dnsruby::Message::SecurityLevel.SECURE, response.security_level)
        assert_equal('', response.security_error)
      end
    end
  ensure
    Dnsruby::Dnssec.validation_policy = previous
  end

  def test_ds_lookup_failure_or_unproven_absence_does_not_mean_insecure
    response = Dnsruby::Message.new(@child, 'DS')
    [->(*) { raise Dnsruby::ServFail, 'lookup failed' }, ->(*) { response }].each do |query|
      resolver = Object.new
      resolver.define_singleton_method(:query_no_validation_or_recursion, query)
      assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @zone, @anchor, resolver) }
    end
  end

  def test_missing_or_unsigned_dnskey_is_a_verification_failure
    response = Dnsruby::Message.new(@zone, 'DNSKEY')
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) { |*| response }
    @verifier.stub(:get_nameservers_for, resolver) do
      assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@zone, @zone, @anchor, resolver) }
      fixture = File.join(__dir__, 'fixtures', 'root-dnskey-2026-11-05.zone')
      key = Dnsruby::RR.create(File.readlines(fixture).find { |line| line.include?(' IN DNSKEY ') })
      key.name = @zone
      response.add_answer(key)
      assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@zone, @zone, @anchor, resolver) }
    end
  end

  def test_unsigned_ds_does_not_establish_child_trust
    response = Dnsruby::Message.new(@child, 'DS')
    response.add_answer(Dnsruby::RR.create('child.example. 60 IN DS 1 8 2 ' + '00' * 32))
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) { |*| response }
    assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @zone, @anchor, resolver) }
  end

  def test_only_authenticated_all_unsupported_ds_sets_are_insecure
    [[3, 6], [15]].each do |algorithms|
      message = Dnsruby::Message.new(@child, 'DS')
      algorithms.each do |algorithm|
        message.add_answer(Dnsruby::RR.create("child.example. 60 IN DS 1 #{algorithm} 2 " + '00' * 32))
      end
      calls = []
      resolver = Object.new
      resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
        calls << type
        message
      end
      @verifier.stub(:verify, true) do
        key, returned_resolver = @verifier.get_anchor_for(@child, @zone, @anchor, resolver)
        assert_equal(false, key)
        assert_same(resolver, returned_resolver)
        assert_equal([Dnsruby::Types.DS], calls)
      end
      @verifier.stub(:verify, false) do
        assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @zone, @anchor, resolver) }
      end
    end
  end

  def test_cached_unsupported_ds_requires_live_provenance_before_insecure_classification
    record = Dnsruby::RR.create('child.example. 60 IN DS 1 3 2 ' + '00' * 32)
    [record, Dnsruby::RRSet.new([record])].each do |anchor|
      admitted = []
      @verifier.stub(:admit_learned_rrset, ->(input) { admitted << input }) do
        @verifier.stub(:get_nameservers_for, ->(*) { flunk('unsupported DS must not fetch DNSKEY') }) do
          result = @verifier.get_anchor_for(@child, @child, anchor)
          assert_equal([false, nil], result)
          assert_equal([anchor], admitted)
        end
      end
      @verifier.stub(:admit_learned_rrset, ->(*) { raise Dnsruby::VerifyError, 'expired learned trust' }) do
        assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @child, anchor) }
      end
    end
  end

  def test_cached_mixed_ds_still_requires_child_authentication
    records = [3, 8].map { |algorithm| Dnsruby::RR.create("child.example. 60 IN DS 1 #{algorithm} 2 " + '00' * 32) }
    anchor = Dnsruby::RRSet.new(records)
    response = Dnsruby::Message.new(@child, 'DNSKEY')
    calls = []
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
      calls << type
      response
    end
    @verifier.stub(:get_nameservers_for, resolver) do
      assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @child, anchor, resolver) }
    end
    assert_equal([Dnsruby::Types.DNSKEY], calls)
  end

  def test_mixed_ds_algorithms_still_require_an_authenticated_child_key
    ds = Dnsruby::Message.new(@child, 'DS')
    [3, 8].each do |algorithm|
      ds.add_answer(Dnsruby::RR.create("child.example. 60 IN DS 1 #{algorithm} 2 " + '00' * 32))
    end
    keys = Dnsruby::Message.new(@child, 'DNSKEY')
    calls = []
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
      calls << type
      type == Dnsruby::Types.DS ? ds : keys
    end
    @verifier.stub(:verify, true) do
      @verifier.stub(:get_nameservers_from_message, resolver) do
        assert_raises(Dnsruby::VerifyError) { @verifier.get_anchor_for(@child, @zone, @anchor, resolver) }
      end
    end
    assert_equal([Dnsruby::Types.DS, Dnsruby::Types.DNSKEY], calls)
  end

  def test_only_authenticated_delegation_denial_returns_insecure
    %w[NSEC NSEC3].each do |type|
      ['A', 'NS'].each do |types|
        record = if type == 'NSEC'
          Dnsruby::RR.create("child.example. 60 IN NSEC z.example. #{types} RRSIG NSEC")
        else
          nsec3 = Dnsruby::RR.create('example. 60 IN NSEC3 1 0 0 - 00000000000000000000000000000000')
          hashed = nsec3.hash_name(@child)
          Dnsruby::RR.create("#{hashed}.example. 60 IN NSEC3 1 0 0 - #{hashed} #{types}")
        end
        signature = OpenStruct.new(signers_name: @zone, labels: record.name.labels.length)
        proof = OpenStruct.new(name: record.name, klass: record.klass, type: record.type, rrs: [record], sigs: [signature])
        authority = Object.new
        authority.define_singleton_method(:rrsets) { |requested| requested == record.type ? [proof] : [] }
        message = OpenStruct.new(question: [Dnsruby::Question.new(@child, 'DS')],
          authority: authority, rcode: Dnsruby::RCode.NOERROR)
        # Stub construction at the crypto boundary; the denial bitmap and hash
        # matching decisions remain real, and no signed DNS response is created.
        Dnsruby::RRSet.stub(:new, proof) do
          @verifier.stub(:verify_rrset, true) do
            expected = types == 'NS' ? :insecure : :secure
            assert_equal(expected, @verifier.send(:authenticated_ds_absence, message, @child, @anchor))
          end
          @verifier.stub(:verify_rrset, ->(*) { raise Dnsruby::VerifyError, 'not authenticated' }) do
            assert_raises(Dnsruby::VerifyError) do
              @verifier.send(:authenticated_ds_absence, message, @child, @anchor)
            end
          end
        end
      end
    end
  end

  def test_actual_wildcard_nsec_signature_is_eligible_as_denial_evidence
    record = Dnsruby::RR.create('*.example. 60 IN NSEC z.example. A RRSIG NSEC')
    signature = OpenStruct.new(signers_name: @zone, labels: 1)
    proof = OpenStruct.new(name: record.name, klass: record.klass, type: record.type, rrs: [record], sigs: [signature])
    authority = Object.new
    authority.define_singleton_method(:rrsets) { |type| type == Dnsruby::Types.NSEC ? [proof] : [] }
    message = OpenStruct.new(question: [Dnsruby::Question.new(@child, 'DS')],
      authority: authority, rcode: Dnsruby::RCode.NOERROR)
    verified = false
    Dnsruby::RRSet.stub(:new, proof) do
      @verifier.stub(:verify_rrset, ->(*) { verified = true }) do
        @verifier.stub(:nsec_denial, :secure) do
          assert_equal(:secure, @verifier.send(:authenticated_ds_absence, message, @child, @anchor))
          assert(verified)
        end
      end
    end
  end

  def test_non_delegation_keeps_parent_anchor_without_querying_child_dnskey
    resolver = Object.new
    response = Dnsruby::Message.new(@child, 'DS')
    calls = []
    resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
      calls << [name, type]
      response
    end
    @verifier.stub(:authenticated_ds_absence, :secure) do
      key, returned_resolver = @verifier.get_anchor_for(@child, @zone, @anchor, resolver)
      assert_same(@anchor, key)
      assert_same(resolver, returned_resolver)
      assert_equal([[@child, Dnsruby::Types.DS]], calls)
    end
  end
end
