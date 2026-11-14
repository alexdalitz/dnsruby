require_relative 'tc_key_cache_identity'

class DnssecCacheLifetimeTest < Minitest::Test
  def setup
    @now = Time.utc(2026, 11, 13, 12)
    @private_keys = KeyCacheIdentityTest::PRIVATE_KEYS.map { |pem| OpenSSL::PKey::EC.new(pem) }
    @parent, @child = ['cache.invalid.', 'child.cache.invalid.'].each_with_index.map do |name, index|
      bytes = @private_keys[index].public_key.to_octet_string(:uncompressed).byteslice(1, 64)
      Dnsruby::RR.create("#{name} 300 IN DNSKEY 257 3 13 #{Base64.strict_encode64(bytes)}")
    end
    @ds = Dnsruby::RR::DS.from_key(@child, 2)
    @ds.ttl = 300
  end

  def test_learned_dnskeys_use_every_authenticated_ttl_bound_and_only_a_valid_signature
    limits = [{ ttl: 7 }, { signature_ttl: 7 }, { original_ttl: 7 }, { lifetime: 7 }]
    limits.each do |limit|
      [false, true].each do |invalid_first|
        verifier = new_verifier
        verifier.add_trust_anchor(@ds)
        records = signed(@child, @child, 1, **limit)
        valid = records.sigs.first
        invalid = valid.clone
        invalid.expiration = @now.to_i + 7200
        invalid.signature = "\0" * 64
        signatures = invalid_first ? [invalid, valid] : [valid, invalid]
        records = Dnsruby::RRSet.new(records.rrs + signatures)

        at(0) do
          assert(verifier.verify(records), limit.inspect)
          assert_equal(7, records.ttl, limit.inspect)
        end
        at(6) { assert_cached_child(verifier) }
        at(7) { assert_empty(verifier.get_keys_to_check) }
      end
    end
  end

  def test_bad_dnskey_signature_cannot_publish_a_ds_matched_key
    [:configured, :explicit, :learned].each do |source|
      verifier = new_verifier
      ds_records = signed(@ds, @parent, 0)
      records = signed(@child, @child, 1)
      records.sigs.first.signature = "\0" * 64
      at(0) do
        case source
        when :configured
          verifier.add_trust_anchor(@ds)
        when :learned
          verifier.add_trust_anchor(@parent)
          assert(verifier.verify(ds_records))
        end
        explicit_ds = source == :explicit ? @ds : nil
        assert_raises(Dnsruby::VerifyError) { verifier.verify(records, explicit_ds) }
        refute_cached_child(verifier)
        refute(verifier.trusted_keys.any? { |key| key.type == Dnsruby::Types.DNSKEY && same_key?(key, @child) })
      end
    end
  end

  def test_discovered_ds_limits_child_cache_to_its_original_absolute_deadline
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0, ttl: 10)
    child_records = signed(@child, @child, 1)
    at(0) { assert(verifier.verify(ds_records)) }
    at(7) do
      assert(verifier.verify(child_records, ds_records))
      assert_cached_child(verifier)
    end
    at(9) { assert_cached_child(verifier) }
    at(10) do
      refute_cached_child(verifier)
      refute_includes(verifier.trusted_keys, @ds)
    end
  end

  def test_discovered_ds_expiry_survives_pruning_before_explicit_child_verification
    [{ ttl: 5 }, { signature_ttl: 5 }, { original_ttl: 5 }, { lifetime: 5 }].each do |limit|
      verifier = new_verifier
      verifier.add_trust_anchor(@parent)
      ds_records = signed(@ds, @parent, 0, **limit)
      at(0) { assert(verifier.verify(ds_records)) }
      at(4) { assert_includes(verifier.trusted_keys, @ds) }
      at(5) do
        # This public read prunes the DS cache while the chain lookup retains
        # its original RRset. It must not become fresh explicit trust input.
        refute_includes(verifier.trusted_keys, @ds)
        assert_raises(Dnsruby::VerifyError) do
          verifier.verify(signed(@child, @child, 1), ds_records)
        end
        refute_cached_child(verifier)
      end
    end
  end

  def test_matching_a_message_dnskey_only_supplies_a_candidate_until_its_rrset_verifies
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0, ttl: 5)
    message = Dnsruby::Message.new(@child.name, 'DNSKEY')
    message.add_answer(@child)
    at(0) do
      assert(verifier.verify_ds_rrset(ds_records, nil, message))
      refute_cached_child(verifier)
      assert_includes(verifier.trusted_keys, @ds)
      assert(verifier.verify(signed(@child, @child, 1), ds_records))
      assert_cached_child(verifier)
    end
    at(5) do
      refute_cached_child(verifier)
      assert_raises(Dnsruby::VerifyError) do
        verifier.verify(signed(@child, @child, 1), ds_records)
      end
      refute_cached_child(verifier)
    end
  end

  def test_a_full_message_caches_dnskeys_only_for_the_authenticated_dnskey_lifetime
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    message = message_with(signed(@ds, @parent, 0),
      signed(@child, @child, 1, signature_ttl: 7), signed_child_answer)
    at(0) do
      assert(verifier.verify(message))
      assert_cached_child(verifier)
      assert(verifier.verify(signed_child_answer))
    end
    at(6) { assert_cached_child(verifier) }
    at(7) do
      refute_cached_child(verifier)
      assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
    end
  end

  def test_full_response_ttls_and_cache_honor_every_authenticated_bound
    [{ ttl: 7 }, { signature_ttl: 7 }, { original_ttl: 7 }, { lifetime: 7 }].each do |limit|
      verifier = new_verifier
      verifier.add_trust_anchor(@child)
      record = Dnsruby::RR.create("#{@child.name} 300 IN A 192.0.2.1")
      message = message_with(signed(record, @child, 1, **limit))
      cache = Dnsruby::Cache.new
      at(0) do
        assert(verifier.verify(message), limit.inspect)
        assert_equal([7, 7], message.answer.map(&:ttl), limit.inspect)
      end
      at(2) { cache.add(message) }
      at(4) do
        found = cache.find(@child.name, 'A')
        assert_equal([3, 3], found.answer.map(&:ttl), limit.inspect)
        assert(verifier.verify(found), limit.inspect)
        assert_equal([3, 3], found.answer.map(&:ttl), limit.inspect)
        cache.add(found)
      end
      at(7) { assert_nil(cache.find(@child.name, 'A'), limit.inspect) }
    end
  end

  def test_cached_dnskey_revalidation_cannot_renew_its_authenticated_lifetime
    verifier = new_verifier
    verifier.add_trust_anchor(@ds)
    message = message_with(signed(@child, @child, 1, signature_ttl: 7))
    cache = Dnsruby::Cache.new
    at(0) do
      assert(verifier.verify(message))
      cache.add(message)
    end
    recipient = new_verifier
    recipient.add_trust_anchor(@ds)
    at(4) do
      cached = cache.find(@child.name, 'DNSKEY')
      assert(recipient.verify(cached))
      assert_cached_child(recipient)
      assert_equal([3, 3], cached.answer.map(&:ttl))
    end
    at(7) do
      refute_cached_child(recipient)
      assert_nil(cache.find(@child.name, 'DNSKEY'))
    end
  end

  def test_validation_queue_delay_does_not_restart_received_record_ttls
    verifier = new_verifier
    verifier.add_trust_anchor(@ds)
    wire = message_with(signed(@child, @child, 1, signature_ttl: 7)).encode
    message = at(0) { Dnsruby::Message.decode(wire) }
    cache = Dnsruby::Cache.new
    at(4) do
      assert(verifier.verify(message))
      assert_equal([3, 3], message.answer.map(&:ttl))
      cache.add(message)
      assert_equal([3, 3], cache.find(@child.name, 'DNSKEY').answer.map(&:ttl))
      assert_cached_child(verifier)
    end
    at(7) do
      refute_cached_child(verifier)
      assert_nil(cache.find(@child.name, 'DNSKEY'))
    end
  end

  def test_public_verification_retains_learned_ds_expiration_across_all_verifiers
    [:anchor_verifier, :root_verifier, :dlv_verifier].each do |source|
      with_public_verifiers do |verifiers|
        verifier = Dnsruby::Dnssec.public_send(source)
        verifier.add_trust_anchor(@parent)
        ds_records = signed(@ds, @parent, 0, ttl: 5)
        at(0) { assert(verifier.verify(ds_records), source.to_s) }
        at(4) do
          assert(Dnsruby::Dnssec.verify(signed(@child, @child, 1), ds_records), source.to_s)
        end
        at(5) do
          verifiers.each do |candidate|
            refute_includes(candidate.trusted_keys, @ds)
            refute_cached_child(candidate)
          end
          [ds_records, ds_records.clone, Marshal.load(Marshal.dump(ds_records))].each do |retained|
            assert_raises(Dnsruby::VerifyError, source.to_s) do
              Dnsruby::Dnssec.verify(signed(@child, @child, 1), retained)
            end
          end
          verifiers.each { |candidate| refute_cached_child(candidate) }
          # A newly supplied DS remains explicit trust input.
          assert(Dnsruby::Dnssec.verify(signed(@child, @child, 1), @ds.clone))
        end
      end
    end
  end

  def test_public_fallback_cannot_reuse_learned_ds_after_its_source_trust_is_revoked
    [:anchor_verifier, :root_verifier, :dlv_verifier].product([:remove, :clear]).each do |source, operation|
      with_public_verifiers do |verifiers|
        verifier = Dnsruby::Dnssec.public_send(source)
        verifier.add_trust_anchor(@parent)
        ds_records = signed(@ds, @parent, 0)
        at(0) { assert(verifier.verify(ds_records)) }
        at(1) do
          if operation == :remove
            verifier.remove_trust_anchor(@parent)
          else
            verifier.clear_trust_anchors
          end
          assert_raises(Dnsruby::VerifyError, "#{source} #{operation}") do
            Dnsruby::Dnssec.verify(signed(@child, @child, 1), ds_records)
          end
          verifiers.each { |candidate| refute_cached_child(candidate) }
        end
      end
    end
  end

  def test_fresh_explicit_trust_replaces_expired_or_revoked_provenance_for_the_same_key
    [:remove, :clear, :expire].product([:ds, :dnskey]).each do |operation, key_type|
      source = new_verifier
      recipient = new_verifier
      ds_records = signed(@ds, @parent, 0)
      at(0) do
        if operation == :expire
          source.add_trust_anchor_with_expiration(@parent, @now.to_i + 5)
        else
          source.add_trust_anchor(@parent)
        end
        assert(source.verify(ds_records))
        assert(recipient.verify(signed(@child, @child, 1), ds_records))
        assert_cached_child(recipient)
      end
      renewed_at = operation == :expire ? 5 : 1
      at(renewed_at) do
        source.remove_trust_anchor(@parent) if operation == :remove
        source.clear_trust_anchors if operation == :clear
        refute_cached_child(recipient)
        explicit = key_type == :ds ? @ds.clone : @child.clone
        assert(recipient.verify(signed(@child, @child, 1, ttl: 7), explicit), "#{operation} #{key_type}")
        assert_cached_child(recipient)
        assert(recipient.verify(signed_child_answer))
      end
      at(renewed_at + 6) do
        assert_cached_child(recipient)
        assert(recipient.verify(signed_child_answer))
      end
      at(renewed_at + 7) do
        refute_cached_child(recipient)
        assert_raises(Dnsruby::VerifyError) { recipient.verify(signed_child_answer) }
      end
    end
  end

  def test_closest_anchor_ignores_child_trust_revoked_at_its_source_verifier
    source = new_verifier
    recipient = new_verifier
    source.add_trust_anchor(@parent)
    recipient.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0)
    name = Dnsruby::Name.create('www.child.cache.invalid.')
    at(0) do
      assert(source.verify(ds_records))
      assert(recipient.verify(signed(@child, @child, 1), ds_records))
      assert(same_key?(@child, recipient.find_closest_anchor_for(name)))
    end
    at(1) do
      source.remove_trust_anchor(@parent)
      refute_cached_child(recipient)
      assert(same_key?(@parent, recipient.find_closest_anchor_for(name)))
    end
  end

  def test_an_explicit_array_can_use_fresh_trust_after_a_revoked_copy_of_the_same_key
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    key_records = signed(@child, @child, 1)
    at(0) do
      assert(verifier.verify(signed(@ds, @parent, 0)))
      assert(verifier.verify(key_records))
    end
    at(1) do
      verifier.remove_trust_anchor(@parent)
      learned, fresh = key_records.rrs.first, @child.clone
      assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer, [learned]) }
      [[learned, fresh], [fresh, learned]].each do |keys|
        assert(verifier.verify(signed_child_answer, keys))
      end
    end
  end

  def test_zero_ttl_records_remain_usable_through_one_full_message_only
    [[0, 300], [300, 0], [0, 0]].each do |ds_ttl, key_ttl|
      verifier = new_verifier
      verifier.add_trust_anchor(@parent)
      message = message_with(signed(@ds, @parent, 0, ttl: ds_ttl),
        signed(@child, @child, 1, ttl: key_ttl), signed_child_answer)
      at(0) do
        assert(verifier.verify(message), "DS TTL #{ds_ttl}, DNSKEY TTL #{key_ttl}")
        refute_cached_child(verifier)
        # Even at the same clock time, a separate operation cannot use a
        # zero-TTL key learned by the completed message verification.
        assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
      end
      at(1) do
        refute_cached_child(verifier)
        assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
      end
    end
  end

  def test_zero_ttl_chain_records_remain_usable_through_one_validation_only
    [[0, 300], [300, 0], [0, 0]].each do |ds_ttl, key_ttl|
      verifier = new_verifier
      verifier.add_trust_anchor(@parent)
      ds_records = signed(@ds, @parent, 0, ttl: ds_ttl)
      key_records = signed(@child, @child, 1, ttl: key_ttl)
      message = message_with(signed_child_answer)
      elapsed = 0
      before_response = lambda do |name, type|
        elapsed = 2 if name == @child.name && type == Dnsruby::Types.DNSKEY
      end
      Time.stub(:now, -> { @now + elapsed }) do
        with_chain_resolver(verifier, ds_records, key_records, before_response) do |queries|
          assert(verifier.validate(message, Dnsruby::Message.new(@child.name, 'A')))
          assert_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
          assert_equal(['DNSKEY', 'DS', 'DNSKEY'], queries.map(&:last))
        end
        refute_cached_child(verifier)
        assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
      end
    end
  end

  def test_follow_chain_accepts_zero_ttl_ds_without_learning_a_reusable_key
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0, ttl: 0)
    at(0) do
      with_chain_resolver(verifier, ds_records, signed(@child, @child, 1)) do
        keys = verifier.follow_chain(@parent, @child.name)
        assert_equal(1, keys.rrs.length)
        assert(same_key?(@child, keys.rrs.first))
      end
      refute_cached_child(verifier)
      refute_includes(verifier.trusted_keys, @ds)
      assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
    end
  end

  def test_current_chain_can_finish_after_its_ds_ttl_without_extending_the_cache_deadline
    [4, 6].each do |lookup_delay|
      verifier = new_verifier
      verifier.add_trust_anchor(@parent)
      ds_records = signed(@ds, @parent, 0, ttl: 5)
      elapsed = 0
      before_response = lambda do |name, type|
        elapsed = lookup_delay if name == @child.name && type == Dnsruby::Types.DNSKEY
      end
      Time.stub(:now, -> { @now + elapsed }) do
        with_chain_resolver(verifier, ds_records, signed(@child, @child, 1), before_response) do
          keys = verifier.follow_chain(@parent, @child.name)
          assert_equal(1, keys.rrs.length)
          assert(same_key?(@child, keys.rrs.first))
          if lookup_delay < 5
            assert_cached_child(verifier)
          else
            refute_cached_child(verifier)
          end
        end
        elapsed = [elapsed, 5].max
        refute_cached_child(verifier)
        assert_raises(Dnsruby::VerifyError) { verifier.verify(signed_child_answer) }
      end
    end
  end

  def test_a_ds_signature_expiring_during_chain_discovery_cannot_finish_validation
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    elapsed = 0
    before_response = lambda do |name, type|
      elapsed = 6 if name == @child.name && type == Dnsruby::Types.DNSKEY
    end
    Time.stub(:now, -> { @now + elapsed }) do
      with_chain_resolver(verifier, signed(@ds, @parent, 0, lifetime: 5),
        signed(@child, @child, 1), before_response) do
        assert_raises(Dnsruby::VerifyError) { verifier.follow_chain(@parent, @child.name) }
      end
      refute_cached_child(verifier)
    end
  end

  def test_learned_ds_and_dnskey_rrsets_remain_marshal_and_clone_compatible
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0, ttl: 5)
    key_records = signed(@child, @child, 1)
    at(0) do
      assert(verifier.verify(ds_records))
      assert(verifier.verify(key_records, ds_records))
      [ds_records, key_records].each do |records|
        [records.clone, Marshal.load(Marshal.dump(records))].each do |copy|
          assert_equal(records.rrs.map(&:to_s), copy.rrs.map(&:to_s))
          assert_equal(records.sigs.map(&:to_s), copy.sigs.map(&:to_s))
        end
      end
    end
  end

  def test_cloned_learned_records_preserve_expiration_and_revocation
    [:ds, :dnskey].product([:expire, :revoke]).each do |key_type, reason|
      source = new_verifier
      source.add_trust_anchor(@parent)
      ds_records = signed(@ds, @parent, 0, ttl: 5)
      key_records = signed(@child, @child, 1)
      at(0) do
        assert(source.verify(ds_records))
        assert(source.verify(key_records, ds_records))
      end
      learned = (key_type == :ds ? ds_records : key_records).rrs.first
      container = Dnsruby::Message.new(learned.name, learned.type)
      container.add_answer(learned)
      copies = at(3) do
        [learned.clone, container.clone.answer.first, Dnsruby::RRSet.new([learned.clone])]
      end
      recipients = copies.map { new_verifier }
      at(4) do
        copies.zip(recipients).each do |copy, recipient|
          assert(recipient.verify(signed(@child, @child, 1), copy), "#{key_type} #{reason}")
          assert_cached_child(recipient)
        end
      end
      at(reason == :expire ? 5 : 4) do
        source.remove_trust_anchor(@parent) if reason == :revoke
        copies.zip(recipients).each do |copy, recipient|
          refute_cached_child(recipient)
          assert_raises(Dnsruby::VerifyError, "#{key_type} #{reason}") do
            recipient.verify(signed(@child, @child, 1), copy)
          end
          # A separately supplied original remains explicit trust input.
          fresh = (key_type == :ds ? @ds : @child).clone
          assert(recipient.verify(signed(@child, @child, 1), fresh))
        end
      end
    end
  end

  def test_learning_ds_and_dnskey_records_preserves_equality_and_hash_lookup
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0)
    key_records = signed(@child, @child, 1)
    # Populate crypto memoization before taking identical clean snapshots.
    key_records.rrs.each { |key| key.public_key; key.key_tag }
    records = ds_records.rrs + key_records.rrs
    clean = records.map(&:dup)
    lookup = clean.to_h { |record| [record, :known] }
    at(0) do
      assert(verifier.verify(ds_records))
      assert(verifier.verify(key_records, ds_records))
      clean.zip(records).each do |before, learned|
        assert_equal(before, learned)
        assert_equal(before.hash, learned.hash)
        assert_equal(:known, lookup[learned])
      end
    end
  end

  def test_closest_anchor_lookup_returns_unexpired_learned_ds_rrsets
    verifier = new_verifier
    verifier.add_trust_anchor(@parent)
    ds_records = signed(@ds, @parent, 0, ttl: 5)
    name = Dnsruby::Name.create('www.child.cache.invalid.')
    at(0) { assert(verifier.verify(ds_records)) }
    at(4) { assert_same(ds_records, verifier.find_closest_anchor_for(name)) }
    at(5) { assert_equal(@parent, verifier.find_closest_anchor_for(name)) }
  end

  def test_explicit_dnskey_anchor_ttl_zero_remains_usable
    verifier = new_verifier
    @parent.ttl = 0
    verifier.add_trust_anchor(@parent)
    answer = Dnsruby::RR.create('www.cache.invalid. 300 IN A 192.0.2.1')
    records = signed(answer, @parent, 0)
    at(100) do
      assert_equal([@parent], verifier.trust_anchors)
      assert(verifier.verify(records))
    end
  end

  def test_configured_anchor_expiration_invalidates_descendants_at_the_exact_deadline
    verifier = new_verifier
    verifier.add_trust_anchor_with_expiration(@parent, @now.to_i + 5)
    ds_records = signed(@ds, @parent, 0)
    at(0) do
      assert(verifier.verify(ds_records))
      assert(verifier.verify(signed(@child, @child, 1)))
    end
    at(5) do
      assert_empty(verifier.get_keys_to_check)
      assert_empty(verifier.trusted_keys)
      assert_empty(verifier.trust_anchors)
      assert_raises(Dnsruby::VerifyError) { verifier.verify(signed(@child, @child, 1)) }
    end
  end

  private

  def same_key?(first, second)
    Dnsruby::KeyCache.key_identity(first) == Dnsruby::KeyCache.key_identity(second)
  end

  def assert_cached_child(verifier)
    assert(verifier.get_keys_to_check.any? { |key| same_key?(key, @child) }, 'Expected a cached child DNSKEY')
  end

  def refute_cached_child(verifier)
    refute(verifier.get_keys_to_check.any? { |key| same_key?(key, @child) }, 'Unexpected cached child DNSKEY')
  end

  def new_verifier
    Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
  end

  def with_public_verifiers
    Dnsruby::Dnssec.reset
    yield [Dnsruby::Dnssec.anchor_verifier, Dnsruby::Dnssec.root_verifier, Dnsruby::Dnssec.dlv_verifier]
  ensure
    Dnsruby::Dnssec.reset
  end

  def signed_child_answer
    signed(Dnsruby::RR.create("#{@child.name} 300 IN A 192.0.2.1"), @child, 1)
  end

  def message_with(*rrsets)
    message = Dnsruby::Message.new(rrsets.last.name, rrsets.last.type)
    rrsets.each { |rrset| rrset.each { |rr| message.add_answer(rr) } }
    message
  end

  def with_chain_resolver(verifier, ds_records, key_records, before_response = nil)
    responses = {
      [@parent.name.canonical.to_s, 'DNSKEY'] => message_with(signed(@parent, @parent, 0)),
      [@child.name.canonical.to_s, 'DS'] => message_with(ds_records),
      [@child.name.canonical.to_s, 'DNSKEY'] => message_with(key_records)
    }
    queries = []
    resolver = Object.new
    resolver.define_singleton_method(:query_no_validation_or_recursion) do |name, type|
      queries << [name.canonical.to_s, type.to_s]
      before_response&.call(name, type)
      responses.fetch(queries.last)
    end
    Dnsruby::Dnssec.stub(:do_validation_with_recursor?, false) do
      Dnsruby::Dnssec.stub(:default_resolver, resolver) do
        verifier.stub(:get_nameservers_for, resolver) do
          verifier.stub(:get_nameservers_from_message, resolver) { yield queries }
        end
      end
    end
  end

  def at(seconds, &block)
    Time.stub(:now, @now + seconds, &block)
  end

  def signed(record, key, signer, ttl: 300, signature_ttl: 300, original_ttl: 300, lifetime: 3600)
    record = record.clone
    record.ttl = ttl
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: signature_ttl,
      type_covered: record.type, algorithm: 13, labels: record.name.labels.length,
      original_ttl: original_ttl, expiration: @now.to_i + lifetime, inception: @now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    canonical_record = record.clone
    canonical_record.ttl = original_ttl
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(canonical_record, true) }.to_s
    der = @private_keys[signer].dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + data))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    Dnsruby::RRSet.new([record, signature])
  end
end
