require_relative 'tc_key_cache_identity'

class DnssecDenialProofsTest < Minitest::Test
  def setup
    @private_key = OpenSSL::PKey::EC.new(KeyCacheIdentityTest::PRIVATE_KEYS.first)
    @zone = 'collision.invalid.'
    public_bytes = @private_key.public_key.to_octet_string(:uncompressed).byteslice(1, 64)
    @key = Dnsruby::RR.create("#{@zone} 300 IN DNSKEY 257 3 13 #{Base64.strict_encode64(public_bytes)}")
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    @verifier.add_trust_anchor(@key)
  end

  def test_cname_nodata_checks_final_target_with_nsec
    message = response('alias.collision.invalid.', 'AAAA')
    add_signed(message.answer, 'alias.collision.invalid. 300 IN CNAME target.collision.invalid.')
    add_signed(message.authority, 'target.collision.invalid. 300 IN NSEC z.collision.invalid. TXT NSEC RRSIG')
    assert(@verifier.verify(message))
    remove_set(message.authority, 'target.collision.invalid.', Dnsruby::Types.NSEC)
    add_signed(message.authority, 'target.collision.invalid. 300 IN NSEC z.collision.invalid. TXT AAAA NSEC RRSIG')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_partial_cname_response_and_positive_terminal_answer
    message = Dnsruby::Message.new('alias.collision.invalid.', 'AAAA')
    add_signed(message.answer, 'alias.collision.invalid. 300 IN CNAME target.collision.invalid.')
    assert(@verifier.verify(message))
    add_signed(message.answer, 'target.collision.invalid. 300 IN AAAA 2001:db8::1')
    assert(@verifier.verify(message))
  end

  def test_partial_answer_requires_a_cname_from_the_question
    message = Dnsruby::Message.new('alias.collision.invalid.', 'AAAA')
    add_signed(message.answer, 'target.collision.invalid. 300 IN AAAA 2001:db8::1')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_any_nodata_requires_an_empty_name_but_positive_answers_can_be_subsets
    message = response('target.collision.invalid.', 'ANY')
    add_chain(message)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    message = response('empty.collision.invalid.', 'ANY')
    add_chain(message)
    assert(@verifier.verify(message))

    message = response('missing.wild.collision.invalid.', 'ANY')
    add_chain(message)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    message = Dnsruby::Message.new('target.collision.invalid.', 'ANY')
    add_signed(message.answer, 'target.collision.invalid. 300 IN TXT "one RRset"')
    assert(@verifier.verify(message))
  end

  def test_signed_ds_referral_does_not_require_a_signature_on_parent_side_ns
    child = @key.clone
    child.name = 'child.collision.invalid.'
    message = Dnsruby::Message.new('www.child.collision.invalid.', 'A')
    message.add_authority(Dnsruby::RR.create('child.collision.invalid. 300 IN NS ns.child.collision.invalid.'))
    signed(Dnsruby::RR::DS.from_key(child, 2)).each { |rr| message.add_authority(rr) }
    assert(@verifier.verify(message))
  end

  def test_nsec_consistency_accepts_normal_circular_chain_and_partial_proofs
    message = response('a.collision.invalid.', 'AAAA')
    add_signed(message.authority, 'collision.invalid. 300 IN NSEC a.collision.invalid. SOA NS NSEC RRSIG')
    add_signed(message.authority, 'a.collision.invalid. 300 IN NSEC z.collision.invalid. A NSEC RRSIG')
    add_signed(message.authority, 'z.collision.invalid. 300 IN NSEC collision.invalid. TXT NSEC RRSIG')
    assert(@verifier.verify(message))
    remove_set(message.authority, @zone, Dnsruby::Types.NSEC)
    assert(@verifier.verify(message))
  end

  def test_signed_negative_soa_requires_denial
    message = response('target.collision.invalid.', 'AAAA')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    add_chain(message)
    assert(@verifier.verify(message))
  end

  def test_nsec3_exact_nodata_and_empty_nonterminal
    ['target.collision.invalid.', 'empty.collision.invalid.'].each do |name|
      message = response(name, 'AAAA')
      add_chain(message)
      assert(@verifier.verify(message))
    end
    ['AAAA', 'CNAME'].each do |present|
      message = response('target.collision.invalid.', 'AAAA')
      add_chain(message, entries: zone_entries.merge('target.collision.invalid.' => present))
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    end
  end

  def test_nsec3_nxdomain_after_cname_uses_target_and_complete_closest_encloser
    message = response('alias.collision.invalid.', 'AAAA', nxdomain: true)
    add_signed(message.answer, 'alias.collision.invalid. 300 IN CNAME missing.collision.invalid.')
    add_chain(message)
    assert(@verifier.verify(message))
    remove_set(message.authority, "#{hash_name(@zone)}.#{@zone}", Dnsruby::Types.NSEC3)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_nsec3_wildcard_nodata_and_nxdomain_are_distinct
    message = response('missing.wild.collision.invalid.', 'AAAA')
    add_chain(message)
    assert(@verifier.verify(message))
    message.header.rcode = Dnsruby::RCode.NXDOMAIN
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    message = response('missing.wild.collision.invalid.', 'MX')
    add_chain(message)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_nsec3_nxdomain_and_ds_opt_out_are_insecure
    message = response('missing.collision.invalid.', 'AAAA', nxdomain: true)
    add_chain(message, flags: 1)
    assert_equal(:insecure, @verifier.verify_result(message))
    message = response('child.collision.invalid.', 'DS')
    add_chain(message, flags: 1)
    assert_equal(:insecure, @verifier.verify_result(message))

    message = response('child.collision.invalid.', 'DS')
    add_chain(message)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_nsec3_exact_ds_denial_and_referral
    message = response('child.collision.invalid.', 'DS')
    add_chain(message, entries: zone_entries.merge('child.collision.invalid.' => 'NS'))
    assert(@verifier.verify(message))

    message = Dnsruby::Message.new('www.child.collision.invalid.', 'A')
    message.add_authority(Dnsruby::RR.create('child.collision.invalid. 300 IN NS ns.child.collision.invalid.'))
    add_chain(message, entries: zone_entries.merge('child.collision.invalid.' => 'NS'))
    assert_equal(:insecure, @verifier.verify_result(message))

    message = response(@zone, 'DS')
    add_chain(message)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_cname_to_unsigned_referral_validates_ds_denial_at_terminal_delegation
    message = Dnsruby::Message.new('alias.collision.invalid.', 'A')
    add_signed(message.answer, 'alias.collision.invalid. 300 IN CNAME www.child.collision.invalid.')
    message.add_authority(Dnsruby::RR.create('child.collision.invalid. 300 IN NS ns.child.collision.invalid.'))
    add_chain(message, entries: zone_entries.merge('child.collision.invalid.' => 'NS'))
    assert_equal(:insecure, @verifier.verify_result(message))
  end

  def test_nsec3_wrong_zone_and_mixed_parameters_cannot_form_denial
    foreign_key = @key.clone
    foreign_key.name = 'other.invalid.'
    @verifier.add_trust_anchor(foreign_key)
    message = response('target.collision.invalid.', 'AAAA')
    add_chain(message, key: foreign_key)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    message = response('target.collision.invalid.', 'AAAA')
    add_chain(message)
    add_chain(message, salt: 'abcd')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_nsec3_closest_encloser_cannot_be_dname_or_unsigned_delegation
    ['DNAME', 'NS'].each do |types|
      message = response('missing.wild.collision.invalid.', 'AAAA')
      add_chain(message, entries: zone_entries.merge('wild.collision.invalid.' => types))
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    end
  end

  def test_nsec3_hash_interval_excludes_endpoints_and_supports_wire_empty_salt
    message = response('target.collision.invalid.', 'AAAA')
    records = add_chain(message)
    first = records.first
    refute(first.check_name_in_range(zone_entries.keys.find { |name| hash_name(name) == first.owner_hash }))
    decoded = Dnsruby::Message.decode(message.encode)
    assert(@verifier.verify(decoded))
    assert(records.any? { |record| record.check_name_in_range('missing.collision.invalid.') })
  end

  def test_dnskey_message_authenticates_each_rrset_once
    message = Dnsruby::Message.new(@zone, 'DNSKEY')
    signed(@key).each { |record| message.add_answer(record) }
    calls = 0
    original = @verifier.method(:verify_rrset_with_key)
    @verifier.stub(:verify_rrset_with_key, lambda { |*args| calls += 1; original.call(*args) }) do
      assert(@verifier.verify(message))
    end
    assert_equal(1, calls)
  end

  private

  def remove_set(section, name, type)
    name = Dnsruby::Name.create(name)
    section.delete_if { |rr| rr.name == name && (rr.type == type || (rr.type == Dnsruby::Types.RRSIG && rr.type_covered == type)) }
  end

  def response(name, type, nxdomain: false)
    Dnsruby::Message.new(name, type).tap do |message|
      message.header.qr = true
      message.header.rcode = Dnsruby::RCode.NXDOMAIN if nxdomain
      add_signed(message.authority, "#{@zone} 300 IN SOA ns.#{@zone} hostmaster.#{@zone} 1 3600 600 86400 300")
    end
  end

  def zone_entries
    { @zone => 'SOA NS DNSKEY', 'alias.collision.invalid.' => 'CNAME',
      'target.collision.invalid.' => 'TXT', 'empty.collision.invalid.' => '',
      'wild.collision.invalid.' => 'TXT', '*.wild.collision.invalid.' => 'MX' }
  end

  def hash_name(name, salt = '-')
    Dnsruby::RR::NSEC3.calculate_hash(name, 0, Dnsruby::RR::NSEC3.decode_salt(salt), 1)
  end

  # Build the ordinary sorted NSEC3 chain for a small complete test zone.
  def add_chain(message, entries: zone_entries, flags: 0, salt: '-', key: @key)
    owners = entries.map { |name, types| [hash_name(name, salt), types] }.sort
    owners.each_with_index.map do |(owner, types), index|
      following = owners[(index + 1) % owners.length].first
      record = Dnsruby::RR.create("#{owner}.#{@zone} 300 IN NSEC3 1 #{flags} 0 #{salt} #{following} #{types}")
      signed(record, key: key).each { |rr| message.add_authority(rr) }
      record
    end
  end

  def add_signed(section, text)
    signed(Dnsruby::RR.create(text)).each { |record| section << record }
  end

  def signed(record, key: @key)
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: record.ttl,
      type_covered: record.type, algorithm: 13,
      labels: record.name.labels.length - (record.name.wild? ? 1 : 0),
      original_ttl: record.ttl, expiration: Time.now.to_i + 3600, inception: Time.now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    bytes = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    der = @private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + bytes))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    Dnsruby::RRSet.new([record, signature])
  end
end
