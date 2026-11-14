require_relative 'tc_key_cache_identity'

class DnssecWildcardProofsTest < Minitest::Test
  def setup
    Dnsruby::Dnssec.reset
    @private_key = OpenSSL::PKey::EC.new(KeyCacheIdentityTest::PRIVATE_KEYS.first)
    bytes = @private_key.public_key.to_octet_string(:uncompressed).byteslice(1, 64)
    @zone = 'collision.invalid.'
    @key = Dnsruby::RR.create("#{@zone} 300 IN DNSKEY 257 3 13 #{Base64.strict_encode64(bytes)}")
    @verifier = Dnsruby::Dnssec.anchor_verifier
    @verifier.add_trust_anchor(@key)
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_full_message_requires_proof_but_standalone_rrset_verification_remains_available
    message = wildcard_message
    assert(@verifier.verify_rrset(message.answer.rrset(message.question.first.qname, 'A')))
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    add_nsec(message)
    assert(@verifier.verify(message))
    assert(Dnsruby::Dnssec.validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
  end

  def test_nsec_proof_does_not_need_the_answer_type_in_its_bitmap
    message = wildcard_message
    add_nsec(message, types: 'TXT NSEC RRSIG')
    assert(@verifier.verify(message))
  end

  def test_examples_from_rfc_4035_wildcard_expansion
    # Preserve the RFC's expanded MX owner and denial interval, with fresh
    # signatures so the complete validation path can authenticate the proof.
    key = Dnsruby::RR.create(@key.to_s)
    key.name = 'example.'
    @verifier.add_trust_anchor(key)
    message = Dnsruby::Message.new('a.z.w.example.', 'MX')
    message.header.qr = true
    message.header.rcode = Dnsruby::RCode::NOERROR
    answer = signed(Dnsruby::RR.create('*.w.example. 300 IN MX 1 ai.example.'), key: key)
    answer.each { |rr| rr.name = 'a.z.w.example.'; message.add_answer(rr) }
    signed(Dnsruby::RR.create('x.y.w.example. 300 IN NSEC xx.example. MX RRSIG NSEC'), key: key).
      each { |rr| message.add_authority(rr) }
    assert(@verifier.verify(message))

    signature = answer.sigs.first
    assert_equal(2, signature.labels)
    signature.labels = 4
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    signature.labels = 2
    assert(@verifier.verify(message))

    # A valid signature alone cannot make an interval ending at the next closer
    # name prove that name does not exist.
    message.authority.clear
    signed(Dnsruby::RR.create('x.y.w.example. 300 IN NSEC z.w.example. MX RRSIG NSEC'), key: key).
      each { |rr| message.add_authority(rr) }
    assert(@verifier.verify_rrset(message.authority.rrset('x.y.w.example.', 'NSEC')))
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_any_queries_and_cname_answers_require_their_own_wildcard_proof
    message = wildcard_message(qtype: 'ANY')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    add_nsec(message)
    assert(@verifier.verify(message))

    cname = wildcard_message(type: 'CNAME', data: 'target.collision.invalid.')
    signed(Dnsruby::RR.create('target.collision.invalid. 300 IN A 192.0.2.1')).each { |rr| cname.add_answer(rr) }
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(cname) }
    add_nsec(cname)
    assert(@verifier.verify(cname))
  end

  def test_a_literal_wildcard_owner_has_not_been_expanded
    message = wildcard_message(name: '*.collision.invalid.')
    assert(@verifier.verify(message))
    # This also exercises a genuine wildcard owner in the NSEC proof itself.
    expanded = wildcard_message
    add_nsec(expanded, owner: '*.collision.invalid.')
    assert(@verifier.verify(expanded))
  end

  def test_signature_selection_can_use_an_exact_signature_without_a_wildcard_proof
    message = wildcard_message
    exact = signed(message.answer.rrset(message.question.first.qname, 'A').rrs.first)
    message.add_answer(exact.sigs.first)
    assert(@verifier.verify(message))
  end

  def test_denial_must_cover_next_closer_not_just_the_longer_question
    message = wildcard_message(name: 'x.b.collision.invalid.')
    # This interval covers x.b, but also proves b exists as an empty nonterminal.
    add_nsec(message, owner: 'a.collision.invalid.', following: 'z.b.collision.invalid.')
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    message = wildcard_message(name: 'x.b.collision.invalid.')
    add_nsec(message, owner: 'a.collision.invalid.', following: 'c.collision.invalid.')
    assert(@verifier.verify(message))
  end

  def test_nsec_wraparound_and_strict_endpoints
    message = wildcard_message(name: 'zz.collision.invalid.')
    add_nsec(message, owner: 'z.collision.invalid.', following: @zone)
    assert(@verifier.verify(message))
    ['a.collision.invalid.', 'z.collision.invalid.'].each do |endpoint|
      message = wildcard_message(name: endpoint)
      add_nsec(message)
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
    end
  end

  def test_unsigned_or_other_zone_denial_cannot_supply_the_proof
    message = wildcard_message
    message.add_authority(Dnsruby::RR.create('a.collision.invalid. 300 IN NSEC z.collision.invalid. TXT NSEC RRSIG'))
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }

    foreign = Dnsruby::RR.create(@key.to_s)
    foreign.name = 'other.invalid.'
    @verifier.add_trust_anchor(foreign)
    message = wildcard_message
    record = Dnsruby::RR.create('a.collision.invalid. 300 IN NSEC z.collision.invalid. TXT NSEC RRSIG')
    signed(record, key: foreign).each { |rr| message.add_authority(rr) }
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_nsec3_proofs_with_empty_and_binary_salts
    ['-', 'a1b200ff'].each do |salt|
      message = wildcard_message(name: 'x.b.collision.invalid.')
      add_nsec3(message, salt: salt, next_closer: 'b.collision.invalid.')
      assert(@verifier.verify(message))
      assert(Dnsruby::Dnssec.validate(message))
      assert_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
    end
  end

  def test_nsec3_matching_hash_is_not_a_covering_proof
    message = wildcard_message
    add_nsec3(message, exact: true)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(message) }
  end

  def test_authenticated_opt_out_is_insecure_and_clears_ad
    message = wildcard_message
    add_nsec3(message, flags: 1)
    assert_equal(:insecure, @verifier.verify_result(message))
    refute(@verifier.verify(message))
    refute(Dnsruby::Dnssec.verify(message))
    message.security_level = Dnsruby::Message::SecurityLevel.SECURE
    message.header.ad = true
    assert(Dnsruby::Dnssec.validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.INSECURE, message.security_level)
    refute(message.header.ad)

    message.header.ad = true
    @verifier.stub(:follow_chain, Dnsruby::RRSet.new([@key])) do
      assert(@verifier.validate(message, message))
    end
    assert_equal(Dnsruby::Message::SecurityLevel.INSECURE, message.security_level)
    refute(message.header.ad)
  end

  def test_secure_proof_is_preferred_and_stale_insecure_status_does_not_survive
    message = wildcard_message
    add_nsec3(message, flags: 1)
    add_nsec(message)
    message.security_level = Dnsruby::Message::SecurityLevel.INSECURE
    assert(Dnsruby::Dnssec.validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
  end

  private

  def signed(record, key: @key)
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: 300,
      type_covered: record.type, algorithm: 13,
      labels: record.name.labels.length - (record.name.wild? ? 1 : 0),
      original_ttl: 300, expiration: Time.now.to_i + 3600, inception: Time.now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    bytes = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    der = @private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + bytes))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    Dnsruby::RRSet.new([record, signature])
  end

  def wildcard_message(name: 'b.collision.invalid.', type: 'A', data: '192.0.2.1', qtype: 'A')
    records = signed(Dnsruby::RR.create("*.collision.invalid. 300 IN #{type} #{data}"))
    Dnsruby::Message.new(name, qtype).tap do |message|
      message.header.qr = true
      records.each { |rr| rr.name = name; message.add_answer(rr) }
    end
  end

  def add_nsec(message, owner: 'a.collision.invalid.', following: 'z.collision.invalid.', types: 'TXT NSEC RRSIG')
    signed(Dnsruby::RR.create("#{owner} 300 IN NSEC #{following} #{types}")).each { |rr| message.add_authority(rr) }
  end

  def add_nsec3(message, salt: '-', flags: 0, next_closer: 'b.collision.invalid.', exact: false)
    hash = Dnsruby::RR::NSEC3.calculate_hash(next_closer, 2,
      Dnsruby::RR::NSEC3.decode_salt(salt), Dnsruby::Nsec3HashAlgorithms.SHA_1)
    value = Dnsruby::RR::NSEC3.decode_next_hashed(hash).unpack1('H*').to_i(16)
    hash_at = lambda do |offset|
      bytes = [((value + offset) % (2 ** 160)).to_s(16).rjust(40, '0')].pack('H*')
      Dnsruby::RR::NSEC3.encode_next_hashed(bytes)
    end
    owner, following = hash_at.call(exact ? 0 : -1), hash_at.call(1)
    record = Dnsruby::RR.create("#{owner}.#{@zone} 300 IN NSEC3 1 #{flags} 2 #{salt} #{following} TXT")
    signed(record).each { |rr| message.add_authority(rr) }
  end
end
