require_relative 'spec_helper'
require 'minitest/mock'
require 'openssl'
require 'base64'
require 'timeout'

class KeyCacheIdentityTest < Minitest::Test
  # Test-only keys with different public-key material but the same DNSKEY tag
  # (48708 with flags 257, protocol 3 and algorithm 13). Fixed keys avoid a
  # probabilistic collision search and make the cryptographic checks repeatable.
  PRIVATE_KEYS = [<<~PEM, <<~PEM].freeze
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEICU+8aMcoyz9AMcy/h7MbFCYLKxDS/EtQPgHaXSUhzu8oAoGCCqGSM49
    AwEHoUQDQgAE2dAvoL88tZbfwgPEytuVr9EsFi79Hw3l5YtxTtu1QO2NIzjD8Gdb
    WBuInfkty8P9k2zCOr7ngwuKEFCNHx5Dug==
    -----END EC PRIVATE KEY-----
  PEM
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIAL8ZvOFzy7oNwn/0NhgQ+hWu4UrvSJXK5nKPsAo5evFoAoGCCqGSM49
    AwEHoUQDQgAE1fdv3FiCisktVXjdRZRD7QjneeVdiLSLjFOpp1pynxXBmw0a+1Tw
    4LJ0KKrSuwVVv66IIXXWMRoyOxIfZsOVBA==
    -----END EC PRIVATE KEY-----
  PEM

  DSA_PRIVATE_KEY = <<~PEM.freeze
    -----BEGIN DSA PRIVATE KEY-----
    MIIBvAIBAAKBgQD9x9CuGC3tbWplxT+2Zp030mynG3KnzyBPIKfYRx+TDprNHQH4
    j/ptA/SPEPboIwO4QvQ52jsA94Gz9Frcwc/IxdavY6rS6L5N3y327ogD9Ry30jpB
    kvaHtKjKlJjlnG1jzzj+fKoHImG2B+Be3AmmKuXw2f1wlMdO+FkcNPqdLwIVAOI9
    73RMLRrptdT9VxtgmB2FZjrrAoGBAOG6M628TvLmfGPdlRUlsL6XvW01swv21+e/
    n/wi6UIqmaQZrh0hOQ9PW97/po2mMViG79xcvcbzMshgxF7nNsGethGQ9zbK3ynd
    gxonua6RvQa/6aGvSJ3Yx2MSeeVdyVGhz+kARxumg9lHBNftx6P29NGxqbYHcWhE
    +59wwlQhAoGBAMFmlnzv86whfLgToGZKl9tl6LEMbvR7J9KQZ4czX+LTguMGprtQ
    5WAU3oC9FLAPyUFyBhmSv2VVe5ob+07z/Ofpx3PtWAbZYlJdrgh7ZVtluVWewfGN
    DqPy94Ncz3rORtR96NsGOmct1jmoZOp87KPKTuftb3bzSroLLn/6V1dtAhR77/9H
    DOw8H1aQpmF7D4JVCnyExQ==
    -----END DSA PRIVATE KEY-----
  PEM

  def setup
    @now = Time.now
    @private_keys = PRIVATE_KEYS.map { |pem| OpenSSL::PKey::EC.new(pem) }
    @a, @b = @private_keys.map do |key|
      bytes = key.public_key.to_octet_string(:uncompressed).byteslice(1, 64)
      Dnsruby::RR.create("collision.invalid. 300 IN DNSKEY 257 3 13 #{Base64.strict_encode64(bytes)}")
    end
    @cache = Dnsruby::KeyCache.new
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    @record = Dnsruby::RR.create('www.collision.invalid. 300 IN A 192.0.2.1')
  end

  def test_collision_storage_and_exact_deletion_ignore_ttl_and_owner_case
    refute_equal(@a.key, @b.key)
    assert_equal(@a.key_tag, @b.key_tag)
    @cache.add_key_with_expiration(@a, @now.to_i + 60)
    @cache.add_key_with_expiration(@b, @now.to_i + 120)
    assert_equal([@a, @b], @cache.keys)

    equivalent = Dnsruby::RR.create(@a.to_s)
    equivalent.name = 'COLLISION.INVALID.'
    equivalent.ttl += 1
    assert_equal(@a, @cache.delete(equivalent))
    assert_equal([@b], @cache.keys)
    assert_nil(@cache.delete(equivalent))
  end

  def test_equivalent_additions_retain_longest_expiration
    equivalent = Dnsruby::RR.create(@a.to_s)
    equivalent.ttl += 1
    @cache.add_key_with_expiration(@a, @now.to_i + 120)
    @cache.add_key_with_expiration(equivalent, @now.to_i + 60)
    Time.stub(:now, @now + 90) { assert_equal([@a], @cache.keys) }
    @cache.add_key_with_expiration(equivalent, @now.to_i + 240)
    Time.stub(:now, @now + 180) { assert_equal([equivalent], @cache.keys) }
    Time.stub(:now, @now + 241) { assert_empty(@cache.keys) }
  end

  def test_copy_retains_both_colliding_keys_and_their_individual_expirations
    @cache.add_key_with_expiration(@a, @now.to_i + 60)
    @cache.add_key_with_expiration(@b, @now.to_i + 120)
    copy = Dnsruby::KeyCache.new(@cache)
    assert_equal([[@now.to_i + 60, @a], [@now.to_i + 120, @b]], copy.keys_and_expirations)
    copy.keys_and_expirations.first[0] = 0
    @cache.delete(@b)
    assert_equal([@a, @b], copy.keys)
    Time.stub(:now, @now + 90) { assert_equal([@b], copy.keys) }
    Time.stub(:now, @now + 121) { assert_empty(copy.keys) }
  end

  def test_copy_omits_expired_keys
    @cache.add_key_with_expiration(@a, @now.to_i - 1)
    @cache.add_key_with_expiration(@b, @now.to_i + 120)
    assert_equal([@b], Dnsruby::KeyCache.new(@cache).keys)
  end

  def test_other_rrset_signatures_are_not_changed_or_added_to_key_cache
    records = signed(@record, @a, 0)
    @cache.add_rrset(records)
    assert_empty(@cache.keys)
    assert_equal(Dnsruby::Types.A, records.sigs.first.type_covered)
  end

  def test_both_same_zone_colliding_keys_can_verify_in_either_order
    [0, 1].each do |signer|
      records = signed(@record, [@a, @b][signer], signer)
      [[@a, @b], [@b, @a]].each do |keys|
        assert(@verifier.verify_rrset(records, keys))
        assert(@verifier.verify_rrset(records, Dnsruby::RRSet.new(keys)))
      end
    end
    [@a, @b].each { |key| @verifier.add_trust_anchor(key) }
    assert(@verifier.verify_rrset(signed(@record, @a, 0)))
    assert(@verifier.verify_rrset(signed(@record, @b, 1)))
    assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(signed(@record, @a, 0), @b) }
  end

  def test_same_public_key_at_another_owner_cannot_verify
    foreign_key = Dnsruby::RR.create(@a.to_s)
    foreign_key.name = 'unrelated.invalid.'
    records = signed(@record, @a, 0)
    error = assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, foreign_key) }
    assert_match(/Signing key not found/, error.message)
    assert(@verifier.verify_rrset(records, [foreign_key, @a]))
  end

  def test_wire_decoded_malformed_collision_does_not_hide_valid_signing_key
    malformed = Dnsruby::RR.create(@a.to_s)
    # These bytes have the same key tag but are not a valid P-256 point. Decode
    # from wire to exercise lazy public-key parsing without an OpenSSL cache.
    malformed.key = Base64.strict_encode64("\0" * 62 + [@a.key_tag - 1038].pack('n'))
    message = Dnsruby::Message.new
    message.add_answer(malformed)
    malformed = Dnsruby::Message.decode(message.encode).answer.first
    assert_equal(@a.key_tag, malformed.key_tag)
    refute_equal(@a.key, malformed.key)
    records = signed(@record, @a, 0)
    [[malformed, @a], [@a, malformed]].each do |keys|
      assert(@verifier.verify_rrset(records, keys))
    end
    error = assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, malformed) }
    assert_match(/cryptographically verify/, error.message)
  end

  def test_invalid_signature_candidates_do_not_hide_a_valid_signature
    [:expired, :future, :corrupted].each do |mode|
      valid = signed(@record, @a, 0).sigs.first
      invalid = invalid_signature(valid, mode)
      [[invalid, valid], [valid, invalid]].each do |signatures|
        records = Dnsruby::RRSet.new([@record] + signatures)
        assert(@verifier.verify_rrset(records, @a))
      end
      records = Dnsruby::RRSet.new([@record, invalid])
      assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, @a) }
    end
  end

  def test_truncated_wire_rsa_and_dsa_keys_do_not_hide_another_valid_candidate
    valid = signed(@record, @a, 0).sigs.first
    [5, 8, 3].each do |algorithm|
      ['', "\0", "\xff", "\0\xff", "\xff\0\0", "\0\xff\xff\0"].each do |bytes|
        malformed = wire_key(algorithm, bytes.b)
        assert_raises(OpenSSL::PKey::PKeyError) { malformed.public_key }
        invalid = valid.clone
        invalid.algorithm = algorithm
        invalid.key_tag = malformed.key_tag
        invalid.signature = algorithm == 3 ? [bytes.getbyte(0) || 0].pack('C') + "\0" * 40 : "\0" * 64
        records = Dnsruby::RRSet.new([@record, invalid, valid])
        assert(@verifier.verify_rrset(records, [malformed, @a]))
        assert(@verifier.verify_rrset(records, [@a, malformed]))
        assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, malformed) }
      end
    end
  end

  def test_extended_rsa_exponent_length_preserves_public_key_numbers
    fixture = File.join(__dir__, 'fixtures', 'root-dnskey-2026-11-05.zone')
    original = Dnsruby::RR.create(File.readlines(fixture).find { |line| line.include?(' IN DNSKEY ') })
    length = original.key.getbyte(0)
    extended = wire_key(8, "\0" + [length].pack('n') + original.key.byteslice(1..-1))
    assert_equal(original.public_key.e, extended.public_key.e)
    assert_equal(original.public_key.n, extended.public_key.n)

    # Exercise both octets of the extended length with a 257-byte exponent.
    exponent = "\x01" + "\0" * 255 + "\x03"
    modulus = "\x7f" + "\xff" * 383
    extended = wire_key(8, "\0" + [exponent.bytesize].pack('n') + exponent + modulus)
    assert_equal(OpenSSL::BN.new(exponent, 2), extended.public_key.e)
    assert_equal(OpenSSL::BN.new(modulus, 2), extended.public_key.n)
  end

  def test_dsa_is_rejected_and_does_not_hide_a_supported_signature
    private_key = OpenSSL::PKey::DSA.new(DSA_PRIVATE_KEY)
    bytes = [8].pack('C') + private_key.q.to_s(2).rjust(20, "\0") +
      [:p, :g, :pub_key].map { |part| private_key.public_send(part).to_s(2).rjust(128, "\0") }.join
    key = wire_key(3, bytes)
    valid_ec = signed(@record, @a, 0).sigs.first
    valid_dsa = valid_ec.clone
    valid_dsa.algorithm = 3
    valid_dsa.key_tag = key.key_tag
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(@record, true) }.to_s
    der = private_key.sign(OpenSSL::Digest::SHA1.new, valid_dsa.sig_data + data)
    valid_dsa.signature = [8].pack('C') +
      OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(20, "\0") }.join
    error = assert_raises(Dnsruby::VerifyError) do
      @verifier.verify_rrset(Dnsruby::RRSet.new([@record, valid_dsa]), key)
    end
    assert_match(/prohibited/, error.message)

    ['', "\0", [7].pack('C') + valid_dsa.signature.byteslice(1..-1), [8].pack('C') + "\0" * 40].each do |signature|
      invalid = valid_dsa.clone
      invalid.signature = signature
      records = Dnsruby::RRSet.new([@record, invalid, valid_ec])
      assert(@verifier.verify_rrset(records, [key, @a]))
      assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, key) }
    end
  end

  def test_unsupported_signature_candidate_does_not_hide_supported_signature
    unsupported = Dnsruby::RR.create("collision.invalid. 300 IN DNSKEY 257 3 15 #{Base64.strict_encode64(@a.key)}")
    valid = signed(@record, @a, 0).sigs.first
    invalid = valid.clone
    invalid.algorithm = 15
    invalid.key_tag = unsupported.key_tag
    records = Dnsruby::RRSet.new([@record, invalid, valid])
    assert(@verifier.verify_rrset(records, [unsupported, @a]))
    assert(@verifier.verify_rrset(records, [@a, unsupported]))
    assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, unsupported) }
  end

  def test_invalid_signature_metadata_does_not_control_ds_discovery_expiration
    [:expired, :future].each do |mode|
      verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
      verifier.add_trust_anchor(Dnsruby::RR::DS.from_key(@a, 2))
      valid = signed(@a, @a, 0).sigs.first
      invalid = invalid_signature(valid, mode)
      records = Dnsruby::RRSet.new([@a, invalid])
      assert_raises(Dnsruby::VerifyError) { verifier.verify(records) }
      assert_empty(verifier.get_keys_to_check)
      records = Dnsruby::RRSet.new([@a, invalid, valid])
      assert(verifier.verify(records))
      assert_equal([Dnsruby::KeyCache.key_identity(@a)],
        verifier.get_keys_to_check.map { |key| Dnsruby::KeyCache.key_identity(key) })
      Time.stub(:now, @now + 3601) { assert_empty(verifier.get_keys_to_check) }
    end
  end

  def test_key_class_must_match_signature_class
    foreign_key = Dnsruby::RR.create(@a.to_s)
    foreign_key.klass = Dnsruby::Classes.CH
    records = signed(@record, @a, 0)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, foreign_key) }
    assert(@verifier.verify_rrset(records, [foreign_key, @a]))
  end

  def test_removing_one_collision_preserves_other_anchor_and_revokes_learned_trust
    records_a, records_b = signed(@a, @a, 0), signed(@b, @b, 1)
    [@a, @b].each { |key| @verifier.add_trust_anchor(key) }
    assert(@verifier.verify(records_a))
    assert(@verifier.verify(records_b))
    assert_equal(@a, @verifier.remove_trust_anchor(@a))
    assert_equal([@b], @verifier.trust_anchors)
    assert_empty(@verifier.trusted_keys)
    assert_raises(Dnsruby::VerifyError) { @verifier.verify(records_a) }
    assert(@verifier.verify(records_b))
  end

  def test_removing_an_expired_pruned_anchor_revokes_its_learned_keys
    @verifier.add_trust_anchor_with_expiration(@a, @now.to_i + 1)
    @verifier.add_trust_anchor_with_expiration(@b, @now.to_i + 120)
    records = signed(@a, @a, 0)
    Time.stub(:now, @now) { assert(@verifier.verify(records)) }
    Time.stub(:now, @now + 2) do
      assert_equal([@b], @verifier.trust_anchors) # Naturally expire and prune A.
      assert_empty(@verifier.trusted_keys)
      assert_nil(@verifier.remove_trust_anchor(@a))
      assert_equal([@b], @verifier.trust_anchors)
      assert_empty(@verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(records) }
    end
    Time.stub(:now, @now + 121) do
      assert_empty(@verifier.trust_anchors)
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(records) }
    end
  end

  def test_expired_anchor_removal_prevents_in_flight_key_republication
    @verifier.add_trust_anchor_with_expiration(@a, @now.to_i + 1)
    @verifier.add_trust_anchor_with_expiration(@b, @now.to_i + 120)
    records = signed(@a, @a, 0)
    clock = @now
    Time.stub(:now, -> { clock }) do
      mutation = lambda do
        clock = @now + 2
        assert_equal([@b], @verifier.trust_anchors)
        assert_nil(@verifier.remove_trust_anchor(@a))
      end
      pause_after_verification(mutation) { assert(@verifier.verify(records)) }
      assert_equal([@b], @verifier.trust_anchors)
      assert_empty(@verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { @verifier.verify(records) }
    end
  end

  private

  def wire_key(algorithm, bytes)
    key = Dnsruby::RR.create(@a.to_s)
    key.algorithm = algorithm
    key.instance_variable_set(:@key, bytes.b)
    message = Dnsruby::Message.new
    message.add_answer(key)
    Dnsruby::Message.decode(message.encode).answer.first
  end

  def invalid_signature(valid, mode)
    invalid = valid.clone
    case mode
    when :expired
      invalid.expiration = @now.to_i - 1
    when :future
      invalid.inception = @now.to_i + 3600
      invalid.expiration = @now.to_i + 7200
    when :corrupted
      invalid.signature = "\0" * 64
    end
    invalid
  end

  def signed(record, key, signer)
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: 300,
      type_covered: record.type, algorithm: 13, labels: record.name.labels.length,
      original_ttl: 300, expiration: @now.to_i + 3600, inception: @now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    der = @private_keys[signer].dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + data))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    Dnsruby::RRSet.new([record, signature])
  end

  def pause_after_verification(mutation)
    arrived, resume, start = Queue.new, Queue.new, Queue.new
    original = @verifier.method(:verify_rrset)
    thread = nil
    @verifier.define_singleton_method(:verify_rrset) do |*args|
      result = original.call(*args)
      if Thread.current.equal?(thread)
        arrived << true
        resume.pop
      end
      result
    end
    thread = Thread.new { start.pop; yield }
    start << true
    Timeout.timeout(3) { arrived.pop }
    Timeout.timeout(3) { mutation.call }
    resume << true
    Timeout.timeout(3) { thread.value }
  ensure
    @verifier.singleton_class.remove_method(:verify_rrset) if original
    thread.kill if thread && thread.alive?
    thread.join if thread
  end
end
