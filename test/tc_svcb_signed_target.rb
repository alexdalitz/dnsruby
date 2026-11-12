require_relative 'spec_helper'
require 'openssl'
require 'base64'
require 'stringio'
require 'tempfile'

class SvcbSignedTargetTest < Minitest::Test
  MIXED_CASE_RDATA = ['000103466f6f074578616d706c6503434f4d00'].pack('H*').freeze

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    exponent = @rsa.e.to_s(2)
    key_bytes = [exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2)
    @key = Dnsruby::RR.create("example. 300 IN DNSKEY 256 3 8 #{Base64.strict_encode64(key_bytes)}")
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    @verifier.add_trust_anchor(@key)
  end

  def test_signed_text_roundtrip_preserves_target_case
    [64, 65].each do |type|
      original, signature = signed_record(type)
      assert_signed_copy(original, Dnsruby::RR.create(original.to_s), signature)
    end
  end

  def test_signed_hash_constructor_preserves_string_and_name_targets
    [64, 65].each do |type|
      original, signature = signed_record(type)
      ['Foo.Example.COM.', original.target].each do |target|
        copy = Dnsruby::RR.create(name: original.name, type: type, ttl: 300,
          priority: 1, target: target)
        assert_signed_copy(original, copy, signature)
      end
    end
  end

  def test_signed_saved_zone_roundtrip_preserves_target_case
    [64, 65].each do |type|
      original, signature = signed_record(type)
      Tempfile.create(['dnsruby-signed-target', '.zone']) do |zone|
        zone.write("#{original}\n#{signature}\n")
        zone.flush
        records = Dnsruby::ZoneReader.new('example.').process_file(zone.path)
        assert_signed_copy(original, records.first, records.last)
      end
    end
  end

  def test_signed_relative_zone_target_preserves_target_and_origin_case
    [64, 65].each do |type|
      original, signature = signed_record(type)
      text = "example. 300 IN TYPE#{type} 1 Foo\n#{signature}\n"
      records = Dnsruby::ZoneReader.new('Example.COM.').process_file(StringIO.new(text))
      assert_signed_copy(original, records.first, records.last)
    end
  end

  def test_ascii_escaped_target_preserves_wire_octets
    [64, 65].each do |type|
      target = 'F\\111o\\.Bar.\\255.Example.COM.'
      expected = [1].pack('n') + "\x07Foo.Bar\x01\xff\x07Example\x03COM\0".b
      string = Dnsruby::RR.create("example. IN TYPE#{type} 1 #{target}")
      hash = Dnsruby::RR.create(name: 'example.', type: type, priority: 1, target: target)
      [string, hash, Dnsruby::RR.create(string.to_s)].each do |record|
        assert_equal(expected, record.rdata)
      end
    end
  end

  def test_unicode_targets_retain_idna_conversion
    [64, 65].each do |type|
      target = 'フガフガ。hogehoge.エグザンプル.JP.'
      string = Dnsruby::RR.create("example. IN TYPE#{type} 1 #{target}")
      hash = Dnsruby::RR.create(name: 'example.', type: type, priority: 1, target: target)
      [string, hash].each do |record|
        assert_equal('xn--mcka5jb.hogehoge.xn--ickqs6k2dyb.jp.', record.target.to_s(true))
      end

      text = "example. IN TYPE#{type} 1 Foo\n"
      record = Dnsruby::ZoneReader.new('møllerriis.com.').process_file(StringIO.new(text)).first
      assert_equal('Foo.xn--mllerriis-l8a.com.', record.target.to_s(true))
    end
  end

  private

  def signed_record(type)
    record = Dnsruby::RR.new_from_data('example.', type, Dnsruby::Classes::IN, 300,
      MIXED_CASE_RDATA.bytesize, MIXED_CASE_RDATA, 0)
    now = Time.now.to_i
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: 300,
      type_covered: type, algorithm: 8, labels: 1, original_ttl: 300,
      expiration: now + 3600, inception: now - 60, key_tag: @key.key_tag,
      signers_name: 'example.')
    canonical = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    signature.signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + canonical)
    assert(@verifier.verify(Dnsruby::RRSet.new([record, signature])), 'original wire record must verify')
    [record, signature]
  end

  def assert_signed_copy(original, copy, signature)
    assert_equal(original.rdata, copy.rdata)
    assert_equal('Foo.Example.COM.', copy.target.to_s(true))
    assert(@verifier.verify(Dnsruby::RRSet.new([copy, signature])), 'reconstructed record must retain its signature')
  end
end
