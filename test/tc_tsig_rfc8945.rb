require_relative 'spec_helper'
require 'minitest/mock'
require 'stringio'

class TsigRfc8945Test < Minitest::Test
  SECRET = 'secret'.b

  def key(algorithm = 'hmac-sha256', **options)
    Dnsruby::RR.create({name: 'key.example.', type: 'TSIG', klass: 'ANY',
      key: [SECRET].pack('m0'), algorithm: algorithm}.merge(options))
  end

  def request(signer)
    Dnsruby::Message.new('example.', 'A').tap do |message|
      message.header.id = 12_345
      signer.apply(message)
    end
  end

  def dns_name(text)
    text.sub(/\.$/, '').split('.').map { |label| [label.bytesize].pack('C') + label }.join.b + "\0".b
  end

  # Build expected signatures with OpenSSL and explicit wire fields, independently
  # of TSIG#generate, #calculate_mac and #sig_data.
  def signed_wire(query, algorithm: 'hmac-sha256', length: nil, time: Time.now.to_i,
      fudge: 300, error: 0, other: ''.b, original_id: query.header.id,
      header_id: query.header.id, prior: nil, klass: 255, ttl: 0)
    message = Dnsruby::Message.new('example.', 'A')
    message.header.id, message.header.qr = original_id, true
    message.header.rcode = 9 unless error.zero?
    unsigned = message.encode
    timers = [time >> 32, time & 0xffff_ffff, fudge].pack('nNn')
    variables = dns_name('key.example.') + [klass, ttl].pack('nN') +
      dns_name(algorithm.downcase) + timers + [error, other.bytesize].pack('n2') + other
    prefix = prior || [query.tsig.mac_size].pack('n') + query.tsig.mac
    digest = {'hmac-md5.sig-alg.reg.int' => 'MD5', 'hmac-sha1' => 'SHA1',
      'hmac-sha256' => 'SHA256', 'hmac-sha512' => 'SHA512'}.fetch(algorithm.downcase.sub(/\.$/, ''))
    mac = OpenSSL::HMAC.digest(digest, SECRET, prefix + unsigned + (prior ? timers : variables))
    mac = mac.byteslice(0, length) if length && length <= mac.bytesize
    mac += 'x' * (length - mac.bytesize) if length && length > mac.bytesize
    rdata = dns_name(algorithm) + timers + [mac.bytesize].pack('n') + mac +
      [original_id, error, other.bytesize].pack('n3') + other
    wire = unsigned.dup
    wire[0, 2], wire[10, 2] = [header_id].pack('n'), [1].pack('n')
    wire << dns_name('key.example.') << [250, klass, ttl, rdata.bytesize].pack('n2Nn') << rdata
    [wire, mac]
  end

  def verify(signer, query, wire)
    decoded = Dnsruby::Message.decode(wire)
    [signer.verify(query, decoded, wire), decoded]
  end

  def test_omitted_algorithm_uses_sha256
    default = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY', key: [SECRET].pack('m0'))
    assert_equal(Dnsruby::RR::TSIG::HMAC_SHA256, default.algorithm)
    query = request(default)
    assert_equal(32, query.tsig.mac_size)
    wire, = signed_wire(query)
    assert_equal(true, verify(default, query, wire).first)
    assert_equal(32, request(key('hmac-sha256')).tsig.mac_size)
  end

  def test_explicit_md5_aliases_sign_and_verify_independent_responses
    ['hmac-md5', 'HMAC-MD5.SIG-ALG.REG.INT.', Dnsruby::RR::TSIG::HMAC_MD5].each do |algorithm|
      signer = key(algorithm)
      query = request(signer)
      assert_equal(Dnsruby::RR::TSIG::HMAC_MD5, query.tsig.algorithm)
      assert_equal(16, query.tsig.mac_size)
      wire, = signed_wire(query, algorithm: 'hmac-md5.sig-alg.reg.int')
      result, reply = verify(signer, query, wire)
      assert_equal(true, result)
      assert(reply.verified?)
      restored_key = Dnsruby::Message.decode(wire).tsig
      restored_key.key = [SECRET].pack('m0')
      assert_equal(16, request(restored_key).tsig.mac_size)
    end
  end

  def test_md5_requires_explicit_selection_and_authenticates_errors
    signer = key('hmac-md5')
    query = request(signer)
    [0, 18, 22].each do |error|
      wire, = signed_wire(query, algorithm: 'hmac-md5.sig-alg.reg.int', error: error,
        time: query.tsig.time_signed, other: error == 18 ? [0, Time.now.to_i].pack('nN') : ''.b)
      result, response = verify(signer, query, wire)
      assert_equal(error.zero?, result)
      assert(response.verified?)
      assert_equal(error, response.tsigerror)
      decoded = Dnsruby::Message.decode(wire)
      forged = wire.dup
      mac_offset = decoded.tsigstart + dns_name('key.example.').bytesize + 10 + dns_name('hmac-md5.sig-alg.reg.int').bytesize + 10
      forged.setbyte(mac_offset, forged.getbyte(mac_offset) ^ 1)
      result, response = verify(signer, query, forged)
      assert_equal(false, result)
      assert_equal(Dnsruby::RCode::BADSIG, response.tsigerror)
      refute(response.verified?)
    end
    [['hmac-sha256', 'hmac-md5.sig-alg.reg.int'], ['hmac-md5', 'hmac-sha256']].each do |configured, received|
      signer = key(configured)
      query = request(signer)
      wire, = signed_wire(query, algorithm: received)
      OpenSSL::HMAC.stub(:digest, ->(*) { flunk('Wrong algorithm reached HMAC verification') }) do
        result, response = verify(signer, query, wire)
        assert_equal(false, result)
        assert_equal(Dnsruby::RCode::BADKEY, response.tsigerror)
        refute(response.verified?)
      end
    end
  end

  def test_inbound_md5_does_not_warn_but_presigned_outbound_md5_does
    sender = nil
    signer = key('hmac-md5')
    query = request(signer)
    wire, = signed_wire(query, algorithm: 'hmac-md5.sig-alg.reg.int')
    klass = Dnsruby::RR::TSIG
    mutex = klass.const_get(:LEGACY_WARNING_MUTEX)
    previous = mutex.synchronize do
      old = klass.instance_variable_get(:@legacy_warning_issued)
      klass.instance_variable_set(:@legacy_warning_issued, false)
      old
    end
    output = StringIO.new
    logger = Logger.new(output)
    logger.level = Logger::WARN
    Dnsruby.stub(:log, logger) do
      assert_equal(Dnsruby::RR::TSIG::HMAC_MD5, Dnsruby::Message.decode(wire).tsig.algorithm)
      assert_equal(true, verify(signer, query, wire).first)
      assert_equal(false, verify(key, query, wire).first)
      assert_empty(output.string)
      sender = Dnsruby::PacketSender.new(server: '127.0.0.1')
      message = Dnsruby::Message.decode(wire)
      message.send_raw = true
      sender.make_query_packet(message)
      assert_match(/WARN.*HMAC-MD5/, output.string)
      sender.make_query_packet(message)
      assert_equal(1, output.string.lines.size)
    end
  ensure
    sender&.close
    mutex&.synchronize { klass.instance_variable_set(:@legacy_warning_issued, previous) }
  end

  def test_algorithm_names_are_case_insensitive_strings_and_names
    ['HMAC-SHA256.', Dnsruby::Name.new([Dnsruby::Name::Label.new('HmAc-ShA256')])].each do |algorithm|
      signer = key(algorithm)
      query = request(signer)
      wire, = signed_wire(query, algorithm: 'HmAc-ShA256')
      assert_equal(true, verify(signer, query, wire).first)
    end
  end

  def test_allowed_mac_prefixes_and_protocol_bounds
    {'hmac-sha1' => [10, 12, 20], 'hmac-sha256' => [16, 24, 32], 'hmac-sha512' => [32, 48, 64]}.each do |algorithm, lengths|
      signer = key(algorithm)
      query = request(signer)
      lengths.each do |length|
        wire, = signed_wire(query, algorithm: algorithm, length: length)
        result, reply = verify(signer, query, wire)
        assert_equal(true, result, "#{algorithm}/#{length}")
        assert(reply.verified?)
      end
      [0, lengths.first - 1, lengths.last + 1].each do |length|
        wire, = signed_wire(query, algorithm: algorithm, length: length)
        result, reply = verify(signer, query, wire)
        assert_equal(false, result)
        assert_equal(Dnsruby::RCode::FORMERR, reply.tsigerror)
        refute(reply.verified?)
      end
    end
  end

  def test_configured_mac_length_is_separate_from_wire_size_and_sets_local_minimum
    signer = key(mac_length: 16)
    query = request(signer)
    assert_equal(16, query.tsig.mac_size)
    assert_equal(16, query.tsig.mac_length)
    [16, 24, 32].each do |length|
      wire, = signed_wire(query, length: length)
      assert_equal(true, verify(query.tsig, query, wire).first)
    end
    strict = key(mac_length: 32)
    query = request(strict)
    wire, = signed_wire(query, length: 16)
    result, reply = verify(strict, query, wire)
    assert_equal(false, result)
    assert_equal(22, reply.tsigerror)
    [1, 15, 33].each do |length|
      assert_raises(Dnsruby::EncodeError) { request(key(mac_length: length)) }
    end
    [0, -1, 16.5, '16'].each do |length|
      assert_raises(ArgumentError) { key(mac_length: length) }
    end
  end

  def test_mac_is_checked_before_time_and_badtime_remains_authenticatable
    signer = key
    query = request(signer)
    wire, = signed_wire(query, time: Time.now.to_i - 10_000)
    valid, reply = verify(signer, query, wire)
    assert_equal(false, valid)
    assert_equal(Dnsruby::RCode::BADTIME, reply.tsigerror)
    forged = wire.dup
    decoded = Dnsruby::Message.decode(wire)
    mac_offset = decoded.tsigstart + dns_name('key.example.').bytesize + 10 + dns_name('hmac-sha256').bytesize + 10
    forged.setbyte(mac_offset, forged.getbyte(mac_offset) ^ 1)
    valid, reply = verify(signer, query, forged)
    assert_equal(false, valid)
    assert_equal(Dnsruby::RCode::BADSIG, reply.tsigerror)
    wire, = signed_wire(query, error: 18, time: Time.now.to_i - 10_000, other: [0, Time.now.to_i].pack('nN'))
    result, reply = verify(signer, query, wire)
    assert_equal(false, result)
    refute(reply.verified?)
    wire, = signed_wire(query, error: 18, time: query.tsig.time_signed, other: [0, Time.now.to_i + 10_000].pack('nN'))
    result, reply = verify(signer, query, wire)
    assert_equal(false, result)
    assert(reply.verified?)
    assert_equal(18, reply.tsigerror)
  end

  def test_original_id_is_substituted_in_the_mac_input_without_mutating_the_message
    signer = key
    query = request(signer)
    wire, = signed_wire(query, original_id: query.header.id, header_id: 54321)
    frozen_wire = wire.freeze
    result, reply = verify(signer, query, frozen_wire)
    assert_equal(true, result)
    assert_equal(54321, reply.header.id)
    assert_equal(frozen_wire, wire)
    tampered = wire.dup
    tampered[-6, 2] = [query.header.id + 1].pack('n')
    result, reply = verify(signer, query, tampered)
    assert_equal(false, result)
    assert_equal(Dnsruby::RCode::BADSIG, reply.tsigerror)
    assert_equal(54321, reply.header.id)
  end

  def test_other_data_is_checked_even_with_a_valid_mac
    signer = key
    query = request(signer)
    [[0, 'unexpected'], [18, 'short'], [22, 'unexpected']].each do |error, other|
      wire, = signed_wire(query, error: error, other: other)
      result, reply = verify(signer, query, wire)
      assert_equal(false, result)
      assert_equal(Dnsruby::RCode::FORMERR, reply.tsigerror)
    end
  end

  def test_badtime_generation_echoes_request_timers_and_preserves_server_time
    signer = key(fudge: 123)
    query = request(signer)
    server_time = Time.now.to_i + 10_000
    error_key = key(error: 18, time_signed: server_time, fudge: 30,
      other_size: 6, other_data: [0, server_time].pack('nN'))
    reply = Dnsruby::Message.new('example.', 'A')
    reply.header.qr, reply.header.rcode = true, 9
    error_key.apply(reply, query)
    assert_equal(query.tsig.time_signed, reply.tsig.time_signed)
    assert_equal(query.tsig.fudge, reply.tsig.fudge)
    assert_equal([0, server_time].pack('nN'), reply.tsig.other_data)
    _, expected_mac = signed_wire(query, time: query.tsig.time_signed, fudge: 123,
      error: 18, other: [0, server_time].pack('nN'))
    assert_equal(expected_mac, reply.tsig.mac)
    result, decoded = verify(signer, query, reply.encode)
    assert_equal(false, result)
    assert(decoded.verified?)
    [16, 17].each do |error|
      reply = Dnsruby::Message.new('example.')
      reply.header.qr, reply.header.rcode = true, 9
      assert_raises(Dnsruby::EncodeError) { key(error: error).apply(reply, query) }
    end
  end

  def test_response_to_a_forwarded_request_retains_transport_and_original_ids
    signer = key
    query = request(signer)
    forwarded = query.encode
    forwarded[0, 2] = [54321].pack('n')
    forwarded = Dnsruby::Message.decode(forwarded)
    reply = Dnsruby::Message.new('example.', 'A')
    reply.header.qr = true
    signer.apply(reply, forwarded)
    assert_equal(54321, reply.header.id)
    assert_equal(query.header.id, reply.tsig.original_id)
    _, expected_mac = signed_wire(forwarded, time: reply.tsig.time_signed,
      original_id: query.header.id, header_id: 54321)
    assert_equal(expected_mac, reply.tsig.mac)
    assert_equal(true, verify(signer, query, reply.encode).first)
  end

  def test_stream_chains_received_truncated_macs_and_accepts_99_unsigned_messages
    signer = key(mac_length: 16)
    query = request(signer)
    now = Time.now.to_i
    wire, mac = signed_wire(query, length: 16, time: now)
    assert_equal(true, signer.verify_envelope(Dnsruby::Message.decode(wire), wire))
    prior = [mac.bytesize].pack('n') + mac
    99.times do
      unsigned = Dnsruby::Message.new('example.').encode
      reply = Dnsruby::Message.decode(unsigned)
      assert_equal(true, signer.verify_envelope(reply, unsigned))
      assert_equal(:Intermediate, reply.tsigstate)
      prior += unsigned
    end
    wire, mac = signed_wire(query, length: 32, prior: prior, time: now)
    assert_equal(true, signer.verify_envelope(Dnsruby::Message.decode(wire), wire))
    wire, = signed_wire(query, length: 16, prior: [mac.bytesize].pack('n') + mac, time: now)
    assert_equal(true, signer.verify_envelope(Dnsruby::Message.decode(wire), wire))
    99.times { signer.verify_envelope(Dnsruby::Message.new, Dnsruby::Message.new.encode) }
    assert_equal(false, signer.verify_envelope(Dnsruby::Message.new, Dnsruby::Message.new.encode))
  end

  def test_signed_stream_times_cannot_decrease
    signer = key
    query = request(signer)
    now = Time.now.to_i
    wire, mac = signed_wire(query, time: now)
    assert_equal(true, signer.verify_envelope(Dnsruby::Message.decode(wire), wire))
    wire, = signed_wire(query, prior: [mac.bytesize].pack('n') + mac, time: now - 1)
    reply = Dnsruby::Message.decode(wire)
    assert_equal(false, signer.verify_envelope(reply, wire))
    assert_equal(Dnsruby::RCode::BADTIME, reply.tsigerror)
  end

  def test_signing_rejects_invalid_request_fields_and_supports_full_fudge_range
    assert_equal(65_535, key(fudge: 65_535).fudge)
    [{time_signed: 1 << 48}, {time_signed: -1}, {ttl: 60}, {error: 18}, {other_size: 1}].each do |fields|
      assert_raises(Dnsruby::EncodeError) { request(key(**fields)) }
    end
    query = request(key)
    decoded = Dnsruby::Message.decode(query.encode)
    assert_raises(Dnsruby::EncodeError) { key.apply(decoded) }
  end

  def test_algorithm_name_compression_is_rejected
    signer = key
    query = request(signer)
    wire, = signed_wire(query)
    decoded = Dnsruby::Message.decode(wire)
    rdata_at = decoded.tsigstart + dns_name('key.example.').bytesize + 10
    wire[rdata_at, dns_name('hmac-sha256').bytesize] = [0xc00c].pack('n')
    length_at = rdata_at - 2
    wire[length_at, 2] = [wire.bytesize - rdata_at].pack('n')
    assert_raises(Dnsruby::DecodeError) { Dnsruby::Message.decode(wire) }
  end

  def test_signing_rejects_existing_signatures_in_any_section
    [:answer, :authority, :additional].each do |section|
      message = Dnsruby::Message.new('example.')
      message.public_send(section) << request(key).tsig
      message.add_additional(Dnsruby::RR.create('extra.example. 0 IN TXT "data"'))
      assert_raises(Dnsruby::EncodeError) { key.apply(message) }
    end
  end
end
