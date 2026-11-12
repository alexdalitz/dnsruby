require_relative 'spec_helper'
require 'socket'
require 'timeout'

class EdnsRetryRegressionsTest < Minitest::Test
  def test_formerr_then_truncated_udp_completes_over_tcp_without_mutating_caller
    udp = UDPSocket.new
    udp.bind('127.0.0.1', 0)
    tcp = TCPServer.new('127.0.0.1', udp.addr[1])
    requests = Queue.new
    udp_worker = Thread.new do
      2.times do |index|
        bytes, peer = udp.recvfrom(65_535)
        request = Dnsruby::Message.decode(bytes)
        requests << [:udp, request]
        reply = response(request)
        reply.header.rcode = Dnsruby::RCode::FORMERR if index.zero?
        reply.header.tc = true unless index.zero?
        udp.send(reply.encode, 0, peer[3], peer[1])
      end
    end
    tcp_worker = Thread.new do
      client = tcp.accept
      length = client.read(2).unpack1('n')
      request = Dnsruby::Message.decode(client.read(length))
      requests << [:tcp, request]
      reply = response(request)
      reply.add_answer(Dnsruby::RR.create('retry.example. 0 IN A 192.0.2.44'))
      bytes = reply.encode
      client.write([bytes.bytesize].pack('n') + bytes)
    ensure
      client.close if client && !client.closed?
    end
    [udp_worker, tcp_worker].each { |worker| worker.report_on_exception = false }

    resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', port: udp.addr[1],
      dnssec: false, do_validation: false, do_caching: false, udp_size: 4096,
      packet_timeout: 2, query_timeout: 4, retry_times: 1)
    query = edns_query
    original_opt = query.get_opt
    original_additional = query.additional.to_a.dup
    reply = Timeout.timeout(6) { resolver.send_message(query) }
    refute(reply.header.tc)
    assert_equal('192.0.2.44', reply.answer.first.address.to_s)
    refute(query.send_raw)
    assert_same(original_opt, query.get_opt)
    assert_equal(original_additional, query.additional)
    Timeout.timeout(2) { udp_worker.value; tcp_worker.value }
    observed = 3.times.map { requests.pop(true) }
    assert_equal([:udp, :udp, :tcp], observed.map(&:first))
    assert_equal([true, false, false], observed.map { |_, request| !!request.get_opt })
    observed.each do |_, request|
      assert_equal(query.header.id, request.header.id)
      assert_equal(['keep me'], request.additional.find { |rr| rr.type == Dnsruby::Types::TXT }.strings)
    end
    assert(requests.empty?)
  ensure
    resolver.close if resolver
    [udp_worker, tcp_worker].compact.each do |worker|
      worker.kill if worker.alive?
      worker.join
    end
    tcp.close if tcp && !tcp.closed?
    udp.close if udp && !udp.closed?
  end

  def test_edns_retry_keeps_normal_response_question_validation
    sender, retries = capturing_sender
    query = edns_query
    retry_query = request_edns_retry(sender, retries, query)
    invalid = response(retry_query, 'unrelated.example.')
    assert_equal(false, check(sender, invalid, retry_query))
    assert_equal(1, retries.length, 'invalid response must not start another attempt')
    assert_equal(true, check(sender, response(retry_query), retry_query))
    refute(query.send_raw)
    refute(retry_query.send_raw)
    refute_nil(query.get_opt)
    assert_nil(retry_query.get_opt)
  end

  def test_no_tcp_and_ignore_truncation_are_honoured_after_edns_retry
    [{no_tcp: true}, {ignore_truncation: true}, {no_tcp: true, ignore_truncation: true}].each do |options|
      sender, retries = capturing_sender(options)
      retry_query = request_edns_retry(sender, retries, edns_query)
      truncated = response(retry_query)
      truncated.header.tc = true
      assert_equal(true, check(sender, truncated, retry_query), options.inspect)
      assert_equal(1, retries.length, 'transport policy must prevent a TCP retry')
    end
  end

  def test_public_raw_mode_still_bypasses_protocol_retries
    sender, retries = capturing_sender
    query = edns_query
    query.send_raw = true
    [Dnsruby::RCode::FORMERR, Dnsruby::RCode::NOERROR].each do |rcode|
      reply = response(query, 'raw-reply.example.')
      reply.header.rcode = rcode
      reply.header.tc = true
      assert_equal(true, check(sender, reply, query))
      assert_empty(retries)
      assert(query.send_raw)
      refute_nil(query.get_opt)
    end
  end

  def test_signed_edns_retry_verifies_response_and_resigns_changed_request
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    [:sender_key, :message_key].each do |mode|
      key = Dnsruby::RR.create(name: 'retry-key.example.', type: 'TSIG', klass: 'ANY',
        key: 'c2VjcmV0', algorithm: 'hmac-sha256')
      sender, retries = capturing_sender
      query = edns_query
      if mode == :sender_key
        sender.tsig = key
      else
        query.set_tsig(key)
      end
      original_bytes = sender.make_query_packet(query)
      assert_equal(1, query.additional.count { |rr| rr.type == Dnsruby::Types::TSIG })
      formerr = response(query)
      formerr.header.rcode = Dnsruby::RCode::FORMERR
      key.apply(formerr, query)
      formerr = Dnsruby::Message.decode(formerr.encode)

      assert_equal(false, check(sender, formerr, query))
      assert(formerr.verified?)
      assert_equal(1, retries.length)
      retry_query, _, _, use_tcp, disable_edns = retries.first
      assert_equal(false, use_tcp)
      assert_equal(true, disable_edns)
      bytes = sender.make_query_packet(retry_query, use_tcp, disable_edns)
      decoded = Dnsruby::Message.decode(bytes)
      assert_nil(decoded.get_opt)
      assert_equal(1, decoded.additional.count { |rr| rr.type == Dnsruby::Types::TSIG })
      expected = key.generate(decoded, nil, '', bytes, decoded.tsig)
      assert_equal(expected.mac, decoded.tsig.mac, 'retry must be signed over the changed packet')
      refute_equal(query.tsig.mac, decoded.tsig.mac)
      assert_equal(original_bytes, query.encode, 'retry must not replace the caller\'s signed packet')
      refute(retry_query.send_raw)

      unsigned = response(retry_query)
      assert_instance_of(Dnsruby::TsigNotSignedResponseError, check(sender, unsigned, retry_query))
      signed = response(retry_query)
      key.apply(signed, decoded)
      signed = Dnsruby::Message.decode(signed.encode)
      assert_equal(true, check(sender, signed, retry_query))
      assert(signed.verified?)
      assert_equal(1, retries.length)
    end
  end

  def test_failed_signing_can_be_repaired_and_retried_without_sending_unsigned
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    key = Dnsruby::RR.create(name: 'retry-key.example.', type: 'TSIG', klass: 'ANY',
      key: 'c2VjcmV0', algorithm: 'hmac-sha256')
    sender, = capturing_sender
    sender.tsig = key
    query = edns_query
    invalid = Dnsruby::RR.get_class(62001, 1).new('x'.b * 65_536)
    invalid.name, invalid.ttl, invalid.type, invalid.klass = 'size.example.', 0, 62001, 1
    query.add_additional(invalid)

    assert_raises(Dnsruby::EncodeError) { sender.make_query_packet(query) }
    assert_nil(query.tsig, 'failed signing must not leave a partial signature')
    refute(query.signed?)
    query.remove_additional
    bytes = sender.make_query_packet(query)
    decoded = Dnsruby::Message.decode(bytes)
    assert_equal(1, decoded.additional.count { |rr| rr.type == Dnsruby::Types::TSIG })
    assert(query.signed?)
    expected = key.generate(decoded, nil, '', bytes, decoded.tsig)
    assert_equal(expected.mac, decoded.tsig.mac, 'repaired request must be authenticated')
    reply = response(query)
    key.apply(reply, decoded)
    reply = Dnsruby::Message.decode(reply.encode)
    assert_equal(true, check(sender, reply, query))
    assert(reply.verified?)
  end

  private

  def edns_query
    Dnsruby::Message.new('retry.example.').tap do |query|
      query.header.rd = true
      query.do_validation = query.do_caching = false
      query.add_additional(Dnsruby::RR::OPT.new(4096))
      query.add_additional(Dnsruby::RR.create('extra.example. 0 IN TXT "keep me"'))
    end
  end

  def response(query, name = query.question.first.qname)
    Dnsruby::Message.new(name).tap do |reply|
      reply.header.id = query.header.id
      reply.header.qr = true
    end
  end

  def capturing_sender(options = {})
    sender = Dnsruby::PacketSender.new({server: '127.0.0.1', dnssec: false,
      udp_size: 4096}.merge(options))
    retries = []
    sender.define_singleton_method(:send_async) { |*arguments| retries << arguments }
    [sender, retries]
  end

  def check(sender, reply, query)
    sender.check_response(reply, reply.encode, query, Queue.new, :retry, false)
  end

  def request_edns_retry(sender, retries, query)
    formerr = response(query)
    formerr.header.rcode = Dnsruby::RCode::FORMERR
    assert_equal(false, check(sender, formerr, query))
    assert_equal(1, retries.length)
    retry_query, _, id, use_tcp, disable_edns = retries.first
    assert_equal(:retry, id)
    assert_equal(false, use_tcp)
    assert_equal(true, disable_edns)
    retry_query
  end
end
