require_relative 'spec_helper'
require 'socket'
require 'timeout'

# Exercise cache and retry policy through the public API and real wire packets.
class ReviewTransportNativeTest < Minitest::Test
  def setup
    Dnsruby::PacketSender.clear_caches
    @workers = []
    @sockets = []
    @resolvers = []
  end

  def teardown
    @resolvers.each(&:close)
    @workers.each { |worker| worker.kill if worker.alive? }
    @workers.each(&:value)
    @sockets.each { |socket| socket.close unless socket.closed? }
    Dnsruby::PacketSender.clear_caches
  end

  def test_recursive_and_authoritative_caches_keep_question_classes_separate
    [true, false].each do |recurse|
      Dnsruby::PacketSender.clear_caches
      port, requests = udp_server do |request|
        response(request, request.question.first.qclass.to_s)
      end
      resolver = resolver_for(port, recurse: recurse)
      %w[IN CH IN CH].each_with_index do |klass, index|
        reply = query(resolver, klass)
        assert_equal(klass, reply.question.first.qclass.to_s)
        assert_equal(klass, reply.answer.first.klass.to_s)
        assert_equal([klass], reply.answer.first.strings)
        assert_equal(index >= 2, !!reply.cached)
      end
      assert_equal(2, requests.size, 'both classes should subsequently hit their own cache')
    end
  end

  def test_unsigned_cache_cannot_satisfy_a_tsig_query
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    [true, false].each do |recurse|
      Dnsruby::PacketSender.clear_caches
      port, requests = udp_server { |request| response(request, 'unsigned') }
      resolver = resolver_for(port, recurse: recurse)
      assert_equal(['unsigned'], query(resolver).answer.first.strings)
      resolver.tsig = tsig_key
      assert_raises(Dnsruby::TsigNotSignedResponseError) { query(resolver) }
      assert_equal(2, requests.size, 'authentication must require a new wire exchange')
    end
  end

  def test_verified_tsig_reply_cannot_enter_the_shared_unsigned_cache
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    [true, false].each do |recurse|
      Dnsruby::PacketSender.clear_caches
      key = tsig_key
      port, requests = udp_server do |request|
        reply = response(request, request.tsig ? 'private' : 'public')
        key.apply(reply, request) if request.tsig
        reply
      end
      resolver = resolver_for(port, recurse: recurse)
      resolver.tsig = key
      signed = query(resolver)
      assert(signed.verified?)
      assert_nil(signed.tsig, 'verification strips the wire TSIG record')
      assert_equal(['private'], signed.answer.first.strings)
      resolver.tsig = nil
      unsigned = query(resolver)
      assert_equal(['public'], unsigned.answer.first.strings)
      refute(unsigned.cached)
      assert(query(resolver).cached)
      assert_equal(2, requests.size)
    end
  end

  def test_caller_opt_receives_a_reply_larger_than_the_configured_udp_default
    [false, true].each do |dnssec|
      port, requests = udp_server do |request|
        reply = response(request, 'placeholder')
        reply.answer.first.strings = Array.new(7) { 'x' * 240 }
        reply
      end
      resolver = resolver_for(port, udp_size: 1232, dnssec: dnssec, do_caching: false)
      request = Dnsruby::Message.new('large-opt.example.', 'TXT')
      request.do_caching = request.do_validation = false
      option = Dnsruby::RR::OPT::Option.new(65000, 'opaque'.b)
      request.add_additional(Dnsruby::RR::OPT.new(4096, 0, [option]))
      reply = Timeout.timeout(6) { resolver.send_message(request) }
      refute(reply.cached, 'each variant must receive its own UDP reply')
      assert_equal(Array.new(7) { 'x' * 240 }, reply.answer.first.strings)
      assert_operator(reply.answersize, :>, 1232)
      assert_operator(reply.answersize, :<=, 4096)
      sent = requests.pop(true)
      assert_equal(4096, sent.get_opt.payloadsize)
      assert_equal([[65000, 'opaque']], sent.get_opt.options(nil).map { |opt| [opt.code, opt.data] })
      assert_equal(1232, resolver.udp_size)
      assert_empty(requests)
    end
  end

  def test_authenticated_badtime_and_badtrunc_errors_are_delivered_after_forged_errors
    [18, 22].each do |error_code|
      key = tsig_key
      port, requests = udp_server do |request|
        reply = response(request, 'server error')
        reply.header.rcode = Dnsruby::RCode::NOTAUTH
        signer = key.dup
        signer.error = error_code
        signer.time_signed = request.tsig.time_signed
        if error_code == 18
          signer.other_data = [0, Time.now.to_i + 3600].pack('nN')
          signer.other_size = 6
        end
        signature = signer.generate(reply, request)
        reply.add_additional(signature)
        valid = reply.encode
        forged = Dnsruby::Message.decode(valid)
        forged.tsig.mac = forged.tsig.mac.dup
        forged.tsig.mac.setbyte(0, forged.tsig.mac.getbyte(0) ^ 1)
        [forged.encode, valid]
      end
      resolver = resolver_for(port, do_caching: false)
      resolver.tsig = key
      error = assert_raises(Dnsruby::TsigError) { query(resolver) }
      assert_includes(error.message, error_code == 18 ? 'BADTIME' : 'BADTRUNC')
      assert_equal(1, requests.size, 'authenticated error should complete the original transaction')
    end
  end

  def test_default_udp_advertisement_retries_truncated_responses_over_tcp
    [false, true].each do |dnssec|
      port, udp_requests = udp_server do |request|
        reply = response(request, 'truncated')
        reply.header.tc = true
        reply
      end
      tcp = TCPServer.new('127.0.0.1', port)
      @sockets << tcp
      tcp_requests = Queue.new
      worker do
        client = tcp.accept
        begin
          request = read_frame(client)
          tcp_requests << request
          reply = response(request, 'complete')
          reply.answer.first.strings = Array.new(7) { 'x' * 240 }
          write_frame(client, reply)
        ensure
          client.close
        end
      end
      resolver = resolver_for(port, dnssec: dnssec, do_caching: false)
      request = Dnsruby::Message.new('truncated.example.', 'TXT')
      request.do_caching = request.do_validation = false
      reply = Timeout.timeout(6) { resolver.send_message(request) }
      refute(reply.cached)
      refute(reply.header.tc)
      assert_equal(Array.new(7) { 'x' * 240 }, reply.answer.first.strings)
      assert_operator(reply.encode.bytesize, :>, 1232)
      assert_equal(1232, resolver.udp_size)
      udp_request = udp_requests.pop(true)
      tcp_request = tcp_requests.pop(true)
      assert_equal(1232, udp_request.get_opt.payloadsize)
      assert_equal(dnssec, udp_request.get_opt.dnssec_ok)
      assert_equal(udp_request.header.id, tcp_request.header.id)
      assert_equal(udp_request.question, tcp_request.question)
      assert_empty(udp_requests)
      assert_empty(tcp_requests)
    end
  end

  def test_message_and_resolver_keys_authenticate_edns_and_tcp_retries
    [false, true].product([:message, :resolver]).each do |dnssec, key_source|
      key = tsig_key
      received = 0
      observed = Queue.new
      port, = udp_server do |request, bytes|
        signature = request.tsig
        raise 'invalid UDP request MAC' unless signature &&
          key.generate(request, nil, '', bytes, signature).mac == signature.mac
        observed << [:udp, request.get_opt]
        reply = response(request, 'retry')
        reply.header.rcode = Dnsruby::RCode::FORMERR if received.zero?
        reply.header.tc = true unless received.zero?
        received += 1
        key.apply(reply, request)
        reply
      end
      tcp = TCPServer.new('127.0.0.1', port)
      @sockets << tcp
      worker do
        client = tcp.accept
        begin
          length = client.read(2).unpack1('n')
          bytes = client.read(length)
          request = Dnsruby::Message.decode(bytes)
          signature = request.tsig
          raise 'invalid TCP request MAC' unless signature &&
            key.generate(request, nil, '', bytes, signature).mac == signature.mac
          observed << [:tcp, request.get_opt]
          reply = response(request, 'authenticated')
          key.apply(reply, request)
          write_frame(client, reply)
        ensure
          client.close
        end
      end
      resolver = resolver_for(port, dnssec: dnssec, do_caching: false)
      request = Dnsruby::Message.new('signed-retry.example.', 'TXT')
      request.header.rd = false
      request.do_caching = request.do_validation = false
      key_source == :message ? request.set_tsig(key) : resolver.tsig = key
      reply = Timeout.timeout(6) { resolver.send_message(request) }
      assert(reply.verified?)
      assert_equal(['authenticated'], reply.answer.first.strings)
      attempts = 3.times.map { observed.pop(true) }
      assert_equal([:udp, :udp, :tcp], attempts.map(&:first))
      assert_equal([true, false, false], attempts.map { |_, opt| !!opt })
      assert_equal(1232, attempts.first.last.payloadsize)
      assert_equal(dnssec, attempts.first.last.dnssec_ok)
      assert_empty(observed)
    end
  end

  def test_explicit_tcp_edns_retry_stays_on_tcp
    server = TCPServer.new('127.0.0.1', 0)
    @sockets << server
    requests = Queue.new
    worker do
      2.times do |index|
        client = server.accept
        begin
          request = read_frame(client)
          requests << request
          reply = response(request, 'tcp')
          reply.header.rcode = Dnsruby::RCode::FORMERR if index.zero?
          write_frame(client, reply)
        ensure
          client.close
        end
      end
    end
    resolver = resolver_for(server.addr[1], use_tcp: true, do_caching: false)
    message = Dnsruby::Message.new('review.example.', 'TXT')
    message.do_caching = message.do_validation = false
    message.add_additional(Dnsruby::RR::OPT.new(4096))
    reply = Timeout.timeout(6) { resolver.send_message(message) }
    assert_equal(['tcp'], reply.answer.first.strings)
    assert_equal(2, requests.size)
    assert(requests.pop.get_opt)
    assert_nil(requests.pop.get_opt)
    assert(message.get_opt, 'the caller retains the original EDNS request')
  end

  def test_udp_ignores_query_packets_and_wrong_opcodes_until_valid_reply
    port, requests = udp_server do |request|
      invalid_responses(request) + [response(request, 'valid')]
    end
    reply = query(resolver_for(port, do_caching: false))
    assert_equal(['valid'], reply.answer.first.strings)
    assert_equal(1, requests.size)
  end

  def test_tcp_ignores_query_frames_and_wrong_opcodes_until_valid_reply
    server = TCPServer.new('127.0.0.1', 0)
    @sockets << server
    worker do
      client = server.accept
      begin
        request = read_frame(client)
        (invalid_responses(request) + [response(request, 'valid')]).each do |reply|
          write_frame(client, reply)
        end
      ensure
        client.close
      end
    end
    reply = query(resolver_for(server.addr[1], use_tcp: true, do_caching: false))
    assert_equal(['valid'], reply.answer.first.strings)
  end

  def test_udp_ignores_malformed_packets_with_unrelated_headers_without_retrying
    port, requests = udp_server do |request|
      malformed = invalid_responses(request).flat_map do |invalid|
        [false, true].map do |truncated|
          invalid.header.tc = truncated
          bytes = invalid.encode
          # Advertise an absent additional record, forcing Message.decode to
          # expose its partially decoded header through DecodeError.
          bytes[10, 2] = [1].pack('n')
          bytes
        end
      end
      malformed + [response(request, 'valid')]
    end
    reply = query(resolver_for(port, do_caching: false))
    assert_equal(['valid'], reply.answer.first.strings)
    assert_equal(1, requests.size)
  end

  def test_udp_ignores_incomplete_and_unrelated_malformed_questions_before_a_valid_reply
    port, requests = udp_server do |request|
      unrelated = Dnsruby::Message.new('unrelated.example.', 'AAAA', 'CH')
      unrelated.header.id = request.header.id
      unrelated.header.qr = true
      malformed = [false, true].map do |truncated|
        unrelated.header.tc = truncated
        unrelated.encode.tap { |wire| wire[6, 2] = [1].pack('n') }
      end
      incomplete = [2, 11, 12, 15].map { |length| malformed.first.byteslice(0, length) }
      incomplete + malformed + [response(request, 'valid')]
    end
    reply = query(resolver_for(port, do_caching: false))
    assert_equal(['valid'], reply.answer.first.strings)
    assert_equal(1, requests.size)
  end

  def test_short_deadline_query_on_busy_resolver_is_sent_before_its_deadline
    port, requests = udp_server do |request|
      request.question.first.qname.to_s == 'pending.example' ? [] : response(request, 'fast')
    end
    resolver = resolver_for(port, do_caching: false)
    pending = Dnsruby::Message.new('pending.example.', 'TXT')
    pending.do_caching = pending.do_validation = false
    pending_results = Queue.new
    resolver.send_async(pending, pending_results, :pending)
    Timeout.timeout(2) { requests.pop }
    sleep 0.03 # Start just after the selector's initial tick, while the first query remains pending.
    resolver.query_timeout = 0.2
    assert_equal(['fast'], query(resolver).answer.first.strings)
    assert_equal(1, requests.size, 'the new query must reach the server while the first remains pending')
    assert(pending_results.empty?)
  end

  private

  def worker(&block)
    thread = Thread.new(&block)
    thread.report_on_exception = false
    @workers << thread
    thread
  end

  def udp_server(&handler)
    socket = UDPSocket.new
    socket.bind('127.0.0.1', 0)
    @sockets << socket
    requests = Queue.new
    worker do
      loop do
        bytes, peer = socket.recvfrom(65_535)
        request = Dnsruby::Message.decode(bytes)
        requests << request
        replies = handler.call(request, bytes)
        replies = [replies] unless replies.is_a?(Array)
        replies.each do |reply|
          bytes = reply.is_a?(String) ? reply : reply.encode
          socket.send(bytes, 0, peer[3], peer[1])
        end
      end
    end
    [socket.addr[1], requests]
  end

  def resolver_for(port, options = {})
    resolver = Dnsruby::Resolver.new({nameserver: '127.0.0.1', port: port,
      dnssec: false, do_validation: false,
      packet_timeout: 1, query_timeout: 3, retry_times: 1}.merge(options))
    @resolvers << resolver
    resolver
  end

  def query(resolver, klass = 'IN')
    Timeout.timeout(6) { resolver.query('review.example.', 'TXT', klass) }
  end

  def response(request, text)
    question = request.question.first
    reply = Dnsruby::Message.new
    reply.header.id = request.header.id
    reply.header.qr = reply.header.aa = reply.header.ra = true
    reply.header.rd = request.header.rd
    reply.header.opcode = request.header.opcode
    reply.add_question(question.qname, question.qtype, question.qclass)
    reply.add_answer(Dnsruby::RR.create("#{question.qname} 60 #{question.qclass} TXT \"#{text}\""))
    reply
  end

  def invalid_responses(request)
    query_packet = response(request, 'invalid-query')
    query_packet.header.qr = false
    wrong_opcode = response(request, 'invalid-opcode')
    wrong_opcode.header.opcode = 2 # STATUS
    [query_packet, wrong_opcode]
  end

  def tsig_key
    Dnsruby::RR.create(name: 'review-key.example.', type: 'TSIG', klass: 'ANY',
      key: 'c2VjcmV0', algorithm: 'hmac-sha256')
  end

  def read_frame(socket)
    length = socket.read(2).unpack1('n')
    Dnsruby::Message.decode(socket.read(length))
  end

  def write_frame(socket, reply)
    bytes = reply.encode
    socket.write([bytes.bytesize].pack('n') + bytes)
  end
end
