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
        replies = handler.call(request)
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
      dnssec: false, do_validation: false, udp_size: 512,
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
