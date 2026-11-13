require_relative 'tc_review_transport_native'

class ReviewTransportNativeTest < Minitest::Test
  def test_malformed_unsigned_tsig_reply_cannot_preempt_a_valid_signed_answer
    key = tsig_key
    port, requests = udp_server do |request|
      malformed = response(request, 'untrusted').encode
      malformed[10, 2] = [1].pack('n') # Advertise an absent additional RR.
      truncated = malformed.dup
      truncated.setbyte(2, truncated.getbyte(2) | 2)
      signed = response(request, 'authenticated')
      key.apply(signed, request)
      [[request.header.id].pack('n'), malformed, truncated, signed]
    end
    resolver = resolver_for(port, do_caching: false)
    resolver.tsig = key
    reply = query(resolver)
    assert(reply.verified?)
    assert_equal(['authenticated'], reply.answer.first.strings)
    assert_equal(1, requests.size)
  end

  def test_tcp_connection_loss_reconnects_within_the_configured_retry_plan
    [false, true].product([:success, :exhausted, :deadline]).each do |pipeline, outcome|
      server = TCPServer.new('127.0.0.1', 0)
      @sockets << server
      requests = Queue.new
      worker do
        count = 0
        loop do
          client = server.accept
          begin
            request = read_frame(client)
            requests << request
            count += 1
            write_frame(client, response(request, 'retried')) if count == 2 && outcome == :success
          ensure
            client.close
          end
        end
      end
      resolver = resolver_for(server.addr[1], use_tcp: true, tcp_pipelining: pipeline,
        do_caching: false, retry_times: 2, retry_delay: outcome == :deadline ? 10 : 0.01,
        query_timeout: outcome == :deadline ? 0.15 : 3)
      if outcome == :success
        assert_equal(['retried'], query(resolver).answer.first.strings)
      elsif outcome == :exhausted
        assert_raises(Dnsruby::SocketEofResolvError) { query(resolver) }
      else
        assert_raises(Dnsruby::ResolvTimeout) { query(resolver) }
      end
      assert_equal(outcome == :deadline ? 1 : 2, requests.size)
      resolver.close
    end
  end
end
