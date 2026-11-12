require_relative 'spec_helper'
require 'socket'
require 'timeout'

class TestSVCBTransport < Minitest::Test
  RDATA = ['0001000003000201bb'].pack('H*').freeze

  def test_every_truncated_svcb_and_https_rdata_boundary_retries_over_tcp
    truncated = ->(query) { response(query, truncated_at: query.question.first.qname.to_s[/\Acut(\d+)/, 1].to_i) }
    with_server(truncated, ->(query) { response(query) }) do |port, events|
      resolver = resolver_for(port)
      begin
        [64, 65].each do |type|
          RDATA.bytesize.times do |length|
            answer = Timeout.timeout(3) { resolver.query("cut#{length}.example.", type) }.answer.first
            assert_equal(type, answer.type.code)
            assert_equal(RDATA, answer.data)
            assert_equal('443', answer.params_to_hash['port'])
            assert_equal(:udp, events.pop(true))
            assert_equal(:tcp, events.pop(true))
          end
        end
        assert(events.empty?)
      ensure
        resolver.close
      end
    end
  end

  def test_malformed_svcb_does_not_bypass_transport_policy_or_retry_tcp
    truncated = ->(query) { response(query, truncated_at: 3) }
    malformed = ->(query) { response(query, data: ['0001000003000301bb'].pack('H*')) }
    [
      [{no_tcp: true}, truncated, :udp],
      [{ignore_truncation: true}, truncated, :udp],
      [{no_tcp: true, ignore_truncation: true}, truncated, :udp],
      [{use_tcp: true}, truncated, :tcp],
      [{}, malformed, :udp],
    ].each do |options, reply, expected_transport|
      with_server(reply, reply) do |port, events|
        resolver = resolver_for(port, options)
        begin
          assert_raises(Dnsruby::DecodeError, options.inspect) do
            Timeout.timeout(3) { resolver.query('invalid.example.', 65) }
          end
          assert_equal(expected_transport, events.pop(true))
          assert(events.empty?, 'terminal malformed response must not start another attempt')
        ensure
          resolver.close
        end
      end
    end
  end

  private

  def resolver_for(port, options = {})
    Dnsruby::Resolver.new({nameserver: '127.0.0.1', port: port,
      dnssec: false, do_validation: false, do_caching: false,
      packet_timeout: 1, query_timeout: 2, retry_times: 1}.merge(options))
  end

  # The answer's declared length always describes the complete RDATA, even
  # when the UDP packet ends early. Build that length independently of the
  # production RR encoder so the regression cannot repair its own fixture.
  def response(query, truncated_at: nil, data: RDATA)
    question = query.question.first
    encoded_question = Dnsruby::MessageEncoder.new do |encoder|
      encoder.put_name(question.qname)
      encoder.put_pack('nn', question.qtype.code, question.qclass.code)
    end.to_s
    flags = truncated_at ? 0x8380 : 0x8180
    header = [query.header.id, flags, 1, 1, 0, 0].pack('n6')
    rr = "\xc0\x0c".b + [question.qtype.code, 1, 60, data.bytesize].pack('nnNn')
    header + encoded_question + rr + (truncated_at ? data.byteslice(0, truncated_at) : data)
  end

  def with_server(udp_reply, tcp_reply)
    udp = UDPSocket.new
    udp.bind('127.0.0.1', 0)
    tcp = TCPServer.new('127.0.0.1', udp.addr[1])
    events, errors = Queue.new, Queue.new
    running = true
    workers = [[udp, :udp, udp_reply], [tcp, :tcp, tcp_reply]].map do |listener, transport, reply|
      Thread.new do
        while running
          next unless IO.select([listener], nil, nil, 0.05)
          events << transport
          if transport == :udp
            bytes, peer = listener.recvfrom(4096)
            listener.send(reply.call(Dnsruby::Message.decode(bytes)), 0, peer[3], peer[1])
          else
            socket = listener.accept
            begin
              Timeout.timeout(2) do
                length = socket.read(2).unpack1('n')
                bytes = reply.call(Dnsruby::Message.decode(socket.read(length)))
                socket.write([bytes.bytesize].pack('n') + bytes)
              end
            ensure
              socket.close
            end
          end
        end
      rescue StandardError => error
        errors << error
      end
    end
    yield udp.addr[1], events
    assert(errors.empty?, errors.empty? ? nil : errors.pop.full_message)
  ensure
    running = false
    (workers || []).each do |worker|
      worker.join(0.2)
      worker.kill if worker.alive?
      worker.join
    end
    tcp.close if tcp && !tcp.closed?
    udp.close if udp && !udp.closed?
  end
end
