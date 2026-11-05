require 'socket'
require 'timeout'

# A single DNS exchange over a real socket, independent of system DNS and caches.
module LocalDnsServer
  def with_local_dns_server(transport, rcode: Dnsruby::RCode.NOERROR, answer: nil)
    socket = if transport == :tcp
      TCPServer.new('127.0.0.1', 0)
    else
      UDPSocket.new
    end
    socket.bind('127.0.0.1', 0) if transport == :udp

    server = Thread.new do
      begin
        if transport == :tcp
          client = socket.accept
          length = client.read(2).unpack('n').first
          packet = client.read(length)
        else
          packet, sender = socket.recvfrom(65_535)
        end
        response = Dnsruby::Message.decode(packet)
        response.header.qr = true
        response.header.ra = true
        response.header.rcode = rcode
        response.add_answer(Dnsruby::RR.create(answer)) if answer
        wire = response.encode
        if transport == :tcp
          client.write([wire.bytesize].pack('n') + wire)
        else
          socket.send(wire, 0, sender[3], sender[1])
        end
      rescue StandardError => error
        # Some tests enable Thread.abort_on_exception globally. Report fixture
        # errors in the test thread instead of aborting the whole suite.
        error
      ensure
        client.close if client && !client.closed?
      end
    end

    resolver = Dnsruby::Resolver.new(
      nameserver: '127.0.0.1', port: socket.addr[1], use_tcp: transport == :tcp,
      do_caching: false, dnssec: false, query_timeout: 2, retry_times: 1
    )
    Timeout.timeout(5) do
      yield resolver
      result = server.value
      raise result if result.is_a?(StandardError)
    end
  ensure
    resolver.close if resolver
    server.kill.join if server
    socket.close if socket && !socket.closed?
  end
end
