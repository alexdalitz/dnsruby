require_relative 'spec_helper'
require 'minitest/mock'
require 'socket'
require 'timeout'

class TestScopedIPv6Transport < Minitest::Test
  SCOPED_SERVERS = ['fe80::1%eth0.100', 'fe80::1%4'].freeze
  ANSWER = '192.0.2.184'.freeze

  # These socket-boundary tests run even on hosts without an IPv6 interface.
  # They verify that the transport receives the zone, not just the IPv6 address.
  def test_udp_preserves_scope_and_uses_ipv6
    SCOPED_SERVERS.each do |server|
      sender = Dnsruby::PacketSender.new(server: server, port: 5300, src_port: 55000)
      message = Dnsruby::Message.new('scoped.example.invalid')
      bytes = message.encode
      socket = Minitest::Mock.new(Object.new)
      socket.expect(:bind, 0, ['::', 55000])
      socket.expect(:connect, 0, [server, 5300])
      socket.expect(:send, bytes.bytesize, [bytes, 0])
      selector = Minitest::Mock.new
      selector.expect(:add_to_select, nil) do |settings|
        assert_equal server, settings.dest_server
        assert_equal socket.object_id, settings.socket.object_id
        true
      end

      constructor = lambda do |family|
        assert_equal Socket::AF_INET6, family
        socket
      end
      Dnsruby::SelectThread.stub(:instance, selector) do
        UDPSocket.stub(:new, constructor) do
          sender.send_dnsruby(bytes, message, :udp_scope, Queue.new, false)
        end
      end
      socket.verify
      selector.verify
    end
  end

  def test_tcp_preserves_scope_and_uses_ipv6_source
    SCOPED_SERVERS.each do |server|
      sender = Dnsruby::PacketSender.new(server: server, port: 5300, src_port: 55000)
      message = Dnsruby::Message.new('scoped.example.invalid')
      bytes = message.encode
      socket = Minitest::Mock.new(Object.new)
      socket.expect(:send, 2, [[bytes.bytesize].pack('n'), 0])
      socket.expect(:send, bytes.bytesize, [bytes, 0])
      selector = Minitest::Mock.new
      selector.expect(:add_to_select, nil) do |settings|
        assert_equal server, settings.dest_server
        assert_equal socket.object_id, settings.socket.object_id
        true
      end

      connector = lambda do |host, port, source, source_port, **options|
        assert_equal [server, 5300, '::', 55000], [host, port, source, source_port]
        assert_equal sender.packet_timeout, options[:connect_timeout]
        socket
      end
      Dnsruby::SelectThread.stub(:instance, selector) do
        Socket.stub(:tcp, connector) do
          sender.send_dnsruby(bytes, message, :tcp_scope, Queue.new, true)
        end
      end
      socket.verify
      selector.verify
    end
  end

  def test_tcp_pipeline_preserves_scope_and_selects_socket_family
    (SCOPED_SERVERS + ['127.0.0.1']).each do |server|
      ipv6 = server.include?(':')
      sender = Dnsruby::PacketSender.new(server: server, port: 5300)
      source = Addrinfo.tcp(ipv6 ? '::' : '0.0.0.0', 0)
      target = 'packed destination including scope'
      socket = Minitest::Mock.new(Object.new)
      socket.expect(:bind, 0, [source])
      socket.expect(:connect, 0, [target])

      address_builder = lambda do |port, host|
        assert_equal [5300, server], [port, host]
        target
      end
      constructor = lambda do |family, type, protocol|
        assert_equal ipv6 ? Socket::AF_INET6 : Socket::AF_INET, family
        assert_equal [Socket::SOCK_STREAM, 0], [type, protocol]
        socket
      end
      Socket.stub(:sockaddr_in, address_builder) do
        Socket.stub(:new, constructor) do
          Addrinfo.stub(:tcp, source) do
            connected, new_socket = sender.tcp_pipeline_socket(0)
            assert_equal socket.object_id, connected.object_id
            assert new_socket
          end
        end
      end
      socket.verify
    end
  end

  def test_scoped_ipv6_udp_roundtrip
    assert_local_roundtrip(:udp)
  end

  def test_scoped_ipv6_numeric_zone_udp_roundtrip
    assert_local_roundtrip(:udp, 1, true)
  end

  def test_scoped_ipv6_tcp_roundtrip
    assert_local_roundtrip(:tcp)
  end

  def test_scoped_ipv6_tcp_pipeline_reuses_connection
    assert_local_roundtrip(:pipeline, 2)
  end

  def test_scoped_ipv6_truncated_udp_retries_over_tcp
    assert_local_roundtrip(:fallback)
  end

  private

  def assert_local_roundtrip(transport, count = 1, numeric_scope = false)
    server, udp, tcp = bind_local_servers(transport, numeric_scope)
    port = (udp || tcp).local_address.ip_port
    received = []
    server_errors = Queue.new
    worker = Thread.new do
      Thread.current.abort_on_exception = false
      Thread.current.report_on_exception = false if Thread.current.respond_to?(:report_on_exception=)
      connection = nil
      begin
        if udp
          wait_readable(udp)
          bytes, peer = udp.recvfrom(65_535)
          query = Dnsruby::Message.decode(bytes)
          received << [:udp, query.question.first.qname.to_s]
          response = answer_for(query, transport == :fallback)
          udp.send(response.encode, 0, peer[3], peer[1])
        end
        if tcp
          wait_readable(tcp)
          connection, = tcp.accept
          count.times do
            length = read_exactly(connection, 2).unpack1('n')
            query = Dnsruby::Message.decode(read_exactly(connection, length))
            received << [:tcp, query.question.first.qname.to_s]
            response = answer_for(query).encode
            connection.write([response.bytesize].pack('n') + response)
          end
        end
      rescue StandardError => error
        server_errors << error
      ensure
        connection.close if connection && !connection.closed?
      end
    end

    resolver = Dnsruby::Resolver.new(
      nameserver: server, port: port, src_port: 0,
      dnssec: false, do_caching: false, retry_times: 1,
      packet_timeout: 2, query_timeout: 3,
      use_tcp: [:tcp, :pipeline].include?(transport),
      tcp_pipelining: transport == :pipeline
    )
    count.times do |index|
      name = "scoped-#{transport}-#{index}.example.invalid"
      response = Timeout.timeout(5) { resolver.query(name) }
      assert_equal ANSWER, response.answer.first.address.to_s
      assert_equal name, response.question.first.qname.to_s
    end
    assert worker.join(3), 'local DNS server did not finish'
    raise server_errors.pop unless server_errors.empty?
    expected = transport == :fallback ? [:udp, :tcp] : Array.new(count, transport == :udp ? :udp : :tcp)
    assert_equal expected, received.map(&:first)
  ensure
    resolver.close if resolver
    if worker
      worker.kill if worker.alive?
      worker.join
    end
    [udp, tcp].compact.each { |socket| socket.close unless socket.closed? }
  end

  def answer_for(query, truncated = false)
    query.header.qr = true
    query.header.ra = true
    query.header.tc = truncated
    unless truncated
      query.add_answer(Dnsruby::RR.create("#{query.question.first.qname} 60 IN A #{ANSWER}"))
    end
    query
  end

  def wait_readable(socket)
    raise IOError, 'local DNS server timed out' unless IO.select([socket], nil, nil, 3)
  end

  def read_exactly(socket, length)
    bytes = ''.b
    while bytes.bytesize < length
      wait_readable(socket)
      bytes << socket.readpartial(length - bytes.bytesize)
    end
    bytes
  end

  def bind_local_servers(transport, numeric_scope)
    unless Socket.respond_to?(:getifaddrs)
      skip 'Socket.getifaddrs is unavailable; socket-boundary tests cover scoped transport'
    end
    interfaces = Socket.getifaddrs.select { |entry| entry.addr && entry.addr.ipv6? && entry.addr.ipv6_linklocal? }
    interfaces.sort_by! { |entry| (entry.flags & Socket::IFF_LOOPBACK).zero? ? 1 : 0 }
    interfaces.each do |entry|
      next if numeric_scope && !entry.respond_to?(:ifindex)
      zone = numeric_scope ? entry.ifindex : entry.name
      server = "#{entry.addr.ip_address.split('%').first}%#{zone}"
      udp = tcp = nil
      begin
        if [:udp, :fallback].include?(transport)
          udp = UDPSocket.new(Socket::AF_INET6)
          udp.bind(server, 0)
        end
        if [:tcp, :pipeline, :fallback].include?(transport)
          tcp = Socket.new(Socket::AF_INET6, Socket::SOCK_STREAM, 0)
          tcp.bind(Socket.sockaddr_in(udp ? udp.local_address.ip_port : 0, server))
          tcp.listen(1)
        end
        return [server, udp, tcp]
      rescue SocketError, SystemCallError
        [udp, tcp].compact.each { |socket| socket.close unless socket.closed? }
      end
    end
    skip 'No bindable local IPv6 link-local address; socket-boundary tests cover scoped transport'
  end
end
