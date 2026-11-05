require_relative 'spec_helper'
require 'minitest/mock'
require 'tempfile'

class TestScopedIPv6 < Minitest::Test
  SCOPED_SERVERS = %w[
    fe80::feed:face:c0ff:ee00%en0
    fe80::5054:ff:fe8b:6576%br0
    fe80::1%3
    FE80:0:0:0:0:0:0:ABCD%Eth0
    fe80::1%eth0.100
    fe80::1%veth-1
    fe80::1%interface_1
  ].freeze

  def without_hostname_lookup
    unexpected = ->(*) { flunk('A scoped literal must not trigger DNS resolution') }
    Dnsruby::Resolver.stub(:new, unexpected) do
      Dnsruby::Recursor.stub(:new, unexpected) { yield }
    end
  end

  def test_scoped_nameservers_are_validated_without_dns_and_preserved
    without_hostname_lookup do
      SCOPED_SERVERS.each do |server|
        assert_equal(server, Dnsruby::Config.resolve_server(server))
        config = Dnsruby::Config.new
        config.nameserver = [server]
        assert_equal([server], config.nameserver)
        assert_equal(Dnsruby::IPv6.create(server.split('%').first),
                     Dnsruby::Config.ipv6_server_address(server))
      end
    end
  end

  def test_invalid_scoped_literals_do_not_fall_back_to_dns
    invalid = [
      'fe80::1%', 'fe80::1%en0%en1', 'fe80::1%en 0',
      "fe80::1%en0\n", "fe80::1%en0\0", 'fe80::1%en0/64',
      'fe80::1/64%en0', '[fe80::1%en0]', '192.0.2.1%en0',
      'example.test%en0', '%en0', 'fe80::gggg%en0',
    ]
    without_hostname_lookup do
      invalid.each do |server|
        assert_raises(ArgumentError, server) { Dnsruby::Config.resolve_server(server) }
        assert_raises(ArgumentError, server) { Dnsruby::Config.new.nameserver = [server] }
      end
    end
  end

  def test_resolver_constructor_forms_keep_scoped_nameserver
    server = SCOPED_SERVERS.first
    [server, {nameserver: server}, {nameserver: [server, '192.0.2.1']}].each do |options|
      resolver = Dnsruby::Resolver.new(options)
      expected = options.is_a?(Hash) ? Array(options[:nameserver]) : [server]
      assert_equal(expected, resolver.single_resolvers.map(&:server))
    ensure
      resolver.close if resolver
    end
    single = Dnsruby::SingleResolver.new(server)
    assert_equal(server, single.server)
  end

  def test_resolv_conf_retains_scoped_server_and_ipv4_fallback
    Tempfile.create('dnsruby-scoped-resolv') do |file|
      file.write("nameserver #{SCOPED_SERVERS.first}\nnameserver 192.168.0.1\n")
      file.flush
      resolver = Dnsruby::Resolver.new(config_info: file.path)
      expected = [SCOPED_SERVERS.first, '192.168.0.1']
      assert_equal(expected, resolver.config.nameserver)
      assert_equal(expected, resolver.single_resolvers.map(&:server))
    ensure
      resolver.close if resolver
    end
  end

  def test_server_setter_switches_address_family
    sender = Dnsruby::PacketSender.new('192.0.2.1')
    refute(sender.instance_variable_get(:@ipv6))
    SCOPED_SERVERS.each do |server|
      sender.server = server
      assert_equal(server, sender.server)
      assert(sender.instance_variable_get(:@ipv6))
    end
    sender.server = '192.0.2.2'
    refute(sender.instance_variable_get(:@ipv6))
  end

  def test_unscoped_addresses_remain_supported
    ['192.0.2.1', '2001:db8::1', 'fe80::1', '::1'].each do |server|
      assert_equal(server, Dnsruby::Config.resolve_server(server))
    end
    [Dnsruby::IPv4.create('192.0.2.1'), Dnsruby::IPv6.create('2001:db8::1')].each do |server|
      assert_same(server, Dnsruby::Config.resolve_server(server))
    end
  end

  def test_scope_does_not_become_dns_record_data
    assert_raises(ArgumentError) { Dnsruby::IPv6.create('fe80::1%en0') }
    assert_raises(ArgumentError) { Dnsruby::RR.create('host.test. 60 IN AAAA fe80::1%en0') }
    message = Dnsruby::Message.new
    message.add_answer(Dnsruby::RR.create('host.test. 60 IN AAAA fe80::1'))
    answer = Dnsruby::Message.decode(message.encode).answer.first
    assert_equal('fe80::1', answer.address.to_s)
    assert_equal(16, answer.address.address.bytesize)
  end
end
