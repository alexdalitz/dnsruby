# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'
require 'tempfile'

#  Regression tests for nameserver validation. All offline — no query touches
#  the network.
#
#  * Issue #184: dnsruby could not interpret an IPv6 link-local address with an
#    interface/scope specifier (e.g. "fe80::1%en0").
#  * Issue #179: a non-IP nameserver in resolv.conf (a hostname, or a malformed
#    entry like "8.8.8.8,") sent Config.resolve_server into hostname resolution,
#    which re-parsed resolv.conf and recursed forever.
class TestResolverConfigNameserver < Minitest::Test

  SCOPED_LLA = 'fe80::feed:face:c0ff:ee00%en0'

  # ---- issue #184: scoped IPv6 link-local nameservers ----------------------

  def test_scoped_ipv6_predicate
    assert Dnsruby::Config.scoped_ipv6?(SCOPED_LLA)
    assert Dnsruby::Config.scoped_ipv6?('fe80::1%eth0')
    refute Dnsruby::Config.scoped_ipv6?('fe80::1'),        'plain IPv6 has no zone'
    refute Dnsruby::Config.scoped_ipv6?('192.168.0.1')
    refute Dnsruby::Config.scoped_ipv6?('not-an-address%en0')
    refute Dnsruby::Config.scoped_ipv6?('%en0')
    refute Dnsruby::Config.scoped_ipv6?(nil)
  end

  #  Previously this fell through to hostname resolution, which re-read
  #  resolv.conf and hung. It must return the literal verbatim, no network.
  def test_resolve_server_accepts_scoped_ipv6_verbatim
    assert_equal SCOPED_LLA, Dnsruby::Config.resolve_server(SCOPED_LLA)
  end

  def test_check_ns_accepts_scoped_ipv6
    config = Dnsruby::Config.new
    config.nameserver = [SCOPED_LLA] # must not raise ArgumentError
    assert_includes config.nameserver, SCOPED_LLA
  end

  #  A scoped IPv6 nameserver must be sent over an IPv6 socket, not IPv4.
  def test_packet_sender_treats_scoped_ipv6_as_ipv6
    sender = Dnsruby::PacketSender.new(server: SCOPED_LLA, ignore_config_resolv_errors: true)

    assert_equal SCOPED_LLA, sender.server
    assert sender.instance_variable_get(:@ipv6), 'scoped IPv6 server should use an IPv6 socket'
  end

  # ---- issue #179: non-IP nameserver in resolv.conf ------------------------

  def test_ip_nameserver_predicate
    assert Dnsruby::Config.ip_nameserver?('8.8.8.8')
    assert Dnsruby::Config.ip_nameserver?('2001:4860:4860::8888')
    assert Dnsruby::Config.ip_nameserver?(SCOPED_LLA)
    refute Dnsruby::Config.ip_nameserver?('8.8.8.8,'), 'the #179 malformed entry'
    refute Dnsruby::Config.ip_nameserver?('ns1.example.com')
    refute Dnsruby::Config.ip_nameserver?('')
  end

  def test_parse_resolv_conf_drops_non_ip_nameservers
    parsed = parse_resolv_conf(<<~CONF)
      nameserver 8.8.8.8,
      nameserver 192.168.0.1
      nameserver #{SCOPED_LLA}
      nameserver ns1.example.com
    CONF

    #  Keeps the valid IPv4 and the scoped IPv6, in file order; drops the
    #  malformed entry and the hostname.
    assert_equal ['192.168.0.1', SCOPED_LLA], parsed[:nameserver]
  end

  #  The exact resolv.conf from issue #184.
  def test_parse_resolv_conf_keeps_issue_184_scoped_and_ipv4
    parsed = parse_resolv_conf(<<~CONF)
      nameserver #{SCOPED_LLA}
      nameserver 192.168.0.1
    CONF

    assert_equal [SCOPED_LLA, '192.168.0.1'], parsed[:nameserver]
  end

  private

  def parse_resolv_conf(contents)
    file = Tempfile.new(['resolv', '.conf'])
    file.write(contents)
    file.close
    Dnsruby::Config.parse_resolv_conf(file.path)
  ensure
    file&.unlink
  end
end
