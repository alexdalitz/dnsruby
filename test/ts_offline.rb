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

Dnsruby.log.level = Logger::FATAL

# We'll prepend 'tc_' and append '.rb' to these:
TESTS = %w(
    dnskey
    escapedchars
    edns_retry_regressions
    gpos
    generic_cache
    hash
    header
    ipseckey
    ipv6
    malformed_tcp
    pipeline_send
    pipeline_retirement
    pipeline_retry
    resolver_concurrency
    resolver_validation
    release_transport
    review_transport_fixes
    review_transport_native
    review_packet_contracts
    cancelled_send_capacity
    review_code_mapper
    review_presentation
    record_regressions
    selector_wakeup
    message
    misc
    name
    nameserver_bootstrap
    naptr
    nsec
    nsec3
    nsec3param
    nxt
    tlsa
    packet
    packet_unique_push
    ptrin
    question
    res_config
    res_file
    res_opt
    scoped_ipv6
    scoped_ipv6_select
    scoped_ipv6_transport
    rr
    rr-txt
    rr-unknown
    rrset
    rrsig
    svcb
    svcb_transport
    tcp_pipelining
    tkey
    update
    zone_reader
)

# Omitted:
#
# tc_res_env


TESTS.each { |test| require_relative "tc_#{test}.rb" }


def have_open_ssl?
  have_open_ssl = true
  begin
    require "openssl"
    OpenSSL::Digest::SHA256.digest("data")
  rescue LoadError, StandardError
    have_open_ssl = false
  end
  have_open_ssl
end

if have_open_ssl?
  require_relative 'tc_ds.rb'
  require_relative 'tc_svcb_signed_target.rb'
  require_relative 'tc_dnssec_trust_anchors.rb'
  require_relative 'tc_dnssec_trust_races.rb'
  require_relative 'tc_key_cache_identity.rb'
else
  puts "-----------------------------------------------------------------------"
  puts "OpenSSL SHA256 unavailable - skipping DS and DNSSEC trust-anchor tests"
  puts "-----------------------------------------------------------------------"
end
