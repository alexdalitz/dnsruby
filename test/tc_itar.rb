#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#++

require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestItar < Test::Unit::TestCase
  def test_itar
    Dnsruby::Dnssec.reset
    Dnsruby::PacketSender.clear_caches
    Dnsruby::Recursor.clear_caches
    run_test_se(true)
    Dnsruby::Dnssec.reset
    Dnsruby::Recursor.clear_caches

    # Then try to validate some records in the published zones
    Dnsruby::PacketSender.clear_caches
    # Download the ITAR - add the DS records to dnssec
    Dnssec.load_itar()

    run_test_se(false)
  end

  def test_with_no_dlv_anchor
    Dnsruby::Dnssec.reset
    Dnsruby::PacketSender.clear_caches
    Dnsruby::Recursor.clear_caches
    # Make sure we don't have any other anchors configured!
    res = Dnsruby::Recursor.new
    ret = res.query("frobbit.se.", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::INSECURE, "Level = #{ret.security_level.string}")
    Dnsruby::Dnssec.reset
    Dnsruby::PacketSender.clear_caches
    Dnsruby::Recursor.clear_caches
    Dnssec.load_itar
    res = Dnsruby::Recursor.new
    ret = res.query("frobbit.se.", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::SECURE)

    res = Dnsruby::Recursor.new
    ret = res.query("ns2.nic.se.", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::SECURE)
  end

  def run_test_se(should_fail)
    res = Dnsruby::Recursor.new
    r = res.query("frobbit.se.", Dnsruby::Types.A)
    if (!should_fail)
      assert(r.security_level == Dnsruby::Message::SecurityLevel::SECURE)
    else
      assert(r.security_level != Dnsruby::Message::SecurityLevel::SECURE)
    end
    # Haven't configured key for this, so should fail
    begin
      ret = Dnssec.verify(r)
      if (should_fail)
        fail
      end
    rescue (Dnsruby::VerifyError)
      if (!should_fail)
        fail
      end
    end
    #    assert(!ret, "Dnssec message verification failed")

  end

end
