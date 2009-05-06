require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestItar < Test::Unit::TestCase
  def test_itar
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::InternalResolver.clear_caches
    run_test_se(true)
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors

    # Download the ITAR - add the DS records to dnssec
    Dnssec.load_itar()

    # Then try to validate some records in the published zones
    Dnsruby::InternalResolver.clear_caches
    run_test_se(false)
  end

  def test_with_no_dlv_anchor
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::InternalResolver.clear_caches
    # Make sure we don't have any other anchors configured!
    # @TODO@ Should use whole RRSet of authoritative NS for these resolvers,
    # not individual servers!
#    res = Dnsruby::Resolver.new("a.ns.se")
res = Dnsruby::Recursor.new
#    res.add_server("b.ns.se")
#    res.dnssec=true
#    TheLog.level = Logger::DEBUG
    ret = res.query("se.", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::INSECURE, "Level = #{ret.security_level.string}")
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    Dnssec.load_itar
    Dnsruby::InternalResolver.clear_caches
    ret = res.query("se.", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::SECURE)

    res = Dnsruby::Resolver.new("ns3.nic.se")
    res.add_server("ns2.nic.se")
    res.dnssec = true
    ret = res.query("ns2.nic.se", Dnsruby::Types.A)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::SECURE)
  end

  def run_test_se(should_fail)
    res = Dnsruby::Resolver.new("a.ns.se")
    res.add_server("b.ns.se")
    r = res.query("se", Dnsruby::Types.A)
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
