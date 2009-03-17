require 'test/unit'
require 'dnsruby'
require 'net/ftp'
include Dnsruby

class TestItar < Test::Unit::TestCase
  def test_itar
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::Cache.clear
    run_test_se(true)
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors

    # Download the ITAR - add the DS records to dnssec
    load_itar()

    # Then try to validate some records in the published zones
    Dnsruby::Cache.clear
    run_test_se(false)
  end

  def test_with_no_dlv_anchor
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::Cache.clear
    # Make sure we don't have any other anchors configured!
    # @TODO@ Should use whole RRSet of authoritative NS for these resolvers,
    # not individual servers!
    res = Dnsruby::Resolver.new("a.ns.se")
    res.add_server("b.ns.se")
    res.dnssec=true
#    TheLog.level = Logger::DEBUG
    ret = res.query("se.", Dnsruby::Types.DNSKEY)
    assert(ret.security_level == Dnsruby::Message::SecurityLevel::INSECURE, "Level = #{ret.security_level.string}")
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    load_itar
    Dnsruby::Cache.clear
    ret = res.query("se.", Dnsruby::Types.ANY)
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
    r = res.query("se", Dnsruby::Types.ANY)
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

  def load_itar
    # Should really check the signatures here to make sure the keys are good!
    Net::FTP::open("ftp.iana.org") { |ftp|
      ftp.login("anonymous")
      ftp.chdir("/itar")
      lastname=nil
      ftp.gettextfile("anchors.mf") {|line|
        next if (line.strip.length == 0)
        first = line[0]
        if (first.class == String)
          first = first.getbyte(0) # Ruby 1.9
        end
        #  print "Read : #{line}, first : #{first}\n"
        next if (first==59) # ";")
        if (line.strip=~(/^DS /) || line.strip=~(/^DNSKEY /))
          line = lastname.to_s + ((lastname.absolute?)?".":"") + " " + line
        end
        ds = RR.create(line)
        if ((ds.type == Types.DS) || (ds.type == Types.DNSKEY))
        assert(ds.name.absolute?)
          Dnssec.add_trust_anchor(ds)
        end
        lastname = ds.name
      }
    }
  end
end
