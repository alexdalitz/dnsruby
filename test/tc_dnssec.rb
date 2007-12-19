require 'test/unit'
require 'dnsruby'

class DnssecTest < Test::Unit::TestCase
  def test_dnssec_query
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.dnssec=true

    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")
    keys = r.answer.rrset('DNSKEY')
    
    #    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    #    ret = Dnsruby::DnssecVerifier.verify_message(r)
    #    assert(ret, "Dnssec verification failed")
    #    r.answer.rrset('DNSKEY').each {|rr| keys.add(rr)}

    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message_with_trusted_key(r, keys)
    assert(ret, "Dnssec verification failed")
        
    rrset = r.answer.rrset('NSEC')
    ret = Dnsruby::DnssecVerifier.verify_signature(rrset, keys)
    assert(ret, "Dnssec verification failed")
  end
  
  def test_se_query
    # Run some queries on the .se zone
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    keys = r.answer.rrset('DNSKEY')
    nss = r.answer.rrset('NS')
    ret = Dnsruby::DnssecVerifier.verify_signature(nss, keys)
    assert(ret, "Dnssec verification failed")    
  end
    
  def test_verify_message
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec message verification failed")    
  end
  
  def test_trusted_key
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    bad_key = Dnsruby::RR.create(
      "uk-dnssec.nic.uk. 86400 IN DNSKEY 257 3 5 "+
        "AwEAAbhThsjZqxZDyZLie1BYP+R/G1YRhmuIFCbmuQiF4NB86gpW8EVR l2s+gvNuQw6yh2YdDdyJBselE4znRP1XQbpOTC5UO5CDwge9NYja/jrX lvrX2N048vhIG8uk8yVxJDosxf6nmptsJBp3GAjF25soJs07Bailcr+5 vdZ7GibH")
    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message_with_trusted_key(r, bad_key)
    assert(!ret, "Dnssec trusted key message verification should have failed with bad key")    
    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :flags => 257,
        :protocol => 3,
        :algorithm => 5,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::DnssecVerifier.verify_message_with_trusted_key(r, trusted_key)
    assert(ret, "Dnssec trusted key message verification failed")    
  end
    
  def test_follow_chain_of_trust
    # Descend from the trusted key for the root of uk-dnssec.nic.uk to ensure
    # that NS record for aaa.bigzone.uk-dnssec.nic.uk is properly signed by a
    # trusted key
    #@TODO@
    
  end
end