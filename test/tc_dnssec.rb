require 'test/unit'
require 'dnsruby'

class DnssecTest < Test::Unit::TestCase
  def test_follow_chain_of_trust
    Dnsruby::DnssecVerifier.clear_trusted_keys
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.dnssec=true

    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :flags => 257,
        :protocol => 3,
        :algorithm => 5,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::DnssecVerifier.add_trusted_key(trusted_key)

    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")

    r = res.query("www.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")

    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DS)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")
    
    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")
    
    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec verification failed")
        
    rrset = r.answer.rrset('NSEC')
    ret = Dnsruby::DnssecVerifier.verify_signature(rrset)
    assert(ret, "Dnssec verification failed")
  end
  
  def test_se_query
    # Run some queries on the .se zone
    Dnsruby::DnssecVerifier.clear_trusted_keys
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    keys = r.answer.rrset('DNSKEY')
    keys = Dnsruby::DnssecVerifier::KeyCache.new(keys)
    nss = r.answer.rrset('NS')
    ret = Dnsruby::DnssecVerifier.verify_signature(nss, keys)
    assert(ret, "Dnssec verification failed")    
  end
    
  def test_verify_message
    Dnsruby::DnssecVerifier.clear_trusted_keys
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    # This shouldn't be in the code - but the key is rotated by the .se registry
    # so we can't keep up with it in the test code.
    # Oh, for a signed root...
    Dnsruby::DnssecVerifier.add_trusted_key(r.answer.rrset('DNSKEY'))
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec message verification failed")    
  end
  
  def test_trusted_key
    Dnsruby::DnssecVerifier.clear_trusted_keys
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    bad_key = Dnsruby::RR.create(
      "uk-dnssec.nic.uk. 86400 IN DNSKEY 257 3 5 "+
        "AwEAAbhThsjZqxZDyZLie1BYP+R/G1YRhmuIFCbmuQiF4NB86gpW8EVR l2s+gvNuQw6yh2YdDdyJBselE4znRP1XQbpOTC5UO5CDwge9NYja/jrX lvrX2N048vhIG8uk8yVxJDosxf6nmptsJBp3GAjF25soJs07Bailcr+5 vdZ7GibH")
    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    ret = Dnsruby::DnssecVerifier.verify_message(r, bad_key)
    assert(!ret, "Dnssec trusted key message verification should have failed with bad key")    
    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :flags => 257,
        :protocol => 3,
        :algorithm => 5,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::DnssecVerifier.verify_message(r, trusted_key)
    assert(ret, "Dnssec trusted key message verification failed")    

    # Check that keys have been added to trusted key cache
    ret = Dnsruby::DnssecVerifier.verify_message(r)
    assert(ret, "Dnssec trusted key cache failed")    
  end
end