require 'test/unit'
require 'dnsruby'

class DnssecTest < Test::Unit::TestCase
  def test_follow_chain_of_trust
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.udp_size = 5000
    res.dnssec=true

    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::Dnssec.add_trust_anchor_with_expiration(trusted_key, Time.now.to_i + 500000)

    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec verification failed")

    r = res.query("www.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec verification failed")

    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DS)
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec verification failed")
    
    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec verification failed")
    
    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)

    rrset = r.authority.rrset('NSEC')
    assert(rrset.rrs.length > 0)
    assert(rrset.sigs.length > 0)
    ret = Dnsruby::Dnssec.verify_rrset(rrset)
    assert(ret, "Dnssec verification failed")

    ret = Dnsruby::Dnssec.verify(r) # no DS record for aaa - validate should work
    assert(ret, "Dnssec verification failed")
    ret = Dnsruby::Dnssec.validate(r) # no DS record for aaa - validate should work
    assert(ret, "Dnssec validation failed")

  end
  
  def test_se_query
    # Run some queries on the .se zone
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    res.dnssec = true
    r = res.query("se", Dnsruby::Types.ANY)    
    # See comment below
    Dnsruby::Dnssec.add_trusted_key(r.answer.rrset('DNSKEY'))
    nss = r.answer.rrset('NS')
    ret = Dnsruby::Dnssec.verify_rrset(nss)
    assert(ret, "Dnssec verification failed")    
  end
    
  def test_verify_message
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    res.udp_size = 5000
    r = res.query("se", Dnsruby::Types.ANY)    
    # This shouldn't be in the code - but the key is rotated by the .se registry
    # so we can't keep up with it in the test code.
    # Oh, for a signed root...
    Dnsruby::Dnssec.add_trusted_key(r.answer.rrset('DNSKEY'))
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec message verification failed")    
  end
  
  def test_verify_message_fails
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    # Haven't configured key for this, so should fail
    begin
      ret = Dnsruby::Dnssec.verify(r)
      fail
    rescue (Dnsruby::VerifyError)
    end
    #    assert(!ret, "Dnssec message verification failed")    
  end
  
  def test_validation
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.dnssec=true

    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::Dnssec.add_trust_anchor_with_expiration(trusted_key, Time.now.to_i + 5000)

    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    ret = Dnsruby::Dnssec.validate(r)
    assert(ret, "Dnssec validation failed")
    
    # @TODO@ Test other validation policies!!
  end

  def test_resolver_cd_validation_fails
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)
    # @TODO@ Check the response here
    #    fail("Implement Resolver validation checking!")
    print("Implement Resolver validation checking!")
    # We wanna check with CD on and off, and make sure it fails/works
    # need to remember to get resolver to validate iff cd on query is true
  end
  
  def test_trusted_key
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.dnssec = true
    bad_key = Dnsruby::RR.create(
      "uk-dnssec.nic.uk. 86400 IN DNSKEY 257 3 5 "+
        "AwEAAbhThsjZqxZDyZLie1BYP+R/G1YRhmuIFCbmuQiF4NB86gpW8EVR l2s+gvNuQw6yh2YdDdyJBselE4znRP1XQbpOTC5UO5CDwge9NYja/jrX lvrX2N048vhIG8uk8yVxJDosxf6nmptsJBp3GAjF25soJs07Bailcr+5 vdZ7GibH")
    ret = Dnsruby::Dnssec.add_trust_anchor(bad_key)
    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    
    begin
      ret = Dnsruby::Dnssec.verify(r)
      fail("Dnssec trusted key message verification should have failed with bad key")    
    rescue (Dnsruby::VerifyError)
      #    assert(!ret, "Dnssec trusted key message verification should have failed with bad key")    
    end
    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :flags => 257,
        :protocol => 3,
        :algorithm => 5,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::Dnssec.add_trust_anchor(trusted_key)
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec trusted key message verification failed")    

    #    # Check that keys have been added to trusted key cache
    #    ret = Dnsruby::Dnssec.verify(r)
    #    assert(ret, "Dnssec trusted key cache failed")    
  end
  
  def test_expired_keys
    # Add some keys with an expiration of 1 second.
    # Then wait a second or two, and check they are not available any more.
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    assert(Dnsruby::Dnssec.trusted_keys.length==0)
    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    Dnsruby::Dnssec.add_trust_anchor_with_expiration(trusted_key, Time.now.to_i + 1)
    assert(Dnsruby::Dnssec.trust_anchors.length==1)
    sleep(2)
    assert(Dnsruby::Dnssec.trust_anchors.length==0)
  end
  
  def test_tcp
    #These queries work:
    #		 dig @194.0.1.13 isoc.lu dnskey
    #		 dig @194.0.1.13 isoc.lu dnskey +dnssec
    #		 dig @194.0.1.13 isoc.lu dnskey +tcp
    
    #This one does not
    #
    #		 dig @194.0.1.13 isoc.lu dnskey +dnssec +tcp
    r = Dnsruby::Resolver.new()# "194.0.1.13")
        r.dnssec = true    
        r.use_tcp = true
    ret = r.query("isoc.lu", Dnsruby::Types.DNSKEY)
#    print ret.to_s+"\n"

    r = Dnsruby::Resolver.new("194.0.1.13")
    r.dnssec = true
    #r.use_tcp = true
    ret = r.query("isoc.lu", Dnsruby::Types.DNSKEY)
#    print ret.to_s+"\n"

    r.use_tcp = true
    r.dnssec = false
    ret = r.query("isoc.lu", Dnsruby::Types.DNSKEY)
#    print ret.to_s+"\n"

    r.dnssec = true    
    begin
    ret = r.query("isoc.lu", Dnsruby::Types.DNSKEY)
    rescue (Dnsruby::OtherResolvError)
    end
    print ret.to_s+"\n"

    
  end
end