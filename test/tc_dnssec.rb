require 'test/unit'
require 'dnsruby'

class DnssecTest < Test::Unit::TestCase
  #trusted-keys {
  #"uk-dnssec.nic.uk." 257 3 5 "
  #AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv
  #4uWJR9jLrxMYmsFOGAKWhiis832ISbPTYtF8sxbNVEo
  #tgf9eePruAFPIg6ZixG4yMO9XGLXmcKTQ/cVudqkU00
  #V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLvFe8l
  #ReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yf
  #QwtKlr75pm+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1Tf
  #F5mQYIFoDYASLiDQpvNRN3US0U5DEG9mARulKSSw448
  #urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjbLmc8/v+z
  #";
  #};
  def test_dnssec_query
    res = Dnsruby::SingleResolver.new("dnssec.nominet.org.uk")
    res.dnssec=true

    keyrec = nil
    r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    keys = r.answer.rrset('DNSKEY')
    
    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
    rrset = r.rrset('NSEC')
    sigrec = rrset.sigs[0]
    
    # @TODO@ This should be done by the verifier
    keys.rrs.each {|key|
      if (key.key_tag == sigrec.key_tag)
        keyrec = key
      end
    }
    
#    print "sigrec : #{sigrec}\n"
#    print "rrset : #{rrset.to_s}\n"
#    print "keyrec : #{keyrec.to_s}\n"
#    print "keyrec tag =  : #{keyrec.key_tag.to_s}\n"
    # Now get the DNSKEY and check that the RRSET is signed properly.
    ret = Dnsruby::DnssecResolver.verify_signature(rrset, sigrec, keyrec)
    assert(ret, "Dnssec verification failed")
  end
  
  def test_se_query
    # @TODO@ Run some queries on the .se zone
    res = Dnsruby::SingleResolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)    
    print r
  end
    
  def test_follow_chain_of_trust
    # Descend from the trusted key for the root of uk-dnssec.nic.uk to ensure
    # that NS record for aaa.bigzone.uk-dnssec.nic.uk is properly signed by a
    # trusted key
    #@TODO@
    
  end
end