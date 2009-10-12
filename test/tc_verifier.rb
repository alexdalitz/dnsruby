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

class VerifierTest < Test::Unit::TestCase

  def test_sha256
    key256 = Dnsruby::RR.create("example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
                    my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
                    kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}")
    a = Dnsruby::RR.create("www.example.net. 3600  IN  A  192.0.2.91")
    sig = Dnsruby::RR.create("www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
                    20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
                    l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
                    cFYK/lPtPiVYP4bwg==) ;{id = 9033}")
    rrset = Dnsruby::RRSet.new(a)
    rrset.add(sig)
    verifier = Dnsruby::SingleVerifier.new(nil)
    verifier.verify_rrset(rrset, key256)
  end

  def test_sha512
    key512 = Dnsruby::RR.create("example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
                   p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
                   xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
                   pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
                   );{id = 3740 (zsk), size = 1024b}")
    a = Dnsruby::RR.create("www.example.net. 3600  IN  A  192.0.2.91")
    sig =  Dnsruby::RR.create("www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
                    20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
                    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
                    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
                    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
                    =);{id = 3740}")
    rrset = Dnsruby::RRSet.new(a)
    rrset.add(sig)
    verifier = Dnsruby::SingleVerifier.new(nil)
    verifier.verify_rrset(rrset, key512)
  end

  def test_sha2_zone
    key1 = Dnsruby::RR.create("example.com.    3600    IN      DNSKEY  256 3 8 AwEAAeTXG9RkEnPqrs1gTA
+7R2YdovW5HrObuMcsgIjfgAupTXX7NHBVUVX0oF2x8fJIeYt9pTuogTuUhw9/
kJrCI43VWa7xbsMkTbyj1/
wrfZB25nZnt4DQiqpYm8AZ3XmRBilibsGubVvrzWiQLC1gGXKUJ7JyQyL98G9ODUH2bmnb
  ;{id = 43938 (zsk), size = 1024b}")
    key2 = Dnsruby::RR.create("example.com.    3600    IN      DNSKEY  257 3 8
AwEAAeLAE37+XYbieMtOqPRMbimhCjcyc/bSTbMQtKioxzjzgBPu/gVgHTeITJa
+IBFOD763HkzmG6ZIEcNAagCLg6+xeTnp017CBWWgnU+ksXdjgQ5KLfM/g4d2TL/Xf/BZJP
+JcIYqx3BNDT//bJpuwXqk6WkMtHGDSfSugel26TvgxG9X9xTaJh0u/
QMFpm9H4IyQ8557cYAG04z8Yx3PszE5niE6JGho7Qpv2YhpsuLh7dneUTtdqFajdyqU0lZ3iDHnrfm7ve75LorIMPB0FqIo8Q
+hqV/U44QB/gTuXiBPjxje6D6WLWJdisIKflYZjUBD0FxuOXZQ5+RFVMV5RSc= ;{id =
18976 (ksk), size = 2048b}")
    rrset = Dnsruby::RRSet.new(key1)
    rrset.add(key2)
    sig2 = Dnsruby::RR.create("example.com.    3600    IN      RRSIG   DNSKEY 8 2 3600 20091109083537
20091012083537 18976 example.com. 0S/8cNh9otTenbcqQ2C5fxglGLrkI/EHp/
8Y3NDbJ5M50xUzrXd91wjDCE2X/z7UNGeBtyFRqm2ZeId4MygBIBsFaqOr98X8qQo3qpZ/
ZtudmSSlk8X77bnKzsBxdLQgtE/REiT6j556zJJ9LtQ/
yHgdMmJa5BNPYbQDpJdzJGIYLe1Gx8edOqcPt0LAc3FmjB096Gmlt7JpIWJXrh2Q82eDTkLiEpv7ePAimduKh14
+ERi6mLKFDaQjnfkwZ7/zjw6Ekp3a7L9Pa4S/OKUis/TarEQJf
+w9yAVKKL8HCIFKOXfn1rOWZ8LIEzlmUmOVOV03F1Paww+9fJaG+WDhpQ== ;{id =
18976}")
    rrset.add(sig2)
    verifier = Dnsruby::SingleVerifier.new(nil)
    verifier.verify_rrset(rrset, key2)
    sig = Dnsruby::RR.create("example.com.    3600    IN      RRSIG   DNSKEY 8 2 3600 20091109083537  
20091012083537 43938 example.com. TXaNGZ4QklUIlPtXaGhNegER 
+uwJAvM9fSmnSt55FiMrMgkJDb6b/ 
GTyOF6INgKopO1wZRZI0iWaPUI0SRow6 
+X8Idpk05uG7Two5R9uMGX0hu8PWc8BzuAxgeyawCYkXwXQ6Ah0PF9xkc/ 
Xlieo6T34XsoeHmKjmjMWs1KdFkU= ;{id = 43938}")
    rrset.add(sig)
    verifier.verify_rrset(rrset, key1)
    txt = Dnsruby::RR.create('example.com.    86400   IN      TXT     "v=spf1 -all"')
    rrset = Dnsruby::RRSet.new(txt)
    txt_sig = Dnsruby::RR.create("example.com.    86400   IN      RRSIG   TXT 8 2 86400 20091109083536
20091012083536 43938 example.com. rZcuxDZ7QO1oBSqwlV
+1ar7RTvwWOCYpgZy6oxXQMWkxONXnHVQO32yl
+3WzROW4tYHfFpsdyvo1BCT1PRRXLcLFGJd/
T3Y6ciiq5ZzsesfYV0aChOUhseX7MnMjsaLGbmDDVmGqW78nsoBjv9g
+0YshQa7E1ctz2aQ2sorWN+E= ;{id = 43938}")
    rrset.add(txt_sig)
    verifier.verify_rrset(rrset, key1)
  end
  
  def test_se_query
    # Run some queries on the .se zone
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    res.dnssec = true
    r = res.query("se", Dnsruby::Types.ANY)
    # See comment below
    Dnsruby::Dnssec.anchor_verifier.add_trusted_key(r.answer.rrset("se", 'DNSKEY'))
    nss = r.answer.rrset("se", 'NS')
    ret = Dnsruby::Dnssec.verify_rrset(nss)
    assert(ret, "Dnssec verification failed")
  end

  def test_verify_message
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    res.udp_size = 5000
    r = res.query("se", Dnsruby::Types.DNSKEY)
    # This shouldn't be in the code - but the key is rotated by the .se registry
    # so we can't keep up with it in the test code.
    # Oh, for a signed root...
    #    print "Adding keys : #{r.answer.rrset("se", 'DNSKEY')}\n"
    Dnsruby::Dnssec.anchor_verifier.add_trusted_key(r.answer.rrset("se", 'DNSKEY'))
    ret = Dnsruby::Dnssec.verify(r)
    assert(ret, "Dnssec message verification failed : #{ret}")
  end

  def test_verify_message_fails
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)
    # Haven't configured key for this, so should fail
    begin
      ret = Dnsruby::Dnssec.verify(r)
      fail("Message shouldn't have verified")
    rescue (Dnsruby::VerifyError)
    end
    #    assert(!ret, "Dnssec message verification failed")
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
    assert(Dnsruby::Dnssec.anchor_verifier.trusted_keys.length==0)
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
    r = Dnsruby::SingleResolver.new()# "194.0.1.13")
    r.dnssec = true
    r.use_tcp = true
    ret = r.query("isoc.lu", Dnsruby::Types.DNSKEY)
    #    print ret.to_s+"\n"

    r = Dnsruby::SingleResolver.new("194.0.1.13")
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

  end

  def test_sendraw
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("a.ns.se")
    res.dnssec = true
    message = Dnsruby::Message.new("se", Dnsruby::Types.ANY)
    begin
      res.send_message(message)
      fail()
    rescue (Exception)
    end

    message.send_raw = true
    res.send_message(message)
  end

  def test_dsa
    # Let's check sources.org for DSA keys
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Recursor.new()
    ret = res.query("sources.org", Dnsruby::Types.DNSKEY)
    keys = ret.rrset("sources.org", "DNSKEY")
    assert(keys && keys.length > 0)
    dsa = nil
    keys.each {|key|
      if (key.algorithm == Dnsruby::Algorithms.DSA)
        dsa = key
      end
    }
    assert(dsa)
    # Now do something with it

    response = res.query("sources.org", Dnsruby::Types.ANY)
    verified = 0
    #    response.each_section {|sec|
    response.answer.rrsets.each {|rs|
      if (rs.sigs()[0].algorithm == Dnsruby::Algorithms.DSA &&
            rs.sigs()[0].key_tag == dsa.key_tag)
        ret = Dnsruby::Dnssec.verify_rrset(rs, keys)
        assert(ret)
        verified+=1
      end
    }
    #   }
    assert(verified > 0)
  end
end