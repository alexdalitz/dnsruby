require 'test/unit'
require 'dnsruby'

class RrsetTest < Test::Unit::TestCase
  def test_rrset
    rrset = Dnsruby::RRSet.new

      
    rr=Dnsruby::RR.create({	   :name => "example.com",
        :ttl  => 3600,
        :type         => 'MX',
        :preference   => 10,
        :exchange     => 'mx-exchange.example.com',
      })

    rrset.add(rr)
    rr.preference = 12
    rrset.add(rr)
    rr.preference = 1
    rrset.add(rr)
    
    canon = rrset.sort_canonical
    
    assert(1, canon[0].preference)
    assert(10, canon[1].preference)
    assert(12, canon[2].preference)
    
    assert(rrset.sigs.length == 0)
    assert(rrset.num_sigs == 0)
    assert(rrset.rrs.length == 3)

    # Check RRSIG records (only of the right type) can be added to the RRSet
    sig = Dnsruby::RR.create({:name=>"example.com",         :ttl  => 3600,
        :type         => 'RRSIG',
        :type_covered  => 'A',
        :original_ttl => 3600,
        :algorithm => Dnsruby::Algorithms::RSASHA1,
        :labels => 3,
        :expiration => Time.mktime(2003,03,22,17,31, 03).to_i,
        :inception => Time.mktime(2003,02,20,17,31,03).to_i,
        :key_tag => 2642
      })
    assert(!rrset.add(sig))
    assert(rrset.sigs.length == 0)
    assert(rrset.num_sigs == 0)
    assert(rrset.rrs.length == 3)
    sig.type_covered = Dnsruby::Types.MX
    assert(rrset.add(sig))
    assert(rrset.sigs.length == 1)
    assert(rrset.num_sigs == 1)
    assert(rrset.rrs.length == 3)
    sig.name="example.co.uk"
    assert(!rrset.add(sig))
    assert(rrset.sigs.length == 1)
    assert(rrset.num_sigs == 1)
    assert(rrset.rrs.length == 3)
  end
end