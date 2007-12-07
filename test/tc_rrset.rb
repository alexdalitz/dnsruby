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
    print rrset.to_s + "\n"
    
    canon = rrset.sort_canonical
    
    print canon.to_s + "\n"
    assert(1, canon[0].preference)
    assert(10, canon[1].preference)
    assert(12, canon[2].preference)
  end
end