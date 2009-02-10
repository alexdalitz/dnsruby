require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestCache < Test::Unit::TestCase
  def test_cache
    # @TODO@ Create a cache, add some rrsets, and some negatives
    c = Cache.new
    numrrs = 5
    rs = RRSet.new
    numrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>100,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    print c.inspect
    c.lookup("example.com", Types.NS)
    assert(c.length > 0)
    # @TODO@ Try to find them
    # @TODO@ Add some with ttl of 1 second, then sleep, and make sure they're gone
  end
  
  
end
