require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestCache < Test::Unit::TestCase
  def test_cache
    # Create a cache, add some rrsets
    c = Cache.new
    numrrs = 5
    rs = RRSet.new
    numrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>100,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    # Try to find them
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numrrs)
    ret = c.lookup("example.com", "NS")
    assert(ret.length == numrrs)
    ret = c.lookup("example.com", 2)
    assert(ret.length == numrrs)
    ret = c.lookup(Name.create("example.com"), 2)
    assert(ret.length == numrrs)
    ret = c.lookup("example.com", Types.A)
    assert(ret.length == 0)
    rs = RRSet.new
    numarrs = 10
    numarrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.A, :ttl =>1000,
        :address => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    ret = c.lookup("example.com", Types.A)
    assert(ret.length == numarrs)
    ret = c.rrsets_for_domain("example.com")
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numrrs)
    # @TODO@ Test overwriting with longer and shorter ttls
    numshortrrs = 2
    rs = RRSet.new
    numshortrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>5,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numrrs)
    numlongrrs = 11
    rs = RRSet.new
    numlongrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>200,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numlongrrs)
    
    # Now add some records for a different name
    numnewrrs = 11
    rs = RRSet.new
    numnewrrs.times {|n|
      r = RR.create(:name => "sub.example.com", :type => Types.NS, :ttl =>200,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numlongrrs)
    ret = c.lookup("sub.example.com", Types.NS)
    assert(ret.length == numnewrrs)
    
    c.clear_cache
    ret = c.lookup("sub.example.com", Types.NS)
    assert(ret.length == 0)
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == 0)
    ret = c.lookup("example.com", Types.A)
    assert(ret.length == 0)
  end

  def test_expiry
    c = Cache.new
    numrrs = 5
    rs = RRSet.new
    numrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>1,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    numlongrrs = 11
    rs = RRSet.new
    numlongrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.A, :ttl =>200,
        :address => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    ret = c.lookup("example.com", Types.A)
    assert(ret.length == numlongrrs)
    # Try to find them
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numrrs)
    sleep(2)
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == 0)
    ret = c.lookup("example.com", Types.A)
    assert(ret.length == numlongrrs)
  end  
  
  def test_negatives
    
  end
  
  def test_negatives_expiry
  end
  
  def test_negatives_and_rrsets
    
  end
  
  def test_dnsruby_cache
    c = Dnsruby.cache
    numrrs = 5
    rs = RRSet.new
    numrrs.times {|n|
      r = RR.create(:name => "example.com", :type => Types.NS, :ttl =>100,
        :domainname => "192.168.1.#{n}")
      rs.add(r)
    }
    c.add_rrset(rs)
    # Try to find them
    ret = c.lookup("example.com", Types.NS)
    assert(ret.length == numrrs)    
  end
end
