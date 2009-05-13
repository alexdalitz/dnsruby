require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestCache < Test::Unit::TestCase
  def test_cache
    Dnsruby::PacketSender.clear_caches
    m1 = Message.new("example.com.", Types.A, Classes.IN)
    rr1 = RR.create("example.com.		3	IN	A	208.77.188.166")
    m1.add_answer(rr1)
    m1.header.aa = true
    assert(!m1.cached)
    Cache.add(m1)
    ret = Cache.find("example.com", "A")
    assert(ret.cached)
    assert(ret.answer == m1.answer, "#{m1.answer}end\n#{ret.answer}end" )
    assert(ret.answer.to_s == m1.answer.to_s, "#{m1.answer.to_s}end\n#{ret.answer.to_s}end" )
    assert(ret.header.aa == false)
    assert(ret.answer.rrsets()[0].ttl == 3)
    sleep(1)
    ret = Cache.find("example.com", "A")
    assert(ret.cached)
    assert((ret.answer.rrsets()[0].ttl == 2) || (ret.answer.rrsets()[0].ttl == 1), "ttl = #{ret.answer.rrsets()[0].ttl}")
    assert(ret.answer != m1.answer, "ret.answer=#{ret.answer}\nm1.answer=#{m1.answer}" )
    assert(ret.header.aa == false)
    sleep(2) # TTL of 3 should have timed out now
    ret = Cache.find("example.com", "A")
    assert(!ret)
    Cache.add(m1)
    m2 = Message.new("example.com.", Types.A, Classes.IN)
    rr2 = RR.create("example.com.		200	IN	A	208.77.188.166")
    m2.add_answer(rr2)
    m2.header.aa = true
    Cache.add(m2)
    ret = Cache.find("example.com", "A")
    assert(ret.cached)
    assert(ret.answer.rrsets()[0].ttl == 200)
  end

  def test_opt_record
    # Create a very large message, encode it and decode it - there should be an opt record
    # test getting that in and out the cache
    # We should be able to do this in the online test by getting back a very big
    # record from the test zone
  end

  def test_negative

  end

  def test_online
    # @TODO@ !!!
    # Get the records back from the test zone
    Dnsruby::PacketSender.clear_caches
    res = SingleResolver.new("ns0.validation-test-servers.nominet.org.uk.")
    res.udp_size = 4096
    query = Message.new("overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT)
    ret = res.send_message(query)
#    print "#{ret}\n"
    assert(!ret.cached)
    assert(ret.rcode == RCode.NoError)
    assert(ret.header.aa)
    # Store the ttls
    first_ttls = ret.answer.rrset(
      "overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT).ttl
    # Wait a while
    sleep(1)
    # Ask for the same records
    query = Message.new("overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT)
    ret = res.send_message(query)
#    print "#{ret}\n"
    assert(ret.rcode == RCode.NoError)
    assert(ret.cached)
    second_ttls = ret.answer.rrset(
      "overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT).ttl
    # make sure the ttl is less the time we waited
    assert((second_ttls == first_ttls - 1) || (second_ttls == first_ttls - 2),
            "First ttl = #{first_ttls}, second = #{second_ttls}\n")
    # make sure the header flags (and ID) are right
    assert(ret.header.id == query.header.id, "First id = #{query.header.id}, cached response was #{ret.header.id}\n")
    assert(!ret.header.aa)
  end

  def test_online_uncached
    # @TODO@ Check that wildcard queries are not cached
  end

end
