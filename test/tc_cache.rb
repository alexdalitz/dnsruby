require 'test/unit'
require 'dnsruby'
include Dnsruby

class TestCache < Test::Unit::TestCase
  def test_cache
    m1 = Message.new("example.com.", Types.A, Classes.IN)
    rr1 = RR.create("example.com.		2	IN	A	208.77.188.166")
    m1.add_answer(rr1)
    m1.header.aa = true
    Cache.add(m1)
    ret = Cache.find("example.com", "A")
    assert(ret.answer == m1.answer, "#{m1.answer}end\n#{ret.answer}end" )
    assert(ret.answer.to_s == m1.answer.to_s, "#{m1.answer.to_s}end\n#{ret.answer.to_s}end" )
    assert(ret.header.aa == false)
    assert(ret.answer.rrsets()[0].ttl == 2)
    sleep(1)
    ret = Cache.find("example.com", "A")
    assert(ret.answer.rrsets()[0].ttl == 1)
    assert(ret.answer != m1.answer, "ret.answer=#{ret.answer}\nm1.answer=#{m1.answer}" )
    assert(ret.header.aa == false)
    sleep(1) # TTL of 2 should have timed out now
    ret = Cache.find("example.com", "A")
    assert(!ret)
    Cache.add(m1)
    m2 = Message.new("example.com.", Types.A, Classes.IN)
    rr2 = RR.create("example.com.		200	IN	A	208.77.188.166")
    m2.add_answer(rr2)
    m2.header.aa = true
    Cache.add(m2)
    ret = Cache.find("example.com", "A")
    assert(ret.answer.rrsets()[0].ttl == 200)
  end

  def test_opt_record
# Create a very large message, encode it and decode it - there should be an opt record
# test getting that in and out the cache
  end

  def test_negative

  end

end
