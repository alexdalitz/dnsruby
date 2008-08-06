$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'dnsruby'

class EventMachineTestSingleResolver < Test::Unit::TestCase
  Dnsruby::Resolver.use_eventmachine(true)
  def setup
#    Dnsruby.log.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
    sleep(0.01)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  def test_udp
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), q, id)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), q, id)
    id.times do |i|
      item = q.pop
      assert(item[1].class==Dnsruby::Message)
      assert(item[0] <= id)
      assert(item[0] >= 0)
    end
  end
  
  def test_tcp
    res = Dnsruby::SingleResolver.new
    res.use_tcp = true
    Dnsruby::Resolver.use_eventmachine
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), q, id)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), q, id)
    id.times do |i|
      itemid, response, error = q.pop
      assert(itemid <= id)
      assert(itemid >= 0)
      assert(error==nil)
    end
    #@TODO@ How do we check that TCP was actually used? Do we need a test server for this?
    #Or will the truncated test catch this? (Query retried over TCP to fetch all records)
  end
  
  def test_tcp_queue_timeout
    res = Dnsruby::SingleResolver.new("10.0.1.128")
    Dnsruby::Resolver.use_eventmachine(true)
    res.packet_timeout=2
    res.use_tcp=true
    q = Queue.new
    msg = Dnsruby::Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk")
    res.send_async(msg, q, 1)
    start=Time.now
    id,ret,error = q.pop
    end_time = Time.now
    assert(id==1)
    assert(ret==nil)
    assert(error.class == Dnsruby::ResolvTimeout)
#    p "Difference = #{end_time-start}"
    assert(end_time - start >= 1.9)
    assert(end_time - start <= 2.2)
  end
  
  def test_udp_queue_timeout
    res = Dnsruby::SingleResolver.new("10.0.1.128")
    Dnsruby::Resolver.use_eventmachine(true)
    res.packet_timeout=2
    q = Queue.new
    start=Time.now
    msg = Dnsruby::Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk")
    res.send_async(msg, q, 1)
    id,ret,error = q.pop
    end_time = Time.now
    assert(id==1)
    assert(ret==nil)
#    p "Difference = #{end_time-start}"
    assert(error.class == Dnsruby::ResolvTimeout)
    assert(end_time - start >= 1.9)
    assert(end_time - start <= 2.2)
  end
  
  def test_truncated_response
   res = Dnsruby::SingleResolver.new
    res.packet_timeout = 10
    res.server=('ns0.validation-test-servers.nominet.org.uk')
    m = res.query("overflow.dnsruby.validation-test-servers.nominet.org.uk", 'txt')
    assert(m.header.ancount == 61, "61 answer records expected, got #{m.header.ancount}")
    assert(!m.header.tc, "Message was truncated!")
  end
end
