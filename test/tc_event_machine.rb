$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'Dnsruby'
begin
require 'test/tc_single_resolver'
rescue Exception
  require 'tc_single_resolver'
end

class EventMachineTest < Test::Unit::TestCase
  def setup
    #Dnsruby::TheLog.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
  end
  def test_udp
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), id, q)
    id.times do |i|
      assert(q.pop[0] <= id)
      assert(q.pop[0] >= 0)
    end
  end
  
  def test_tcp
    res = Dnsruby::SingleResolver.new
    res.use_tcp = true
    Dnsruby::Resolver.use_eventmachine
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), id, q)
    id.times do |i|
      assert(q.pop[0] <= id)
      assert(q.pop[0] >= 0)
    end
  end
  
  def test_queue_timeout
    res = Dnsruby::SingleResolver.new("10.0.1.128")
    Dnsruby::Resolver.use_eventmachine
    res.packet_timeout=1
    q = Queue.new
    msg = Dnsruby::Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk")
    res.send_async(msg, 1, q)
    count = 0
    while (q.empty? && count < 50)
      sleep(0.1)
      count += 1
    end
    id,ret,error = q.pop
    assert(id==1)
    assert(ret==nil)
    assert(error.class == Dnsruby::ResolvTimeout)
  end
  
  def test_deferrable_success
    flunk("IMPLEMENT!")
  end

  def test_deferrable_timeout
    flunk("IMPLEMENT!")    
  end
end
