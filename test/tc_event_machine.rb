$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'Dnsruby'

class EventMachineTest < Test::Unit::TestCase
  Dnsruby::Resolver.use_eventmachine(true)
  def setup
#    Dnsruby::TheLog.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  def test_udp
    Dnsruby::TheLog.level=Logger::DEBUG
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), id, q)
    id.times do |i|
      item = q.pop
      assert(item[0] <= id)
      assert(item[0] >= 0)
    end
    Dnsruby::TheLog.level=Logger::ERROR
  end
  
  def test_tcp
    flunk ("IMPLEMENT TCP!!")
    res = Dnsruby::SingleResolver.new
    res.use_tcp = true
    Dnsruby::Resolver.use_eventmachine
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), id, q)
    id.times do |i|
      itemid = q.pop[0]
      assert(itemid <= id)
      assert(itemid >= 0)
    end
  end
  
  def test_udp_queue_timeout
    res = Dnsruby::SingleResolver.new("10.0.1.128")
    Dnsruby::Resolver.use_eventmachine(true)
    res.packet_timeout=2
    q = Queue.new
    msg = Dnsruby::Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk")
    res.send_async(msg, 1, q)
    id,ret,error = q.pop
    assert(id==1)
    assert(ret==nil)
    puts "Timeout returns " + error.class.to_s
    assert(error.class == Dnsruby::ResolvTimeout)
  end
  
  def test_deferrable_success
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    q = Queue.new
    id = 1
    done = false
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q) #@TODO@ Shouldn't need ID and queue
      df.callback {|id, msg| puts "callback: #{id}, #{msg}"; done = true; EM.stop}
      df.errback {|id, msg, err| 
        puts "errback: #{id}, #{msg}, #{err}"
        done = true
        EM.stop 
        assert(false)}
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  
  def test_deferrable_timeout
    res = Dnsruby::SingleResolver.new("10.0.1.128")
    Dnsruby::Resolver.use_eventmachine
    res.packet_timeout=2
    Dnsruby::Resolver.start_eventmachine_loop(false)
    q = Queue.new
    id = 1
    done = false
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"), id, q) #@TODO@ Shouldn't need ID and queue
      df.callback {|id, msg| puts "callback: #{id}, #{msg}"; done = true; EM.stop; assert(false)}
      df.errback {|id, msg, err| 
        puts "errback: #{id}, #{msg}, #{err}"
        done = true
        EM.stop 
        }
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
end
