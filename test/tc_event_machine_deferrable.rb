$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'dnsruby'

class EventMachineTestDeferrable < Test::Unit::TestCase
  Dnsruby::Resolver.use_eventmachine(true)
  def setup
#    Dnsruby.log.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  
  def test_deferrable_success
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"))
      df.callback {|msg| EM.stop}
      df.errback {|msg, err| 
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
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"))
      df.callback {|msg| EM.stop; assert(false)}
      df.errback {|msg, err| 
        EM.stop 
        }
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end

  def test_deferrable_success
    sleep(0.1) # Give the Event loop a chance to close down from previous test
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    res = Dnsruby::Resolver.new
    q = Queue.new
    id = 1
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"))
      df.callback {|msg| done = true; EM.stop}
      df.errback {|msg, err| 
        puts "errback: #{msg}, #{err}"
        done = true
        EM.stop 
        assert(false)}
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  
  def test_deferrable_timeout
    sleep(0.1) # Give the Event loop a chance to close down from previous test
    Dnsruby::Resolver.start_eventmachine_loop(false)
    Dnsruby::Resolver.use_eventmachine
    res = Dnsruby::Resolver.new("10.0.1.128")
    res.query_timeout=2
    q = Queue.new
    id = 1
    EM.run {
      df = res.send_async(Dnsruby::Message.new("nominet.org.uk"))
      df.callback {|msg| EM.stop; assert(false)}
      df.errback {|msg, err| 
        EM.stop 
      }
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
end
