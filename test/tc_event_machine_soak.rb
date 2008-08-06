require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'dnsruby'
begin
  require 'test/tc_soak_base'
rescue Exception
  require 'tc_soak_base'
end

class TestEventMachineSoak < Test::Unit::TestCase
  def setup
    #    Dnsruby.log.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
  end
  def test_single_res
    #    TestSoakBase.test_continuous_queries_asynch_single_res
  end
  def test_single_deferrable
    sleep(0.1)
    @@dfs = {}
    @@num_sent = 0
    #Dnsruby.log.level=Logger::DEBUG
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    q = Queue.new
    id = 1
    done = false
    EM.run {
      100.times do |i|
        send_next_deferrable(res)
      end
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  
  def test_sequential
    #Dnsruby.log.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
    res = Dnsruby::SingleResolver.new
    res.packet_timeout = 2
    q = Queue.new
    240.times do |i|
      puts i
      res.send_async(Dnsruby::Message.new("example#{i}.com"), q, i)      
    end
    240.times do |i|
      puts "Receiving #{i}"
      id, msg, error = q.pop
      if (error != nil)
        puts ("Error : #{error}")
      end
    end
  end
  
  def test_resolver_deferrable
    sleep(0.1)
    @@dfs = {}
    @@num_sent = 0
    #Dnsruby.log.level=Logger::DEBUG
    res = Dnsruby::Resolver.new
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    q = Queue.new
    id = 1
    done = false
    EM.run {
      50.times do |i|
        send_next_deferrable(res)
      end
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)    
  end

  def send_next_deferrable(res)
    if (@@num_sent>2000) 
      EM.stop
      return
    end
    id = @@num_sent
    @@num_sent+=1
    @@dfs[id] = res.send_async(Dnsruby::Message.new("example.com"))
    @@dfs[id].callback {|msg| puts "callback: #{id}"
      @@dfs.delete(id)
      send_next_deferrable(res)
    }
    @@dfs[id].errback {|msg, err| 
      @@dfs.delete(id)
      puts "errback: #{id}, #{err}"
      send_next_deferrable(res)
    }
  end  
end
