require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'Dnsruby'
begin
  require 'test/tc_soak_base'
rescue Exception
  require 'tc_soak_base'
end

class TestEventMachineSoak < Test::Unit::TestCase
  def setup
#    Dnsruby::TheLog.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
  end
  def test_single_res
    #    TestSoakBase.test_continuous_queries_asynch_single_res
  end
  @@dfs = []
  @@num_sent = 0
  def test_deferrable
#    Dnsruby::TheLog.level=Logger::DEBUG
    res = Dnsruby::SingleResolver.new
    Dnsruby::Resolver.use_eventmachine
    Dnsruby::Resolver.start_eventmachine_loop(false)
    q = Queue.new
    id = 1
    done = false
    EM.run {
      10.times do |i|
        puts i
        #        dfs, num_sent = send_next_deferrable(dfs, num_sent)
        send_next_deferrable(res)
      end
    }
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  
  def send_next_deferrable(res) # (dfs, num_sent)
    if (@@num_sent>1000) 
    EM.stop
    return
    end
    @@dfs[@@num_sent] = res.send_async(Dnsruby::Message.new("example#{@@num_sent}.com"), @@num_sent, Queue.new) #@TODO@ Shouldn't need ID and queue
    @@dfs[@@num_sent].callback {|id, msg| puts "callback: #{id}" # , #{msg}"
      send_next_deferrable(res) # (dfs, num_sent)
    }
    @@dfs[@@num_sent].errback {|id, msg, err| 
      puts "errback: #{id}, #{err}" # , #{msg}"
      send_next_deferrable(res) # (dfs, num_sent)
    }
    puts @@num_sent
    @@num_sent+=1
    #    return dfs, num_sent  
  end
  
  #  def test_sequential
  #    res = Dnsruby::SingleResolver.new
  #    q = Queue.new
  #    1500.times do |i|
  #      puts i
  #          res.send_async(Dnsruby::Message.new("example#{i}.com"), i, q)      
  #    end
  #    1500.times do |i|
  #      puts "Receiving #{i}"
  #      q.pop
  #    end
  #  end
end
