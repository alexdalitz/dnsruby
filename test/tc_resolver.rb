#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require 'dnsruby'
require 'socket'
require 'test/unit'
include Dnsruby
#@TODO@ We also need a test server so we can control behaviour of server to test
#different aspects of retry strategy.
#Of course, with Ruby's limit of 256 open sockets per process, we'd need to run 
#the server in a different Ruby process.

class TestResolver < Test::Unit::TestCase
  include Dnsruby
  Thread::abort_on_exception = true
  PORT = 42138
  @@port = PORT
  def setup
    Dnsruby::Config.reset
  end
  
  def test_send_message
    res = Resolver.new
    ret = res.send_message(Message.new("example.com", Types.A))
    assert(ret.kind_of?(Message))
  end
  
  def test_query
    res = Resolver.new
    ret = res.query("example.com")
    assert(ret.kind_of?(Message))
  end
  
  def test_query_async
    res = Resolver.new
    q = Queue.new
    res.send_async(Message.new("example.com", Types.A),q,q)
    id, ret, error = q.pop
    assert_equal(id, q, "Id wrong!")
    assert(ret.kind_of?(Message), "Ret wrong!")
    assert(error==nil)
  end
  
  def test_query_one_duff_server_one_good
    res = Resolver.new({:nameserver => ["localhost", "128.8.10.90"]})
    res.retry_delay=1
    q = Queue.new
    res.send_async(Message.new("example.com", Types.A),q,q)
    id, ret, error = q.pop
    assert_equal(id, q, "Id wrong!")
    assert(ret.kind_of?(Message), "Ret wrong! (#{ret.class}")
    assert(error==nil)
  end

  # @TODO@ Implement!!  But then, why would anyone want to do this?
  #  def test_many_threaded_clients
  #    assert(false, "IMPLEMENT!")
  #  end
  
  def test_reverse_lookup
    m = Message.new("210.251.121.214", Types.PTR)
    r = Resolver.new
    q=Queue.new
    r.send_async(m,q,q)
    id,ret, error=q.pop
    assert(ret.kind_of?(Message))
    no_pointer=true
    ret.each_answer do |answer|
      if (answer.type==Types.PTR)
        no_pointer=false
        assert(answer.domainname.to_s=~/ruby-lang/)      
      end
    end
    assert(!no_pointer)
  end
  
  def test_bad_host
    res = Resolver.new({:nameserver => "localhost"})
    res.retry_times=1
    res.retry_delay=0
    res.query_timeout = 1
    q = Queue.new
    res.send_async(Message.new("example.com", Types.A), q, q)
    id, m, err = q.pop
    assert(id==q)
    assert(m == nil)
    assert(err.kind_of?(OtherResolvError) || err.kind_of?(IOError), "OtherResolvError or IOError expected : got #{err.class}")
  end
  
  def test_nxdomain
    res=Resolver.new
    q = Queue.new
    res.send_async(Message.new("dklfjhdFHFHDVVUIEWRFDSAJKVCNASDLFJHN.com", Types.A), q, 1)
    id, m, err = q.pop
    assert(id==1)
    assert(m.rcode == RCode.NXDOMAIN)
    assert(err.kind_of?(NXDomain))
  end
  
  def test_timeouts
    #test timeout behaviour for different retry, retrans, total timeout etc.
    #Problem here is that many sockets will be created for queries which time out. 
    # Run a query which will not respond, and check that the timeout works
    if (!RUBY_PLATFORM=~/darwin/)
      start=stop=0
      retry_times = 3
      retry_delay=1
      packet_timeout=2
      # Work out what time should be, then time it to check
      expected = ((2**(retry_times-1))*retry_delay) + packet_timeout
      begin
        res = Resolver.new({:nameserver => "10.0.1.128"})
        #      res = Resolver.new({:nameserver => "213.248.199.17"})
        res.packet_timeout=packet_timeout
        res.retry_times=retry_times
        res.retry_delay=retry_delay
        start=Time.now
        m = res.send_message(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A))
        fail
      rescue ResolvTimeout
        stop=Time.now
        time = stop-start
        assert(time <= expected *1.2 && time >= expected *0.9, "Wrong time take, expected #{expected}, took #{time}")        
      end
  end
  end
  
  def test_packet_timeout
    if (!RUBY_PLATFORM=~/darwin/)
      res = Resolver.new({:nameserver => "10.0.1.128"})
      start=stop=0
      retry_times = retry_delay = packet_timeout= 10
      query_timeout=1
      begin
        res.packet_timeout=packet_timeout
        res.retry_times=retry_times
        res.retry_delay=retry_delay
        res.query_timeout=query_timeout
        # Work out what time should be, then time it to check
        expected = query_timeout
        start=Time.now
        m = res.send_message(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A))
        fail
      rescue ResolvTimeout
        stop=Time.now
        time = stop-start
        assert(time <= expected *1.1 && time >= expected *0.9, "Wrong time take, expected #{expected}, took #{time}")        
      end    #
  end
  end
  
  def test_queue_packet_timeout
    if (!RUBY_PLATFORM=~/darwin/)
      res = Resolver.new({:nameserver => "10.0.1.128"})
      bad = SingleResolver.new("localhost")
      res.add_resolver(bad)
      expected = 1
      res.query_timeout=expected    
      q = Queue.new
      start = Time.now
      m = res.send_async(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A), q, q)
      id,ret,err = q.pop
      stop = Time.now
      assert(id=q)
      assert(ret==nil)
      assert(err.class == ResolvTimeout, "#{err.class}, #{err}")
      time = stop-start
      assert(time <= expected *1.2 && time >= expected *0.9, "Wrong time take, expected #{expected}, took #{time}")            
    end
  end
  
end