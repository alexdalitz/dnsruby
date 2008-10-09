$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'dnsruby'

class EventMachineTestResolver < Test::Unit::TestCase
  include Dnsruby
  Dnsruby::Resolver.use_eventmachine(true)
  Thread::abort_on_exception = true
  def setup
    Dnsruby::Config.reset
    #    Dnsruby.log.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
    Dnsruby::Resolver.start_eventmachine_loop(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
    Dnsruby::Resolver.start_eventmachine_loop(true)
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
    start=stop=0
    retry_times = 3
    retry_delay=1
    packet_timeout=2
    # Work out what time should be, then time it to check
    expected = ((2**(retry_times-1))*retry_delay) + packet_timeout
    begin
      res = Resolver.new("10.0.1.128")
      res.packet_timeout=packet_timeout
      res.retry_times=retry_times
      res.retry_delay=retry_delay
      start=Time.now
      m = res.send_message(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A))
      fail
    rescue ResolvTimeout
      stop=Time.now
      time = stop-start
      assert(time <= expected *1.1 && time >= expected *0.9, "Wrong time taken, expected #{expected}, took #{time}")        
    end
  end
  
  def test_query_timeout
    res = Resolver.new({:nameserver => "10.0.1.128"})
    start=stop=0
    retry_times = retry_delay = packet_timeout= 10
    query_timeout=2
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
    end    
  end
  
  def test_queue_query_timeout
    res = Resolver.new({:nameserver => "10.0.1.128"})
    bad = SingleResolver.new("localhost")
    res.add_resolver(bad)
    expected = 2
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
  
  
  
  def test_tcp
    res = Dnsruby::Resolver.new
    res.use_tcp = true
    Dnsruby::Resolver.use_eventmachine
    q = Queue.new
    id = 1
    res.send_async(Dnsruby::Message.new("nominet.org.uk"), q, id)
    id+=1
    res.send_async(Dnsruby::Message.new("example.com"), q, id)
    id.times do |i|
      itemid = q.pop[0]
      assert(itemid <= id)
      assert(itemid >= 0)
    end
  end
  
  def test_truncated_response
    res = Dnsruby::Resolver.new('ns0.validation-test-servers.nominet.org.uk')
    res.packet_timeout = 10
    m = res.query("overflow.dnsruby.validation-test-servers.nominet.org.uk", 'txt')
    assert(m.header.ancount == 61, "61 answer records expected, got #{m.header.ancount}")
    assert(!m.header.tc, "Message was truncated!")
  end
  
end
