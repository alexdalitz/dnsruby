require 'test/unit'
require 'dnsruby'

class TestQueue < Test::Unit::TestCase
  def test_queue
    q = Queue.new
    r = Dnsruby::Resolver.new
    timeout = 5
    num_queries = 1000
    r.query_timeout = timeout
    num_queries.times do |i| 
      r.send_async(Dnsruby::Message.new("example#{i}.com"), q, i)
    end
    sleep(timeout * 1.5)
    assert(q.size == num_queries, "#{num_queries} expected, but got #{q.size}")
  end
end
