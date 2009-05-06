require 'test/unit'
require 'dnsruby'

class TestQueue < Test::Unit::TestCase
  def test_queue
    q = Queue.new
    r = Dnsruby::Resolver.new
#    Dnsruby::TheLog.level=Logger::DEBUG
    timeout = 15
    num_queries = 100
    r.query_timeout = timeout
    num_queries.times do |i|
      r.send_async(Dnsruby::Message.new("example.com"), q, i)
#      print "Sent #{i}\n"
    end
    sleep(timeout * 2)
    assert(q.size == num_queries, "#{num_queries} expected, but got #{q.size}")
  end
end
