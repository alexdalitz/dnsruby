require 'test/unit'
require 'dnsruby'

class TestCache < Test::Unit::TestCase
  def test_cache
    # @TODO@ Create a cache, add some rrsets, and some negatives
    c = Cache.new
    # @TODO@ Try to find them
    # @TODO@ Add some with ttl of 1 second, then sleep, and make sure they're gone
  end
  
  
end
