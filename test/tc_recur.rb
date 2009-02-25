require 'dnsruby'
require 'test/unit'

class TestRecur < Test::Unit::TestCase
  def test_recur
    Dnsruby::Cache.clear
    r = Dnsruby::Recursor.new
#    Dnsruby::TheLog.level = Logger::DEBUG
    ret = r.query_dorecursion("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
#    print ret
    assert(ret.answer.length > 0)
  end
end
