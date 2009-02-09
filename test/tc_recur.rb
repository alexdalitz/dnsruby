require 'dnsruby'
require 'test/unit'

class TestRecur < Test::Unit::TestCase
  def test_recur
    r = Dnsruby::Recursor.new
    ret = r.query_dorecursion("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
    assert(ret.answer.length > 0)
  end
end
