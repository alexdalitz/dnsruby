require 'dnsruby'
require 'test/unit'

class TestRecur < Test::Unit::TestCase
  def test_recur
    Dnsruby::PacketSender.clear_caches
    r = Dnsruby::Recursor.new
#    Dnsruby::TheLog.level = Logger::DEBUG
    ret = r.query("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
#    print ret
    assert(ret.answer.length > 0)
#    ret = r.query_dorecursion("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
#    ret = r.query_dorecursion("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
  end
end
