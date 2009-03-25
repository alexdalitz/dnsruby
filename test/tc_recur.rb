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
#    ret = r.query_dorecursion("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
#    ret = r.query_dorecursion("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
  end

  def test_use_as_a_resolver
    # @TODO@ Try to use the recursor as a normal resolver.
    print "Test recursor as normal resolver!\n"
  end

  def test_recursor_caching
    # @TODO@ Test the recursor caching.
    print "Test recursor caching!\n"
  end
end
