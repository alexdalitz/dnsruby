require 'test/unit'
require 'dnsruby'

class RrsigTest < Test::Unit::TestCase
  INPUT = "host.example.com. 86400 IN RRSIG A 5 3 86400 20030322173103 ( " + 
    "20030220173103 2642 example.com. " +
    "oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr" +
    "PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o" +
    "B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t" +
    "GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG" +
    "J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )"
  def test_rrsig_from_string
    rrsig = Dnsruby::RR.create(INPUT)
    
    assert_equal(Dnsruby::Types.A, rrsig.type_covered)
    assert_equal(Dnsruby::Algorithms::RSASHA1, rrsig.algorithm)
    assert_equal(3, rrsig.labels)
    assert_equal(86400, rrsig.original_ttl)
    assert_equal(Time.mktime(2003,03,22,17,31, 03).to_i, rrsig.expiration)
    assert_equal(Time.mktime(2003,02,20,17,31,03).to_i, rrsig.inception)
    assert_equal(2642, rrsig.key_tag)
    assert_equal(Dnsruby::Name.create("example.com."), rrsig.signers_name)
    assert_equal("oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr" +
    "PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o" +
    "B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t" +
    "GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG" +
    "J5D6fwFm8nN+6pBzeDQfsS3Ap3o=", ([rrsig.signature].pack("m*")).gsub(/\n/,"").chomp)
    
    rrsig2 = Dnsruby::RR.create(rrsig.to_s)
    assert(rrsig2.to_s == rrsig.to_s)
  end

  def test_string_with_comments
    r = Dnsruby::RR.create("tjeb.nl.		 3600		 IN		 RRSIG		 NSEC3PARAM 7 2 3600 20090630164649 20090602164649 53177 tjeb.nl. Fw70WQMviRFGyeze3MUpfafaAcWIvHRpnq4ZK3lxexrR1p+rLxK5C4qVKU71XYrPYR7XEBxgUG1oyKNOhFOVyx31EjC462dz7Vxn6UDpD1LIwNnD28+oHfS9AFzGKcn4zUZqT+8IvOO1jiS9c3Y8WAkOloN9AwGIIKWU8zAp1n4= ;{id = 53177}")
    assert_equal("Fw70WQMviRFGyeze3MUpfafaAcWIvHRpnq4ZK3lxexrR1p+rLxK5C4qVKU71XYrPYR7XEBxgUG1oyKNOhFOVyx31EjC462dz7Vxn6UDpD1LIwNnD28+oHfS9AFzGKcn4zUZqT+8IvOO1jiS9c3Y8WAkOloN9AwGIIKWU8zAp1n4=", ([r.signature].pack("m*")).gsub(/\n/,"").chomp)
  end
end