require 'test/unit'
require 'dnsruby'

class NsecTest < Test::Unit::TestCase
  INPUT = "alfa.example.com. 86400 IN NSEC host.example.com. ( " +
    "A MX RRSIG NSEC TYPE1234 )"
  include Dnsruby
  def test_nsec_from_string
    nsec = Dnsruby::RR.create(INPUT)
    assert_equal("host.example.com", nsec.next_domain.to_s)
    assert_equal([Types.A, Types.MX, Types.RRSIG, Types.NSEC, Types.TYPE1234], nsec.types)
    
    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)
  end

  def test_nsec_from_data
    nsec = Dnsruby::RR.create(INPUT)
    m = Dnsruby::Message.new
    m.add_additional(nsec)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    nsec3 = m2.additional()[0]
    assert_equal(nsec.to_s, nsec3.to_s)
  end
  
  def test_nsec_types
    # Test types in last section to 65536.
    #Test no zeros
    nsec = Dnsruby::RR.create(INPUT)
    nsec.add_type(Types.TYPE65534)
    assert(nsec.types.include?(Types.TYPE65534))
    assert(nsec.to_s.include?(Types.TYPE65534.string))
  end
  
end