require 'test/unit'
require 'dnsruby'

class DnskeyTest < Test::Unit::TestCase
  INPUT = "example.com. 86400 IN DNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3" + 
    "Cbl+BBZH4b/0PY1kxkmvHjcZc8no" + 
    "kfzj31GajIQKY+5CptLr3buXA10h" +
    "WqTkF7H6RfoRqXQeogmMHfpftf6z" +
    "Mv1LyBUgia7za6ZEzOJBOztyvhjL" + 
    "742iU/TpPSEDhm2SNKLijfUppn1U" +
    "aNvv4w==  )"
  def test_dnskey_from_string
    dnskey = Dnsruby::RR.create(INPUT)
    assert_equal(3, dnskey.protocol)
    assert_equal(256, dnskey.flags)
    assert_equal(Dnsruby::Algorithms::RSASHA1, dnskey.algorithm)
    assert_equal(Dnsruby::RR::DNSKEY::ZONE_KEY, dnskey.flags & Dnsruby::RR::DNSKEY::ZONE_KEY)
    assert_equal(0, dnskey.flags & Dnsruby::RR::DNSKEY::SEP_KEY)
    
    dnskey2 = Dnsruby::RR.create(dnskey.to_s)
    assert(dnskey2.to_s == dnskey.to_s, "#{dnskey.to_s} not equal to \n#{dnskey2.to_s}")
  end

  def test_dnskey_from_data
    dnskey = Dnsruby::RR.create(INPUT)
    m = Dnsruby::Message.new
    m.add_additional(dnskey)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    dnskey3 = m2.additional()[0]
    assert_equal(dnskey.to_s, dnskey3.to_s)
  end
  
  def test_bad_values
    dnskey = Dnsruby::RR.create(INPUT)
    begin
      dnskey.protocol=4
      fail()
    rescue Dnsruby::DecodeError
    end
    begin
      dnskey.flags=4
      fail()
    rescue Dnsruby::DecodeError
    end
    dnskey.flags=256
    dnskey.flags=257
    dnskey.flags=1
    dnskey.protocol=3
     
  end
end