require 'test/unit'
require 'dnsruby'

class DsTest < Test::Unit::TestCase
  INPUT = "dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A" + 
    "98631FAD1A292118 )"
  include Dnsruby
  def test_ds_from_string
    ds = Dnsruby::RR.create(INPUT)
    assert_equal(60485, ds.key_tag)
    assert_equal(Algorithms.RSASHA1, ds.algorithm)
    assert_equal(1, ds.digest_type)
    assert_equal("2BB183AF5F22588179A53B0A98631FAD1A292118", Base64.encode64(ds.digest).chomp!)
    
    ds2 = Dnsruby::RR.create(ds.to_s)
    assert(ds2.to_s == ds.to_s)
  end

  def test_ds_from_data
    ds = Dnsruby::RR.create(INPUT)
    m = Dnsruby::Message.new
    m.add_additional(ds)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    ds3 = m2.additional()[0]
    assert_equal(ds.to_s, ds3.to_s)
  end
  
  def test_ds_values
    ds = Dnsruby::RR.create(INPUT)
    begin
      ds.digest_type = 2
      fail
    rescue DecodeError
    end
  end
  
end