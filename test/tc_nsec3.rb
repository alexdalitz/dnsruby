require 'test/unit'
require 'dnsruby'

class Nsec3Test < Test::Unit::TestCase
  INPUT = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd ( " + 
    "2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG )"
  include Dnsruby
  def test_nsec_from_string
    nsec = Dnsruby::RR.create(INPUT)
#    assert_equal(H("x.y.w.example"), nsec.next_hashed.to_s)
    assert_equal([Types.A, Types.RRSIG], nsec.types)
    assert(nsec.opt_out?)
    assert_equal(12, nsec.iterations)
    assert_equal("aabbccdd", nsec.salt)
    assert_equal(Dnsruby::Nsec3HashAlgorithms.SHA_1, nsec.hash_alg)
    
    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)
  end

  def test_base32
   inputs = [["",""], ["f","CO======"],
     ["fo","CPNG===="], ["foo", "CPNMU==="],
     ["foob", "CPNMUOG="], ["fooba", "CPNMUOJ1"],
     ["foobar", "CPNMUOJ1E8======"]]

    inputs.each {|dec, enc|
      assert(Base32.encode32hex(dec) == enc, "Failed encoding #{dec}")
      assert(Base32.decode32hex(enc) == dec, "Failed decoding #{enc}")
    }
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
  
  def test_nsec_other_stuff
    nsec = Dnsruby::RR.create(INPUT)
#    begin
#      nsec.salt_length=256
#      fail
#    rescue DecodeError
#    end
#    begin
#      nsec.hash_length=256
#      fail
#    rescue DecodeError
#    end
    # Be liberal in what you accept...
#    begin
#      nsec.hash_alg = 8
#      fail
#    rescue DecodeError
#    end
    begin
      nsec.flags = 2
      fail
    rescue DecodeError
    end
  end
  
  def test_nsec_types
    # Test types in last section to 65536.
    #Test no zeros
    nsec = Dnsruby::RR.create(INPUT)
    nsec.add_type(Types.TYPE65534)
    assert(nsec.types.include?(Types.TYPE65534))
    assert(nsec.to_s.include?(Types.TYPE65534.string))
  end

  def test_rfc_examples
    print "IMPLEMENT NSEC3 validation!\n"
    return
  end
end