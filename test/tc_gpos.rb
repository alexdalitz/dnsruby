require_relative 'spec_helper'

require_relative '../lib/dnsruby/resource/GPOS.rb'

include Dnsruby


class TestGPOS < Minitest::Test

  EXAMPLE_LONGITUDE  = '10.0'
  EXAMPLE_LATITUDE   = '20.0'
  EXAMPLE_ALTITUDE   = '30.0'
  EXAMPLE_HOSTNAME   = 'a.dnsruby.com'
  EXAMPLE_TTL        = 3 * 60 * 60  # 10,800 seconds, or 3 hours
  EXAMPLE_GPOS_HASH  = {
      name:       EXAMPLE_HOSTNAME,
      type:       Types::GPOS,
      ttl:        EXAMPLE_TTL,
      longitude:  EXAMPLE_LONGITUDE,
      latitude:   EXAMPLE_LATITUDE,
      altitude:   EXAMPLE_ALTITUDE,
  }

  def gpos_from_response

    # query = Message.new(EXAMPLE_HOSTNAME, 'GPOS')
    # query_binary = "E0\u0000\u0000\u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0000\u0001a\adnsruby\u0003com\u0000\u0000\e\u0000\u0001"
    # response, _error = Resolver.new('127.0.0.1').query_raw(query)

    response_binary = "E0\x84\x80\x00\x01\x00\x01\x00\x01\x00\x01\x01a\adnsruby\x03com\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\x00*0\x00\x0F\x0410.0\x0420.0\x0430.0\xC0\x0E\x00\x02\x00\x01\x00\x00*0\x00\x06\x03ns1\xC0\x0E\xC0F\x00\x01\x00\x01\x00\x00*0\x00\x04\x7F\x00\x00\x01"
    response = Message.decode(response_binary)


    # response_binary = "\xE7\x01\x85\x90\x00\x01\x00\x01\x00\x01\x00\x01\x01g\adnsruby\x03com" +
    #     "\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\t:\x80\x00\x0F\x0420.0\x0430.0\x0410.0" +
    #     "\xC0\x0E\x00\x02\x00\x01\x00\t:\x80\x00\x05\x02ns\xC0\x0E\xC0F\x00\x01\x00\x01\x00" +
    #     "\t:\x80\x00\x04\xC0\xA8\x01\n"; nil
    #
    # response = Message.decode(response_binary)

    response.answer[0]
  end


  def gpos_from_hash
    RR.new_from_hash(EXAMPLE_GPOS_HASH)
  end

  def gpos_from_string
    RR.create('a.dnsruby.com.	10800	IN	GPOS	10.0 20.0 30.0')
  end

  def gpos_from_array
    RR.create([])
  end

  def test_answer
    # answer = RESPONSE.answer[0]
    answer = gpos_from_response
    puts answer
    assert answer.is_a?(RR::GPOS), "Expected RR::GPOS but got #{answer}"
    assert_equal(EXAMPLE_LONGITUDE, answer.longitude)
    assert_equal(EXAMPLE_LATITUDE, answer.latitude)
    assert_equal(EXAMPLE_ALTITUDE, answer.altitude)
    assert_equal(EXAMPLE_TTL, answer.ttl)
  end


  def test_a
    m = Message.new('techhumans.com')
    r = Resolver.new
    p, e = r.send_message(m)
puts 1
    ans = p.answer[0]
puts 2
    puts; puts "Answer:"; puts ans; puts
puts 3
    puts "Answer rdata is: #{ans.rdata}"
    # require 'pry'; binding.pry

    # ans_from_string = RR.create('techhumans.com.	14271	IN	A	69.89.31.97')
    puts 'about to create A from hash:'
    ans_from_hash = RR.create(
        name: EXAMPLE_HOSTNAME,
        type: RR::A,
        ttl: EXAMPLE_TTL,
        address: '69.89.31.97')
    puts "Answer from hash rdata is: #{ans_from_hash.rdata}"

  end
  def test_equals
    assert_equal(gpos_from_hash.rdata, gpos_from_response.rdata)
    assert_equal(gpos_from_hash, gpos_from_response)
  end

  # def test_hash # ?
  #   expected = gpos_built_for_comparison
  #   actual = gpos_from_response
  #
  #   require 'pp'
  #   puts "\n\n"
  #   puts "expected:"; pp expected
  #   puts "\n\nactual:"; pp actual; puts "\n\n"
  #   puts "classes are: #{expected.class}, #{actual.class}"
  #   assert_equal(expected.hash, actual.hash)
  # end

  # should be: <owner> <ttl> <class> GPOS <longitude> <latitude> <altitude>
  def test_to_s
    actual = gpos_from_response.to_s.split
    expected = %w(a.dnsruby.com.  10800  IN  GPOS  10.0  20.0  30.0)
    assert_equal(expected, actual)
  end

  def test_creation_methods
    # gpos_from_hash =
  end

end

