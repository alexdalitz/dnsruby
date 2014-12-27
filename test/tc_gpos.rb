require_relative 'spec_helper'

require_relative '../lib/dnsruby/resource/GPOS.rb'

include Dnsruby

# ";nil" added temporarily for ease of use when pasting into irb/pry.

GPOS_QUERY_BYTES = "\xE7\u0001\u0001 \u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0001\u0001g\adnsruby\u0003com" +
    "\u0000\u0000\e\u0000\u0001\u0000\u0000)\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0000"; nil

GPOS_QUERY = Message.decode(GPOS_QUERY_BYTES); nil

RESP, ERR = Resolver.new('127.0.0.1').query_raw(GPOS_QUERY); nil

RESPONSE_BINARY = "\xE7\x01\x85\x90\x00\x01\x00\x01\x00\x01\x00\x01\x01g\adnsruby\x03com" +
    "\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\t:\x80\x00\x0F\x0420.0\x0430.0\x0410.0" +
    "\xC0\x0E\x00\x02\x00\x01\x00\t:\x80\x00\x05\x02ns\xC0\x0E\xC0F\x00\x01\x00\x01\x00" +
    "\t:\x80\x00\x04\xC0\xA8\x01\n"; nil

RESPONSE = Message.decode(RESPONSE_BINARY); nil


class TestGPOS < Minitest::Test


  def gpos_from_response


    # query_binary = "\xE7\u0001\u0001 \u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0001\u0001g\adnsruby\u0003com" +
    #     "\u0000\u0000\e\u0000\u0001\u0000\u0000)\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0000"
    #
    # query = Message.decode(query_binary)

    # query = Message.new('a.dnsruby.com', 'GPOS')
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


  def gpos_built_for_comparison
    RR.new_from_hash(
        name: 'a.dnsruby.com.',
        type: Types::GPOS,
        ttl: 10800,
        longitude: '10.0',
        latitude: '20.0',
        altitude: '30.0',
    )
  end

  def test_answer
    # answer = RESPONSE.answer[0]
    answer = gpos_from_response
    assert answer.is_a?(RR::GPOS), "Expected RR::GPOS but got #{answer}"
    assert_equal('10.0', answer.longitude)
    assert_equal('20.0', answer.latitude)
    assert_equal('30.0', answer.altitude)
  end


  def test_equals
    assert_equal(gpos_built_for_comparison, gpos_from_response)
  end

  def test_hash # ?
    expected_hash = gpos_built_for_comparison.hash
    actual_hash = gpos_from_response.hash
    assert_equal(expected_hash, actual_hash)
  end

  def test_to_s
    # contains GPOS
    # has long/lat/alt in correct order
    # has TTL, etc.
  end
end

