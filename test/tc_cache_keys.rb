require_relative 'spec_helper'

class TestCacheKeys < Minitest::Test
  include Dnsruby

  def test_numeric_query_spellings_find_the_decoded_response
    cache = Cache.new
    query = Message.new('cache.example.', 'TYPE0001', 'CLASS0001')
    response = Message.decode(query.encode)
    response.header.qr = true
    response.add_answer(RR.create('cache.example. 300 IN A 192.0.2.1'))
    cache.add(response)

    ['A', 'TYPE1', 'TYPE0001', Types.new('TYPE01'), 1].each do |type|
      ['IN', 'CLASS1', 'CLASS0001', Classes.new('CLASS01'), 1].each do |klass|
        found = cache.find('CACHE.example', type, klass)
        refute_nil(found, "#{type}/#{klass}")
        assert(found.cached)
        assert_equal('192.0.2.1', found.answer.first.address.to_s)
      end
    end
    assert_nil(cache.find('cache.example.', 'AAAA', 'IN'))
    assert_nil(cache.find('cache.example.', 'A', 'CH'))
  end

  def test_unknown_numeric_aliases_share_one_cache_entry
    cache = Cache.new
    [['TYPE65001', 'CLASS65000'], ['TYPE065001', 'CLASS065000']].each do |type, klass|
      response = Message.new('cache.example.', type, klass)
      response.add_answer(RR.create('cache.example. 300 CLASS65000 TYPE65001 \\# 1 01'))
      cache.add(response)
    end
    assert_equal(1, cache.length)
    assert_equal("\x01".b, cache.find('cache.example.', 'TYPE0065001', 'CLASS0065000').answer.first.data)
  end
end
