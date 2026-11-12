require_relative 'spec_helper'
require 'stringio'

class TestRecordRegressions < Minitest::Test
  include Dnsruby

  def zone(text)
    ZoneReader.new('example.').process_io(StringIO.new(text))
  end

  def rdata(rr)
    MessageEncoder.new { |encoder| rr.encode_rdata(encoder) }.to_s
  end

  def wire_rr(type, klass, data)
    # Build this without the encoder under test so malformed RDATA can reach
    # both decoding entry points, including their actual class handling.
    "\0".b + [type, klass, 0, data.bytesize].pack('nnNn') + data
  end

  def test_txt_layout_newlines_do_not_become_data
    ['txt 60 IN TXT', 'txt IN TXT', 'txt TXT'].each do |prefix|
      rr = zone("#{prefix} (\"one\" ; comment\n \"two\"\n)\n").first
      assert_equal(['one', 'two'], rr.strings, prefix)
      assert_equal('onetwo', rr.data, prefix)
    end
    rr = RR.create("txt.example. 60 IN TXT (\"one\"\n \"two\")")
    assert_equal(['one', 'two'], rr.strings)
  end

  def test_literal_multiline_txt_preserves_whitespace_and_quoted_punctuation
    rr = zone("txt 60 IN TXT (\"one  \n two;(three)\"\n \"four\")\n").first
    assert_equal(["one  \n two;(three)", 'four'], rr.strings)
    copy = MessageDecoder.new(wire_rr(16, 1, rdata(rr))).get_rr
    assert_equal(rr.strings, copy.strings)
  end

  def test_manual_continuation_lines_without_terminating_newlines
    reader = ZoneReader.new('example.')
    assert_nil(reader.process_line('txt 60 IN TXT ("one"'))
    line = reader.process_line('"two")')
    assert_equal(['one', 'two'], RR.create(line).strings)
  end

  def test_known_and_unknown_rfc3597_layout_newlines
    {'TYPE65400' => '01020304', 'A' => 'c0000201'}.each do |type, hex|
      record = "name 60 IN #{type} ( \\# 4 #{hex[0, 4]}\n #{hex[4, 4]} )\n"
      assert_equal(hex, rdata(zone(record).first).unpack1('H*'), type)
      assert_equal(hex, rdata(RR.create(record)).unpack1('H*'), type)
    end
  end

  def test_single_quoted_txt_and_spf_keep_literal_punctuation
    %w[TXT SPF TYPE16 TYPE99].each do |type|
      text = "txt 60 IN #{type} ('one(two);three' 'four')"
      assert_equal(['one(two);three', 'four'], RR.create(text).strings, type)
      assert_equal(['one(two);three', 'four'], zone(text).first.strings, type)
      inherited_owner = zone("txt 60 IN #{type} 'first'\n IN #{type} 'two(three)'\n")
      assert_equal(['two(three)'], inherited_owner.last.strings, type)
    end
    assert_equal(["one  \n two(three)"], zone("txt IN TXT ('one  \n two(three)')\n").first.strings)
    assert_equal(['one(two)'], zone("o'clock IN TXT 'one(two)'\n").first.strings)
  end

  def test_apostrophes_are_ordinary_characters_in_other_record_formats
    record = zone("svc IN SVCB (1 o'clock.example. ; comment\n port=443)\n").first
    assert_equal("o'clock.example.", record.target.to_s(true))
    assert_equal('443', record.params_to_hash['port'])
  end

  def test_adjacent_quoted_txt_strings_keep_literal_punctuation
    ["'one''two(three);four'", "\"one\"'two(three);four'",
     "'one'\"two(three);four\""].each do |value|
      %w[TXT SPF].each do |type|
        text = "txt IN #{type} #{value}"
        assert_equal(['one', 'two(three);four'], RR.create(text).strings, text)
        assert_equal(['one', 'two(three);four'], zone(text).first.strings, text)
      end
    end
  end

  def test_grouping_parentheses_touching_the_type_and_header
    ["txt IN TXT('one(two)')", "txt IN(TXT('one(two)'))",
     "txt\\(name IN TXT('one(two)')", "o'clock IN TXT('one(two)')",
     "'host.example IN TXT 'one(two)'"].each do |text|
      assert_equal(['one(two)'], RR.create(text).strings, text)
      assert_equal(['one(two)'], zone(text).first.strings, text)
    end
  end

  def test_non_in_svcb_and_https_zone_records_remain_opaque
    [64, 65].each do |type|
      [Classes::CH, Classes::HS, 65_280].each do |klass|
        rr = zone("name 60 CLASS#{klass} TYPE#{type} \\# 3 000100\n").first
        assert_kind_of(RR::Generic, rr)
        assert_equal(klass, rr.klass)
        assert_equal('000100', rdata(rr).unpack1('H*'))
      end
    end
  end

  def test_svcb_target_must_be_complete_and_uncompressed
    [64, 65].each do |type|
      # Priority only; unterminated label list; truncated label; pointer.
      %w[0001 00010161 00010361 0001c000].each do |hex|
        data = [hex].pack('H*')
        assert_raises(DecodeError, "TYPE#{type} #{hex}") do
          RR.new_from_data('.', type, Classes::IN, 0, data.bytesize, data, 0)
        end
        assert_raises(DecodeError, "TYPE#{type} #{hex}") do
          MessageDecoder.new(wire_rr(type, Classes::IN, data)).get_rr
        end
      end
      data = ['000100'].pack('H*')
      assert_equal('.', MessageDecoder.new(wire_rr(type, Classes::IN, data)).get_rr.target.to_s(true))
    end
  end

  def test_empty_svcb_wire_data_only_decodes_for_update_classes
    [64, 65].each do |type|
      assert_raises(DecodeError) { RR.new_from_data('.', type, Classes::IN, 0, 0, ''.b, 0) }
      assert_raises(DecodeError) { MessageDecoder.new(wire_rr(type, Classes::IN, ''.b)).get_rr }
      [Classes::ANY, Classes::NONE].each do |klass|
        rr = RR.new_from_data('.', type, klass, 0, 0, ''.b, 0)
        assert_equal(klass, rr.klass)
        assert_equal('', rdata(rr))
        copy = MessageDecoder.new(wire_rr(type, klass, ''.b)).get_rr
        assert_equal(klass, copy.klass)
        assert_equal('', rdata(copy))
      end
      # Empty objects used to build UPDATE messages remain constructible.
      assert_nil(RR.create(name: '.', type: type).priority)
    end
  end

  def test_svcb_rejects_oversized_values_at_construction_and_after_mutation
    [64, 65].each do |type|
      assert_raises(DecodeError) do
        RR.create(name: '.', type: type, priority: 1, target: '.', params: {key667: 'x' * 65_536})
      end
      rr = RR.create(name: '.', type: type, priority: 1, target: '.')
      rr.params[667] = 'x' * 65_536
      assert_raises(EncodeError) { rdata(rr) }
    end
  end

  def test_svcb_total_rdata_length_boundary
    rr = RR.create(name: '.', type: 64, priority: 1, target: '.')
    rr.params[667] = 'x' * 65_528 # 2 priority + 1 root + 4 param header.
    bytes = rdata(rr)
    assert_equal(65_535, bytes.bytesize)
    assert_equal(bytes, rdata(MessageDecoder.new(wire_rr(64, 1, bytes)).get_rr))
    rr.params[667] << 'x'
    assert_raises(EncodeError) { rdata(rr) }

    rr.params = {667 => 'x' * 32_764, 668 => 'x' * 32_764}
    assert_raises(EncodeError) { rdata(rr) }
    rr.params = {667 => 'x' * 65_528}
    rr.target = Name.create('a.')
    assert_raises(EncodeError) { rdata(rr) }
  end

  def test_mutated_utf8_svcparam_is_encoded_as_octets
    rr = RR.create(name: '.', type: 64, priority: 1, target: '.')
    rr.params[667] = 'é'
    encoder = MessageEncoder.new { |output| output.put_rr(rr) }
    copy = MessageDecoder.new(encoder.to_s).get_rr
    assert_equal('é'.b, copy.params[667])
    assert_equal(9, rdata(copy).bytesize)
  end

  def test_generic_length16_field_does_not_wrap
    encoder = MessageEncoder.new
    encoder.put_length16 { encoder.put_bytes('x' * 65_535) }
    assert_equal(65_535, encoder.to_s.unpack1('n'))
    assert_raises(EncodeError) do
      encoder = MessageEncoder.new
      encoder.put_length16 { encoder.put_bytes('x' * 65_536) }
    end
    assert_raises(EncodeError) do
      encoder = MessageEncoder.new
      encoder.put_length16 { encoder.put_bytes('é' * 32_768) }
    end
  end

  def test_length16_cannot_extend_a_physical_or_nested_buffer
    decoder = MessageDecoder.new([5].pack('n') + 'abc')
    assert_raises(DecodeError) { decoder.get_length16 { flunk('decoded outside physical buffer') } }
    assert_equal('abc', decoder.get_bytes, 'failed boundary check must restore the enclosing limit')

    # The inner length exceeds its containing item, but not the whole packet.
    decoder = MessageDecoder.new([4, 5].pack('nn') + 'ab' + 'trailer')
    decoder.get_length16 do
      assert_raises(DecodeError) { decoder.get_length16 { flunk('decoded outside nested buffer') } }
      assert_equal('ab', decoder.get_bytes)
    end
    assert_equal('trailer', decoder.get_bytes)
  end

  def test_length16_restores_enclosing_limit_when_the_parser_raises
    decoder = MessageDecoder.new([4, 2].pack('nn') + 'ab' + 'trailer')
    decoder.get_length16 do
      assert_raises(DecodeError) do
        decoder.get_length16 { raise DecodeError, 'malformed nested value' }
      end
      assert_equal('ab', decoder.get_bytes)
    end
    assert_equal('trailer', decoder.get_bytes)
  end

  def test_truncated_svcb_and_https_preserve_partial_header_at_every_byte
    bytes = ['0001000003000201bb'].pack('H*')
    [64, 65].each do |type|
      header = [123, 0x8200, 0, 1, 0, 0].pack('n6')
      complete = header + wire_rr(type, Classes::IN, bytes)
      bytes.bytesize.times do |length|
        truncated = complete.byteslice(0, complete.bytesize - bytes.bytesize + length)
        error = assert_raises(DecodeError, "TYPE#{type} with #{length} RDATA bytes") { Message.decode(truncated) }
        assert(error.partial_message.header.tc)
        assert_equal(123, error.partial_message.header.id)
      end
      assert_equal(bytes, Message.decode(complete).answer.first.rdata)
    end
  end
end
