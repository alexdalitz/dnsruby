# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

class TestName < Minitest::Test

  include Dnsruby

  # Names on either side of the 255-octet wire limit: 249 octets of label text
  # in 5 labels, plus a length octet each and the root's zero octet, is 255.
  AT_LIMIT_NAME = "#{'a' * 63}.#{'b' * 63}.#{'c' * 63}.#{'d' * 59}.e."
  OVER_LIMIT_NAME = "#{'a' * 63}.#{'b' * 63}.#{'c' * 63}.#{'d' * 60}.e."

  def test_label_length
    Name::Label.set_max_length(Name::Label::MaxLabelLength) # Other tests may have changed this
    #  Test max label length = 63
    begin
      Name.create("a.b.12345678901234567890123456789012345678901234567890123456789012345.com")
      assert(false, "Label of more than max=63 allowed")
    rescue ResolvError
    end
  end

  def wire_length(name)
    MessageEncoder.new { |msg| msg.put_name(name, true) }.to_s.length
  end

  # Test max name length=255. The limit is on the wire form, two octets more
  # than the dotted presentation form without its trailing dot.
  def test_name_length
    assert_equal(255, wire_length(Name.create(AT_LIMIT_NAME)))

    error = assert_raises(ResolvError) { Name.create(OVER_LIMIT_NAME) }
    assert_match(/Name length is 256,/, error.message)
  end

  # An oversized name must not reach the wire through Message either, and a
  # name right at the limit must still survive the round trip.
  def test_name_length_in_message
    assert_raises(ResolvError) { Message.new(OVER_LIMIT_NAME, "A") }

    message = Message.new(AT_LIMIT_NAME, "A")
    message.add_answer(RR.create("#{AT_LIMIT_NAME} 3600 IN NS #{AT_LIMIT_NAME}"))
    decoded = Message.decode(message.encode)
    assert_equal(AT_LIMIT_NAME, decoded.question[0].qname.to_s + ".")
    assert_equal(AT_LIMIT_NAME, decoded.answer[0].domainname.to_s + ".")
  end

  def test_deep_backward_compression_chain_is_iterative_and_preserves_position
    wire = "\x07example\x03com\0".b
    target = 0
    8_000.times do
      offset = wire.bytesize
      wire << [0xc000 | target].pack('n')
      target = offset
    end
    wire << "!"
    decoder = MessageDecoder.new(wire)
    decoder.get_bytes(target)
    assert_equal('example.com.', decoder.get_name.to_s(true))
    assert_equal(target + 2, decoder.index)
    assert_equal('!', decoder.get_bytes)
  end

  def test_compressed_names_share_suffixes_and_chain_to_complete_names
    wire = "\x07example\x03com\0".b
    www = wire.bytesize
    wire << "\x03www".b << [0xc000].pack('n')
    wire << "\x04mail".b << [0xc000].pack('n')
    wire << [0xc000 | www].pack('n')
    decoder = MessageDecoder.new(wire)
    assert_equal(['example.com.', 'www.example.com.', 'mail.example.com.', 'www.example.com.'],
      Array.new(4) { decoder.get_name.to_s(true) })
    assert_equal(wire.bytesize, decoder.index)
  end

  def test_compressed_rdata_can_reference_a_name_before_its_length_field
    wire = "\x07example\x03com\0".b + [2, 0xc000].pack('nn') + '!'
    decoder = MessageDecoder.new(wire)
    expected = decoder.get_name
    assert_equal(expected, decoder.get_length16 { decoder.get_name })
    assert_equal('!', decoder.get_bytes)
  end

  def test_compression_rejects_loops_forward_pointers_and_reserved_labels
    malformed = [
      ["\xc0\x00".b, 0],                 # Self pointer.
      ["\xc0\x02\0".b, 0],             # Forward pointer.
      ["\xc0\x02\xc0\x00".b, 2],     # Two-pointer cycle.
      ["\x01a\xc0\x00".b, 0],         # Label followed by a pointer into itself.
      ["\xc0".b, 0],                     # Incomplete pointer.
      ["\x01a".b, 0],                    # Missing root label.
      ["\x02a".b, 0],                    # Truncated label.
      ["\x40".b + 'a' * 64 + "\0", 0],
      ["\x80\0".b, 0],                 # Reserved label types.
      ["\xbf\0".b, 0]
    ]
    malformed.each do |wire, offset|
      decoder = MessageDecoder.new(wire)
      decoder.get_bytes(offset)
      assert_raises(DecodeError, wire.unpack1('H*')) { decoder.get_name }
    end
  end

  def test_expanded_compressed_names_obey_the_wire_length_limit
    encoded = MessageEncoder.new { |encoder| encoder.put_name(Name.create(AT_LIMIT_NAME), true) }.to_s
    decoder = MessageDecoder.new(encoded + [0xc000].pack('n') + "\x01x".b + [0xc000].pack('n'))
    assert_equal(AT_LIMIT_NAME, decoder.get_name.to_s(true))
    assert_equal(AT_LIMIT_NAME, decoder.get_name.to_s(true))
    assert_raises(DecodeError) { decoder.get_name }

    oversized = OVER_LIMIT_NAME.split('.').map { |label| [label.bytesize].pack('C') + label }.join + "\0"
    assert_raises(DecodeError) { MessageDecoder.new(oversized).get_name }
  end

  def test_name_cannot_read_a_root_label_beyond_its_rdata_boundary
    decoder = MessageDecoder.new([2].pack('n') + "\x01a\0".b)
    assert_raises(DecodeError) { decoder.get_length16 { decoder.get_name } }
    assert_equal("\0", decoder.get_bytes)
  end

  def test_absolute
    n = Name.create("example.com")
    assert(!n.absolute?)
    n = Name.create("example.com.")
    assert(n.absolute?)
  end

  def test_wild
    n = Name.create("example.com")
    assert(!n.wild?)
    n = Name.create("*.example.com.")
    assert(n.wild?)
  end

  def test_canonical_ordering
    names = []
    names.push(Name.create("example"))
    names.push(Name.create("a.example"))
    names.push(Name.create("yljkjljk.a.example"))
    names.push(Name.create("Z.a.example"))
    names.push(Name.create("zABC.a.EXAMPLE"))
    names.push(Name.create("z.example"))
    names.push(Name.create("\001.z.example"))
    names.push(Name.create("*.z.example"))
#    names.push(Name.create("\200.z.example"))
    names.push(Name.create(["c8"].pack("H*")+".z.example"))
    names.each_index {|i|
      if (i < (names.length() - 1))
        assert(names[i].canonically_before(names[i+1]))
        assert(!(names[i+1].canonically_before(names[i])))
      end
    }
    assert(Name.create("x.w.example").canonically_before(Name.create("z.w.example")))
    assert(Name.create("x.w.example").canonically_before(Name.create("a.z.w.example")))
  end

  def test_escapes
    n1 = Name.create("\\nall.all.")
    n2 = Name.create("nall.all.")
    assert(n1 == n2, n1.to_s)
  end

  def test_punycode
    [
      [
        "møllerriis.com",
        "xn--mllerriis-l8a.com"
      ],
      [
        "フガフガ。hogehoge.エグザンプル.JP",
        "xn--mcka5jb.hogehoge.xn--ickqs6k2dyb.jp"
      ],
      [
        "フガ#フガ。hogehoge.エグザンプル.JP",
        "xn--#-yeub5nc.hogehoge.xn--ickqs6k2dyb.jp"
      ]
    ].each do |tc|
      assert_equal(Dnsruby::Name.create(tc[0]).to_s, tc[1])
    end
  end
end
