require_relative 'spec_helper'

# Tests for the SVCB (type 64) and HTTPS (type 65) resource records, RFC 9460.
class TestSVCB < Minitest::Test

  include Dnsruby

  # Encodes just the RDATA of an RR to a hex string.
  def rdata_hex(rr)
    enc = Dnsruby::MessageEncoder.new
    rr.encode_rdata(enc)
    enc.to_s.unpack1('H*')
  end

  # Builds an RR from the RDATA half of its presentation format.
  def svcb(rdata, type = 'SVCB')
    RR.create("example.com. 3600 IN #{type} #{rdata}")
  end

  # Builds an RR from its RDATA in wire-format hex.
  def decode(hex, type = RR::IN::SVCB)
    type.decode_rdata(Dnsruby::MessageDecoder.new([hex].pack('H*')))
  end

  # Asserts every case raises DecodeError. A Hash labels its cases for the
  # failure message; an Array labels each case with itself.
  def assert_all_rejected(cases)
    cases = cases.to_h { |input| [input, input] } unless cases.is_a?(Hash)
    cases.each { |label, input| assert_raises(Dnsruby::DecodeError, label.to_s) { yield(input) } }
  end

  # Round-trips an RR through a Message and asserts wire and presentation equality.
  def assert_roundtrip(rr)
    m = Dnsruby::Message.new
    m.add_additional(rr)
    m2 = Dnsruby::Message.decode(m.encode)
    rr2 = m2.additional[0]
    assert_equal(rr, rr2, 'record should survive encode/decode')
    assert_equal(rr.rdata_to_string, rr2.rdata_to_string, 'presentation should survive encode/decode')
    rr2
  end

  # HTTPS shares SVCB's whole implementation by subclassing it.
  def test_types_registered
    assert_equal(64, Types::SVCB)
    assert_equal(65, Types::HTTPS)
    assert_equal('SVCB',  Types.new(64).string)
    assert_equal('HTTPS', Types.new(65).string)
    assert(RR::IN::HTTPS < RR::SVCB)
    assert_equal(RR::IN::HTTPS, svcb('1 .', 'HTTPS').class)
  end

  def test_basic_parse
    rr = RR.create('crypto.cloudflare.com. 300 IN HTTPS 1 . alpn="h2,h3" ipv4hint=162.159.135.79')
    assert_instance_of(RR::IN::HTTPS, rr)
    assert_equal(Types::HTTPS, rr.type)
    assert_equal(1, rr.priority)
    assert_equal('.', rr.target.to_s(true))
    assert_equal(%w[h2 h3].join(','), rr.params_to_hash['alpn'])
    assert_equal('162.159.135.79', rr.params_to_hash['ipv4hint'])
    assert_roundtrip(rr)
  end

  def test_alias_mode
    rr = svcb('0 foo.example.com.')
    assert_equal(Types::SVCB, rr.type)
    assert_equal(0, rr.priority)
    assert_equal('foo.example.com.', rr.target.to_s(true))
    assert_empty(rr.params)
    assert_roundtrip(rr)

    # RFC 9460 sec 2.5.1: a "." TargetName in AliasMode means the service does
    # not exist, which is a meaningful record rather than one to reject.
    root = svcb('0 .', 'HTTPS')
    assert_equal('0 .', root.rdata_to_string)
    assert_roundtrip(root)
  end

  # RFC 9460 sec 2.4.3 calls a ServiceMode RR self-consistent when its SvcParams
  # meet each other's requirements. Sec 7.1.1 gives one of the two: alpn must
  # accompany no-default-alpn. The other, that mandatory name only keys the
  # record carries (sec 8), is the "mandatory key absent" case in the two
  # rejection tables below.
  def test_no_default_alpn_requires_alpn
    assert_raises(Dnsruby::DecodeError) { svcb('1 . no-default-alpn') }
    # And on the wire: key 2 present, with no alpn.
    assert_raises(Dnsruby::DecodeError) { decode('000100' '0002' '0000') }

    rr = svcb('1 . alpn=h2 no-default-alpn')
    assert_equal('1 . alpn=h2 no-default-alpn', rr.rdata_to_string)
    assert_roundtrip(rr)
  end

  # sec 2.4.2: "In AliasMode, recipients MUST ignore any SvcParams that are
  # present" -- ignore, so they stay on the record rather than being dropped or
  # rejected, and the sec 2.4.3 rules above do not apply at priority 0. The
  # sec 8 rules about the mandatory value itself still do.
  def test_alias_mode_ignores_svcparams
    ['0 foo.example.com. alpn=h2',
     '0 foo.example.com. mandatory=alpn',
     '0 foo.example.com. no-default-alpn'].each do |rdata|
      rr = svcb(rdata)
      assert_equal(rdata, rr.rdata_to_string)
      assert_roundtrip(rr)
    end

    assert_all_rejected(['0 foo.example.com. mandatory=mandatory',
                         '0 foo.example.com. mandatory=alpn,alpn alpn=h2']) { |r| svcb(r) }
  end

  # RFC 6840 sec 5.1: a TargetName is not downcased for DNSSEC. Decoded from the
  # wire, because Name.create lowercases a presentation string.
  def test_targetname_case_preserved_in_canonical_encoding
    # priority 0, TargetName "Foo.Example.COM." with mixed case.
    mixed_case_rdata = '000003466f6f074578616d706c6503434f4d00'
    rr = decode(mixed_case_rdata)
    assert_equal(%w[Foo Example COM], rr.target.to_a.map(&:to_s))

    enc = Dnsruby::MessageEncoder.new
    rr.encode_rdata(enc, true) # canonical
    assert_equal(mixed_case_rdata, enc.to_s.unpack1('H*'))
  end

  # RFC 9460 sec 2.2: the TargetName MUST NOT be compressed. The owner name here
  # ends in the same two labels, so a compressing encoder would write a pointer
  # to it and still decode correctly, which is why this counts octets rather
  # than round-tripping.
  def test_targetname_not_compressed
    m = Dnsruby::Message.new
    m.add_answer(svcb('0 foo.example.com.'))
    # RDLENGTH=19, SvcPriority=0, then the TargetName in full. Compressed, the
    # tail would be RDLENGTH=8 ... 03666f6f c00c.
    assert_equal('0013' '0000' '03666f6f076578616d706c6503636f6d00',
                 m.encode[-21..-1].unpack1('H*'))
  end

  # RFC 9460 Appendix D wire-format test vectors, in the appendix's own order and
  # labelled with its figure numbers: Figure 2 is the whole of D.1 and Figures 3
  # to 9 are D.2. Figure 10 prints one record in two presentation formats, so it
  # needs a comparison rather than a table entry: test_escaped_alpn_value has it.
  def test_rfc9460_wire_vectors
    {
      # Figure 2: AliasMode
      'example.com. 3600 IN HTTPS 0 foo.example.com.' =>
        '000003666f6f076578616d706c6503636f6d00',
      # Figure 3: TargetName is "."
      'example.com. 3600 IN SVCB 1 .' =>
        '000100',
      # Figure 4: specifies a port
      'example.com. 3600 IN SVCB 16 foo.example.com. port=53' =>
        '001003666f6f076578616d706c6503636f6d00000300020035',
      # Figure 5: a generic key and unquoted value
      'example.com. 7200 IN SVCB 1 foo.example.com. key667=hello' =>
        '0001' '03666f6f076578616d706c6503636f6d00' '029b' '0005' '68656c6c6f',
      # Figure 6: a generic key and quoted value with a decimal escape
      'example.com. 7200 IN SVCB 1 foo.example.com. key667="hello\210qoo"' =>
        '0001' '03666f6f076578616d706c6503636f6d00' '029b' '0009' '68656c6c6fd2716f6f',
      # Figure 7: two quoted IPv6 hints
      'example.com. 7200 IN SVCB 1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"' =>
        '0001' '03666f6f076578616d706c6503636f6d00' '0006' '0020' \
        '20010db8000000000000000000000001' '20010db8000000000000000000530001',
      # Figure 8: an IPv6 hint using the embedded IPv4 syntax
      'example.com. 7200 IN SVCB 1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"' =>
        '0001' '076578616d706c6503636f6d00' '0006' '0010' \
        '20010db80122034400000000c0000221',
      # Figure 9: SvcParamKey ordering is arbitrary in presentation format but
      # sorted in wire format
      'example.com. 7200 IN SVCB 16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1' =>
        '001003666f6f076578616d706c65036f7267000000000400010004000100090268320568332d313900040004c0000201',
    }.each do |text, expected_hex|
      rr = RR.create(text)
      assert_equal(expected_hex, rdata_hex(rr), "wire format mismatch for: #{text}")
      assert_roundtrip(rr)
    end
  end

  def test_all_known_params
    rr = RR.create('example.com. 3600 IN SVCB 1 svc.example.net. ' \
                   'mandatory=alpn,ipv4hint alpn=h2,h3 no-default-alpn port=8443 ' \
                   'ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 ech=Zm9vYmFy')
    params = rr.params_to_hash
    assert_equal('alpn,ipv4hint', params['mandatory'])
    assert_equal('h2,h3', params['alpn'])
    assert_equal('', rr.params[2], 'no-default-alpn must be stored, value-less')
    assert_nil(params['no-default-alpn'])
    assert_equal('8443', params['port'])
    assert_equal('192.0.2.1,192.0.2.2', params['ipv4hint'])
    assert_equal('Zm9vYmFy', params['ech'])
    assert_roundtrip(rr)
  end

  # RFC 9460 sec 2.2: SvcParams are written in increasing key order, which is
  # numeric, so mandatory(0) alpn(1) port(3) rather than anything alphabetical.
  def test_params_sorted_on_output
    rr = svcb('1 . port=443 alpn=h2 mandatory=alpn', 'HTTPS')
    assert_equal('1 . mandatory=alpn alpn=h2 port=443', rr.rdata_to_string)
  end

  # A literal comma and backslash within an ALPN id must survive; both reach the
  # zone file doubled. RFC 9460 Appendix D.2 Figure 10 prints the record twice,
  # quoted and unquoted, so both spellings must give the same wire value.
  def test_escaped_alpn_value
    rr, unquoted = ['alpn="f\\\\\\\\oo\\\\,bar,h2"',
                    'alpn=f\\\\\\092oo\\092,bar,h2'].map do |param|
      RR.create("example.com. 7200 IN SVCB 16 foo.example.org. #{param}")
    end
    # Wire: [8]"f\oo,bar" [2]"h2"
    assert_equal('08665c6f6f2c626172026832', rr.params[1].unpack1('H*'))
    assert_equal(rr.params, unquoted.params, 'the RFC prints these as one record')
    rr2 = assert_roundtrip(rr)
    # The presentation of rr2 must re-parse to the same wire value.
    rr3 = RR.create("example.com. IN SVCB #{rr2.rdata_to_string}")
    assert_equal(rr.params, rr3.params)
  end

  # The RFC 9460 Appendix A example of "decoding of value-lists happens after
  # character-string decoding": two spellings it states are equivalent.
  def test_value_list_decoded_after_char_string
    quoted, unquoted = ['alpn="part1,part2,part3\\\\,part4\\\\\\\\"',
                        'alpn=part1\\,\\p\\a\\r\\t2\\044part3\\092,part4\\092\\\\'].map do |param|
      RR.create("example.com. 7200 IN SVCB 1 . #{param}")
    end
    assert_equal('0570617274310570617274320c70617274332c70617274345c',
                 quoted.params[1].unpack1('H*'))
    assert_equal(quoted.params, unquoted.params, 'the RFC states these spellings are equivalent')
    # The emitter must write back at the same depth it read.
    assert_equal('1 . alpn=part1,part2,part3\\\\,part4\\\\\\\\', quoted.rdata_to_string)
  end

  # RFC 9461 sec 5 makes dohpath a UTF-8 URI Template, so a value can be
  # multibyte, and every wire length is an octet count.
  def test_multibyte_values_encode_as_octets
    { 'dohpath=/é{?dns}' => [7,   '2fc3a97b3f646e737d'],
      'alpn=hé2'         => [1,   '0468c3a932'],         # [4]"h\xC3\xA92"
      'key667="é\210q"'  => [667, 'c3a9d271'],
    }.each do |param, (num, hex)|
      rr = svcb("1 . #{param}")
      assert_equal(hex, rr.params[num].unpack1('H*'), param)
      assert_roundtrip(rr)
    end
  end

  # The emitter uses numeric escapes for whitespace and characters with
  # lexical meaning in the unquoted presentation form it produces.
  def test_presentation_escaping
    { # dohpath = /a()o
      '00010000070005' + '2f6128296f'     => '1 . dohpath=/a\040\041o',
      # dohpath = /a" né
      '00010000070007' + '2f6122206ec3a9' => '1 . dohpath=/a\034\032n\195\169',
      # alpn = "a b", key667 = "x;y"
      '000100' + '0001' + '0004' + '03612062' + '029b' + '0003' + '783b79' =>
        '1 . alpn=a\032b key667=x\059y',
    }.each do |hex, presentation|
      rr = decode(hex, RR::IN::HTTPS)
      assert_equal(presentation, rr.rdata_to_string)

      rr2 = svcb(rr.rdata_to_string, 'HTTPS')
      assert_equal(rr.params, rr2.params, presentation)
    end
  end

  # The literal escape another implementation may emit is equally valid, and
  # SvcParamKeys are case-insensitive in both forms.
  def test_alternative_presentation_spellings
    { '1 . alpn=a\ b key667=x\"y' => '1 . alpn=a\032b key667=x\034y',
      '1 . ALPN=h2 KEY667=hi'     => '1 . alpn=h2 key667=hi',
    }.each do |rdata, expected|
      assert_equal(expected, svcb(rdata).rdata_to_string)
    end
  end

  def test_parentheses_are_data_when_quoted_or_escaped
    {
      'key667="a(b)c"'     => 'a(b)c',
      'key667="a\(b\)c"'   => 'a(b)c',
      'key667=a\(b\)c'     => 'a(b)c',
      'key667=a\040b\041c' => 'a(b)c',
      'key667="a\("'       => 'a(',
      'key667=a\)'         => 'a)',
      'key667="a\"(b)c"'  => 'a"(b)c',
      'key667="a;(b)c"'    => 'a;(b)c',
    }.each do |param, expected|
      %w[SVCB HTTPS].each do |type|
        rr = svcb("(1 . #{param}) ; comment with an unmatched (", type)
        assert_equal(expected, rr.params[667], "#{type} #{param}")
        assert_roundtrip(rr)
      end
    end
  end

  # A \DDD escape stands for a single octet, so 255 is as high as it can reach.
  def test_ddd_escape_octet_boundary
    rr = svcb('1 . key667="\000\255"')
    assert_equal('00ff', rr.params[667].unpack1('H*'))
    assert_equal('1 . key667=\000\255', rr.rdata_to_string)
    assert_roundtrip(rr)
  end

  # A SvcParamValue must be stored as octets, or a multibyte one raises
  # Encoding::CompatibilityError out of Message#encode.
  def test_from_hash_stores_octets
    rr = RR.create(name: 'example.com.', type: Types::HTTPS, ttl: 3600, priority: 1, target: '.',
                   params: { alpn: 'hé2', dohpath: '/é{?dns}', key667: 'é' })
    rr.params.each do |num, value|
      assert_equal(Encoding::BINARY, value.encoding, "key #{num} must hold octets")
    end
    assert_equal(9, rr.params[7].bytesize)
    assert_roundtrip(rr)
  end

  # A hash value is presentation format, the same text a zone file carries after
  # the "=", so the two constructors must agree.
  def test_from_hash_matches_from_string
    { 'alpn=h2,h3 port=443'          => { alpn: 'h2,h3', port: 443 },
      'dohpath=/é{?dns}'             => { dohpath: '/é{?dns}' },
      'key667=é'                     => { key667: 'é' },
      'key667="a\032b" alpn=h2,h\,3' => { key667: '"a\032b"', alpn: 'h2,h\,3' },
      'key1=\002h2 key3=\001\187' => { key1: '\002h2', key3: '\001\187' },
    }.each do |rdata, params|
      from_string = svcb("1 . #{rdata}", 'HTTPS')
      from_hash   = RR.create(name: 'example.com.', type: Types::HTTPS, ttl: 3600,
                              priority: 1, target: '.', params: params)
      assert_equal(from_string, from_hash, rdata)
      assert_equal(from_string.rdata_to_string, from_hash.rdata_to_string, rdata)
    end
  end

  # params_to_hash emits presentation format, which is exactly what from_hash
  # accepts.
  def test_params_to_hash_round_trips_through_from_hash
    # key667 holds one of every octet the emitter escapes: space, semicolon,
    # quote, both parens, backslash, comma, a multibyte pair and NUL.
    nasty = [0x61, 0x20, 0x3b, 0x22, 0x28, 0x29, 0x5c, 0x2c, 0xc3, 0xa9, 0x00].pack('C*')
    from_wire = RR::IN::SVCB.decode_rdata(Dnsruby::MessageDecoder.new(
      ['0001' '00' '029b'].pack('H*') + [nasty.bytesize].pack('n') + nasty))
    assert_equal(nasty, from_wire.params[667])

    all_keys = RR.create('example.com. 3600 IN SVCB 1 svc.example.net. ' \
                         'mandatory=alpn,port alpn=h2,h3 no-default-alpn port=8443 ' \
                         'ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 ' \
                         'ech=Zm9vYmFy dohpath=/dns{?dns}')

    [from_wire, all_keys].each do |orig|
      rebuilt = RR.create(name: 'example.com.', type: Types::SVCB, ttl: 3600,
                          priority: orig.priority, target: orig.target.to_s(true),
                          params: orig.params_to_hash)
      # from_wire has no name/type/class, so compare the RDATA only.
      assert_equal(orig.params, rebuilt.params, orig.rdata_to_string)
      assert_equal(orig.rdata_to_string, rebuilt.rdata_to_string)
    end
  end

  # ech carries a base64 ECHConfigList (RFC 9460 sec 5), and Base64.decode64
  # discards anything outside the alphabet rather than failing.
  def test_ech_requires_valid_base64
    assert_all_rejected(
      ['1 . ech=!!!not-base64!!!', # decoded to 6 octets, emitted as "ech=notbase6"
       '1 . ech=Zm9vYmF@',         # single stray character
       '1 . ech=aGk',              # unpadded
       '1 . ech=']                 # an ECHConfigList is length-prefixed, never empty
    ) { |r| svcb(r) }

    rr = svcb('1 . ech=Zm9vYmFy')
    assert_equal('foobar', rr.params[5])
    assert_equal('1 . ech=Zm9vYmFy', rr.rdata_to_string)
    assert_roundtrip(rr)
  end

  # RFC 9461 sec 5 requires a URI Template containing the "dns" variable, so
  # there is no empty dohpath, in any of its three spellings.
  def test_dohpath_requires_a_value
    assert_all_rejected(['1 . dohpath', '1 . dohpath=', '1 . dohpath=""']) { |r| svcb(r, 'HTTPS') }

    rr = svcb('1 . dohpath=/dns{?dns}', 'HTTPS')
    assert_equal('1 . dohpath=/dns{?dns}', rr.rdata_to_string)
    assert_roundtrip(rr)
  end

  # RFC 9540 sec 4: "Both the presentation and wire-format values for the
  # 'ohttp' parameter MUST be empty", so it behaves like no-default-alpn.
  def test_ohttp
    ['1 . ohttp', '1 . ohttp=""'].each do |rdata|
      rr = svcb(rdata, 'HTTPS')
      assert_equal('', rr.params[8])
      assert_nil(rr.params_to_hash['ohttp'])
      assert_equal('1 . ohttp', rr.rdata_to_string)
      assert_roundtrip(rr)
    end

    assert_raises(Dnsruby::DecodeError) { svcb('1 . ohttp=x', 'HTTPS') }
    # And the same on the wire: key 8 with a one-octet value.
    assert_raises(Dnsruby::DecodeError) { decode('000100' '0008' '0001' '61') }
  end

  # RFC 9953 sec 3: length-prefixed segments like alpn, except that zero
  # segments is legal and means the root path.
  def test_docpath
    rr = svcb('1 . docpath=.well-known,core', 'HTTPS')
    assert_equal(['0b2e77656c6c2d6b6e6f776e04636f7265'].pack('H*'), rr.params[10])
    assert_equal('.well-known,core', rr.params_to_hash['docpath'])
    assert_roundtrip(rr)

    # The root path: an empty value, however it is written, goes back out as
    # the standalone key RFC 9953 sec 3.2.1 spells it with.
    ['1 . docpath', '1 . docpath=""', '1 . docpath='].each do |rdata|
      root = svcb(rdata, 'HTTPS')
      assert_equal('', root.params[10], rdata)
      assert_nil(root.params_to_hash['docpath'], rdata)
      assert_equal('1 . docpath', root.rdata_to_string, rdata)
      assert_roundtrip(root)
    end

    # An empty *segment* is still an error -- only the whole list may be empty.
    assert_raises(Dnsruby::DecodeError) { svcb('1 . docpath=a,,b', 'HTTPS') }
    # A zero-length segment on the wire is the same error.
    assert_raises(Dnsruby::DecodeError) { decode('000100' '000a' '0001' '00') }
  end

  # RFC 9460 sec 14.3.2 reserves 65535 as an invalid SvcParamKey. 65534 is
  # the top of the private-use range and stays usable.
  def test_key_65535_reserved
    assert_raises(Dnsruby::DecodeError) { svcb('1 . key65535=a') }
    assert_raises(Dnsruby::DecodeError) { decode('000100' 'ffff' '0001' '61') }

    # A mandatory list naming it. AliasMode has no self-consistency rule to
    # catch the dangling key, so validity is checked on the value itself.
    assert_raises(Dnsruby::DecodeError) { decode('000100' '0000' '0002' 'ffff') }
    assert_raises(Dnsruby::DecodeError) { decode('000000' '0000' '0002' 'ffff') }

    rr = svcb('1 . key65534=a')
    assert_equal('1 . key65534=a', rr.rdata_to_string)
    assert_roundtrip(rr)
  end

  # RFC 9460 sec 2.1 writes the number of an unknown key "without leading
  # zeros", so a padded spelling is not that key by another name. Left accepted,
  # key01 read as alpn and its value was parsed as an ALPN list.
  def test_key_leading_zeros_rejected
    assert_all_rejected(['key01=h2', 'mandatory=key01,alpn alpn=h2']) { |p| svcb("1 . #{p}") }

    # key0 uses generic wire octets for mandatory, so the zero stays legal.
    assert_equal('1 . mandatory=alpn alpn=h2',
                 svcb('1 . key0=\000\001 alpn=h2').rdata_to_string)
  end

  # Numeric syntax carries raw wire octets even for a key with a registered
  # mnemonic. In particular alpn must not acquire a second length prefix, and
  # a port's two binary octets must not be parsed as decimal text.
  def test_numeric_keys_use_generic_wire_values
    {
      'key0=\000\001\000\003 alpn=h2 port=443' => 'mandatory=alpn,port alpn=h2 port=443',
      'key1=\002h2' => 'alpn=h2',
      'KEY1="\002h2"' => 'alpn=h2',
      'key2 alpn=h2' => 'no-default-alpn alpn=h2',
      'key3=\001\187' => 'port=443',
      'key4=\192\000\002\001' => 'ipv4hint=192.0.2.1',
      'key5=foo' => 'ech=Zm9v',
      'key6=\032\001\013\184\000\000\000\000\000\000\000\000\000\000\000\001' => 'ipv6hint=2001:db8::1',
      'key7=/dns{?dns}' => 'dohpath=/dns{?dns}',
      'key8=""' => 'ohttp',
      'key10=\003foo\003bar' => 'docpath=foo,bar',
    }.each do |generic, mnemonic|
      %w[SVCB HTTPS].each do |type|
        rr = svcb("1 . #{generic}", type)
        assert_equal(rdata_hex(svcb("1 . #{mnemonic}", type)), rdata_hex(rr), generic)
        assert_roundtrip(rr)
      end
    end
  end

  def test_numeric_keys_still_validate_wire_values_and_duplicates
    assert_all_rejected([
      'key1=h2', 'key1', 'key3=443', 'key3', 'key2=x alpn=h2',
      'key4=\192\000\002', 'key6=\000',
      'key0=\000\003\000\001 alpn=h2 port=443',
      'key1=\002h2 alpn=h2', 'alpn=h2 key1=\002h2',
    ]) { |params| svcb("1 . #{params}") }
  end

  # RFC 9460 sec 8 puts the mandatory keys in "strictly increasing numeric
  # order" on the wire. Presentation format has no such rule and the encoder
  # sorts, so an unsorted zone-file list is fine.
  def test_mandatory_wire_order
    tail = '0001' '0003' '026832' '0003' '0002' '01bb' # alpn=h2 port=443
    ascending  = '000100' + '0000' + '0004' + '00010003' + tail
    descending = '000100' + '0000' + '0004' + '00030001' + tail

    rr = decode(ascending)
    assert_equal('1 . mandatory=alpn,port alpn=h2 port=443', rr.rdata_to_string)

    assert_raises(Dnsruby::DecodeError) { decode(descending) }

    from_zone = svcb('1 . mandatory=port,alpn alpn=h2 port=443')
    assert_equal(['00010003'].pack('H*'), from_zone.params[0], 'the encoder must sort')
    assert_equal(rr.params, from_zone.params)
  end

  # priority= is a real setter, so it range-checks like the presentation format.
  def test_priority_setter_validates
    rr = svcb('1 .')
    rr.priority = 65535
    assert_equal(65535, rr.priority)
    assert_equal('65535 .', rr.rdata_to_string)

    assert_all_rejected(['65536', 65536, -1, 'abc', nil]) { |bad| rr.priority = bad }
    assert_equal(65535, rr.priority, 'a rejected assignment must not change the record')
  end

  # String#to_i and pack('n') fail silently, turning a typo into a wrong number.
  def test_out_of_range_numeric_fields_rejected
    assert_all_rejected(['1 . port=65536', '1 . port=-1', '1 . port=abc',
                         '65536 .', 'foo.example. 1']) { |r| svcb(r) }
    # 65535 is in range -- the check must not be off by one.
    rr = svcb('65535 . port=65535')
    assert_equal('65535 . port=65535', rr.rdata_to_string)
  end

  # Presentation-format records a parser must reject: all ten of RFC 9460
  # Appendix D.3 (Figure 12 alone lists five value-less keys), empty value-list
  # items, and addresses and escapes that fail underneath as ArgumentError or
  # RangeError. All must surface as DecodeError, or a zone loader rescuing one
  # line at a time dies on the whole file.
  def test_presentation_failures_rejected
    assert_all_rejected(
      'duplicate key'             => '1 foo.example.com. key123=abc key123=def',
      'mandatory with no value'   => '1 foo.example.com. mandatory',
      'alpn with no value'        => '1 foo.example.com. alpn',
      'port with no value'        => '1 foo.example.com. port',
      'ipv4hint with no value'    => '1 foo.example.com. ipv4hint',
      'ipv6hint with no value'    => '1 foo.example.com. ipv6hint',
      'port is not a number'      => '1 foo.example.com. port=NaN',
      'no-default-alpn has value' => '1 foo.example.com. no-default-alpn=abc',
      'mandatory key absent'      => '1 foo.example.com. mandatory=key123',
      'mandatory lists itself'    => '1 foo.example.com. mandatory=mandatory',
      'mandatory lists a dup'     => '1 foo.example.com. mandatory=key123,key123 key123=abc',
      'empty alpn'                => '1 . alpn=',
      'alpn trailing comma'       => '1 . alpn=h2,',
      'alpn leading comma'        => '1 . alpn=,h2',
      'empty mandatory'           => '1 . mandatory=',
      'empty ipv4hint'            => '1 . ipv4hint=',
      'ipv4hint trailing comma'   => '1 . ipv4hint=192.0.2.1,',
      'empty ipv6hint'            => '1 . ipv6hint=',
      'ipv4 octet out of range'   => '1 . ipv4hint=999.1.1.1',
      'ipv4 too short'            => '1 . ipv4hint=1.2.3',
      'second ipv4 invalid'       => '1 . ipv4hint=192.0.2.1,not-an-address',
      'ipv6 is not hex'           => '1 . ipv6hint=zz::1',
      'escape above 255'          => '1 . key667="\256"',
      'escape far above 255'      => '1 . key667="\999"'
    ) { |r| svcb(r) }
  end

  # RFC 1035 sec 5.1 escapes: a backslash must escape something, \DDD is exactly
  # three digits, and an unescaped quote is not character-string data. An
  # unterminated quote must be reported as one, not as an unknown key.
  def test_invalid_escapes_and_quotes_rejected
    assert_all_rejected(
      # Unquoted: inside quotes this escapes the closing quote instead.
      'trailing backslash'        => '1 . key667=abc\\',
      'one-digit escape'          => '1 . key667="\\1"',
      'two-digit escape'          => '1 . key667="\\12"',
      'digits then non-digit'     => '1 . key667="\\12x"',
      'unescaped quote mid-token' => '1 . dohpath=/a"b"c'
    ) { |r| svcb(r) }

    ['1 . key667="abc\\"', '1 . key667="abc', '1 . alpn="h2,h3 port=443'].each do |rdata|
      e = assert_raises(Dnsruby::DecodeError, rdata) { svcb(rdata) }
      assert_match(/unterminated quoted SvcParamValue/, e.message, rdata)
    end

    # The valid neighbours of each case must still work.
    assert_equal('1 . key667=a\\\\\\\\b',
                 svcb('1 . key667="a\\\\\\\\b"').rdata_to_string)
    assert_equal('1 . key667=\\012',
                 svcb('1 . key667="\\012"').rdata_to_string)
    assert_equal('1 . key667=\\034',
                 svcb('1 . key667="\\034"').rdata_to_string)
  end

  # The length prefix is a single octet, so a longer id has no representation.
  def test_oversized_alpn_id_rejected
    assert_raises(Dnsruby::DecodeError) { svcb("1 . alpn=#{'a' * 256}") }
    # 255 octets fits -- the check must not be off by one.
    rr = svcb("1 . alpn=#{'a' * 255}")
    assert_equal(256, rr.params[1].bytesize)
    assert_roundtrip(rr)
  end

  # RFC 2136 sec 2.5.2: "delete an RRset" is the type with class ANY and no
  # RDATA, which is what Update#delete builds, and must encode to a zero RDLENGTH.
  def test_empty_rdata
    rr = RR.create('example.com. 3600 IN SVCB')
    assert_nil(rr.priority)
    assert_empty(rr.params)
    assert_equal('', rr.rdata_to_string)
    # The same record built from a Hash, where the two fields are set separately.
    assert_equal('', RR.create(name: 'example.com.', type: Types::SVCB).rdata_to_string)

    update = Dnsruby::Update.new('example.com.')
    deleted = update.delete('www.example.com.', 'SVCB')
    assert_equal(Dnsruby::Classes.ANY, deleted.klass)
    encoder = Dnsruby::MessageEncoder.new
    encoder.put_rr(deleted)
    # ... TYPE=SVCB(64) CLASS=ANY(255) TTL=0 RDLENGTH=0, and nothing after it.
    assert_equal('0040' '00ff' '00000000' '0000', encoder.to_s[-10..-1].unpack1('H*'))

    # And the whole message must survive the round trip a resolver puts it through.
    decoded = Dnsruby::Message.decode(update.encode).authority.first
    assert_equal(Types::SVCB, decoded.type)
    assert_nil(decoded.target)
    assert_empty(decoded.params)
  end

  def test_other_dns_classes_preserve_opaque_rdata_and_class_identity
    [64, 65].each do |type|
      [Classes::CH, Classes::HS, 65_280].each do |klass|
        ['ff', '000100'].each do |hex|
          rr = RR.create("example.com. 60 CLASS#{klass} TYPE#{type} \\# #{hex.length / 2} #{hex}")
          assert_kind_of(RR::Generic, rr)
          assert_equal(klass, rr.class::ClassValue)
          assert_same(rr.class, RR.get_class(type, klass))
          assert_equal(hex, rdata_hex(rr))
          assert_equal(rr, rr.clone)
          assert_equal(rr.hash, rr.clone.hash)
          assert_equal(rr, RR.create(rr.to_s))
        end

        # An unknown format can also have empty RDATA; the IN constraints
        # must not be imposed on it during decoding or encoding.
        empty = RR.new_from_data('example.com.', type, klass, 60, 0, ''.b, 0)
        assert_kind_of(RR::Generic, empty)
        assert_equal('', rdata_hex(empty))
        assert_equal(empty, empty.clone)
      end
    end
  end

  def test_update_pseudo_classes_keep_svcb_and_https_codecs
    %w[SVCB HTTPS].each do |type|
      update = Dnsruby::Update.new('example.com.')
      present = update.present('www.example.com.', type)
      absent = update.absent('www.example.com.', type)
      delete_set = update.delete('www.example.com.', type)
      delete_record = update.delete('www.example.com.', type, '1 . alpn=h2')
      [present, absent, delete_set].each do |rr|
        assert_kind_of(RR::SVCB, rr)
        assert_equal('', rdata_hex(rr))
      end
      assert_equal(Classes::ANY, present.klass)
      assert_equal(Classes::NONE, absent.klass)
      assert_equal(Classes::ANY, delete_set.klass)
      assert_equal(Classes::NONE, delete_record.klass)
      assert_equal('1 . alpn=h2', delete_record.rdata_to_string)

      decoded = Dnsruby::Message.decode(update.encode)
      original_records = update.answer + update.authority
      decoded_records = decoded.answer + decoded.authority
      original_records.zip(decoded_records).each do |rr, copy|
        assert_same(rr.class, copy.class)
        assert_equal(rr.klass, copy.klass)
        assert_equal(rdata_hex(rr), rdata_hex(copy))
      end
      assert_equal(update.encode, decoded.encode)

      # Explicit pseudo-class construction must accept the same presentation
      # format, and keep the requested class on the wire.
      [Classes::ANY, Classes::NONE].each do |klass|
        rr = RR.create("example.com. 0 CLASS#{klass} #{type} 1 . alpn=h2")
        assert_equal(rr, rr.clone)
        assert_equal(rr, RR.create(rr.to_s))
        assert_same(rr.class, RR.get_class(type, klass))
      end
    end
  end

  # Outside that dynamic-update case an incomplete record is a bug, and a Hash
  # sets the two mandatory fields independently, so half a record is buildable.
  def test_incomplete_record_rejected
    [{ priority: 1 }, { target: 'foo.example.com.' }].each do |fields|
      assert_raises(Dnsruby::DecodeError, fields.inspect) do
        RR.create({ name: 'example.com.', type: Types::SVCB }.merge(fields))
      end
    end

    ['1', '0', '1 '].each do |rdata|
      assert_raises(Dnsruby::DecodeError, rdata.inspect) do
        svcb(rdata)
      end
    end

    # An empty record is legal to hold, but only the update classes may encode it.
    ['example.com. 3600 IN SVCB', 'example.com. 3600 IN HTTPS'].each do |str|
      rr = RR.create(str)
      assert_raises(Dnsruby::EncodeError, str) { rr.encode_rdata(Dnsruby::MessageEncoder.new) }
    end

    rr = svcb('1 . alpn=h2')
    rr.target = nil
    assert_raises(Dnsruby::EncodeError) { rr.encode_rdata(Dnsruby::MessageEncoder.new) }
    # And it has no presentation format either, rather than raising ArgumentError.
    assert_equal('', rr.rdata_to_string)
  end

  # A malformed value off the wire would be truncated or padded and re-encode to
  # the same bad octets, so it is rejected on the way in.
  def test_decode_rejects_malformed_rdata
    {
      'ech, empty'             => '000100' + '0005' + '0000',
      'dohpath, empty'         => '000100' + '0007' + '0000',
      'port, 4 octets'         => '000100' + '0003' + '0004' + '000001bb',
      'ipv4hint, 3 octets'     => '000100' + '0004' + '0003' + 'c00002',
      'ipv6hint, 15 octets'    => '000100' + '0006' + '000f' + '20010db80000000000000000000000',
      'alpn id overruns'       => '000100' + '0001' + '0003' + '036831',
      'alpn zero-length id'    => '000100' + '0001' + '0001' + '00',
      'mandatory odd length'   => '000100' + '0000' + '0003' + '000101',
      'no-default-alpn, value' => '000100' + '0002' + '0003' + '616263',
      'mandatory lists itself' => '000100' + '0000' + '0002' + '0000',
      'mandatory key absent'   => '000100' + '0000' + '0002' + '0003',
      # mandatory=[port,port], with a port param present
      'mandatory lists a dup'  => '000100' + '0000' + '0004' + '00030003' +
                                             '0003' + '0002' + '01bb',
      # key 3 (port) before key 1 (alpn): SvcParams must strictly increase
      'params out of order'    => '000100' + '0003' + '0002' + '01bb' +
                                             '0001' + '0003' + '026832',
    }.each do |label, hex|
      assert_raises(Dnsruby::DecodeError, label) do
        decode(hex)
      end
    end
  end

  # Message.decode rejects a SvcParamValue length past the end of the RDATA at
  # the RDLENGTH boundary; the RFC 3597 "\# len hex" form decodes RDATA alone.
  def test_decode_rejects_truncated_svcparamvalue
    {
      'dohpath, 3 of 10 octets' => '000100' + '0007' + '000a' + '616263',
      'ech, 3 of 4 octets'      => '000100' + '0005' + '0004' + 'abcdef',
      'alpn, no value at all'   => '000100' + '0001' + '0003',
    }.each do |label, hex|
      assert_raises(Dnsruby::DecodeError, label) { decode(hex) }
      assert_raises(Dnsruby::DecodeError, label) do
        RR.create("example.com. 3600 IN SVCB \\# #{hex.length / 2} #{hex}")
      end
    end
  end

  # params is public, so a value can reach the decoder without the .b every
  # constructor applies, which is why the length-prefixed decoders count
  # octets. With String#[] this decoded to ["\xC3\xA9\x02", "2"].
  def test_length_prefixed_decode_counts_octets
    rr = svcb('1 .')
    # [2]"\xC3\xA9" [2]"h2"
    rr.params[1] = "\x02\xc3\xa9\x02h2"
    assert_equal(6, rr.params[1].bytesize)
    assert_equal(5, rr.params[1].length, 'the point of the test is that these differ')
    assert_equal('1 . alpn=\195\169,h2', rr.rdata_to_string)
  end

  # Same trigger as above, for the fixed-width address hints. Splitting these in
  # characters dropped the trailing address of each pair.
  def test_address_hint_decode_counts_octets
    rr = svcb('1 .')

    rr.params[4] = "\xc3\xa9\x01\x02\x03\x04\x05\x06"
    assert_equal(8, rr.params[4].bytesize)
    assert_equal(7, rr.params[4].length, 'the point of the test is that these differ')
    assert_equal('1 . ipv4hint=195.169.1.2,3.4.5.6', rr.rdata_to_string)

    rr.params.delete(4)
    rr.params[6] = "\xc3\xa9" + "\x00" * 14 + "\x20\x01\x0d\xb8" + "\x00" * 12
    assert_equal(32, rr.params[6].bytesize)
    assert_equal(31, rr.params[6].length, 'the point of the test is that these differ')
    assert_equal('1 . ipv6hint=c3a9::,2001:db8::', rr.rdata_to_string)
  end
end
