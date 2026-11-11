
require_relative 'spec_helper'

class ZoneReaderTest < Minitest::Test

  include Dnsruby

  def setup
    @zone_data = <<ZONEDATA
$TTL 3600
; Comment
 ; Comment with whitespace in front
@                   IN SOA    ns1.example.com. hostmaster.example.com. (
                                1993112101
                                10800
                                3600
                                604800
                                7200
                              )
                    IN NS     ns1.example.com.
                    IN NS     ns2.example.com.
                    IN MX     10 mx.example.com.
                    IN TXT    "v=spf1 mx ~all"
www                 IN A      192.0.2.10
                    IN AAAA   2001:DB8::10
ftp.example.com.    IN CNAME  www
db                  IN CNAME  www.example.com.
foo.example.com.    IN CAA    0 issue "ca.example.net; account=230123"
ZONEDATA

    @zone_file = Tempfile.new('zonefile')
    @zone_file << @zone_data
    @zone_file.flush
    @zone_file.rewind
    @reader = Dnsruby::ZoneReader.new("example.com.")
  end

  def teardown
    @zone_file.close
    @zone_file.unlink
  end

  def check_zone_data_is_valid(zone)
    assert_equal(1993112101, zone[0].serial)
    assert_equal("ns1.example.com.", zone[1].rdata)
    assert_equal("ns2.example.com.", zone[2].rdata)
    assert_equal("10 mx.example.com.", zone[3].rdata)
    assert_equal("\"v=spf1 mx ~all\"", zone[4].rdata)
    assert_equal("192.0.2.10", zone[5].rdata)
    assert_equal("2001:DB8::10", zone[6].rdata)
    assert_equal("www.example.com.", zone[7].rdata)
    assert_equal("www.example.com.", zone[8].rdata)
    assert_equal('0 issue "ca.example.net; account=230123"', zone[9].rdata)
  end

  def test_process_file_with_filename
    zone = @reader.process_file(@zone_file.path)
    check_zone_data_is_valid(zone)
  end

  def test_process_file_with_file_object
    zone = @reader.process_file(@zone_file)
    check_zone_data_is_valid(zone)
    assert_equal(false, @zone_file.closed?)
  end

  def test_process_file_with_stringio_object
    stringio = StringIO.new(@zone_data)
    zone = @reader.process_file(stringio)
    check_zone_data_is_valid(zone)
    assert_equal(false, stringio.closed?)
    stringio.close
  end

  # The reader reattaches a quoted tail for every type, so a parenthesis right
  # before a quote must separate it too: the parenthesis is stripped from the
  # line before the quoted text goes back on.
  PAREN_QUOTE_ZONE = <<~ZONEDATA
    $TTL 3600
    caa    IN CAA   0 issue("ca.example.net")
    hinfo  IN HINFO ("cpu" "os")
    txt    IN TXT   ("abc" "def")
  ZONEDATA

  def test_zone_parenthesis_before_quote
    reader = Dnsruby::ZoneReader.new('example.com.')
    caa, hinfo, txt = reader.process_file(StringIO.new(PAREN_QUOTE_ZONE))

    assert_equal('issue', caa.property_tag)
    assert_equal('ca.example.net', caa.property_value)

    assert_equal('cpu', hinfo.cpu)
    assert_equal('os', hinfo.os)

    assert_equal(['abc', 'def'], txt.strings)
  end

  # A backslash escaping the quote abuts it too. RFC 1035 sec 5.1 makes \" a
  # literal quote within an unquoted character-string, so each of these is one
  # string, not two.
  ESCAPED_QUOTE_ZONE = <<~'ZONEDATA'
    $TTL 3600
    lead   IN TXT   \"escaped
    mid    IN TXT   abc\"def
  ZONEDATA

  def test_zone_escaped_quote_not_separated
    reader = Dnsruby::ZoneReader.new('example.com.')
    lead, mid = reader.process_file(StringIO.new(ESCAPED_QUOTE_ZONE))

    assert_equal(['"escaped'], lead.strings)
    assert_equal(['abc"def'], mid.strings)
  end

  # SVCB/HTTPS records carry a TargetName in the middle of the RDATA. The zone
  # reader must resolve relative TargetNames against the origin, while leaving
  # the root (".") and already-absolute names untouched.
  SVCB_ZONE = <<~ZONEDATA
    $TTL 3600
    $ORIGIN example.com.
    @      IN SOA  ns1.example.com. hostmaster.example.com. 1 2 3 4 5
    @      IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1
    alias  IN SVCB  0 svc4.example.com.
    rel    IN SVCB  1 foo alpn=h2
    svc    IN HTTPS 1 svc.example.net. port=8443
  ZONEDATA

  def svcb_zone_records
    reader = Dnsruby::ZoneReader.new('example.com.')
    records = reader.process_file(StringIO.new(SVCB_ZONE))
    records.reject { |rr| rr.type == Types::SOA }
  end

  def test_zone_svcb_https_targets_resolved
    https_root, svcb_alias, svcb_rel, https_svc = svcb_zone_records

    # Root TargetName stays as the root.
    assert_equal(Types::HTTPS, https_root.type)
    assert_equal('.', https_root.target.to_s(true))
    assert_equal('h2,h3', https_root.params_to_hash['alpn'])

    # Absolute AliasMode TargetName is untouched.
    assert_equal(0, svcb_alias.priority)
    assert_equal('svc4.example.com.', svcb_alias.target.to_s(true))

    # Relative TargetName gains the origin.
    assert_equal('foo.example.com.', svcb_rel.target.to_s(true))
    assert_equal('h2', svcb_rel.params_to_hash['alpn'])

    # Absolute TargetName in another zone is untouched.
    assert_equal('svc.example.net.', https_svc.target.to_s(true))
    assert_equal('8443', https_svc.params_to_hash['port'])
  end

  # A HTTPS record spread across several lines with parentheses is valid zone
  # format and must be parsed as a single record.
  MULTILINE_ZONE = <<~ZONEDATA
    $TTL 3600
    $ORIGIN example.com.
    @   IN SOA  ns1.example.com. hostmaster.example.com. 1 2 3 4 5
    @   IN HTTPS ( 1 .  alpn=h2,h3
                   port=443
                   ipv4hint=192.0.2.1 )
  ZONEDATA

  def test_zone_multiline_https
    reader = Dnsruby::ZoneReader.new('example.com.')
    records = reader.process_file(StringIO.new(MULTILINE_ZONE))
    https = records.find { |rr| rr.type == Types::HTTPS }
    refute_nil(https)
    assert_equal(1, https.priority)
    assert_equal('.', https.target.to_s(true))
    assert_equal('h2,h3', https.params_to_hash['alpn'])
    assert_equal('443', https.params_to_hash['port'])
    assert_equal('192.0.2.1', https.params_to_hash['ipv4hint'])
  end

  # RFC 9460 Appendix A: a SvcParamValue may be quoted, and the quotes open
  # mid-token, unlike the quoted RDATA of a TXT record. The ech value also puts
  # base64 padding inside the quotes, and an unquoted param after them.
  QUOTED_SVCB_ZONE = <<~ZONEDATA
    $TTL 3600
    alpn   IN HTTPS 1 . alpn="h2,h3"
    ech    IN HTTPS 1 . ech="AEX+DQBBzQAgACD/AA==" port=8443
  ZONEDATA

  def test_zone_quoted_svcparam_values
    reader = Dnsruby::ZoneReader.new('example.com.')
    alpn, ech = reader.process_file(StringIO.new(QUOTED_SVCB_ZONE))

    assert_equal('h2,h3', alpn.params_to_hash['alpn'])

    assert_equal('AEX+DQBBzQAgACD/AA==', ech.params_to_hash['ech'])
    assert_equal('8443', ech.params_to_hash['port'])
  end

  # A quoted SvcParamValue inside the parentheses that group a record across
  # lines. The quote opens mid-token, so the closing parenthesis travels with
  # the quoted tail rather than with the rest of the line. An ech value is what
  # gets wrapped in practice, being long enough to want a second line.
  PAREN_QUOTED_SVCB_ZONE = <<~ZONEDATA
    $TTL 3600
    one    IN HTTPS ( 1 . alpn="h2,h3" )
    two    IN HTTPS ( 1 .  ech="AEX+DQBBzQAgACD/AA=="
                      port=8443 )
  ZONEDATA

  def test_zone_parenthesised_quoted_svcparam_values
    reader = Dnsruby::ZoneReader.new('example.com.')
    one_line, wrapped = reader.process_file(StringIO.new(PAREN_QUOTED_SVCB_ZONE))

    assert_equal('h2,h3', one_line.params_to_hash['alpn'])

    assert_equal('AEX+DQBBzQAgACD/AA==', wrapped.params_to_hash['ech'])
    assert_equal('8443', wrapped.params_to_hash['port'])
  end

  def test_zone_literal_parentheses_do_not_continue_a_record
    zone = <<~'ZONE'
      quoted IN HTTPS 1 . key667="a(b)c"
      escaped IN SVCB 1 . key667=a\(b\)c
      decimal IN HTTPS 1 . key667=a\040b\041c
      open IN HTTPS 1 . key667="a\("
      close IN SVCB 1 . key667=a\)
      quote IN HTTPS 1 . key667="a\"(b)c"
      following IN A 192.0.2.1
    ZONE
    records = @reader.process_file(StringIO.new(zone))
    assert_equal(7, records.size)
    assert_equal(['a(b)c', 'a(b)c', 'a(b)c', 'a(', 'a)', 'a"(b)c'],
                 records.first(6).map { |rr| rr.params[667] })
    assert_equal('192.0.2.1', records.last.address.to_s)
  end

  def test_zone_grouping_ignores_parentheses_in_values_and_comments
    zone = <<~'ZONE'
      wrapped IN HTTPS (1 . key667="a;(b)c" ; unmatched ) in comment
        key668=a\) ; unmatched ( in comment
        port=443) ; ignored (
      following IN A 192.0.2.1
    ZONE
    wrapped, following = @reader.process_file(StringIO.new(zone))
    assert_equal('a;(b)c', wrapped.params[667])
    assert_equal('a)', wrapped.params[668])
    assert_equal('443', wrapped.params_to_hash['port'])
    assert_equal('192.0.2.1', following.address.to_s)
  end

  def test_normalise_line_handles_grouping_when_called_directly
    line = @reader.normalise_line('svc IN HTTPS (1 . key667="a\(b\)c")')
    rr = RR.create(line)
    assert_equal('svc.example.com.', rr.name.to_s(true))
    assert_equal('a(b)c', rr.params[667])
  end

  def test_normalise_line_preserves_standalone_unmatched_grouping
    ['host IN A (192.0.2.7', 'host IN A 192.0.2.7)'].each do |input|
      rr = RR.create(@reader.normalise_line(input))
      assert_equal('host.example.com.', rr.name.to_s(true))
      assert_equal('192.0.2.7', rr.address.to_s)
    end
  end

  def test_unbalanced_grouping_is_rejected
    assert_raises(Dnsruby::ZoneReader::ParseException) do
      @reader.process_file(StringIO.new('bad IN HTTPS 1 .)'))
    end
    assert_raises(Dnsruby::ZoneReader::ParseException) do
      @reader.process_file(StringIO.new('bad IN HTTPS (1 .'))
    end
  end
end
