require_relative 'spec_helper'

# Tests for the RFC 5952 text representation of IPv6 addresses
class TestIPv6 < Minitest::Test

  include Dnsruby

  def test_compression_requires_at_least_one_omitted_field
    %w[
      1:2:3:4:5:6:7::8 ::1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:8::
      1:2:3:4:5:6::192.0.2.1 ::1:2:3:4:5:6:192.0.2.1
    ].each do |address|
      assert_raises(ArgumentError, address) { IPv6.create(address) }
    end
    assert_equal('1:2:3:4:5:6:0:8', IPv6.create('1:2:3:4:5:6::8').to_s)
    assert_equal('1:2:3:4:5:0:c000:201', IPv6.create('1:2:3:4:5::192.0.2.1').to_s)
  end

  # RFC 5952 section 4.1: leading zeros in a field are suppressed
  def test_leading_zeros_suppressed
    assert_equal('2001:db8::1', IPv6.create('2001:0db8:0000:0000:0000:0000:0000:0001').to_s)
    assert_equal('2001:db8:0:1:1:1:1:1', IPv6.create('2001:0db8:0000:0001:0001:0001:0001:0001').to_s)
  end

  # RFC 5952 section 4.2.1: a run of all-zero fields is replaced by '::'
  def test_zero_run_shortened
    assert_equal('::', IPv6.create('0:0:0:0:0:0:0:0').to_s)
    assert_equal('::1', IPv6.create('0:0:0:0:0:0:0:1').to_s)
    assert_equal('1::', IPv6.create('1:0:0:0:0:0:0:0').to_s)
    assert_equal('2001:db8::1', IPv6.create('2001:db8:0:0:0:0:0:1').to_s)
  end

  # RFC 5952 section 4.2.2: '::' must not shorten a single all-zero field
  def test_single_zero_field_not_shortened
    assert_equal('2001:db8:0:1:1:1:1:1', IPv6.create('2001:db8:0:1:1:1:1:1').to_s)
    assert_equal('1:2:3:4:5:6:0:8', IPv6.create('1:2:3:4:5:6:0:8').to_s)
    assert_equal('0:1:2:3:4:5:6:7', IPv6.create('0:1:2:3:4:5:6:7').to_s)
    assert_equal('1:2:3:4:5:6:7:0', IPv6.create('1:2:3:4:5:6:7:0').to_s)
  end

  # RFC 5952 section 4.2.3: the longest run is shortened. If there's a tie,
  # shorten the first run.
  def test_longest_zero_run_shortened
    assert_equal('1:0:0:1::1', IPv6.create('1:0:0:1:0:0:0:1').to_s)
    assert_equal('1::1:0:0:1:1', IPv6.create('1:0:0:1:0:0:1:1').to_s)
    assert_equal('2001:db8::1:0:0:1', IPv6.create('2001:db8:0:0:1:0:0:1').to_s)
  end

  # RFC 5952 section 4.3: downcase hexadecimal digits
  def test_lowercase_hex
    assert_equal('2001:db8::ab', IPv6.create('2001:0DB8::AB').to_s)
    assert_equal('fe80::abcd:ef01', IPv6.create('FE80::ABCD:EF01').to_s)
    assert_equal('2606:4700:20::681a:205', IPv6.create('2606:4700:20::681A:205').to_s)
  end

  # RFC 5952 section 5: an embedded IPv4 address under the well-known
  # ::ffff:0:0/96 prefix uses mixed notation
  def test_ipv4_mapped_mixed_notation
    assert_equal('::ffff:192.0.2.1', IPv6.create('::ffff:192.0.2.1').to_s)
    assert_equal('::ffff:192.0.2.1', IPv6.create('0:0:0:0:0:ffff:c000:201').to_s)
    assert_equal('::ffff:0.0.0.0', IPv6.create('::ffff:0:0').to_s)
  end

  # Only ::ffff:0:0/96 gets the mixed notation. IPv4-compatible addresses
  # (::/96) are deprecated by RFC 4291 section 2.5.5.1, so a dotted quad there
  # would imply a semantic that no longer exists - they keep the hexadecimal
  # form. Note this is a deliberate departure from IPAddr and inet_ntop, which
  # write ::a:b as ::0.10.0.11.
  def test_non_mapped_addresses_stay_hexadecimal
    assert_equal('::', IPv6.create('::').to_s)
    assert_equal('::1', IPv6.create('::1').to_s)
    assert_equal('::102:304', IPv6.create('::1.2.3.4').to_s)
    assert_equal('64:ff9b::102:304', IPv6.create('64:ff9b::1.2.3.4').to_s)
  end

  # The mixed notation requires the whole ::ffff:0:0/96 prefix, not just 0xffff
  # in the sixth field
  def test_mixed_notation_requires_the_full_prefix
    assert_equal('1::ffff:102:304', IPv6.create('1::ffff:1.2.3.4').to_s)
    assert_equal('::1:ffff:102:304', IPv6.create('::1:ffff:1.2.3.4').to_s)
    assert_equal('::fffe:102:304', IPv6.create('::fffe:1.2.3.4').to_s)
  end

  # Whatever we emit must be readable back as the same address
  def test_output_round_trips_through_create
    [
      '2001:0DB8:0:8002::2000:1',
      '2001:db8:0:1:1:1:1:1',
      '1:0:0:1:0:0:0:1',
      '::ffff:192.0.2.1',
      '::',
      '::1',
      '1::',
      'fe80::1',
    ].each do |text|
      address = IPv6.create(text)
      assert_equal(address, IPv6.create(address.to_s), "#{text} did not survive to_s / create")
    end
  end
end
