
require_relative 'spec_helper'

include Dnsruby

class ZoneReaderTest < Minitest::Test

  def test_txt_zonefile
    reader = Dnsruby::ZoneReader.new("example.com.")
    zone = reader.process_file("#{File.dirname(__FILE__)}/zone_file.txt")
    assert(zone[0].serial == 1993112101)
    assert(zone[1].rdata == "ns1.example.com.")
    assert(zone[2].rdata == "ns2.example.com.")
    assert(zone[3].rdata == "10 mx.example.com.")
    assert(zone[4].rdata == "\"v=spf1 mx ~all\"")
    assert(zone[5].rdata == "192.0.2.10")
    assert(zone[6].rdata == "2001:DB8::10")
    #assert(zone[7].rdata == "www.example.com.")
    assert(zone[8].rdata == "www.example.com.")
  end
end

