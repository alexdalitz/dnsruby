
require_relative 'spec_helper'

include Dnsruby

class ZoneReaderTest < Minitest::Test

  def check_zone_data_is_valid(zone)
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

  def test_process_file_with_filename
    reader = Dnsruby::ZoneReader.new("example.com.")
    zone = reader.process_file("#{File.dirname(__FILE__)}/zone_file.txt")
    check_zone_data_is_valid(zone)
  end

  def test_process_file_with_file_object
    reader = Dnsruby::ZoneReader.new("example.com.")
    file = File.new("#{File.dirname(__FILE__)}/zone_file.txt")
    zone = reader.process_file(file)
    check_zone_data_is_valid(zone)
    assert(file.closed? == true)
  end

  def test_process_io_with_file_object
    reader = Dnsruby::ZoneReader.new("example.com.")
    file = File.new("#{File.dirname(__FILE__)}/zone_file.txt")
    zone = reader.process_io(file)
    check_zone_data_is_valid(zone)
    assert(file.closed? == false)
    file.close
  end

  def test_process_io_with_stringio_object
    reader = Dnsruby::ZoneReader.new("example.com.")
    string = File.read("#{File.dirname(__FILE__)}/zone_file.txt")
    stringio = StringIO.new(string)
    zone = reader.process_io(stringio)
    check_zone_data_is_valid(zone)
    assert(stringio.closed? == false)
    stringio.close
  end
end

