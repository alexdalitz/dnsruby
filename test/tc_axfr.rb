#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require 'rubygems'
require 'test/unit'
require 'dnsruby'
class TestAxfr < Test::Unit::TestCase
  def test_axfr
    zt = Dnsruby::ZoneTransfer.new
    zt.transfer_type = Dnsruby::Types.AXFR
    zt.server = "ns0.validation-test-servers.nominet.org.uk"
    zone = zt.transfer("validation-test-servers.nominet.org.uk")
    assert(zone.length > 0)
    assert(zt.last_tsigstate==nil)
  end

  KEY_NAME="rubytsig"
  KEY = "8n6gugn4aJ7MazyNlMccGKH1WxD2B3UvN/O/RA6iBupO2/03u9CTa3Ewz3gBWTSBCH3crY4Kk+tigNdeJBAvrw=="
  
  def test_ixfr
  # Check the SOA serial, do an update, check that the IXFR for that soa serial gives us the update we did,
  # then delete the updated record
   start_soa_serial = get_soa_serial("validation-test-servers.nominet.org.uk")
    
    # Now do an update
    res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    res.query_timeout=10
    res.tsig=KEY_NAME, KEY
    
    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    # Generate update record name, and test it has been made. Then delete it and check it has been deleted
    update_name = Time.now.to_i.to_s + rand(100).to_s + ".update.validation-test-servers.nominet.org.uk"
    update.absent(update_name)
    update.add(update_name, 'TXT', 100, "test zone transfer")
    assert(!update.signed?, "Update has been signed")
    
    response = res.send_message(update)
    assert(response.header.rcode == Dnsruby::RCode.NOERROR)
    
   end_soa_serial = get_soa_serial("validation-test-servers.nominet.org.uk")
    
    zt = Dnsruby::ZoneTransfer.new
    zt.transfer_type = Dnsruby::Types.IXFR
    zt.server = "ns0.validation-test-servers.nominet.org.uk"
    zt.serial = start_soa_serial # 2007090401
    deltas = zt.transfer("validation-test-servers.nominet.org.uk")
    assert(deltas.length > 0)
    assert(deltas[0].class == Dnsruby::ZoneTransfer::Delta)
    assert_equal("test zone transfer", deltas[0].adds[1].strings.join(" "))
    assert(zt.last_tsigstate==nil)
    
    # Now delete the updated record
    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    update.present(update_name, 'TXT')
    update.delete(update_name)
    response = res.send_message(update)
    assert_equal( Dnsruby::RCode.NOERROR, response.header.rcode)
  end
  
  def get_soa_serial(name)
    soa_serial = nil
    Dnsruby::DNS.open {|dns|
      soa_rr = dns.getresource(name, 'SOA')
      soa_serial = soa_rr.serial
    }
    return soa_serial    
  end
end