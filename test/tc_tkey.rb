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
require "digest/md5"
class TestTKey < Test::Unit::TestCase
  def is_empty(string)
    return (string == "; no data" || string == "; rdlength = 0")
  end
  
  def test_tkey
    
    
    #------------------------------------------------------------------------------
    # Canned data.
    #------------------------------------------------------------------------------
    
    zone	= "example.com"
    name	= "123456789-test"
    klass	= "IN"
    type	= Dnsruby::Types.TKEY
    algorithm   = "fake.algorithm.example.com"
    key         = "fake key"
    inception   = 100000 # use a strange fixed inception time to give a fixed
    # checksum
    expiration  = inception + 24*60*60
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Packet creation.
    #------------------------------------------------------------------------------
    
    rr = Dnsruby::RR.create(
      :name       => name,
      :type       => "TKEY",
      :ttl        => 0,
      :klass      => "ANY",
      :algorithm  => algorithm,
      :inception  => inception,
      :expiration => expiration,
      :mode       => 3, # GSSAPI
      :key        => "fake key",
      :other_data => ""
    )
    
    packet = Dnsruby::Message.new(name, Dnsruby::Types.TKEY, "IN")
    packet.add_answer(rr)
    
    z = (packet.zone)[0]
    
    assert(packet,                                'new() returned packet')  #2
    assert_equal(Dnsruby::OpCode.QUERY,       packet.header.opcode, 'header opcode correct')  #3 
    assert_equal(name,                      z.zname.to_s,  'zname correct')          #4
    assert_equal(Dnsruby::Classes.IN,                       z.zclass, 'zclass correct')         #5
    assert_equal(Dnsruby::Types.TKEY,                     z.ztype,  'ztype correct')          #6       
    
    
  end
  
  def test_tsig
    
    name="example.com."
    key = "1234"
    print key.to_s + "\n"
    tsig = Dnsruby::RR.create({
        :name        => name,
        :type        => "TSIG",
        :ttl         => 0,
        :klass       => "ANY",
        :algorithm   => "HMAC-MD5.SIG-ALG.REG.INT.",
        :time_signed => 1189686346,
        :fudge       => 300,
        :key         => key,
        :error       => 0
      })


    message = Dnsruby::Message.new
    message.header.id=(1234)
    tsig.apply(message)
    
    mac_string = Base64.encode64(message.additional[0].mac)
    print mac_string + "\n"
    
    assert_equal("S8w22c0nlOhC9wNwwHPY7g==", mac_string, "MAC wrong")
        
    res = Dnsruby::Resolver.new
    response = res.send_message(message)
    print response+"\n"
  end
end
