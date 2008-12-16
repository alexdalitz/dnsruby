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
module Dnsruby
  class RR
    ClassInsensitiveTypes = [
      NS, CNAME, DNAME, DNSKEY, SOA, PTR, HINFO, MINFO, MX, TXT,
      ISDN, MB, MG, MR, NAPTR, NSAP, OPT, RP, RT, X25,
      SPF, CERT, LOC, TSIG, TKEY, ANY, RRSIG, NSEC, DS, NSEC3,
      NSEC3PARAM, DLV
    ] #:nodoc: all
    
    # module IN contains ARPA Internet specific RRs
    module IN
      ClassValue = Classes::IN
      
      ClassInsensitiveTypes::each {|s|
        c = Class.new(s)
        #          c < Record
        c.const_set(:TypeValue, s::TypeValue)
        c.const_set(:ClassValue, ClassValue)
        ClassHash[[s::TypeValue, ClassValue]] = c
        self.const_set(s.name.sub(/.*::/, ''), c)
      }
      
      # RFC 1035, Section 3.4.2 (deprecated)
      class WKS < RR
        ClassHash[[TypeValue = Types::WKS, ClassValue = ClassValue]] = self  #:nodoc: all
        
        def initialize(address, protocol, bitmap)
          @address = IPv4.create(address)
          @protocol = protocol
          @bitmap = bitmap
        end
        attr_reader :address, :protocol, :bitmap
        
        def encode_rdata(msg, canonical=false) #:nodoc: all
          msg.put_bytes(@address.address)
          msg.put_pack("n", @protocol)
          msg.put_bytes(@bitmap)
        end
        
        def self.decode_rdata(msg) #:nodoc: all
          address = IPv4.new(msg.get_bytes(4))
          protocol, = msg.get_unpack("n")
          bitmap = msg.get_bytes
          return self.new(address, protocol, bitmap)
        end
      end
      
    end
  end
end
require 'Dnsruby/resource/A'
require 'Dnsruby/resource/AAAA'
require 'Dnsruby/resource/AFSDB'
require 'Dnsruby/resource/PX'
require 'Dnsruby/resource/SRV'
