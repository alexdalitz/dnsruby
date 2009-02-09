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
#See the License f181or the specific language governing permissions and 
#limitations under the License.
#++
module Dnsruby
  class RR
    #RFC4034, section 2
    #DNSSEC uses public key cryptography to sign and authenticate DNS
    #resource record sets (RRsets).  The public keys are stored in DNSKEY
    #resource records and are used in the DNSSEC authentication process
    #described in [RFC4035]: A zone signs its authoritative RRsets by
    #using a private key and stores the corresponding public key in a
    #DNSKEY RR.  A resolver can then use the public key to validate
    #signatures covering the RRsets in the zone, and thus to authenticate
    #them.
    class DNSKEY < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::DNSKEY #:nodoc: all
      
      #Key is a zone key
      ZONE_KEY = 0x100

      #Key is a secure entry point key
      SEP_KEY = 0x1

      #The flags for the DNSKEY RR
      attr_accessor :flags
      #The protocol for this DNSKEY RR.
      #MUST be 3.
      attr_reader :protocol
      #The algorithm used for this key
      #See Dnsruby::Algorithms for permitted values
      attr_reader :algorithm
      #The public key
      attr_reader :key
      
      def init_defaults
        self.protocol=3
        self.flags=ZONE_KEY
        @algorithm=Algorithms.RSASHA1
      end
      
      def protocol=(p)
        if (p!=3)
          raise DecodeError.new("DNSKEY protocol field set to #{p}, contrary to RFC4034 section 2.1.2")
        else @protocol = p
        end
      end
      
      def algorithm=(a)
        if (a.instance_of?String)
          if (a.length == 1)
            a = a.to_i
          end
        end
        begin
          alg = Algorithms.new(a)
          @algorithm = alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end        
      end
      
      def zone_key=(on)
        if (on)
          @flags |= ZONE_KEY
        else
          @flags &= (~ZONE_KEY)
        end
      end
      
      def zone_key?
        return @flags & ZONE_KEY
      end
      
      def sep_key=(on)
        if (on)
          @flags |= SEP_KEY
        else
          @flags &= (~SEP_KEY)
        end
      end
      
      def sep_key?
        return @flags & SEP_KEY
      end
      
      def flags=(f)
        # Only two values allowed - 
        # Zone Key flag (bit 7)
        # Secure Entry Point flag (bit 15)
        if ((f & ~ZONE_KEY & ~SEP_KEY) > 0)
          raise DecodeError.new("Only zone key and secure entry point flags allowed for DNSKEY" +
              " (RFC4034 section 2.1.1)")
        else
          @flags = f
        end
      end
      
      def from_data(data) #:nodoc: all
        flags, protocol, algorithm, @key = data
        self.flags=(flags)
        self.protocol=(protocol)
        self.algorithm=(algorithm)
      end
      
      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.flags=(data[0].to_i)
          self.protocol=(data[1].to_i)
          self.algorithm=(data[2])
          # key can include whitespace - include all text
          # until we come to " )" at the end, and then gsub
          # the white space out
          # Also, brackets may or may not be present
          buf = ""
          index = 3
          end_index = data.length - 1
          if (data[index]=="(")
            end_index = data.length - 2
            index = 4
          end
          (index..end_index).each {|i|
            buf += data[i]
          }
          self.key=(buf)
        end
      end
      
      def rdata_to_string #:nodoc: all
        if (@flags!=nil)
          #          return "#{@flags} #{@protocol} #{@algorithm.string} ( #{Base64.encode64(@key.to_s)} )"
          return "#{@flags} #{@protocol} #{@algorithm.string} ( #{[@key.to_s].pack("m*").gsub("\n", "")} )"
        else
          return ""
        end
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        # 2 octets, then 2 sets of 1 octet
        msg.put_pack('ncc', @flags, @protocol, @algorithm.code)
        msg.put_bytes(@key)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        # 2 octets, then 2 sets of 1 octet
        flags, protocol, algorithm = msg.get_unpack('ncc')
        key = msg.get_bytes
        return self.new(
          [flags, protocol, algorithm, key])
      end
      
      def key_tag
        tag=0
        rdata = MessageEncoder.new {|msg|
          encode_rdata(msg)
        }.to_s
        if (@algorithm == Algorithms.RSAMD5)
          #The key tag for algorithm 1 (RSA/MD5) is defined differently from the
          #key tag for all other algorithms, for historical reasons.
          d1 = rdata[rdata.length - 3] & 0xFF
          d2 = rdata[rdata.length - 2] & 0xFF
          tag = (d1 << 8) + d2
        else
          tag = 0
          last = 0
          0.step(rdata.length - 1, 2) {|i|
            last = i
            d1 = rdata[i]
            d2 = rdata[i + 1] || 0 # odd number of bytes possible

            if (d1.class == String) # Ruby 1.9
              d1 = d1.getbyte(0)
              d2 = d2.getbyte(0)
            end
          
            d1 = d1  & 0xFF
            d2 = d2  & 0xFF

            tag += ((d1 << 8) + d2)
          }
          last+=2
          if (last < rdata.length)
            d1 = rdata[last] 
            
            if (d1.class == String) # Ruby 1.9
              d1 = d1.getbyte(0)
            end
            
            d1 = d1 & 0xFF
            tag += (d1 << 8)
          end
          tag += ((tag >> 16) & 0xFFFF)
        end
        tag=tag&0xFFFF
        return tag
      end
      
      def key=(key_text)
        key_text.gsub!(/\n/, "")
        key_text.gsub!(/ /, "")
        #        @key=Base64.decode64(key_text)        
        @key=key_text.unpack("m*")[0]
      end
      
      def public_key
        if (@public_key==nil)
          if (@algorithm == Algorithms.RSASHA1)
            @public_key = rsa_key
          end
        end
        # @TODO@ Support other key encodings!
        return @public_key
      end
      
      def rsa_key
        exponentLength = @key[0]
        if (exponentLength.class == String)
          exponentLength = exponentLength.getbyte(0) # Ruby 1.9
        end
        pos = 1
        if (exponentLength == 0)
          key1 = @key[1]
          if (key1.class == String) # Ruby 1.9
            key1 = key1.getbyte(0)
          end
          exponentLength = (key1<<8) + key1
          pos += 2
        end
        exponent = get_num(@key[pos, exponentLength])
        pos += exponentLength

        modulus = get_num(@key[pos, @key.length])

        key = OpenSSL::PKey::RSA.new
        key.e = exponent
        key.n = modulus
        return key 
      end
      
      def get_num(bytes)
        ret = 0
        shift = (bytes.length-1) * 8
        bytes.each_byte {|byte|
          ret += byte.to_i << shift
          shift -= 8
        }
        return ret
      end
    end 
  end
end