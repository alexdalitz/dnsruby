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
require 'base64'
require "digest/md5"
require "digest/sha1"
#require "digest/sha256"
module Dnsruby
  class RR
    class TSIG < RR
      HMAC_MD5 = Name.create("HMAC-MD5.SIG-ALG.REG.INT.")
      HMAC_SHA1 = Name.create("hmac-sha1.")
      HMAC_SHA256 = Name.create("hmac-sha256.")
      
      DEFAULT_FUDGE     = 300
      
      DEFAULT_ALGORITHM = HMAC_MD5
      
      #  Generates a TSIG record and adds it to the message.
      #  Takes an optional original_request argument for the case where this is
      #  a response to a query (RFC2845 3.4.1)
      def apply(message, original_request=nil)
        if (!message.signed?)
          tsig_rr = generate(message, original_request)
          message.add_additional(tsig_rr)
          message.tsigstate = :Signed
        end
      end
      
      
      #@TODO@ How is the generate / verify method going to be called?
      # resolver will encode packet, and then add TSIG to it.
      #  [res] b = packet.encode
      #        rr = @tsig.generate(packet, b)
      #        packet.add_additional(rr)
      #        b = packet.encode
      #        send(b)
      # @TODO@ Then generate signed response to that message : need request_tsig_rr
      
      # [res]  bytes = get_incoming
      #        msg = Message.decode(bytes)
      #        request_tsig_rr.verify(msg)
      # @TODO@ OR msg.verify(key, request_tsig_rr)
      # #@TODO@ Need to know the request mac so we can validate the response (rfc2845 4.1/4.2/4.3)
      # #@TODO@ Remove TSIG from packet before passing to client?
      # YES! RFC2845 says TSIG should be removed. Then client doesn't have to do
      # any verify stuff - all handled in Resolver.
      # @TODO@ But client *should* be able to do verification stuff if it wants to
      # Client just sets TSIG_RR (or just key name and key) in Resolver and off it goes.
      # @TODO@ Resolver will throw some kinda error if verify fails?
      
      
      # Generates a TSIG record
      def generate(msg, msg_bytes=nil, original_request = nil, tsig_rr=self)
        time_signed=@time_signed
        if (!time_signed)
          time_signed=Time.now.to_i
        end
        if (tsig_rr.time_signed)
          time_signed = tsig_rr.time_signed
        end
        
        key = @key.gsub(" ", "")
        key = Base64::decode64(key)
      
        data = ""
        
        if (original_request)
          #	# Add the request MAC if present (used to validate responses).
          #	  hmac.update(pack("H*", request_mac))
          mac_bytes = MessageEncoder.new {|m|
            m.put_pack('n', original_request.tsig.mac_size)
            m.put_bytes(original_request.tsig.mac)
          }.to_s
          data  += mac_bytes
          # Original ID - should we set message ID to original ID?
          if (tsig_rr != self)
            msg.header.id = tsig_rr.original_id
          else
            msg.header.id = original_request.header.id
          end
        end
        
        if (!msg_bytes)
          msg_bytes = msg.encode
          data += msg_bytes
        else
          # If msg_bytes came in, we need somehow to remove the TSIG RR
          # It is the last record, so we can strip it if we know where it starts
          # We must also poke the header ARcount to decrement it
          msg_bytes = Header.decrement_arcount_encoded(msg_bytes)
          data += msg_bytes[0, msg.tsigstart]
        end
        
        data += sig_data(tsig_rr, time_signed)
        
        mac=nil

        if (tsig_rr.algorithm == HMAC_MD5)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, data)
        elsif (tsig_rr.algorithm == HMAC_SHA1)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, key, data)
        elsif (tsig_rr.algorithm == HMAC_SHA256)
          mac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, data)
        else
          # Should we allow client to pass in their own signing function?
          raise RuntimeError.new("Algorithm #{tsig_rr.algorithm} unsupported by TSIG")
        end

        mac_size = mac.length

        new_tsig_rr = Dnsruby::RR.create({
            :name        => tsig_rr.name,
            :type        => Types.TSIG,
            :ttl         => tsig_rr.ttl,
            :klass       => tsig_rr.klass,
            :algorithm   => tsig_rr.algorithm,
            :fudge       => tsig_rr.fudge,
            :key         => @key,
            :mac         => mac,
            :mac_size    => mac_size,
            :error       => tsig_rr.error,
            :time_signed => time_signed,
            :original_id => msg.header.id
          })
        return new_tsig_rr
        
      end
      
      def sig_data(tsig_rr, time_signed=@time_signed)
        return MessageEncoder.new { |msg|
          msg.put_name(tsig_rr.name.downcase, true)
          msg.put_pack('nN', tsig_rr.klass.code, tsig_rr.ttl)
          msg.put_name(tsig_rr.algorithm.downcase, true)
          
          time_high = (time_signed >> 32)
          time_low = (time_signed & 0xFFFFFFFF)
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', tsig_rr.fudge)
          msg.put_pack('n', tsig_rr.error)
          msg.put_pack('n', tsig_rr.other_size)
          msg.put_bytes(tsig_rr.other_data)
        }.to_s
      end
      
      def verify(query, response, response_bytes)
        #        4.6. Client processing of answer
        #
        #   When a client receives a response from a server and expects to see a
        #   TSIG, it first checks if the TSIG RR is present in the response.
        #   Otherwise, the response is treated as having a format error and
        #   discarded.  The client then extracts the TSIG, adjusts the ARCOUNT,
        #   and calculates the keyed digest in the same way as the server.  If
        #   the TSIG does not validate, that response MUST be discarded, unless
        #   the RCODE is 9 (NOTAUTH), in which case the client SHOULD attempt to
        #   verify the response as if it were a TSIG Error response, as specified
        #   in [4.3].  A message containing an unsigned TSIG record or a TSIG
        #   record which fails verification SHOULD not be considered an
        #   acceptable response; the client SHOULD log an error and continue to
        #   wait for a signed response until the request times out.

        # So, this verify method should simply remove the TSIG RR and calculate
        # the MAC (using original request MAC if required).
        # Should set tsigstate on packet appropriately, and return error.
        # Side effect is packet is stripped of TSIG.
        # Resolver (or client) can then decide what to do...

        
        msg_tsig_rr = response.tsig
        response.additional.delete(msg_tsig_rr)
        response.header.arcount-=1
        new_msg_tsig_rr = generate(response, response_bytes, query, msg_tsig_rr)
        
        # @TODO@ CHECK THE TIME_SIGNED!!! (RFC2845, 4.5.2)
        
        if (msg_tsig_rr.mac == new_msg_tsig_rr.mac)
          response.tsigstate = :Verified
          return true
        else
          response.tsigstate = :Failed
          return false
        end
      end
      
      TypeValue = Types::TSIG #:nodoc: all
      ClassValue = nil #:nodoc: all
      ClassHash[[TypeValue, Classes.ANY.code]] = self #:nodoc: all
      
      #Gets or sets the domain name that specifies the name of the algorithm.
      #The only algorithm currently supported is hmac-md5.
      #
      #    rr.algorithm=(algorithm_name)
      #    print "algorithm = ", rr.algorithm, "\n"
      #
      attr_accessor :algorithm
      
      #Gets or sets the signing time as the number of seconds since 1 Jan 1970
      #00:00:00 UTC.
      #
      #The default signing time is the current time.
      #
      #    rr.time_signed=(time)
      #    print "time signed = ", rr.time_signed, "\n"
      #
      attr_accessor :time_signed
      
      #Gets or sets the "fudge", i.e., the seconds of error permitted in the
      #signing time.
      #
      #The default fudge is 300 seconds.
      #
      #    rr.fudge=(60)
      #    print "fudge = ", rr.fudge, "\n"
      #
      attr_accessor :fudge
      
      #Returns the number of octets in the message authentication code (MAC).
      #The programmer must call a Net::DNS::Packet object's data method
      #before this will return anything meaningful.
      #
      #    print "MAC size = ", rr.mac_size, "\n"
      #
      attr_accessor :mac_size
      
      #Returns the message authentication code (MAC) as a string of hex
      #characters.  The programmer must call a Net::DNS::Packet object's
      #data method before this will return anything meaningful.
      #
      #    print "MAC = ", rr.mac, "\n"
      #
      attr_accessor :mac
      
      #Gets or sets the original message ID.
      #
      #    rr.original_id(12345)
      #    print "original ID = ", rr.original_id, "\n"
      #
      attr_accessor :original_id
      
      #Returns the RCODE covering TSIG processing.  Common values are
      #NOERROR, BADSIG, BADKEY, and BADTIME.  See RFC 2845 for details.
      #
      #    print "error = ", rr.error, "\n"
      #
      attr_accessor :error
      
      #Returns the length of the Other Data.  Should be zero unless the
      #error is BADTIME.
      #
      #    print "other len = ", rr.other_size, "\n"
      #
      attr_accessor :other_size
      
      #Returns the Other Data.  This field should be empty unless the
      #error is BADTIME, in which case it will contain the server's
      #time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
      #
      #    print "other data = ", rr.other_data, "\n"
      #
      attr_accessor :other_data
      attr_accessor :key
      
      def init_defaults
        # @TODO@ Have new() method which takes key_name and key?
        @algorithm   = DEFAULT_ALGORITHM
        #        @time_signed = Time.now.to_i
        @fudge       = DEFAULT_FUDGE
        @mac_size    = 0
        @mac         = ""
        @original_id = rand(65536)
        @error       = 0
        @other_size   = 0
        @other_data  = ""
        
        # RFC 2845 Section 2.3
        @klass = "ANY"
        
        @ttl = 0 # RFC 2845 Section 2.3
      end
      
      def from_data(data) #:nodoc: all
        @algorithm, @time_signed, @fudge, @mac_size, @mac, @original_id, @error, @other_size, @other_data = data
      end
      
      # Create the RR from a standard string
      def from_string(str) #:nodoc: all
        parts = str.split("[:/]")
        if (parts.length < 2 || parts.length > 3)
          raise ArgumentException.new("Invalid TSIG key specification")
        end
        if (parts.length == 3)
          return TSIG.new(parts[0], parts[1], parts[2]);
        else
          return TSIG.new(HMAC_MD5, parts[0], parts[1]);
        end
      end
      
      #Set the algorithm to use to generate the HMAC
      #Supported values are :
      #* hmac-md5
      #* hmac-sha1
      #* hmac-sha256
      def algorithm=(alg)
        case alg.class
        when String
          if (alg.downcase=="hmac-md5")
            @algorithm = HMAC_MD5;
          elsif (algorithm.downcase=="hmac-sha1")
            @algorithm = HMAC_SHA1;
          elsif (algorithm.downcase=="hmac-sha256")
            @algorithm = HMAC_SHA256;
          else
            raise ArgumentException.new("Invalid TSIG algorithm")
          end
        when Name
          if (alg!=HMAC_MD5 && alg!=HMAC_SHA1 && alg!=HMAC_SHA256)
            raise ArgumentException.new("Invalid TSIG algorithm")
          end
          @algorithm=alg
        end
      end
      
      def fudge=(f)
        if (f < 0 || f > 0x7FFF)
          @fudge = DEFAULT_FUDGE
        else
          @fudge = f
        end
      end
      
      def rdata_to_string        
        rdatastr=""
        if (@algorithm!=nil)
          error = @error
          error = "UNDEFINED" unless error!=nil
          rdatastr = "#{@original_id} #{@time_signed} #{@algorithm}. #{error}";
          if (@other_size > 0 && @other_data!=nil)
            rdatastr += " #{@other_data}"
          end
          rdatastr += " " + mac.unpack("H*").to_s
        end
        
        return rdatastr
      end
      
      def encode_rdata(msg) #:nodoc: all
        # @TODO@ Name needs to be added with no compression!
        msg.put_name(@algorithm.downcase, true)
        time_high = (@time_signed >> 32)
        time_low = (@time_signed & 0xFFFFFFFF)
        msg.put_pack('nN', time_high, time_low)
        msg.put_pack('n', @fudge)
        msg.put_pack('n', @mac_size)
        msg.put_bytes(@mac)
        msg.put_pack('n', @original_id)
        msg.put_pack('n', @error)
        msg.put_pack('n', @other_size)
        msg.put_bytes(@other_data)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        alg=msg.get_name
        time_high, time_low = msg.get_unpack("nN")
        time_signed = (time_high << 32) + time_low
        fudge, = msg.get_unpack("n")
        mac_size, = msg.get_unpack("n")
        mac = msg.get_bytes(mac_size)
        original_id, = msg.get_unpack("n")
        error, = msg.get_unpack("n")
        other_size, = msg.get_unpack("n")
        other_data = msg.get_bytes(other_size)
        return self.new([alg, time_signed, fudge, mac_size, mac, original_id, error, other_size, other_data])
      end
    end
  end   
end