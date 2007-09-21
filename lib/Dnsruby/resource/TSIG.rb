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
      HMAC_MD5 = Name.create("HMAC-MD5.SIG-ALG.REG.INT")
      HMAC_SHA1 = Name.create("hmac-sha1.")
      HMAC_SHA256 = Name.create("hmac-sha256.")
      
      DEFAULT_FUDGE     = 300
      
      DEFAULT_ALGORITHM = HMAC_MD5
      
      #  Generates a TSIG record and adds it to the message.
      def apply(message)
        if (!message.is_signed)
          generate(message)
          message.add_additional(self)
          message.tsigstate = :Signed
        end
      end
      
      # Generates a TSIG record
      def generate(m)
        if (!@time_signed)
          time_signed=Time.now
        end
        hmac = nil
        if (@algorithm == HMAC_MD5)
          hmac = Digest::MD5.new
        elsif (@algorithm == HMAC_SHA1)
          hmac=Digest::SHA1.new
        elsif (@algorithm == HMAC_SHA256)
          hmac=Digest::SHA256.new
        end
        hmac.update(@key)

        s=""
        @key.length.times do |i|
          s << @key[i].to_s + ","
        end
        
        print "key : #{s}\n"
        
        b = m.encode
        s=""
        b.length.times do |i|
          s << b[i].to_s + ","
        end
        print "encoded message : #{s}\n"
        
# Digest the message
        if (hmac)
          hmac.update(b) # @TODO@ b is RENDERED MESSAGE!! NOT m.encode!
# Dnsjava has render method for messages
# pnet-dns signs message during encoding process.
        end
        
        data = sig_data        
        s=""
        
        data.length.times do |i|
          s << data[i].to_s + ","
        end
        
        print "encoded TSIG : #{s}\n"
        hmac.update(data)
        
        @mac = hmac.digest
        @mac_size = @mac.length
        
        s=""
        
        @mac.length.times do |i|
          s << @mac[i].to_s + ","
        end
          print "hmac : #{s}\n"
        
      end
      
      def sig_data
        return MessageEncoder.new { |msg|
          msg.put_name(name.downcase)
          msg.put_pack('nN', @klass.code, @ttl)
          print "Alg : #{@algorithm}\n"
          #@TODO@ ALGORITHM IS GOING TO LOWER-CASE!!!
          msg.put_name(@algorithm.downcase)
          
          time_high = (@time_signed >> 32)
          time_low = (@time_signed & 0xFFFFFFFF)
          print "time_signed : #{@time_signed}, high : #{time_high}, low : #{time_low}\n"
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', @fudge)
          print "Fudge : #{@fudge}\n"
          msg.put_pack('n', @error)
          print "Error : #{@error}\n"
          msg.put_pack('n', 0) # no other data
        }.to_s
      end
      
      def self.verify()
        # 3.2. TSIG processing on incoming messages
        #
        #   If an incoming message contains a TSIG record, it MUST be the last
        #   record in the additional section.  Multiple TSIG records are not
        #   allowed.  If a TSIG record is present in any other position, the
        #   packet is dropped and a response with RCODE 1 (FORMERR) MUST be
        #   returned.  Upon receipt of a message with a correctly placed TSIG RR,
        #   the TSIG RR is copied to a safe location, removed from the DNS
        #   Message, and decremented out of the DNS message header's ARCOUNT.  At
        #   this point the keyed message digest operation is performed.  If the
        #   algorithm name or key name is unknown to the recipient, or if the
        #   message digests do not match, the whole DNS message MUST be
        #   discarded.  If the message is a query, a response with RCODE 9
        #   (NOTAUTH) MUST be sent back to the originator with TSIG ERROR 17
        #   (BADKEY) or TSIG ERROR 16 (BADSIG).  If no key is available to sign
        #   this message it MUST be sent unsigned (MAC size == 0 and empty MAC).
        #   A message to the system operations log SHOULD be generated, to warn
        #   the operations staff of a possible security incident in progress.
        #   Care should be taken to ensure that logging of this type of event
        #   does not open the system to a denial of service attack.      
      end
      
      ClassHash[[TypeValue = Types::TSIG, ClassValue = Classes.ANY]] = self #:nodoc: all
      
      #Gets or sets the domain name that specifies the name of the algorithm.
      #The only algorithm currently supported is HMAC-MD5.SIG-ALG.REG.INT.
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
      attr_writer :mac_size
      
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
      attr_writer :error
      
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
      
      def initialize
        @algorithm   = DEFAULT_ALGORITHM
        @time_signed = Time.now.to_i
        @fudge       = DEFAULT_FUDGE
        @mac_size    = 0
        @mac         = ""
        @original_id = 0
        @error       = 0
        @other_size   = 0
        @other_data  = nil
        
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
        #@TODO@ Provide more info?     
        rdatastr=""
        if (@algorithm!=nil)
          error = @error
          error = "UNDEFINED" unless error!=nil
          rdatastr = "#{@algorithm}. #{error}";
          if (@other_size > 0 && @other_data!=nil)
            rdatastr += " #{@other_data}"
          end
        end
        
        return rdatastr
      end
      
      def encode_rdata(msg) #:nodoc: all
        msg.put_name(@algorithm)
        time_high = (@time_signed >> 32)
        time_low = (@time_signed & 0xFFFFFFFF)
        msg.put_pack('nN', time_high, time_low)
        msg.put_pack('n', @fudge)
        msg.put_pack('n', @mac_size)
        msg.put_bytes(@mac)
        msg.put_pack('n', @original_id)
        msg.put_pack('n', @error)
        msg.put_pack('n', @other_size)
        if (@other_size > 0)
          msg.put_bytes(@other_data)
        end
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        alg=msg.get_name
        time_high, time_low = msg.get_unpack("nN")
        time_signed = (timeHigh << 32) + timeLow
        fudge = msg.get_unpack("n")
        mac_size = msg.get_unpack("n")
        mac = msg.get_string
        original_id = msg.get_unpack("n")
        error = msg.get_unpack("n")
        other_size = msg.get_unpack("n")
        other_data=""
        if (other_size > 0)
          other_data = msg.get_bytes(other_size)
        end
        return self.new(alg, time_signed, fudge, mac_size, mac, original_id, error, other_size, other_data)
      end
    end
  end   
end