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
    #Class for EDNS pseudo resource record OPT.
    #This class is effectively internal to Dnsruby
    #See RFC 2671, RFC 2435 Section 3
    class OPT < RR #:nodoc: all
      ClassValue = nil #:nodoc: all
      TypeValue = Types::OPT #:nodoc: all
      DO_BIT = 0x8000
      attr_accessor :options
      
      # From RFC 2671 :
      # 4.3. The fixed part of an OPT RR is structured as follows:
      #
      #     Field Name   Field Type     Description
      #     ------------------------------------------------------
      #     NAME         domain name    empty (root domain)
      #     TYPE         u_int16_t      OPT
      #     CLASS        u_int16_t      sender's UDP payload size
      #     TTL          u_int32_t      extended RCODE and flags
      #     RDLEN        u_int16_t      describes RDATA
      #     RDATA        octet stream   {attribute,value} pairs
      
      def flags_from_ttl
        if (@ttl)
          return [@ttl].pack("N")
        else
          return [0].pack("N")
        end
      end
      
      def xrcode
        return flags_from_ttl[0, 1].unpack("C")[0]
      end
      
      def xrcode=(code)
        @ttl = (code << 24) + (version() << 16) + flags()
      end
      
      def version
        return flags_from_ttl[1, 1].unpack("C")[0]
      end
      
      def version=(code)
        @ttl = (xrcode() << 24) + (code << 16) + flags()
      end
      
      def flags
        return flags_from_ttl[2, 2].unpack("n")[0]
      end
      
      def flags=(code)
        set_flags(code)
      end
      
      def set_flags(code)
        @ttl = (xrcode() << 24) + (version() << 16) + code
      end
      
      def d_o
        return ((flags() & DO_BIT) == DO_BIT)
      end
      
      def d_o= (on)
        if (on)
          set_flags(flags() | DO_BIT)
        else
          set_flags(flags() & (~DO_BIT))
        end
      end
      
      attr_accessor :class
      
      def payloadsize
        return @class
      end
      
      def payloadsize=(size)
        @class=size
      end
      
      def options(args)
        if (args==nil)
          return @options
        elsif args.kind_of?Fixnum
          #@todo@ return list of options with that code
        end
      end
      
      def from_data(data)
        @options = data
      end
      
      def from_string(input)
        if input
          @options = input.split(" ")
        end
      end
      
      def rdata_to_string
        ret = ""
        if @options
          @options.each do |opt|
            ret = ret + opt.to_s + " "
          end
          ret.chomp!
        end
        return ret
      end
      
      def encode_rdata(msg)
        options.each do |opt|
          msg.pack('n', opt.code)
          msg.pack('n', opt.data.length)
          msg.put_bytes(opt.data)
        end
        msg.put_array(@options)
      end
      
      def self.decode_rdata(msg)
        if (msg.has_remaining)
          options = new ArrayList();
          while (msg.has_remaining) do
            code = msg.unpack('n');
            len = msg.unpack('n');
            data = msg.get_bytes(len);
            options.add(Option.new(code, data));
          end
        end
        return self.new([options])
      end
      
      class Option
        attr_accessor :code, :data
      end
    end
  end
end