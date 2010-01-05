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
    #Class for DNS Naming Authority Pointer (NAPTR) resource records.
    #RFC 2168
    class NAPTR < RR
      ClassValue = nil #:nodoc: all
      TypeValue= Types::NAPTR #:nodoc: all
      
      # The NAPTR RR order field      
      attr_accessor :order
      # The NAPTR RR preference field      
      attr_accessor :preference
      # The NAPTR RR flags field      
      attr_accessor :flags
      # The NAPTR RR service field      
      attr_accessor :service
      # The NAPTR RR regexp field      
      attr_accessor :regexp
      # The NAPTR RR replacement field      
      attr_accessor :replacement
      
      def from_hash(hash) #:nodoc: all
        @order = hash[:order]
        @preference = hash[:preference]
        @flags  = hash[:flags]
        @service = hash[:service]
        @regexp = hash[:regexp]
        @replacement = Name.create(hash[:replacement])
      end
      
      def from_data(data) #:nodoc: all
        @order,  @preference, @flags, @service, @regexp, @replacement = data
      end
      
      def from_string(input) #:nodoc: all
        if (input.length > 0)
          values = input.split(" ")
          @order = values [0].to_i
          @preference = values [1].to_i
          @flags = values [2].gsub!("\"", "")
          @service = values [3].gsub!("\"", "")
          re = values [4].gsub!("\"", "")
          re.gsub!("\\\\", "\\")
          @regexp = re
          @replacement = Name.create(values[5])
        end
      end

      def rdata_to_string #:nodoc: all
        if (@order!=nil)
          ret =  "#{@order} #{@preference} \"#{@flags}\" \"#{@service}\" \""
          ##{@regexp}
          @regexp.each_byte {|b|
            c = b.chr
            if (c == "\\")
              ret += "\\"
            end
            ret += c
          }
          ret += "\" #{@replacement}"
          return ret
        else
          return ""
        end
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('n', @order)
        msg.put_pack('n', @preference)
        msg.put_string(@flags)
        msg.put_string(@service)
        msg.put_string(@regexp)
        msg.put_name(@replacement, true)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        order, = msg.get_unpack('n')
        preference, = msg.get_unpack('n')
        flags = msg.get_string
        service = msg.get_string
        regexp = msg.get_string
        replacement = msg.get_name
        return self.new([order, preference, flags, service, regexp, replacement])
      end
    end
  end
end	    