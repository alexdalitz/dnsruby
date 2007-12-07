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
require 'shellwords'
module Dnsruby
  class RR
    #Class for DNS Text (TXT) resource records.
    #RFC 1035 Section 3.3.14
    class TXT < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::TXT #:nodoc: all
      
      #List of the individual elements
      attr_accessor :strings
      
      def data
        @strings[0]
      end
      
      def from_data(data)
        @strings = data
      end
      
      def from_hash(hash)
        if (hash.has_key?:strings)
          from_string(hash[:strings])
        end
      end
      
      def from_string(input)
        words = Shellwords.shellwords(input)
        
        @strings=[]
        
        if (words != nil)
          words.each { |string|
            string .gsub!(/\\"/, '"')
            @strings.push(string)
          }
        end
      end
      
      def rdata_to_string
        if (defined?@strings)
          temp = @strings.map {|str|
            str.gsub(/"/, '\\"')
              %<"#{str}">
          }
          return temp.join(' ')
        end          
        return ''
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_string_list(@strings)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        strings = msg.get_string_list
        return self.new(strings)
      end
    end
  end
end