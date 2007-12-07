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
    #RFC4034, section 4
    class NSEC3PARAM < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::NSEC3PARAM #:nodoc: all
      
      #The Hash Algorithm field identifies the cryptographic hash algorithm
      #used to construct the hash-value.
      attr_reader :hash_alg
      #The Flags field contains 8 one-bit flags that can be used to indicate
      #different processing.  All undefined flags must be zero.  The only
      #flag defined by the NSEC3 specification is the Opt-Out flag.
      attr_reader :flags
      #The Iterations field defines the number of additional times the hash
      #function has been performed.
      attr_accessor :iterations
      #The Salt Length field defines the length of the Salt field in octets,
      #ranging in value from 0 to 255.
      attr_reader :salt_length
      #The Salt field is appended to the original owner name before hashing
      #in order to defend against pre-calculated dictionary attacks.
      attr_accessor :salt
      
      def hash_alg=(a)
        if (a.instance_of?String)
          if (a.length == 1)
            a = a.to_i
          end
        end
        begin
          alg = Algorithms.new(a)
          @hash_alg = alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end        
      end
      
      def types=(t)
        @types = NSEC.get_types(t)
      end
      
      def flags=(f)
        if (f==0 || f==1)
          @flags=f
        else
          raise DecodeError.new("Unknown NSEC3 flags field - #{f}")
        end
      end
      
      def salt_length=(l)
        if ((l < 0) || (l > 255))
          raise DecodeError.new("NSEC3 salt length must be between 0 and 255")
        end
        @salt_length = l
      end
      
      def from_data(data) #:nodoc: all
        hash_alg, flags, iterations, salt_length, salt = data
        self.hash_alg=(hash_alg)
        self.flags=(flags)
        self.iterations=(iterations)
        self.salt_length=(salt_length)
        self.salt=(salt)
      end
      
      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.hash_alg=(data[0]).to_i
          self.flags=(data[1]).to_i
          self.iterations=(data[2]).to_i
          self.salt=(data[3])
          self.salt_length=(data[3].length)
        end
      end
      
      def rdata_to_string #:nodoc: all
        if (@next_hashed!=nil)
          return "#{@hash_alg.code} #{@flags} #{@iterations} #{@salt}"
        else
          return ""
        end
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("ccnc", @hash_alg.code, @flags, @iterations, @salt_length)
        msg.put_bytes(@salt)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        hash_alg, flags, iterations, salt_length = msg.get_unpack("ccnc")
        salt = msg.get_bytes(salt_length)
        return self.new(
          [hash_alg, flags, iterations, salt_length, salt])
      end
    end 
  end
end