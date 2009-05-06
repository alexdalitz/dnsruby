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
    #The NSEC3 Resource Record (RR) provides authenticated denial of
    #existence for DNS Resource Record Sets.
    #
    #The NSEC3 RR lists RR types present at the original owner name of the
    #NSEC3 RR.  It includes the next hashed owner name in the hash order
    #of the zone.  The complete set of NSEC3 RRs in a zone indicates which
    #RRSets exist for the original owner name of the RR and form a chain
    #of hashed owner names in the zone.  This information is used to
    #provide authenticated denial of existence for DNS data.  To provide
    #protection against zone enumeration, the owner names used in the
    #NSEC3 RR are cryptographic hashes of the original owner name
    #prepended as a single label to the name of the zone.  The NSEC3 RR
    #indicates which hash function is used to construct the hash, which
    #salt is used, and how many iterations of the hash function are
    #performed over the original owner name.
    class NSEC3 < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::NSEC3 #:nodoc: all
      
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
      #The Hash Length field defines the length of the Next Hashed Owner
      #Name field, ranging in value from 1 to 255 octets.
      attr_reader :hash_length
      #The Next Hashed Owner Name field contains the next hashed owner name
      #in hash order.        
      attr_accessor :next_hashed
      #The Type Bit Maps field identifies the RRset types that exist at the
      #NSEC RR's owner name
      attr_reader :types
      
      def check_name_in_range(name)
        # @TODO@ Check if the name is covered by this record
        return false
      end

      def check_name_in_wildcard_range(name)
        # @TODO@ Check if the name is covered by this record
        return false
      end

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
      
      def add_type(t)
        self.types=(@types + [t])
      end
      
      def flags=(f)
        if (f==0 || f==1)
          @flags=f
        else
          raise DecodeError.new("Unknown NSEC3 flags field - #{f}")
        end
      end
      
      #If the Opt-Out flag is set, the NSEC3 record covers zero or more
      #unsigned delegations.
      def opt_out?
        return (@flags==1)
      end
      
      def salt_length=(l)
        if ((l < 0) || (l > 255))
          raise DecodeError.new("NSEC3 salt length must be between 0 and 255")
        end
        @salt_length = l
      end
      
      def hash_length=(l)
        if ((l < 0) || (l > 255))
          raise DecodeError.new("NSEC3 hash length must be between 0 and 255")
        end
        @hash_length = l        
      end
   
      def from_data(data) #:nodoc: all
        hash_alg, flags, iterations, salt_length, salt, hash_length, next_hashed, types = data
        self.hash_alg=(hash_alg)
        self.flags=(flags)
        self.iterations=(iterations)
        self.salt_length=(salt_length)
        self.salt=(salt)
        self.hash_length=(hash_length)
        self.next_hashed=(next_hashed)
        self.types=(types)
      end
      
      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.hash_alg=(data[0]).to_i
          self.flags=(data[1]).to_i
          self.iterations=(data[2]).to_i
          self.salt=(data[3])
          self.salt_length=(data[3].length)
          self.next_hashed=(data[5])
          self.hash_length=(data[5].length)
          len = data[0].length + data[1].length + data[2].length + data[3].length + data[5].length + 7
          self.types=(input[len, input.length-len])
        end
      end
      
      def rdata_to_string #:nodoc: all
        if (@next_hashed!=nil)
          type_strings = []
          @types.each do |t|
            type_strings.push(t.string)
          end
          types = type_strings.join(" ")
          return "#{@hash_alg.code} #{@flags} #{@iterations} #{@salt} ( #{@next_hashed} #{types} )"
        else
          return ""
        end
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("ccnc", @hash_alg.code, @flags, @iterations, @salt_length)
        msg.put_bytes(@salt)
        msg.put_pack("c", @hash_length)
        msg.put_bytes(@next_hashed)
        types = NSEC.encode_types(self)
        msg.put_bytes(types)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        hash_alg, flags, iterations, salt_length = msg.get_unpack("ccnc")
        salt = msg.get_bytes(salt_length)
        hash_length, = msg.get_unpack("c")
        next_hashed = msg.get_bytes(hash_length)
        types = NSEC.decode_types(msg.get_bytes)
        return self.new(
          [hash_alg, flags, iterations, salt_length, salt, hash_length, next_hashed, types])
      end
    end 
  end
end