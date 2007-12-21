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
    class DS < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::DS #:nodoc: all
      
      #The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
      #Algorithm field, a 1 octet Digest Type field, and a Digest field.
      #
      #                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
      # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #|           Key Tag             |  Algorithm    |  Digest Type  |
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #/                                                               /
      #/                            Digest                             /
      #/                                                               /
      #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   

      #The Key Tag field lists the key tag of the DNSKEY RR referred to by
      #the DS record, in network byte order.
      attr_accessor :key_tag
      #The algorithm used for this key
      #See Dnsruby::Algorithms for permitted values
      attr_reader :algorithm
      #The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
      #RR.  The Digest Type field identifies the algorithm used to construct
      #the digest.
      attr_reader :digest_type
      #The DS record refers to a DNSKEY RR by including a digest of that
      #DNSKEY RR.
      attr_accessor :digest
      
      def digest_type=(d)
        if ((d == 1) || (d == "SHA-1") || (d == "1"))
          @digest_type = 1
        else
          raise DecodeError.new("Unsupported DS digest type (#{d})")
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
      
      # Return the digest of the specified DNSKEY RR
      def digest_key(key)
        data = MessageEncoder.new {|msg|
          msg.put_rr(key, true)
        }.to_s

        OpenSSL::Digest::SHA1.new(data)
        return digest

      end
      
      def check_key(key)
        if (key.key_tag == @key_tag)
          # @TODO@ If digests match then add key to trusted keys
          digest = digest_key(key)
          if (@digest == digest)
            if (!key.zone_key?)
            else
              return true
            end
          else
          end
        end
        return false
      end
      

      def from_data(data) #:nodoc: all
        key_tag, algorithm, digest_type, digest = data
        self.key_tag=(key_tag)
        self.algorithm=(algorithm)
        self.digest_type=(digest_type)
        self.digest=(digest)
      end
      
      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.key_tag=(data[0].to_i)
          self.algorithm=(data[1])
          self.digest_type=(data[2])

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
          self.digest=Base64.decode64(buf)
        end
      end
      
      def rdata_to_string #:nodoc: all
        if (@key_tag != nil)
          return "#{@key_tag.to_i} #{@algorithm.string} #{@digest_type} ( #{Base64.encode64(@digest)} )"
        else
          return ""
        end
      end
      
      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("ncc", @key_tag, @algorithm.code, @digest_type)
        msg.put_bytes(@digest)
      end
      
      def self.decode_rdata(msg) #:nodoc: all
        key_tag, algorithm, digest_type = msg.get_unpack("ncc")
        digest = msg.get_bytes
        return self.new(
          [key_tag, algorithm, digest_type, digest])
      end
    end 
  end
end