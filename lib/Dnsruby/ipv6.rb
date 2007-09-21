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
#== Dnsruby::IPv6 class
#=== class methods
#* Dnsruby::IPv6.create(address)
#
#=== methods
#* Dnsruby::IPv6#to_s
#* Dnsruby::IPv6#to_name
#
#=== constants
#* Dnsruby::IPv6::Regex
#    regular expression for IPv6 address.
#    
  class IPv6
    Regex_8Hex = /\A
     (?:[0-9A-Fa-f]{1,4}:){7}
    [0-9A-Fa-f]{1,4}
    \z/x
    
    Regex_CompressedHex = /\A
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
    \z/x
    
    Regex_6Hex4Dec = /\A
     ((?:[0-9A-Fa-f]{1,4}:){6,6})
     (\d+)\.(\d+)\.(\d+)\.(\d+)
    \z/x
    
    Regex_CompressedHex4Dec = /\A
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
     ((?:[0-9A-Fa-f]{1,4}:)*)
     (\d+)\.(\d+)\.(\d+)\.(\d+)
    \z/x
    
    Regex = /
     (?:#{Regex_8Hex}) |
     (?:#{Regex_CompressedHex}) |
     (?:#{Regex_6Hex4Dec}) |
     (?:#{Regex_CompressedHex4Dec})/x
     
     def self.create(arg)
      case arg
      when IPv6
        return arg
      when String
        address = ''
        if Regex_8Hex =~ arg
          arg.scan(/[0-9A-Fa-f]+/) {|hex| address << [hex.hex].pack('n')}
        elsif Regex_CompressedHex =~ arg
          prefix = $1
          suffix = $2
          a1 = ''
          a2 = ''
          prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
          suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
          omitlen = 16 - a1.length - a2.length
          address << a1 << "\0" * omitlen << a2
        elsif Regex_6Hex4Dec =~ arg
          prefix, a, b, c, d = $1, $2.to_i, $3.to_i, $4.to_i, $5.to_i
          if (0..255) === a && (0..255) === b && (0..255) === c && (0..255) === d
            prefix.scan(/[0-9A-Fa-f]+/) {|hex| address << [hex.hex].pack('n')}
            address << [a, b, c, d].pack('CCCC')
          else
            raise ArgumentError.new("not numeric IPv6 address: " + arg)
          end
        elsif Regex_CompressedHex4Dec =~ arg
          prefix, suffix, a, b, c, d = $1, $2, $3.to_i, $4.to_i, $5.to_i, $6.to_i
          if (0..255) === a && (0..255) === b && (0..255) === c && (0..255) === d
            a1 = ''
            a2 = ''
            prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
            suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
            omitlen = 12 - a1.length - a2.length
            address << a1 << "\0" * omitlen << a2 << [a, b, c, d].pack('CCCC')
          else
            raise ArgumentError.new("not numeric IPv6 address: " + arg)
          end
        else
          raise ArgumentError.new("not numeric IPv6 address: " + arg)
        end
        return IPv6.new(address)
      else
        raise ArgumentError.new("cannot interpret as IPv6 address: #{arg.inspect}")
      end
    end
    
    def initialize(address)
      unless address.kind_of?(String) && address.length == 16
        raise ArgumentError.new('IPv6 address must be 16 bytes')
      end
      @address = address
    end
    attr_reader :address
    
    def to_s
      address = sprintf("%X:%X:%X:%X:%X:%X:%X:%X", *@address.unpack("nnnnnnnn"))
      unless address.sub!(/(^|:)0(:0)+(:|$)/, '::')
        address.sub!(/(^|:)0(:|$)/, '::')
      end
      return address
    end
    
    def inspect
      return "#<#{self.class} #{self.to_s}>"
    end
    
    def to_name
      # ip6.arpa should be searched too. [RFC3152]
      return Name.create(
#                           @address.unpack("H32")[0].split(//).reverse + ['ip6', 'arpa'])
                           @address.unpack("H32")[0].split(//).reverse.join(".") + ".ip6.arpa")
    end
    
    def ==(other)
      return @address == other.address
    end
    
    def eql?(other)
      return self == other
    end
    
    def hash
      return @address.hash
    end
  end
end