# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  # Dnsruby::IPv6 class
  class IPv6
    # IPv6 address format a:b:c:d:e:f:g:h
    Regex_8Hex = /\A
     (?:[0-9A-Fa-f]{1,4}:){7}
    [0-9A-Fa-f]{1,4}
    \z/x

    # Compresses IPv6 format a::b
    Regex_CompressedHex = /\A
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
    \z/x

    #  IPv4 mapped IPv6 address format a:b:c:d:e:f:w.x.y.z
    Regex_6Hex4Dec = /\A
     ((?:[0-9A-Fa-f]{1,4}:){6,6})
     (\d+)\.(\d+)\.(\d+)\.(\d+)
    \z/x

    #  Compressed IPv4 mapped IPv6 address format a::b:w.x.y.z
    Regex_CompressedHex4Dec = /\A
     ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
     ((?:[0-9A-Fa-f]{1,4}:)*)
     (\d+)\.(\d+)\.(\d+)\.(\d+)
    \z/x

    #  A composite IPv6 address RegExp
    Regex = /
     (?:#{Regex_8Hex}) |
     (?:#{Regex_CompressedHex}) |
     (?:#{Regex_6Hex4Dec}) |
     (?:#{Regex_CompressedHex4Dec})/x

    #  Created a new IPv6 address from +arg+ which may be:
    # 
    # * IPv6:: returns +arg+
    # * String:: +arg+ must match one of the IPv6::Regex* constants
    def self.create(arg)
      case arg
      when IPv6
        return arg
      when String
        address = +''
        if Regex_8Hex =~ arg
          arg.scan(/[0-9A-Fa-f]+/) {|hex| address << [hex.hex].pack('n')}
        elsif Regex_CompressedHex =~ arg
          prefix = $1
          suffix = $2
          a1 = +''
          a2 = +''
          prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
          suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
          omitlen = 16 - a1.length - a2.length
          raise ArgumentError, "not numeric IPv6 address: #{arg}" unless omitlen > 0
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
            a1 = +''
            a2 = +''
            prefix.scan(/[0-9A-Fa-f]+/) {|hex| a1 << [hex.hex].pack('n')}
            suffix.scan(/[0-9A-Fa-f]+/) {|hex| a2 << [hex.hex].pack('n')}
            omitlen = 12 - a1.length - a2.length
            raise ArgumentError, "not numeric IPv6 address: #{arg}" unless omitlen > 0
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

    def initialize(address) #:nodoc:
      unless address.kind_of?(String) && address.length == 16
        raise ArgumentError.new('IPv6 address must be 16 bytes')
      end
      @address = address
    end

    #  The raw IPv6 address as a String
    attr_reader :address

    # The historical Dnsruby representation, retained for callers that compare
    # address strings. Use #to_s_canonical for RFC 5952 formatting.
    def to_s
      text = sprintf("%X:%X:%X:%X:%X:%X:%X:%X", *@address.unpack("n8"))
      unless text.sub!(/(^|:)0(:0)+(:|$)/, '::')
        text.sub!(/(^|:)0(:|$)/, '::')
      end
      text
    end

    # The RFC 5952 canonical text representation of the address, opt-in.
    def to_s_canonical
      fields = @address.unpack("n8")

      #  RFC 5952 section 5: an address carrying an embedded IPv4 address
      #  under the well-known ::ffff:0:0/96 prefix is written in the mixed
      #  hexadecimal / dotted decimal notation.
      if fields[0, 5].all?(&:zero?) && fields[5] == 0xffff
        return "::ffff:" + fields[6, 2].pack("n2").unpack("C4").join(".")
      end

      #  RFC 5952 section 4.2.3: "::" replaces the longest run of consecutive
      #  all-zero fields, and the first such run when several are equally long.
      #  Section 4.2.2: a run of a single all-zero field is never replaced.
      run_start = nil
      best_start, best_length = nil, 1
      fields.each_with_index do |field, i|
        if field == 0
          run_start ||= i
          length = i - run_start + 1
          best_start, best_length = run_start, length if length > best_length
        else
          run_start = nil
        end
      end

      #  RFC 5952 sections 4.1 and 4.3: no leading zeros, and lowercase hex
      strings = fields.map {|field| field.to_s(16)}
      if best_start
        strings[best_start, best_length] = ['']
        strings.unshift('') if best_start == 0
        strings.push('') if best_start + best_length == fields.length
      end
      return strings.join(':')
    end

    def inspect #:nodoc:
      return "#<#{self.class} #{self.to_s}>"
    end

    # Turns this IPv6 address into a Dnsruby::Name
    # --
    #  ip6.arpa should be searched too. [RFC3152]
    def to_name
      return Name.create(
        #                            @address.unpack("H32")[0].split(//).reverse + ['ip6', 'arpa'])
        @address.unpack("H32")[0].split(//).reverse.join(".") + ".ip6.arpa")
    end

    def ==(other) #:nodoc:
      return @address == other.address
    end

    def eql?(other) #:nodoc:
      return self == other
    end

    def hash
      return @address.hash
    end
  end
end
