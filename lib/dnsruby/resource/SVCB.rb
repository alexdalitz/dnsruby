require 'base64'

module Dnsruby
  class RR
    # Class for DNS Service Binding (SVCB) resource records.
    #
    # RFC 9460
    #
    # The presentation format is:
    #   Name TTL Class SVCB SvcPriority TargetName SvcParams
    #
    # A SvcPriority of 0 is AliasMode, where TargetName aliases the service to
    # another name; non-zero is ServiceMode, where the SvcParams describe the
    # endpoint.
    #
    # RR.create also takes a Hash, whose :params values are in presentation
    # format -- the text a zone file carries after the "=". #params_to_hash is
    # the inverse of that Hash.
    class SVCB < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::SVCB #:nodoc: all

      # The registered SvcParamKey mnemonics: 0-4 and 6 from RFC 9460, 5 (ech)
      # from RFC 9848, 7 (dohpath) from RFC 9461, 8 (ohttp) from RFC 9540 sec 4
      # and 10 (docpath) from RFC 9953 sec 3. Keys whose value format is not
      # yet published as an RFC are left out, and read and write as keyNNNNN.
      KEY_NAME_TO_NUM = {
        'mandatory'       => 0,
        'alpn'            => 1,
        'no-default-alpn' => 2,
        'port'            => 3,
        'ipv4hint'        => 4,
        'ech'             => 5,
        'ipv6hint'        => 6,
        'dohpath'         => 7,
        'ohttp'           => 8,
        'docpath'         => 10,
      }.freeze

      # The same table by number, for naming a key in presentation format and
      # in error messages. A number with no mnemonic here becomes keyNNNNN.
      KEY_NUM_TO_NAME = KEY_NAME_TO_NUM.invert.freeze

      # Keys whose presentation format requires a SvcParamValue. An empty
      # docpath means the root path, and an unknown key may stand alone.
      KEYS_REQUIRING_VALUE = [0, 1, 3, 4, 5, 6, 7].freeze

      # Keys defined to carry no value at all: no-default-alpn and ohttp.
      KEYS_FORBIDDING_VALUE = [2, 8].freeze

      # RFC 9460 sec 14.3.2 reserves 65535 as an invalid SvcParamKey.
      INVALID_KEY = 0xffff

      # The SvcPriority field (0-65535). Zero indicates AliasMode.
      attr_reader :priority

      # Sets the SvcPriority, raising DecodeError unless the value is an
      # integer in 0..65535.
      def priority=(value)
        @priority = to_uint16(value, 'SvcPriority')
      end

      # The TargetName field, a Dnsruby::Name.
      attr_accessor :target

      # The SvcParams, an ordered Hash mapping the numeric SvcParamKey to the
      # SvcParamValue in wire format. See #params_to_hash for a readable view.
      attr_accessor :params

      def from_hash(hash) #:nodoc: all
        self.priority = hash[:priority] if hash[:priority]
        @target = Name.create(hash[:target]) if hash[:target]
        @params = {}
        if hash[:params]
          hash[:params].each do |key, value|
            store_param(key.to_s,
                        value.nil? ? nil : decode_presentation_value(value.to_s))
          end
        end
        validate_svcparams(@priority, @params)
        check_complete_pair
      end

      def from_data(data) #:nodoc: all
        @priority, @target, @params = data
      end

      def from_string(input) #:nodoc: all
        @params = {}
        return if input.nil? || input.strip.empty?

        tokens = split_svcparams(input.strip)
        self.priority = tokens.shift
        target = tokens.shift
        # Name.create(nil) would raise ArgumentError, not DecodeError.
        raise DecodeError.new('SVCB record expects a TargetName after the SvcPriority') if target.nil?

        @target = Name.create(target)

        tokens.each do |token|
          key, eq, value = token.partition('=')
          store_param(key, eq.empty? ? nil : decode_presentation_value(value))
        end
        validate_svcparams(@priority, @params)
      end

      def rdata_to_string #:nodoc: all
        return '' if @priority.nil? || @target.nil?

        params_to_hash.inject(+"#{@priority} #{@target.to_s(true)}") do |s, (name, value)|
          s << (value.nil? ? " #{name}" : " #{name}=#{value}")
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        # An RRset delete (RFC 2136 sec 2.5.2) names the type with no RDATA at
        # all, which is what Update#delete builds; domain_name.rb does the same.
        if @priority.nil? && @target.nil?
          return if [Classes::NONE, Classes::ANY].include?(klass)
        end

        if @priority.nil? || @target.nil?
          raise EncodeError.new('SVCB record needs both a SvcPriority and a ' \
                                "TargetName, got #{@priority.inspect} and #{@target.inspect}")
        end

        msg.put_pack('n', @priority)
        # RFC 9460 sec 2.2: the TargetName MUST NOT be compressed. RFC 6840 sec
        # 5.1: nor downcased for DNSSEC, SVCB post-dating RFC 4034.
        msg.put_name(@target, true, false)
        sorted_params.each do |num, value|
          msg.put_pack('n', num)
          msg.put_pack('n', value.bytesize)
          msg.put_bytes(value)
        end
      end

      def self.decode_rdata(msg) #:nodoc: all
        # The reading half of the empty record above.
        return new([nil, nil, {}]) unless msg.has_remaining?

        priority, = msg.get_unpack('n')
        target = msg.get_name
        params = {}
        last_key = nil
        while msg.has_remaining?
          key, length = msg.get_unpack('nn')
          if last_key && key <= last_key
            raise DecodeError.new('SvcParams must be in strictly increasing key order without duplicates')
          end
          last_key = key
          # get_bytes returns what is there, so a length past the end would end
          # this loop short. Message.decode catches that at the RDLENGTH
          # boundary; RR.new_from_data, decoding RDATA alone, has none.
          value = msg.get_bytes(length).to_s # nil past the end of the buffer
          if value.bytesize != length
            raise DecodeError.new("SvcParamValue for #{num_to_key(key)} is truncated: " \
                                  "#{length} octets declared, #{value.bytesize} present")
          end
          validate_param_value(key, value)
          params[key] = value
        end
        validate_svcparams(priority, params)
        new([priority, target, params])
      end

      # Returns the SvcParams as a Hash mapping the mnemonic (or "keyNNNNN") to
      # its presentation-format value, nil for a value-less key.
      def params_to_hash
        sorted_params.each_with_object({}) do |(num, value), result|
          result[num_to_key(num)] = decode_param_value(num, value)
        end
      end

      private

      # RFC 9460 sec 2.2: the SvcParams are written in increasing key order.
      def sorted_params
        (@params || {}).sort_by(&:first)
      end

      # Neither field at all is the empty record above, which stays allowed.
      def check_complete_pair
        return if @priority.nil? == @target.nil?

        given, missing = @priority.nil? ? %w[target priority] : %w[priority target]
        raise DecodeError.new("SVCB record given a #{given} but no #{missing}; both are mandatory")
      end

      # RFC 9460 sec 2.1 forbids a duplicate key.
      def store_param(key, value)
        num = key_to_num(key)
        if @params.key?(num)
          raise DecodeError.new("duplicate SvcParamKey: #{num_to_key(num)}")
        end
        # RFC 9460 sec 2.1: keyNNNNN uses the generic character-string form,
        # even when that number has a known mnemonic. Its decoded octets are
        # already wire format, rather than input for the mnemonic's codec.
        if key.downcase.start_with?('key')
          wire = value.to_s.b
          validate_param_value(num, wire)
          @params[num] = wire
        else
          @params[num] = encode_param_value(num, value)
        end
      end

      # The presentation <-> wire codec for the SvcParams, needed by
      # .decode_rdata and by the instance methods alike. Extended and included
      # so that the one `private` above covers both scopes.
      module Codec #:nodoc: all
        private

        # Translates a mnemonic or "keyNNNNN" token to its number. RFC 9460 sec
        # 2.1 writes that number without leading zeros, so key01 is not alpn.
        def key_to_num(key)
          key = key.downcase
          return KEY_NAME_TO_NUM[key] if KEY_NAME_TO_NUM.key?(key)
          if (m = /\Akey(0|[1-9]\d*)\z/.match(key))
            num = m[1].to_i
            raise DecodeError.new("SvcParamKey out of range: #{key}") if num > 0xffff
            if num == INVALID_KEY
              raise DecodeError.new("SvcParamKey #{INVALID_KEY} is reserved as invalid")
            end
            return num
          end
          raise DecodeError.new("Unknown SvcParamKey: #{key.inspect}")
        end

        def num_to_key(num)
          KEY_NUM_TO_NAME[num] || "key#{num}"
        end

        # String#to_i and pack('n') fail silently: "99999" becomes 34463.
        def to_uint16(value, field)
          text = value.to_s.strip
          unless /\A\d+\z/.match?(text) && text.to_i <= 0xffff
            raise DecodeError.new("#{field} must be an integer in 0..65535, got #{value.inspect}")
          end
          text.to_i
        end

        # Splits the SvcParams into whitespace-separated tokens, keeping
        # double-quoted sections (which may contain spaces) intact and treating
        # a backslash as escaping the octet after it.
        def split_svcparams(str)
          # Checked first: on an unterminated quote the scan below silently
          # splits the value at its spaces instead.
          if unterminated_quote?(str)
            raise DecodeError.new("unterminated quoted SvcParamValue in #{str.inspect}")
          end

          str.scan(/(?:"(?:\\.|[^"\\])*"|\\.|[^\s"])+/m)
        end

        # Drops the escaped octets, then an odd number of quotes is left open.
        def unterminated_quote?(str)
          str.gsub(/\\./m, '').count('"').odd?
        end

        # Runs before the per-key encoding -- see the value-list note below.
        def decode_presentation_value(value)
          unescape_char_string(unquote(value))
        end

        def unquote(value)
          if value.length >= 2 && value.start_with?('"') && value.end_with?('"')
            value[1...-1]
          else
            value
          end
        end

        # Resolves the backslash escapes of a character-string (\X and \DDD
        # decimal), in octets, so a multibyte character becomes the octets it
        # stands for.
        def unescape_char_string(str)
          str = str.b
          result = +''.b
          i = 0
          while i < str.length
            c = str[i]
            if c == '\\'
              # RFC 1035 sec 5.1: the backslash escapes the octet after it.
              raise DecodeError.new("escape at end of #{str.inspect} has nothing to escape") if
                i + 1 >= str.length

              nxt = str[i + 1]
              if nxt =~ /\d/
                # \DDD is exactly three digits, and stands for one octet.
                unless str[i + 1, 3] =~ /\A\d{3}\z/
                  raise DecodeError.new("escape #{str[i, 4].inspect} must be three digits")
                end
                octet = str[i + 1, 3].to_i
                if octet > 0xff
                  raise DecodeError.new("escape \\#{str[i + 1, 3]} is not an octet value")
                end
                result << octet.chr
                i += 4
              else
                result << nxt
                i += 2
              end
            elsif c == '"'
              # The surrounding quotes came off in unquote, so this one is data.
              raise DecodeError.new("unescaped double quote in SvcParamValue #{str.inspect}")
            else
              result << c
              i += 1
            end
          end
          result
        end

        # Escapes raw octets into a presentation character-string. Four printable
        # characters need escaping in an unquoted value: the quote delimits a
        # character-string, a semicolon starts a comment, and parentheses group
        # a record across lines. The numeric form handles them all uniformly.
        def escape_char_string(str)
          result = +''
          str.each_byte do |b|
            if b == 0x5c # backslash
              result << '\\\\'
            elsif b <= 0x20 || b > 0x7e ||          # non-printable or space
                  b == 0x22 || b == 0x3b ||         # " and ;
                  b == 0x28 || b == 0x29            # ( and )
              result << format('\\%03d', b)
            else
              result << b.chr
            end
          end
          result
        end

        # RFC 9460 Appendix A: "Decoding of value-lists happens after
        # character-string decoding", so the only escapes reaching the three
        # methods below are the "\," and "\\" that layer leaves behind.

        def split_value_list(str)
          str = str.b
          items = []
          current = +''.b
          i = 0
          while i < str.length
            c = str[i]
            if c == '\\' && i + 1 < str.length
              current << str[i + 1]
              i += 2
            elsif c == ','
              items << current
              current = +''.b
              i += 1
            else
              current << c
              i += 1
            end
          end
          items << current
          items
        end

        # Splits a value-list, rejecting the empty item a leading, trailing or
        # doubled comma leaves behind. No SvcParamValue list admits one.
        def value_list_items(num, value)
          items = split_value_list(value)
          if items.any?(&:empty?)
            raise DecodeError.new(
              "SvcParamValue for #{num_to_key(num)} must not contain an empty item")
          end
          items
        end

        def join_value_list(items)
          items.map do |item|
            escaped = +''.b
            item.to_s.each_byte do |b|
              escaped << '\\' if b == 0x5c || b == 0x2c # backslash or comma
              escaped << b.chr
            end
            escaped
          end.join(',')
        end

        # Packs a value-list of address text into an address hint. IPv4.create
        # and IPv6.create raise ArgumentError rather than DecodeError, and the
        # key already names the family their message would.
        def join_addresses(num, value, klass)
          value_list_items(num, value).map do |text|
            klass.create(text).address
          rescue ArgumentError
            raise DecodeError.new(
              "SvcParamValue for #{num_to_key(num)} is not an address: #{text.inspect}")
          end.join
        end

        # True when single-octet-length-prefixed items exactly tile the value,
        # none of them empty -- the format shared by alpn and docpath. An empty
        # value tiles trivially.
        def length_prefixed_tile?(bytes)
          i = 0
          while i < bytes.bytesize
            len = bytes.getbyte(i)
            return false if len.zero? || i + 1 + len > bytes.bytesize
            i += 1 + len
          end
          true
        end

        def pack_length_prefixed(num, items)
          items.map do |item|
            # pack('C') would truncate a longer item to a zero-length one and
            # shift every item after it.
            if item.bytesize > 0xff
              raise DecodeError.new("#{num_to_key(num)} item must be at most 255 " \
                                    "octets, got #{item.bytesize}")
            end
            [item.bytesize].pack('C') + item
          end.join
        end

        # Counts in octets: see #decode_param_value.
        def unpack_length_prefixed(bytes)
          items = []
          i = 0
          while i < bytes.bytesize
            len = bytes.getbyte(i)
            items << bytes.byteslice(i + 1, len)
            i += 1 + len
          end
          items
        end

        # Rejects a value whose length does not fit the shape its key defines,
        # which the decoders below would truncate or pad. Unlisted keys take
        # any octets.
        def validate_param_value(num, bytes)
          if num == INVALID_KEY
            raise DecodeError.new("SvcParamKey #{INVALID_KEY} is reserved as invalid")
          end

          size = bytes.bytesize
          expected =
            case num
            when 0 # mandatory
              'a non-empty, even number of octets' unless size.positive? && size.even?
            when 1, 10 # alpn, docpath
              # Zero docpath segments is the root path (RFC 9953 sec 3).
              unless length_prefixed_tile?(bytes) && (num == 10 || size.positive?)
                'a sequence of non-empty length-prefixed items'
              end
            when *KEYS_FORBIDDING_VALUE
              'empty' unless size.zero?
            when 3 # port
              'exactly 2 octets' unless size == 2
            when 4, 6 # ipv4hint, ipv6hint
              width = num == 4 ? 4 : 16
              "a non-empty multiple of #{width} octets" unless size.positive? && (size % width).zero?
            when 5, 7 # ech, dohpath
              'non-empty' unless size.positive?
            end
          return if expected.nil?

          raise DecodeError.new(
            "SvcParamValue for #{num_to_key(num)} must be #{expected}, got #{size} octets")
        end

        def validate_svcparams(priority, params)
          validate_mandatory_value(params)
          validate_self_consistency(priority, params)
        end

        # RFC 9460 sec 8 on the mandatory list itself: it names "valid"
        # SvcParamKeys, must not name itself, must not repeat a key, and must be
        # in strictly increasing wire order. These describe one SvcParamValue,
        # so they hold in either mode.
        def validate_mandatory_value(params)
          bytes = params[0]
          return if bytes.nil?

          keys = bytes.unpack('n*')
          raise DecodeError.new('mandatory must not list itself') if keys.include?(0)
          if keys.include?(INVALID_KEY)
            raise DecodeError.new("mandatory must not list key #{INVALID_KEY}, " \
                                  'which sec 14.3.2 reserves as invalid')
          end
          unless keys.uniq.length == keys.length
            raise DecodeError.new('mandatory must not list a key more than once')
          end
          # Mnemonic presentation format is unordered and the encoder sorts
          # it. Wire input and generic key0 presentation must already be sorted.
          unless keys == keys.sort
            raise DecodeError.new('mandatory keys must be in strictly increasing order, got ' \
                                  "#{keys.map { |k| num_to_key(k) }.join(', ')}")
          end
        end

        # RFC 9460 sec 2.4.3: a ServiceMode RR is self-consistent when its
        # SvcParams meet each other's requirements. Sec 8 gives mandatory one,
        # and sec 7.1.1 gives no-default-alpn another. Sec 2.4.2 has recipients
        # ignore an AliasMode RR's SvcParams, so neither applies at priority 0.
        def validate_self_consistency(priority, params)
          return if priority.nil? || priority.zero?

          if params.key?(2) && !params.key?(1)
            raise DecodeError.new('no-default-alpn requires alpn')
          end

          keys = params[0]&.unpack('n*') || []
          missing = keys.reject { |k| params.key?(k) }
          return if missing.empty?

          raise DecodeError.new("mandatory lists #{missing.map { |k| num_to_key(k) }.join(', ')}, " \
                                'which the record does not contain')
        end

        # Converts a SvcParamValue whose character-string escapes are already
        # resolved (a String, or nil for a value-less key) into wire-format
        # octets.
        def encode_param_value(num, value)
          if KEYS_FORBIDDING_VALUE.include?(num)
            # An explicitly empty value encodes to the same nothing.
            unless value.nil? || value.empty?
              raise DecodeError.new("SvcParamValue for #{num_to_key(num)} must be empty")
            end
            return ''.b
          end
          if value.nil? && KEYS_REQUIRING_VALUE.include?(num)
            raise DecodeError.new("#{num_to_key(num)} requires a SvcParamValue")
          end

          wire =
            case num
            when 0 # mandatory
              value_list_items(num, value).map { |k| key_to_num(k) }.sort.
                map { |k| [k].pack('n') }.join
            when 1, 10 # alpn, docpath
              # The root path must not reach value_list_items, which rejects an
              # empty item.
              items = value.nil? || value.empty? ? [] : value_list_items(num, value)
              pack_length_prefixed(num, items)
            when 3 # port
              [to_uint16(value, 'port')].pack('n')
            when 4 # ipv4hint
              join_addresses(num, value, IPv4)
            when 5 # ech
              # Base64.decode64 discards anything outside the alphabet.
              begin
                Base64.strict_decode64(value)
              rescue ArgumentError
                raise DecodeError.new(
                  "SvcParamValue for ech must be base64, got #{value.inspect}")
              end
            when 6 # ipv6hint
              join_addresses(num, value, IPv6)
            else # dohpath and unknown keys
              value.to_s
            end

          # dohpath and unknown keys hand the value straight back, and from_hash
          # can pass in UTF-8, which MessageEncoder#put_bytes would reject.
          wire = wire.b

          # Applied here too, so a zone file cannot build a record that
          # .decode_rdata would refuse.
          validate_param_value(num, wire)
          wire
        end

        # Converts a SvcParamValue into presentation format, or nil for a key
        # written without one. The value normally arrives from the wire, but
        # #params is public, so it may be any String the caller assigned, which
        # is why the branches below work in octets rather than characters.
        def decode_param_value(num, bytes)
          case num
          when 0 # mandatory
            join_value_list(bytes.unpack('n*').map { |k| num_to_key(k) })
          when 1, 10 # alpn, docpath
            # Alone among the value-lists, these items are arbitrary octets, so
            # they need the character-string layer. Empty is the docpath root
            # path, and RFC 9460 Appendix A has no empty char-string, so it
            # stands alone. alpn is never empty.
            unless bytes.empty?
              escape_char_string(join_value_list(unpack_length_prefixed(bytes)))
            end
          when *KEYS_FORBIDDING_VALUE
            nil
          when 3 # port
            bytes.unpack1('n').to_s
          when 4 # ipv4hint
            # .b: String#scan and IPv4/IPv6::new count characters.
            join_value_list(bytes.b.scan(/.{4}/m).map { |a| IPv4.new(a).to_s })
          when 5 # ech
            Base64.strict_encode64(bytes)
          when 6 # ipv6hint
            join_value_list(bytes.b.scan(/.{16}/m).map { |a| IPv6.new(a).to_s_canonical })
          else # dohpath and unknown keys
            bytes.empty? ? nil : escape_char_string(bytes)
          end
        end
      end
      private_constant :Codec
      extend Codec
      include Codec
    end
  end
end
