module Dnsruby
  # Shared lexical handling for RR strings and zone-file continuation lines.
  # Character-string escapes remain intact for the record-specific parser.
  module Presentation #:nodoc: all
    # TXT (and its SPF subclass) historically also accept single quotes. Do
    # not extend that convention to domain names or other RDATA formats, where
    # an apostrophe is an ordinary character. Return the end of the type token
    # so that even a leading apostrophe in the owner cannot open a TXT string.
    def self.single_quoted_start(text, owner_omitted: false)
      # Grouping parentheses can touch the type (TXT('value')), while an
      # escaped parenthesis in the owner remains part of that owner's token.
      fields = []
      position = 0
      while fields.length < 4 && (field = /\G[\s()]*((?:\\.|[^\s()])+)/m.match(text, position))
        fields << [field[1], field.end(0)]
        position = field.end(0)
      end
      fields.shift unless owner_omitted
      fields.shift if fields.first&.first&.match?(/\A\d/)
      if fields.first&.first&.match?(/\A(?:#{Classes.regexp}|CLASS\d+)\z/i)
        fields.shift
      end
      fields.first.last if %w[TXT SPF TYPE16 TYPE99].include?(fields.first&.first&.upcase)
    end

    def self.scan(text, depth = 0, quoted = false, allow_unbalanced: false,
                  single_quoted_from: nil)
      result = +''
      escaped = false
      comment = false
      quoted = '"' if quoted == true
      just_closed_quote = false

      text.each_char.with_index do |char, index|
        after_quote = just_closed_quote
        just_closed_quote = false
        if comment
          next unless char == "\n"
          comment = false
        end

        if escaped
          result << char
          escaped = false
        elsif char == '\\'
          result << char
          escaped = true
        elsif char == '"' || (single_quoted_from && index >= single_quoted_from && char == "'" &&
              (quoted == "'" || (!quoted && (after_quote || index.zero? || /[\s(]/.match?(text[index - 1])))))
          result << char
          if quoted == char
            quoted = false
            just_closed_quote = true
          elsif !quoted
            quoted = char
          end
        elsif !quoted && char == ';'
          comment = true
        elsif !quoted && (char == '(' || char == ')')
          depth += char == '(' ? 1 : -1
          if depth.negative? && !allow_unbalanced
            raise DecodeError.new('Unmatched closing parenthesis in record')
          end
          # Parentheses separate tokens when neither neighbor is whitespace.
          # Preserve existing spacing otherwise; some older RR parsers use
          # offsets into the original RDATA rather than whitespace tokens.
          if !result.empty? && /\S/.match?(result[-1]) &&
             text[index + 1] && /\S/.match?(text[index + 1])
            result << ' '
          end
        elsif !quoted && (char == "\n" || char == "\r")
          # A physical line break outside a quoted value is layout, not an
          # octet in a TXT string or part of an RFC3597 hexadecimal value.
          result << ' '
        else
          result << char
        end
      end

      [result, depth, quoted]
    end
  end
  private_constant :Presentation
end
