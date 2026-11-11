module Dnsruby
  # Shared lexical handling for RR strings and zone-file continuation lines.
  # Character-string escapes remain intact for the record-specific parser.
  module Presentation #:nodoc: all
    def self.scan(text, depth = 0, quoted = false, allow_unbalanced: false)
      result = +''
      escaped = false
      comment = false

      text.each_char.with_index do |char, index|
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
        elsif char == '"'
          result << char
          quoted = !quoted
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
        else
          result << char
        end
      end

      [result, depth, quoted]
    end
  end
  private_constant :Presentation
end
