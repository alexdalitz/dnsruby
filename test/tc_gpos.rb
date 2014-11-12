require_relative 'spec_helper'

require 'dnsruby'
include Dnsruby

# ";nil" added temporarily for ease of use when pasting into irb/pry.

GPOS_QUERY_BYTES = "\xE7\u0001\u0001 \u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0001\u0001g\adnsruby\u0003com" +
    "\u0000\u0000\e\u0000\u0001\u0000\u0000)\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0000"; nil

GPOS_QUERY = Message.decode(GPOS_QUERY_BYTES); nil

# RESPONSE = Resolver.new('127.0.0.1').send_message(GPOS_QUERY); nil

RESPONSE_BINARY = "\xE7\x01\x85\x90\x00\x01\x00\x01\x00\x01\x00\x01\x01g\adnsruby\x03com" +
    "\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\t:\x80\x00\x0F\x0420.0\x0430.0\x0410.0" +
    "\xC0\x0E\x00\x02\x00\x01\x00\t:\x80\x00\x05\x02ns\xC0\x0E\xC0F\x00\x01\x00\x01\x00" +
    "\t:\x80\x00\x04\xC0\xA8\x01\n"; nil

RESPONSE = Message.decode(RESPONSE_BINARY); nil

def test_answer_is_a_gpos
  answer = RESPONSE.answer[0]
  assert answer.is_a?(RR::GPOS)
end

# puts "Query:\n#{GPOS_QUERY}\n\n"
# puts "Response:\n#{RESPONSE}\n\n"


