#!/usr/bin/env ruby

require 'dnsruby'
include Dnsruby
GPOS_QUERY_BYTES = "\xE7\u0001\u0001 \u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0001\u0001g\adnsruby\u0003com\u0000\u0000\e\u0000\u0001\u0000\u0000)\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0000"
GPOS_QUERY = Message.decode(GPOS_QUERY_BYTES)
RESPONSE = Resolver.new('127.0.0.1').send_message(GPOS_QUERY)
puts "Query:\n#{GPOS_QUERY}\n\n"
puts "Response:\n#{RESPONSE}\n\n"

