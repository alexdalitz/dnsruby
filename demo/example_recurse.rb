# Example usage for Net::DNS::Resolver::Recurse
# Performs recursion for a query.

require 'dnsruby'

res = Dnsruby::Recursor.new
Dnsruby::TheLog.level = Logger::DEBUG
res.hints=("198.41.0.4") # A.ROOT-SERVER.NET.
packet = res.query_dorecursion("www.rob.com.au.", "A")
print packet.to_s
