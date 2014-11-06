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

# = NAME
# 
# rubydig - Ruby script to perform DNS queries
# 
# = SYNOPSIS
# 
# rubydig [ @nameserver ] name [ type [ class ] ]
# 
# = DESCRIPTION
# 
# Performs a DNS query on the given name.  The record type
# and class can also be specified; if left blank they default
# to A and IN.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# 

require 'dnsruby'
include Dnsruby

res = Dnsruby::Resolver.new
zt=Dnsruby::ZoneTransfer.new

if (ARGV && (ARGV[0] =~ /^@/))
  nameserver = ARGV.shift
  if (nameserver == "@auth")
    res = Dnsruby::Recursor.new
  else
  print "Setting nameserver : #{nameserver}\n"
  res.nameserver=(nameserver.sub(/^@/, ""))
  print "nameservers = #{res.config.nameserver}\n"
  zt.server=(nameserver.sub(/^@/, ""))
  end
end

raise RuntimeError, "Usage: #{$0} [ \@nameserver ] name [ type [ class ] ]\n" unless (ARGV.length >= 1) && (ARGV.length <= 3)

name, type, klass = ARGV
type  ||= "A"
klass ||= "IN"

if (type.upcase == "AXFR")
  rrs = zt.transfer(name) # , klass)

  if (rrs)
    rrs.each do |rr|
      print rr.to_s + "\n"
    end
  else
    raise RuntimeError, "zone transfer failed: ", res.errorstring, "\n"
  end

else

#    Dnsruby::TheLog.level=Logger::DEBUG
  begin
    answer = nil
    answer = res.query(name, type, klass)
    print answer
  rescue Exception => e
    print "query failed: #{e}\n"
  end
end
