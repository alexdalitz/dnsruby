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

#= NAME
#
#digitar - Ruby script to perform DNS queries, validated against the IANA TAR
#(trust anchor repository).
#
#= SYNOPSIS
#
#digitar name [ type [ class ] ]
#
#= DESCRIPTION
#
#Performs a DNS query on the given name.  The record type
#and class can also be specified; if left blank they default
#to A and IN. The program firstly performs the requested DNS
# query. The response is then validated
#- the ITAR is searched for the keys of the closest ancestor
#of the query name, and the chain of trust is followed to prove
#that the DNSSEC records are correct, or that we do not expect the
#response to be signed.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#Alex D <alexd@nominet.org.uk>

begin
require 'rubygems'
rescue LoadError
end
require 'dnsruby'
include Dnsruby

raise RuntimeError, "Usage: #{$0} name [ type [ class ] ]\n" unless (ARGV.length >= 1) && (ARGV.length <= 3)

Dnssec.load_itar
res = Dnsruby::Recursor.new
zt=Dnsruby::ZoneTransfer.new
  
  
#    Dnsruby::TheLog.level=Logger::DEBUG

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

  begin
    answer = nil
    answer = res.query(name, type, klass)
    print answer
  rescue Exception => e
    print "query failed: #{e}\n"
  end
end
