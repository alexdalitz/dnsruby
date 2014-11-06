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
# digitar - Ruby script to perform DNS queries, validated against the IANA TAR
# (trust anchor repository).
# 
# = SYNOPSIS
# 
# digroot name [ type [ class ] ]
# 
# = DESCRIPTION
# 
# Performs a DNS query on the given name.  The record type
# and class can also be specified; if left blank they default
# to A and IN. The program firstly performs the requested DNS
# query. The response is then validated from the signed root.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# Alex D <alexd@nominet.org.uk>

begin
require 'rubygems'
rescue LoadError
end
require 'dnsruby'
include Dnsruby

raise RuntimeError, "Usage: #{$0} name [ type [ class ] ]\n" unless (ARGV.length >= 1) && (ARGV.length <= 3)

resolver = Dnsruby::Resolver.new()
resolver.do_validation = true
res = Dnsruby::Recursor.new(resolver)

#    Dnsruby::TheLog.level=Logger::DEBUG

name, type, klass = ARGV
type  ||= "A"
klass ||= "IN"

  begin
    answer = nil
    answer = res.query(name, type, klass)
    print answer
  rescue Exception => e
    print "query failed: #{e}\n"
  end
