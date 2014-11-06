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
# check_zone - Check a DNS zone for errors
# 
# = SYNOPSIS
# 
# check_zone [ -r ] <domain>
# 
# = DESCRIPTION
# 
# Checks a DNS zone for errors.  Current checks are:
# 
# * Checks that all A records have corresponding PTR records.
# 
# * Checks that hosts listed in NS, MX, and CNAME records have
# A records.
# 
# = OPTIONS
# 
# * -r Perform a recursive check on subdomains.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# (Ruby version AlexD, Nominet UK)
# 


require 'dnsruby'
require 'getoptLong'

def check_domain(args)
  domain = args[0]
  klass = "IN"
  if (args.length > 1)
    klass = args[1]
  end
  print "----------------------------------------------------------------------\n"
  print "#{domain} (class #{klass}\n"
  print "\n"

  res = Dnsruby::Resolver.new
  res.retry_times=(2)
  nspack = nil
  begin
    nspack = res.query(domain, "NS", klass)
  rescue Exception => e
    print "Couldn't find nameservers for #{domain}: #{e}\n"
    return
  end

  print "nameservers (will request zone from first available):\n"
  ns=""
  (nspack.answer.select {|r| r.type == "NS"}).each do |ns|
    print "\t", ns.domainname, "\n"
  end
  print "\n"

  res.nameserver= (nspack.answer.select {|i| i.type == "NS"}).collect {|i| i.domainname.to_s}

  zt = Dnsruby::ZoneTransfer.new
  zt.server=(nspack.answer.select {|i| i.type == "NS"}).collect {|i| i.domainname.to_s}
  zone = zt.transfer(domain) # , klass)
  unless (zone)
    print "Zone transfer failed: ", res.errorstring, "\n"
    return
  end

  print "checking PTR records\n"
  check_ptr(domain, klass, zone)
  print "\n"

  print "checking NS records\n"
  check_ns(domain, klass, zone)
  print "\n"

  print "checking MX records\n"
  check_mx(domain, klass, zone)
  print "\n"

  print "checking CNAME records\n"
  check_cname(domain, klass, zone)
  print "\n"

  if (@recurse)
    print "checking subdomains\n\n"
    subdomains = Hash.new
    #           foreach (grep { $_->type eq "NS" and $_->name ne $domain } @zone) {
    (zone.select {|i| i.type == "NS" && i.name != domain}).each do |z|
      subdomains[z.name] = 1
    end
    #           foreach (sort keys %subdomains) {
    subdomains.keys.sort.each do |k|
      check_domain(k, klass)
    end
  end
end

def check_ptr(domain, klass, zone)
  res = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "A" } @zone) {
  (zone.select {|z| z.type == "A"}).each do |rr|
    host = rr.name
    addr = rr.address
    ans= nil
    begin
    ans = res.query(addr.to_s, "A") #, klass)
    print "\t#{host} (#{addr}) has no PTR record\n" if (ans.header.ancount < 1)
    rescue Dnsruby::NXDomain
      print "\t#{host} (#{addr}) returns NXDomain\n"
    end
  end
end

def check_ns(domain, klass, zone)
  res = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "NS" } @zone) {
  (zone.select { |z| z.type == "NS" }).each do |rr|
    ans = res.query(rr.nsdname, "A", klass)
    print "\t", rr.nsdname, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def check_mx(domain, klass, zone)
  res = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "MX" } @zone) {
  zone.select {|z| z.type == "MX"}.each do |rr|
    ans = res.query(rr.exchange, "A", klass)
    print "\t", rr.exchange, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def check_cname(domain, klass, zone)
  res = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "CNAME" } @zone)
  zone.select {|z| z.type == "CNAME"}.each do |rr|
    ans = res.query(rr.cname, "A", klass)
    print "\t", rr.cname, " has no A record\n" if (ans.header.ancount < 1)
  end
end

opts = GetoptLong.new(["-r", GetoptLong::NO_ARGUMENT])
@recurse = false
opts.each do |opt, arg|
  case opt
  when '-r'
    @recurse=true
  end
end

if (ARGV.length >=1 && ARGV.length <=2)

  check_domain(ARGV)
  exit
else
  print "Usage: #{$0} [ -r ] domain [ class ]\n"
end
