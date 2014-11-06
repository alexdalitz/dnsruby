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
# check_soa - Check a domain's nameservers
# 
# = SYNOPSIS
# 
# check_soa domain
# 
# = DESCRIPTION
# 
# check_soa queries each of a domain's nameservers for the Start
# of Authority (SOA) record and prints the serial number.  Errors
# are printed for nameservers that couldn't be reached or didn't
# answer authoritatively.
# 
# = AUTHOR
# 
# The original Bourne Shell and C versions were printed in
# "DNS and BIND" by Paul Albitz & Cricket Liu.
# 
# This Perl version was written by Michael Fuhr <mike@fuhr.org>.
# 
# = SEE ALSO
# 
# axfr, check_zone, mresolv, mx, perldig, Net::DNS

require 'dnsruby'

# ------------------------------------------------------------------------------
# Get the domain from the command line.
# ------------------------------------------------------------------------------

if ARGV.length ==1
  domain = ARGV[0]

  # ------------------------------------------------------------------------------
  #  Find all the nameservers for the domain.
  # ------------------------------------------------------------------------------

  res = Dnsruby::Resolver.new

  #   res.defnames=(0)
  res.retry_times=(2)
  ns_req = nil
  begin
    ns_req = res.query(domain, "NS")
  rescue Exception => e
    print "Error : #{e}"
    return
  end
  if (ns_req.header.ancount == 0)
    print "No nameservers found for #{domain}\n"
    return
  end

  #  Send out non-recursive queries
  res.recurse=(0)


  # ------------------------------------------------------------------------------
  #  Check the SOA record on each nameserver.
  # ------------------------------------------------------------------------------

   (ns_req.answer.select {|r| r.type == "NS"}).each do |nsrr|

    # ----------------------------------------------------------------------
    #  Set the resolver to query this nameserver.
    # ----------------------------------------------------------------------
    ns = nsrr.domainname

    #  In order to lookup the IP(s) of the nameserver, we need a Resolver
    #  object that is set to our local, recursive nameserver.  So we create
    #  a new object just to do that.

    local_res = Dnsruby::Resolver.new
    a_req=nil
    begin
      a_req = local_res.query(ns, 'A')
    rescue Exception => e
      print "Can not find address for #{ns}: #{e}\n"
      next
    end

     (a_req.answer.select {|r| r.type == 'A'}).each do |r|
      ip = r.address
      # ----------------------------------------------------------------------
      #  Ask this IP.
      # ----------------------------------------------------------------------

      res.nameserver=(ip.to_s)

      print "#{ns} (#{ip}): "

      # ----------------------------------------------------------------------
      #  Get the SOA record.
      # ----------------------------------------------------------------------
      soa_req=nil
      begin
        soa_req = res.query(domain, 'SOA', 'IN')
      rescue Exception => e
        print "Error : #{e}\n"
        next
      end

      # ----------------------------------------------------------------------
      #  Is this nameserver authoritative for the domain?
      # ----------------------------------------------------------------------

      unless (soa_req.header.aa)
        print "isn't authoritative for #{domain}\n"
        next
      end

      # ----------------------------------------------------------------------
      #  We should have received exactly one answer.
      # ----------------------------------------------------------------------

      unless (soa_req.header.ancount == 1)
        print "expected 1 answer, got ", soa_req.header.ancount, "\n"
        next
      end

      # ----------------------------------------------------------------------
      #  Did we receive an SOA record?
      # ----------------------------------------------------------------------

      unless ((soa_req.answer)[0].type == "SOA")
        print "expected SOA, got ", (soa_req.answer)[0].type, "\n"
        next
      end

      # ----------------------------------------------------------------------
      #  Print the serial number.
      # ----------------------------------------------------------------------

      print "has serial number ", (soa_req.answer)[0].serial, "\n"
    end
  end
else
  print "Usage: #{$0} domain\n"
end
