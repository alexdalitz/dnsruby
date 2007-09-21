#= NAME
#
#rubydig - Ruby script to perform DNS queries
#
#= SYNOPSIS
#
#rubydig [ @nameserver ] name [ type [ class ] ]
#
#= DESCRIPTION
#
#Performs a DNS query on the given name.  The record type
#and class can also be specified; if left blank they default
#to A and IN.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#

require 'Dnsruby'

res = Dnsruby::Resolver.new
zt=Dnsruby::ZoneTransfer.new
  
if (ARGV && (ARGV[0] =~ /^@/))
  nameserver = ARGV.shift 
  print "Setting nameserver : #{nameserver}\n"
  res.nameserver=(nameserver.sub(/^@/, ""))
  print "nameservers = #{res.config.nameserver}\n"
  zt.server=(nameserver.sub(/^@/, ""))
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

  begin
    answer = res.query(name, type, klass)
    print answer
  rescue Exception => e
    print "query failed: #{e}\n"
  end
end
