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

require 'dnsruby'
include Dnsruby

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

    dlv_key = RR.create("dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh")
    Dnssec.add_dlv_key(dlv_key)
#    Dnsruby::TheLog.level=Logger::DEBUG
  begin
    answer = res.query(name, type, klass)
    print answer
  rescue Exception => e
    print "query failed: #{e}\n"
  end
end
