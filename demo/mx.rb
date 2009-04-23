require 'dnsruby'

#= NAME
#
#mx - Print a domain's MX records
#
#= SYNOPSIS
#
#mx domain
#
#= DESCRIPTION
#
#mx prints a domain's MX records, sorted by preference.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#(Ruby port AlexD, Nominet UK)
#

if ARGV.length == 1
  dname = ARGV[0]
  res   = Dnsruby::DNS.new
  begin
    res.each_resource(dname, 'MX') { |rr|
      print rr.preference, "\t", rr.exchange, "\n"
    }
  rescue Exception => e
    print "Can't find MX hosts for #{dname}: ", e, "\n"
  end
else
  print "Usage: #{$0} domain\n"
end
