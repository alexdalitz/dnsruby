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

require 'dnsruby'

# = NAME
# 
# mx - Print a domain's MX records
# 
# = SYNOPSIS
# 
# mx domain
# 
# = DESCRIPTION
# 
# mx prints a domain's MX records, sorted by preference.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# (Ruby port AlexD, Nominet UK)
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
