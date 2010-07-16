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
begin
require 'rubygems'
rescue Exception
end
require 'dnsruby'
Dnsruby.log.level = Logger::FATAL
require "test/unit"
# Disable these tests if we're not online
require 'socket'
sock = UDPSocket.new()
online = false
begin
  sock.connect('193.0.14.129', # k.root-servers.net.
    25)
  online = true
  sock.close
rescue Exception
  puts "----------------------------------------"
  puts "Cannot bind to socket:\n\t"+$!+"\n"
  puts "This is an indication you have network problems\n"
  puts "\n\nNo online tests will be run!!\n\n"
  puts "----------------------------------------"
end
if (online)
  #   OK - online and ready to go
  print "Running online tests. These tests send UDP packets - some may be lost.\n"
  print "If you get the odd timeout error with these tests, try running them again.\n"
  print "It may just be that some UDP packets got lost the first time...\n"
  require "test/tc_resolver.rb"
  require "test/tc_dnsruby.rb"
  #  require "test/tc_inet6.rb"
  #  require "test/tc_recurse.rb"
  require "test/tc_tcp.rb"
#  require "test/tc_queue.rb"
  require "test/tc_recur.rb"
  #  require "test/tc_soak.rb"

  # Check if we can contact the server - if we can't, then abort the test 
  # (but tell user that test has not been run due to connectivity problems)
  server_up = false
  begin
    sock = UDPSocket.new
    sock.connect('ns0.validation-test-servers.nominet.org.uk',
      25)
    sock.close
    server_up = true
  rescue Exception
    puts "----------------------------------------"
    puts "Cannot connect to test server\n\t"+$!+"\n"
    puts "\n\nNo tests targetting this server will be run!!\n\n"
    puts "----------------------------------------"
  end
  if (server_up)

    require "test/tc_single_resolver.rb"
    require "test/tc_axfr.rb"
    require "test/tc_cache.rb"
    require "test/tc_dns.rb"
    require "test/tc_rr-opt.rb"
    require "test/tc_res_config.rb"

    have_openssl = false
    begin
      require "openssl"
      OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, "key", "data")
      key = OpenSSL::PKey::RSA.new
      key.e = 111
      
      have_openssl=true
    rescue Exception => e
      puts "-------------------------------------------------------------------------"
      puts "OpenSSL not present (with full functionality) - skipping TSIG/DNSSEC test"
      puts "-------------------------------------------------------------------------"
    end
    if (have_openssl)
      require "test/tc_tsig.rb"
      puts "------------------------------------------------------"
      puts "Running DNSSEC test - may fail if OpenSSL not complete"
      puts "------------------------------------------------------"      
      require "test/tc_verifier.rb"
      require "test/tc_dlv.rb"
      require "test/tc_validator.rb"
    end

#    have_em = false
#    begin
#      require 'eventmachine'
#      have_em = true
#    rescue LoadError => e
#      puts "----------------------------------------"
#      puts "EventMachine not installed - skipping test"
#      puts "----------------------------------------"
#    end
#    if (have_em)
#      require 'test/tc_event_machine_single_res.rb'
#      require 'test/tc_event_machine_res.rb'
#      require 'test/tc_event_machine_deferrable.rb'
#    end
  end
end
