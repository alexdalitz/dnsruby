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
rescue LoadError
end
require 'dnsruby'
Dnsruby.log.level = Logger::FATAL
require "test/unit"
require "test/tc_header.rb"
require "test/tc_name.rb"
require "test/tc_misc.rb"
require "test/tc_packet.rb"
require "test/tc_packet_unique_push.rb"
require "test/tc_question.rb"
require "test/tc_res_file.rb"
require "test/tc_res_opt.rb"
require "test/tc_res_config.rb"
#require "test/tc_res_env.rb"
require "test/tc_rr-txt.rb"
require "test/tc_rr-unknown.rb"
require "test/tc_rr.rb"
require "test/tc_rrset.rb"
require "test/tc_tkey.rb"
require "test/tc_update.rb"
require "test/tc_escapedchars.rb"
require "test/tc_dnskey.rb"
require "test/tc_rrsig.rb"
require "test/tc_nsec.rb"
require "test/tc_nsec3.rb"
require "test/tc_nsec3param.rb"
require "test/tc_ipseckey.rb"
require "test/tc_naptr.rb"

begin
  require "openssl"
  OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, "key", "data")
  key = OpenSSL::PKey::RSA.new
  key.e = 111
      
  have_openssl=true
rescue Exception => e
    puts "-----------------------------------------------------------------------"
    puts "OpenSSL not present (with full functionality) - skipping DS digest test"
    puts "-----------------------------------------------------------------------"
end
if (have_openssl)
    require "test/tc_ds.rb"
end
