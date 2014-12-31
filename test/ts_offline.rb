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

require_relative 'spec_helper'

Dnsruby.log.level = Logger::FATAL

require_relative 'tc_gpos.rb'
require_relative 'tc_header.rb'
require_relative "tc_name.rb"
require_relative 'tc_message.rb'
require_relative "tc_misc.rb"
require_relative "tc_hash.rb"
require_relative "tc_packet.rb"
require_relative "tc_packet_unique_push.rb"
require_relative "tc_question.rb"
require_relative "tc_res_file.rb"
require_relative "tc_res_opt.rb"
require_relative "tc_res_config.rb"
# require_relative "tc_res_env.rb"
require_relative "tc_rr-txt.rb"
require_relative "tc_rr-unknown.rb"
require_relative "tc_rr.rb"
require_relative "tc_rrset.rb"
require_relative "tc_tkey.rb"
require_relative "tc_update.rb"
require_relative "tc_escapedchars.rb"
require_relative "tc_dnskey.rb"
require_relative "tc_rrsig.rb"
require_relative "tc_nsec.rb"
require_relative "tc_nsec3.rb"
require_relative "tc_nsec3param.rb"
require_relative "tc_ipseckey.rb"
require_relative "tc_naptr.rb"

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
    require_relative "tc_ds.rb"
end
