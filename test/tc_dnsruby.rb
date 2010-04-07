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
require 'test/unit'
require 'dnsruby'
include Dnsruby
class TestDnsruby < Test::Unit::TestCase
  def test_dnsruby
    a = Resolv.getaddress("www.ruby-lang.org")
    assert_equal(a.to_s, "221.186.184.68")
    a = Resolv.getaddresses("www.ruby-lang.org")
    assert(a.length==1)
    assert_equal(a[0].to_s, "221.186.184.68")
    Resolv.each_address("www.ruby-lang.org") {|address| assert_equal(address, "221.186.184.68")}
    
    n = Resolv.getname("210.251.121.214")
    assert_equal(n, "ci.ruby-lang.org")
    begin
      ret = Resolv.getname("www.ruby-lang.org")
      assert(false, ret)
    rescue Exception => e
      assert(e.kind_of?(ResolvError))
    end
    n = Resolv.getnames("210.251.121.214")
    assert(n.length==1)
    assert_equal(n[0], "ci.ruby-lang.org")
    Resolv.each_name("210.251.121.214") {|name| assert_equal(name, "ci.ruby-lang.org")}
  end
end