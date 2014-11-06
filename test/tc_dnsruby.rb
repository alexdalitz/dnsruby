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

include Dnsruby
class TestDnsruby < Minitest::Test
  def test_dnsruby
    a = Resolv.getaddress("google-public-dns-a.google.com.")
    assert_equal(a.to_s, "8.8.8.8")
    a = Resolv.getaddresses("google-public-dns-a.google.com.")
    if (a.length == 1) 
      assert(a.length==1, a.to_s + " should only have one response. Had " + a.length.to_s)
      assert(a.any? {|s| s.to_s == ("8.8.8.8")})
      Resolv.each_address("google-public-dns-a.google.com.") {|address| assert_equal(address, "8.8.8.8")}
    else 
      assert(a.length==2, a.to_s + " should have had two responses. Had " + a.length.to_s)
      assert(a.any? {|s| s.to_s == ("8.8.8.8")})
      assert(a.any? {|s| s.to_s == ("2001:4860:4860::8888")})
      Resolv.each_address("google-public-dns-a.google.com.") {|address|
        assert((address == "8.8.8.8") || (address = "2001:4860:4860::8888")) }
    end

    n = Resolv.getname("8.8.8.8")
    assert_equal(n, "google-public-dns-a.google.com")
    begin
      ret = Resolv.getname("google-public-dns-a.google.com.")
      assert(false, ret)
    rescue Exception => e
#      assert(e.kind_of?(ResolvError))
      assert(e.kind_of?(Resolv::ResolvError), "Error was a #{e.class}: #{e}")
    end
    n = Resolv.getnames("8.8.8.8")
    assert(n.length==1)
    assert_equal(n[0], "google-public-dns-a.google.com")
    Resolv.each_name("8.8.8.8") {|name| assert_equal(name, "google-public-dns-a.google.com")}
  end
end