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
class TestTcp < Test::Unit::TestCase
  def test_TCP
    res = Dnsruby::Resolver.new()
    res.use_tcp = true
    ret=res.query("example.com")
    assert(ret.is_a?(Dnsruby::Message))
  end
  def test_TCP_port
    #@TODO@ Need a test server so we can tell what port this message was actually sent on!
    res = Dnsruby::Resolver.new()
    res.use_tcp = true
    res.src_port=60123
    ret=res.query("example.com")
    assert(ret.is_a?(Dnsruby::Message))
  end
  #@TODO@ Check stuff like persistent sockets
end
