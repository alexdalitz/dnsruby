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
require 'socket'
class TestTcp < Test::Unit::TestCase
  def test_TCP
    res = Dnsruby::Resolver.new()
    res.use_tcp = true
    ret=res.query("example.com")
    assert(ret.is_a?(Dnsruby::Message))
  end
  def test_TCP_port
    # Need a test server so we can tell what port this message was actually sent on!
    port = 59125
    src_port = 57923
    Dnsruby::PacketSender.clear_caches
    received_port = nil
    server_thread = Thread.new {
      ts = TCPServer.new(port)
      t = ts.accept
      # Check that the source port was src_port
      received_port = t.peeraddr()[1]
      packet = t.recvfrom(2)[0]

      len = (packet[0]<<8)+packet[1]
      if (RUBY_VERSION >= "1.9")
        len = (packet[0].getbyte(0)<<8)+packet[1].getbyte(0)# Ruby 1.9
      end
      packet = t.recvfrom(len)[0]
      tcpPacket = Dnsruby::Message.decode(packet)
      tcpPacket.header.tc = true
      lenmsg = [tcpPacket.encode.length].pack('n')
      t.send(lenmsg, 0)
      t.write(tcpPacket.encode)
      t.close
      ts.close
    }
    ret = nil
    client_thread = Thread.new {
      res = Dnsruby::SingleResolver.new("127.0.0.1")
      res.port = port
      res.use_tcp = true
      res.src_port=src_port
      ret=res.query("example.com")
    }
    server_thread.join
    client_thread.join
    assert(received_port == src_port)
      assert(ret.is_a?(Dnsruby::Message))
  end
  
  def test_no_tcp
    # Try to get a long response (which is truncated) and check that we have
    # tc bit set
    res = Dnsruby::Resolver.new()
    res.udp_size = 512
    res.no_tcp = true
    ret = res.query("overflow.dnsruby.validation-test-servers.nominet.org.uk", Dnsruby::Types.TXT)
    assert(ret.header.tc, "Message should be truncated with no TCP")
  end

  #@TODO@ Check stuff like persistent sockets
end
