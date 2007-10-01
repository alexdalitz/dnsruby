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
require 'Dnsruby/select_thread'
require 'Dnsruby/event_machine_interface'
module Dnsruby
  #== Dnsruby::SingleResolver
  #
  # The SingleResolver class targets a single resolver, and controls the sending of a single 
  # packet with a packet timeout. It performs no retries. Only two threads are used - the client 
  # thread and a select thread (which is reused across all queries).
  # 
  #== Methods
  # 
  #=== Synchronous
  #These methods raise an exception or return a response message with rcode==NOERROR
  #
  #*  Dnsruby::SingleResolver#send_message(msg [, use_tcp]))
  #*  Dnsruby::SingleResolver#query(name [, type [, klass]])
  #
  #=== Asynchronous
  #These methods use a response queue to return the response and the error
  #
  #*  Dnsruby::SingleResolver#send_async(msg, query_id, response_queue [, use_tcp])
  #
  class SingleResolver
    attr_accessor :packet_timeout
    
    # The port on the resolver to send queries to.
    # 
    # Defaults to 53
    attr_accessor :port
    
    # Use TCP rather than UDP as the transport.
    # 
    # Defaults to false
    attr_accessor :use_tcp
    
    attr_accessor :tsig_key
    
    # Don't worry if the response is truncated - return it anyway.
    # 
    # Defaults to false
    attr_accessor :ignore_truncation
    
    # The source address to send queries from
    # 
    # Defaults to localhost
    attr_accessor :src_address
    # The source port to send queries from
    # 
    # Defaults to 0 - random port
    attr_accessor :src_port
    
    # Should the TCP socket persist between queries?
    # 
    # Defaults to false
    attr_accessor :persistent_tcp
    
    # Should the UDP socket persist between queries?
    # 
    # Defaults to false
    attr_accessor :persistent_udp
    
    # should the Recursion Desired bit be set on queries?
    # 
    # Defaults to true
    attr_accessor :recurse
    
    # The max UDP packet size
    # 
    # Defaults to 512
    attr_accessor :udp_size
    
    # The address of the resolver to send queries to
    attr_reader :server
    
    def udp_size=(size)
      @udp_size = size
    end
    
    def server=(server)
      TheLog.debug("SingleResolver setting server to #{server}")
      @server=Config.resolve_server(server)
    end
    
    # Can take a hash with the following optional keys : 
    # 
    # * :server
    # * :port
    # * :use_tcp
    # * :ignore_truncation
    # * :src_addr
    # * :src_port
    # * :udp_size
    # * :persistent_tcp
    # * :persistent_udp
    # * :tsig_key
    # * :packet_timeout
    # * :recurse
    def initialize(*args)
      arg=args[0]
      @packet_timeout = Resolver::DefaultPacketTimeout
      @port = Resolver::DefaultPort
      @udp_size = Resolver::DefaultUDPSize
      @use_tcp = false
      @tsig_key = nil
      @ignore_truncation = false
      @src_addr        = '0.0.0.0'
      @src_port        = 0
      @recurse = true
      @persistent_udp = false
      @persistent_tcp = false
      
      if (arg==nil)
        # Get default config
        config = Config.new
        @server = config.nameserver[0]
      elsif (arg.kind_of?String)
        @server=arg
      elsif (arg.kind_of?Hash)
        arg.keys.each do |attr|
          begin
            send(attr.to_s+"=", arg[attr])
          rescue Exception
            TheLog.error("Argument #{attr} not valid\n")
          end
          #        end
        end
      end
      #Check server is IP
      @server=Config.resolve_server(@server)
      
    end
    
    def close
      # @TODO@ What about closing?
    end
    
    # Synchronously send a query for the given name. The type will default to A, 
    # and the class to IN.
    def query(name, type=Types.A, klass=Classes.IN)
      msg = Message.new
      msg.header.rd = 1
      msg.add_question(name, type, klass)
      return send_message(msg)
    end
    
    
    # Synchronously send a Message to the server. If a valid response is returned, 
    # then that is returned to the client. Otherwise a ResolvError or ResolvTimeout 
    # will be thrown. 
    # 
    # Takes the message to send, and an optional use_tcp parameter which defaults to
    # SingleResolver.use_tcp
    def send_message(msg, use_tcp=@use_tcp)
      q = Queue.new
      send_async(msg, q, q, use_tcp)
      id, msg, error = q.pop
      if (error != nil)
        raise error
      else
        return msg
      end
    end
    
    
    # Asynchronously send a Message to the server. A client_queue is supplied by the client, 
    # along with a client_query_id to identify the response. When the response is known, the tuple
    # (query_id, response_message, response_exception) is put in the queue for the client to process. 
    # 
    # The query is sent synchronously in the caller's thread. The select thread is then used to 
    # listen for and process the response (up to pushing it to the client_queue). The client thread 
    # is then used to retrieve the response and deal with it.
    # 
    # Takes :
    # 
    # * msg - the message to send
    # * client_query_id - an ID to identify the query to the client
    # * client_queue - a Queue to push the response to, when it arrives
    # * use_tcp - whether to use TCP (defaults to SingleResolver.use_tcp)
    #
    #
    # If EventMachine is being used (see Dnsruby::Resolver::use_eventmachine, then this method returns
    # an EM::Deferrable object
    #
    # If the native Dsnruby networking layer is being used, then this method returns the client_query_id
    # @TODO@ Need to turn round the queue and id here, so that nil ID can be passed in.
    #    deferrable = res.send_async(msg)
    #    id = res.send_async(msg, queue)
    #    res.send(msg, queue, id, true)
    def send_async(msg, client_query_id, client_queue, use_tcp=@use_tcp)
      if (msg.kind_of?String)
        msg = Message.new(msg)
      end
      query_packet = make_query_packet(msg)
      if (udp_packet_size < query_packet.length)
        use_tcp = true
      end
      #@TODO@ Are we using EventMachine or native Dnsruby?
      if (Resolver.eventmachine?)
        return send_eventmachine(query_packet, msg.header.id, client_query_id, client_queue, use_tcp)
      else
        send_dnsruby(query_packet, msg.header.id, client_query_id, client_queue, use_tcp)
      end
    end
      
    def send_eventmachine(msg, header_id, client_query_id, client_queue, use_tcp) #:nodoc: all
#        em = EventMachineInterface.instance
#        return em.send(:msg=>msg, :header_id=>header_id, :client_query_id=>client_query_id, :client_queue=>client_queue, :timeout=>@packet_timeout, :server=>@server, :port=>@port, :src_addr=>@src_addr, :src_port=>@src_port, :tsig_key=>@tsig_key, :ignore_truncation=>@ignore_truncation, :use_tcp=>use_tcp)
        return EventMachineInterface.send(:msg=>msg, :header_id=>header_id, :client_query_id=>client_query_id, :client_queue=>client_queue, :timeout=>@packet_timeout, :server=>@server, :port=>@port, :src_addr=>@src_addr, :src_port=>@src_port, :tsig_key=>@tsig_key, :ignore_truncation=>@ignore_truncation, :use_tcp=>use_tcp)
    end

    def send_dnsruby(query_packet, header_id, client_query_id, client_queue, use_tcp) #:nodoc: all
      endtime = Time.now + @packet_timeout
      # First send the query (synchronously)
      # @TODO@ persisent sockets
      st = SelectThread.instance
      socket = nil
      begin
        #@TODO@ Different OSes have different interpretations of "random port" here.
        #Apparently, Linux will just give you the same port as last time, unless it is still
        #open, in which case you get n+1.
        #We need to determine an actual (random) number here, then ask the OS for it, and
        #continue until we get one.
        if (use_tcp) 
          print "Setting src_port to #{@src_port}"
          socket = TCPSocket.new(@server, @port, @src_addr, @src_port)
        else
          socket = UDPSocket.new()
          socket.bind(@src_addr, @src_port)
          socket.connect(@server, @port)
        end
      rescue Exception => e
        if (socket!=nil)
          socket.close
        end
        err=IOError.new("dnsruby can't connect to #{@server}:#{@port} from #{@src_addr}:#{@src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e}")
        TheLog.error("#{err}")
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end
      if (socket==nil)
        err=IOError.new("dnsruby can't connect to #{@server}:#{port} from #{@src_addr}:#{@src_port}, use_tcp=#{use_tcp}")
        TheLog.error("#{err}")
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end
      TheLog.debug("Sending packet to #{@server}:#{@port} from #{@src_addr}:#{@src_port}, use_tcp=#{use_tcp}")
      begin
        if (use_tcp)
          lenmsg = [query_packet.length].pack('n')
          socket.send(lenmsg, 0)
        end
        socket.send(query_packet, 0)
      rescue Exception => e
        socket.close
        err=IOError.new("Send failed to #{@server}:#{@port} from #{@src_addr}:#{@src_port}, use_tcp=#{use_tcp}, exception : #{e}")
        TheLog.error("#{err}")
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end
      
      # Then listen for the response
      query_settings = SelectThread::QuerySettings.new(query_packet, header_id, @tsig_key, @ignore_truncation, client_queue, client_query_id, socket, @server, @port, endtime)
      # The select thread will now wait for the response and send that or a timeout
      # back to the client_queue
      st.add_to_select(query_settings)
    end
    
    # Prepare the packet for sending
    def make_query_packet(packet) #:nodoc: all
      if (packet.header.opcode == OpCode.QUERY || @recurse)
        packet.header.rd=true
      end
      
      if (@dnssec)
        # RFC 3225
        TheLog.debug(";; Adding EDNS extention with UDP packetsize #{udp_packet_size} and DNS OK bit set\n")
        
        optrr = Resource.create({
            :type         => 'OPT',
            :name         => '',
            :rrclass        => udp_packet_size,  # Decimal UDPpayload
            :ednsflags    => 0x8000, # first bit set see RFC 3225 
          })
        
        packet.add_additional(optrr)
        
      elsif (udp_packet_size > Resolver::DefaultUDPSize)
        TheLog.debug(";; Adding EDNS extention with UDP packetsize  #{udp_packet_size}.\n")
        # RFC 3225
        optrr = Resource.create( {
            :type         => 'OPT',
            :name         => '',
            :rrclass        => udp_packet_size,  # Decimal UDPpayload
            :ttl          => 0x0000 # RCODE 32bit Hex
          })
        
        packet.add_additional(optrr)
      end
      
      if (@tsig_key)
        @tsig_key.apply(packet)
      end
      # @TODO@ TSIG!!!      
      #      if (@tsig_rr != nil && @tsig_rr.length > 0)
      #        #          if (!grep { $_.type == 'TSIG' } packet.additional)
      #        if (packet.additional.select { |i| i.type == 'TSIG' }.length > 0)
      #          packet.push('additional', @tsig_rr)
      #        end
      #      end
      
      #      TheLog.debug("#{packet}")
      return packet.encode
    end
    
    # Return the packet size to use for UDP
    def udp_packet_size
      # if @udp_size > DefaultUDPSize then we use EDNS and 
      # @udp_size should be taken as the maximum packet_data length
      ret = (@udp_size > Resolver::DefaultUDPSize ? @udp_size : Resolver::DefaultUDPSize) 
      return ret
    end
  end
end