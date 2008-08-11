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
  #These methods use a response queue, or an EventMachine::Deferrable
  #to return the response and the error to the client. See Dnsruby::Resolver for 
  #details of how to enable the EventMachine implementation.
  #More information about the EventMachine implementation is available in the 
  #EVENTMACHINE file in the Dnsruby distribution
  #
  #*  Dnsruby::SingleResolver#send_async(...)
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
    
    # The TSIG record to sign/verify messages with
    attr_reader :tsig
    
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
    attr_reader :udp_size
    
    # The address of the resolver to send queries to
    attr_reader :server
    
    # Use DNSSEC for this SingleResolver
    attr_reader :dnssec
    
    #Sets the TSIG to sign outgoing messages with.
    #Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    #Pass in nil to stop tsig signing.
    #It is possible for client code to sign packets prior to sending - see
    #Dnsruby::RR::TSIG#apply and Dnsruby::Message#sign
    #Note that pre-signed packets will not be signed by SingleResolver.
    #* res.tsig=(tsig_rr)
    #* res.tsig=(key_name, key)
    #* res.tsig=nil # Stop the resolver from signing
    def tsig=(*args)
      @tsig = SingleResolver.get_tsig(args)
    end
    
    MIN_DNSSEC_UDP_SIZE = 1220
    
    def dnssec=(on)
      @dnssec=on
      if (on)
        # Set the UDP size (RFC 4035 section 4.1)
        if (udp_packet_size < MIN_DNSSEC_UDP_SIZE)
          self.udp_size = MIN_DNSSEC_UDP_SIZE
        end
      end
    end
    
    def SingleResolver.get_tsig(args)
      tsig = nil
      if (args.length == 1)
        if (args[0])
          if (args[0].instance_of?RR::TSIG)
            tsig = args[0]
          elsif (args[0].instance_of?Array)
            tsig = RR.new_from_hash({:type => Types.TSIG, :klass => Classes.ANY, :name => args[0][0], :key => args[0][1]})
          end
        else
          Dnsruby.log.info{"TSIG signing switched off"}
          return nil
        end
      elsif (args.length ==2)
        tsig = RR.new_from_hash({:type => Types.TSIG, :klass => Classes.ANY, :name => args[0], :key => args[1]})
      else
        raise ArgumentError.new("Wrong number of arguments to tsig=")
      end
      Dnsruby.log.info{"TSIG signing now using #{tsig.name}, key=#{tsig.key}"}
      return tsig
    end
    
    def udp_size=(size)
      @udp_size = size
    end
    
    def server=(server)
      Dnsruby.log.debug{"SingleResolver setting server to #{server}"}
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
    # * :tsig
    # * :packet_timeout
    # * :recurse
    def initialize(*args)
      arg=args[0]
      @packet_timeout = Resolver::DefaultPacketTimeout
      @port = Resolver::DefaultPort
      @udp_size = Resolver::DefaultUDPSize
      @use_tcp = false
      @tsig = nil
      @ignore_truncation = false
      @src_addr        = '0.0.0.0'
      @src_port        = 0
      @recurse = true
      @persistent_udp = false
      @persistent_tcp = false
      @dnssec = true
      
      seen_dnssec = false
      
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
            if (attr.to_s == "dnssec")
                seen_dnssec = true
            end
          rescue Exception
            Dnsruby.log.error{"Argument #{attr} not valid\n"}
          end
        #        end
        end
      end
      if (!seen_dnssec) 
        @dnssec = true
      end
      #Check server is IP
      @server=Config.resolve_server(@server)
      
    end
    
    def close
      # @TODO@ What about closing?
      # Any queries to complete? Sockets to close?
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
      send_async(msg, q, Time.now + rand(1000000), use_tcp)
      id, reply, error = q.pop
      if (error != nil)
        raise error
      else
        return reply
      end
    end
    
    
    #Asynchronously send a Message to the server. The send can be done using just
    #Dnsruby, or using EventMachine.
    # 
    #== Dnsruby pure Ruby event loop :
    # 
    #A client_queue is supplied by the client, 
    #along with an optional client_query_id to identify the response. The client_query_id
    #is generated, if not supplied, and returned to the client.
    #When the response is known, the tuple
    #(query_id, response_message, response_exception) is put in the queue for the client to process. 
    # 
    #The query is sent synchronously in the caller's thread. The select thread is then used to 
    #listen for and process the response (up to pushing it to the client_queue). The client thread 
    #is then used to retrieve the response and deal with it.
    # 
    #Takes :
    # 
    #* msg - the message to send
    #* client_queue - a Queue to push the response to, when it arrives
    #* client_query_id - an optional ID to identify the query to the client
    #* use_tcp - whether to use TCP (defaults to SingleResolver.use_tcp)
    # 
    #Returns :
    # 
    #* client_query_id - to identify the query response to the client. This ID is
    #generated if it is not passed in by the client
    #
    #If the native Dsnruby networking layer is being used, then this method returns the client_query_id
    # 
    #    id = res.send_async(msg, queue)
    #    NOT SUPPORTED : id = res.send_async(msg, queue, use_tcp)
    #    id = res.send_async(msg, queue, id)
    #    id = res.send_async(msg, queue, id, use_tcp)
    #
    #== If EventMachine is being used :
    # 
    #If EventMachine is being used (see Dnsruby::Resolver::use_eventmachine),then this method returns
    #an EM::Deferrable object. If a queue (and ID) is passed in, then the response will also be 
    #pushed to the Queue (as well as the deferrable completing).
    #
    #    deferrable = res.send_async(msg)
    #    deferrable = res.send_async(msg, use_tcp)
    #    deferrable = res.send_async(msg, q, id, use_tcp)
    def send_async(*args) # msg, client_queue, client_query_id, use_tcp=@use_tcp)
      # @TODO@ Need to select a good Header ID here - see forgery-resilience RFC draft for details
      msg = args[0]
      client_query_id = nil
      client_queue = nil
      use_tcp = @use_tcp
      if (msg.kind_of?String)
        msg = Message.new(msg)
      end
      query_packet = make_query_packet(msg, use_tcp)
      if (udp_packet_size < query_packet.length)
        Dnsruby.log.debug{"Query packet length exceeds max UDP packet size - using TCP"}
        use_tcp = true
      end
      if (args.length > 1)
        if (args[1].class==Queue)
          client_queue = args[1]
        elsif (args.length == 2)
          use_tcp = args[1]
        end
        if (args.length > 2)
          client_query_id = args[2]
          if (args.length > 3)
            use_tcp = args[3]
          end
        end
      end
      # Need to keep track of the request mac (if using tsig) so we can validate the response (RFC2845 4.1)
      #Are we using EventMachine or native Dnsruby?
      if (Resolver.eventmachine?)
        return send_eventmachine(query_packet, msg, client_query_id, client_queue, use_tcp)
      else
        if (!client_query_id)
          client_query_id = Time.now + rand(10000) # is this safe?!
        end
        send_dnsruby(query_packet, msg, client_query_id, client_queue, use_tcp)
        return client_query_id
      end
    end

    # This method sends the packet using EventMachine
    def send_eventmachine(msg_bytes, msg, client_query_id, client_queue, use_tcp, client_deferrable=nil, packet_timeout = @packet_timeout) #:nodoc: all
      start_time = Time.now
      if (!client_deferrable)
        client_deferrable = EventMachine::DefaultDeferrable.new
      end
      packet_deferrable = EventMachineInterface.send(:msg=>msg_bytes, :timeout=>packet_timeout, :server=>@server, :port=>@port, :src_addr=>@src_addr, :src_port=>get_next_src_port, :use_tcp=>use_tcp)
      packet_deferrable.callback { |response, response_bytes|
        ret = true
        if (response.header.tc && !use_tcp && !@ignore_truncation)
          # Try to resend over tcp
          Dnsruby.log.debug{"Truncated - resending over TCP"}
          send_eventmachine(msg_bytes, msg, client_query_id, client_queue, true, client_deferrable, packet_timeout - (Time.now-start_time))
        else
          if (!check_tsig(msg, response, response_bytes))
            send_eventmachine(msg_bytes, msg, client_query_id, client_queue, true, client_deferrable, packet_timeout - (Time.now-start_time))
            return
          end
          client_deferrable.set_deferred_status :succeeded, response
          if (client_queue)
            client_queue.push([client_query_id, response, nil])
          end
        end
      }
      packet_deferrable.errback { |response, error|
        client_deferrable.set_deferred_status :failed, response, error
        if (client_queue)
          client_queue.push([client_query_id, response, error])
        end
      }
      return client_deferrable
    end

    # This method sends the packet using the built-in pure Ruby event loop, with no dependencies.
    def send_dnsruby(query_bytes, query, client_query_id, client_queue, use_tcp) #:nodoc: all
      endtime = Time.now + @packet_timeout
      # First send the query (synchronously)
      # @TODO@ persisent sockets
      st = SelectThread.instance
      socket = nil
      begin
        src_port = get_next_src_port
        if (use_tcp) 
          socket = TCPSocket.new(@server, @port, @src_addr, src_port)
        else
          socket = UDPSocket.new()
          socket.bind(@src_addr, src_port)
          socket.connect(@server, @port)
        end
      rescue Exception => e
        if (socket!=nil)
          socket.close
        end
        err=IOError.new("dnsruby can't connect to #{@server}:#{@port} from #{@src_addr}:#{src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e}")
        Dnsruby.log.error{"#{err}"}
        st.push_exception_to_select(client_query_id, client_queue, err, nil) # @TODO Do we still need this? Can we not just send it from here?
        return
      end
      if (socket==nil)
        err=IOError.new("dnsruby can't connect to #{@server}:#{@port} from #{@src_addr}:#{src_port}, use_tcp=#{use_tcp}")
        Dnsruby.log.error{"#{err}"}
        st.push_exception_to_select(client_query_id, client_queue, err, nil) # @TODO Do we still need this? Can we not just send it from here?
        return
      end
      Dnsruby.log.debug{"Sending packet to #{@server}:#{@port} from #{@src_addr}:#{src_port}, use_tcp=#{use_tcp}"}
      begin
        if (use_tcp)
          lenmsg = [query_bytes.length].pack('n')
          socket.send(lenmsg, 0)
        end
        socket.send(query_bytes, 0)
      rescue Exception => e
        socket.close
        err=IOError.new("Send failed to #{@server}:#{@port} from #{@src_addr}:#{src_port}, use_tcp=#{use_tcp}, exception : #{e}")
        Dnsruby.log.error{"#{err}"}
        st.push_exception_to_select(client_query_id, client_queue, err, nil)
        return
      end
      
      # Then listen for the response
      query_settings = SelectThread::QuerySettings.new(query_bytes, query, @ignore_truncation, client_queue, client_query_id, socket, @server, @port, endtime, udp_packet_size, self)
      # The select thread will now wait for the response and send that or a timeout
      # back to the client_queue.
      st.add_to_select(query_settings)
    end
    
    def get_next_src_port
        #Different OSes have different interpretations of "random port" here.
        #Apparently, Linux will just give you the same port as last time, unless it is still
        #open, in which case you get n+1.
        #We need to determine an actual (random) number here, then ask the OS for it, and
        #continue until we get one.
      if (@src_port > 0 && @src_port < 65535)
        return @src_port
      else
        return (rand(65535-1024) + 1024)
      end
    end
    
    def check_response(response, response_bytes, query, client_queue, client_query_id, tcp)
      if (!check_tsig(query, response, response_bytes))
        return false
      end
      if (response.header.tc && !tcp)
        # Try to resend over tcp
        Dnsruby.log.debug{"Truncated - resending over TCP"}
        send_async(query, client_queue, client_query_id, true)
        return false
      end
      return true
    end
    
    def check_tsig(query, response, response_bytes)
      if (query.tsig)
        if (response.tsig)
          if !query.tsig.verify(query, response, response_bytes)
            # Discard packet and wait for correctly signed response
            Dnsruby.log.error{"TSIG authentication failed!"}
            return false
          end
        else
          # Treated as having format error and discarded (RFC2845, 4.6)
          Dnsruby.log.error{"Expecting TSIG signed response, but got unsigned response - discarding"}
          return false
        end
      elsif (response.tsig)
        # Error - signed response to unsigned query
        Dnsruby.log.error{"Signed response to unsigned query"}
        return false
      end      
      return true
    end
    
    # Prepare the packet for sending
    def make_query_packet(packet, use_tcp) #:nodoc: all
      if (packet.header.opcode == OpCode.QUERY || @recurse)
        packet.header.rd=true
      end
      
      if (@dnssec)
        # RFC 4035
        Dnsruby.log.debug{";; Adding EDNS extention with UDP packetsize #{udp_packet_size} and DNS OK bit set\n"}
        optrr = RR::OPT.new(udp_packet_size)   # Decimal UDPpayload
        optrr.dnssec_ok=true
              
        packet.add_additional(optrr)
        
        packet.header.ad = false # RFC 4035 section 4.6
        
        packet.header.cd = false # We trust the upstream resolver and the link to it
              
      elsif ((udp_packet_size > Resolver::DefaultUDPSize) && !use_tcp)
        #      if ((udp_packet_size > Resolver::DefaultUDPSize) && !use_tcp)
        Dnsruby.log.debug{";; Adding EDNS extention with UDP packetsize  #{udp_packet_size}.\n"}
        # RFC 3225
        optrr = RR::OPT.new(udp_packet_size)
        
        packet.add_additional(optrr)
      end
      
      if (@tsig && !packet.signed?)
        @tsig.apply(packet)
      end
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