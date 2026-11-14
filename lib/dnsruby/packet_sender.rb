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
require 'dnsruby/select_thread'
require 'ipaddr'
require 'securerandom'
# require 'dnsruby/iana_ports'
module Dnsruby

  class PacketSender # :nodoc: all

    include Socket::Constants

    @@authoritative_cache = Cache.new
    @@recursive_cache = Cache.new
    PIPELINE_MUTEX_CREATION = Mutex.new
    private_constant :PIPELINE_MUTEX_CREATION


    def PacketSender.cache(query, response)
      return if response.cached
      # TSIG authentication belongs to this transaction. Verification removes
      # the response's TSIG record, so its absence does not make it cacheable.
      return if query.tsig || query.signed? || response.signed?
      #  ONLY cache the response if it is not an update response
      question = query.question()[0]
      if (query.do_caching && (query.class != Update) &&
          (question.qtype != Types::AXFR) && (question.qtype != Types::IXFR) &&
          (response.rcode == RCode::NOERROR) &&(!response.tsig) &&
          (query.class != Update) &&
          (response.header.ancount > 0))
        # # @TODO@ What about TSIG-signed responses?
        #  Don't cache any packets with "*" in the query name! (RFC1034 sec 4.3.3)
        if (!question.qname.to_s.include? "*")
          #  Now cache response RRSets
          if (query.header.rd)
            PacketSender.cache_recursive(response);
          else
            PacketSender.cache_authoritative(response);
          end
        end
      end
    end

    def PacketSender.cache_authoritative(answer)
      return if !answer.header.aa
      @@authoritative_cache.add(answer)
    end

    def PacketSender.cache_recursive(answer)
      @@recursive_cache.add(answer)
    end

    def PacketSender.clear_caches
      @@recursive_cache.clear
      @@authoritative_cache.clear
    end

    def PacketSender.recursive_cache_length
      @@recursive_cache.length
    end

    attr_accessor :packet_timeout

    #  The port on the resolver to send queries to.
    # 
    #  Defaults to 53
    attr_accessor :port

    #  Use TCP rather than UDP as the transport.
    # 
    #  Defaults to false
    attr_accessor :use_tcp

    # Reuse tcp connection
    #
    # Defaults to false
    attr_accessor :tcp_pipelining

    # Limit the number of queries per pipeline
    attr_accessor :tcp_pipelining_max_queries

    #  Use UDP only - don't use TCP
    #  For test/debug purposes only
    #  Defaults to false
    attr_accessor :no_tcp

    #  The TSIG record to sign/verify messages with
    attr_reader :tsig

    #  Don't worry if the response is truncated - return it anyway.
    # 
    #  Defaults to false
    attr_accessor :ignore_truncation

    #  The source address to send queries from
    # 
    #  Defaults to localhost
    attr_reader :src_address

    #  should the Recursion Desired bit be set on queries?
    # 
    #  Defaults to true
    attr_accessor :recurse

    # Maximum UDP DNS payload size. Defaults to 1232 bytes; the minimum is 512.
    # A caller-supplied OPT record sets the receive size for that query.
    attr_reader :udp_size

    #  The address of the resolver to send queries to
    attr_reader :server

    #  Use DNSSEC for this PacketSender
    #  dnssec defaults to false
    attr_reader :dnssec

    #  Set the source address. If the arg is nil, do nothing
    def src_address6=(arg)
      if (not arg.nil?)
        @src_address6 = arg
      end
    end

    #  Set the source address. If the arg is nil, do nothing
    def src_address=(arg)
      if (not arg.nil?)
        @src_address = arg
      end
    end

    # Sets the TSIG to sign outgoing messages with.
    # Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    # Pass in nil to stop tsig signing.
    # Defaults to hmac-sha256; the algorithm must match the server's key.
    # You can select hmac-md5 for legacy servers, which logs a warning.
    # It is possible for client code to sign packets prior to sending - see
    # Dnsruby::RR::TSIG#apply and Dnsruby::Message#sign
    # Note that pre-signed packets will not be signed by PacketSender.
    # * res.tsig=(tsig_rr)
    # * res.tsig=(key_name, key)
    # * res.tsig=nil # Stop the resolver from signing
    def tsig=(*args)
      @tsig = Resolver.get_tsig(args)
    end

    def dnssec=(on)
      @dnssec=on
      if (on)
        #  Set the UDP size (RFC 4035 section 4.1)
        if (udp_packet_size < Resolver::AbsoluteMinDnssecUdpSize)
          self.udp_size = Resolver::AbsoluteMinDnssecUdpSize
        end
      end
    end


    def udp_size=(size)
      @udp_size = size
    end

    def server=(server)
      Dnsruby.log.debug { "InternalResolver setting server to #{server}" }
      @server=Config.resolve_server(server)
      check_ipv6
    end

    #  Can take a hash with the following optional keys :
    # 
    #  * :server
    #  * :port
    #  * :use_tcp
    #  * :tcp_pipelining
    #  * :tcp_pipelining_max_queries
    #  * :no_tcp
    #  * :ignore_truncation
    #  * :src_address
    #  * :src_address6
    #  * :src_port
    #  * :udp_size
    #  * :tsig
    #  * :packet_timeout
    #  * :recurse
    def initialize(*args)
      arg=args[0]
      @ipv6 = false
      @packet_timeout = Resolver::DefaultPacketTimeout
      @port = Resolver::DefaultPort
      @udp_size = Resolver::DefaultUDPSize
      @dnssec = Resolver::DefaultDnssec
      @use_tcp = false
      @no_tcp = false
      @tsig = nil
      @ignore_truncation = false
      @src_address = '0.0.0.0'
      @src_address6 = '::'
      @src_port = [0]
      @recurse = true
      @tcp_pipelining = false
      @tcp_pipelining_max_queries = :infinite
      @use_counts = {}

      ignore_config_resolv_errors = false;
      if arg.nil?
      elsif arg.kind_of? String
        @server = arg
      elsif arg.kind_of? Name
        @server = arg
      elsif arg.kind_of? Hash
        arg.keys.each do |attr|
          begin
            if (attr.to_s == "ignore_config_resolv_errors")
              ignore_config_resolv_errors = arg[attr]
            else
              if ((attr.to_s == "src_address" || attr.to_s == "src_address6") &&
                  (arg[attr] == nil || arg[attr] == ""))
              else
                send(attr.to_s + "=", arg[attr])
              end
            end
          rescue Exception => e
            raise if attr.to_s == 'tsig'
            Dnsruby.log.error { "PacketSender : Argument #{attr}, #{arg[attr]} not valid : #{e}\n" }
          end
        end
      end
      # Check server is IP
      # We should allow the call of PacketSender.new to flag just to log an error if this fails
      # and then return null
        if ignore_config_resolv_errors
          begin
            @server=Config.resolve_server(@server)
          rescue ArgumentError
            return
          end
        else
            @server=Config.resolve_server(@server)
        end

      check_ipv6
      #       ResolverRegister::register_single_resolver(self)
    end

    def check_ipv6
      begin
        IPv4.create(@server)
        #         @src_address = '0.0.0.0'
        @ipv6=false
      rescue Exception
        begin
          Config.ipv6_server_address(@server)
          #           @src_address6 = '::'
          @ipv6=true
        rescue Exception
          Dnsruby.log.error { "Server is neither IPv4 or IPv6!\n" }
        end
      end
    end

    def close
      # Idle streams close immediately; streams still serving another Resolver
      # drain before closing. Do not wait for a writer blocked in connect.
      @selector.retire_sender(self) if @selector
    end

    # Reserve ownership while Resolver still holds its query lock, then perform
    # the synchronous public send after releasing that lock. close/timeout can
    # cancel this reservation even before send_async has started.
    def prepare_send_async(message, queue, id, retire_connection = false) #:nodoc:
      selector = @selector = SelectThread.instance
      pending = SelectThread::QuerySettings.new(nil, message, @ignore_truncation,
        queue, id, nil, @server, @port, TransportClock.now + @packet_timeout, udp_packet_size, self)
      pending.retire_connection = retire_connection
      return unless selector.reserve_send(pending)
      -> do
        next unless selector.query_settings_for_id(id).equal?(pending)
        previous_context = Thread.current[:dnsruby_response_query]
        begin
          Thread.current[:dnsruby_response_query] = pending
          send_async(message, queue, id)
        rescue StandardError => error
          selector.fail_query_if_current(id, queue, pending, error)
        ensure
          Thread.current[:dnsruby_response_query] = previous_context
        end
      end
    end

    # Asynchronously send a Message to the server. The send can be done using just
    # Dnsruby. Support for EventMachine has been deprecated.
    # 
    # == Dnsruby pure Ruby event loop :
    # 
    # A client_queue is supplied by the client,
    # along with an optional client_query_id to identify the response. The client_query_id
    # is generated, if not supplied, and returned to the client.
    # When the response is known, the tuple
    # (query_id, response_message, response_exception) is put in the queue for the client to process.
    # 
    # The query is sent synchronously in the caller's thread. The select thread is then used to
    # listen for and process the response (up to pushing it to the client_queue). The client thread
    # is then used to retrieve the response and deal with it.
    # 
    # Takes :
    # 
    # * msg - the message to send
    # * client_queue - a Queue to push the response to, when it arrives
    # * client_query_id - an optional ID to identify the query to the client
    # * use_tcp - whether to use TCP (defaults to PacketSender.use_tcp)
    # 
    # Returns :
    # 
    # * client_query_id - to identify the query response to the client. This ID is
    # generated if it is not passed in by the client
    # 
    # If the native Dsnruby networking layer is being used, then this method returns the client_query_id
    # 
    #     id = res.send_async(msg, queue)
    #     NOT SUPPORTED : id = res.send_async(msg, queue, use_tcp)
    #     id = res.send_async(msg, queue, id)
    #     id = res.send_async(msg, queue, id, use_tcp)
    # 
    # Use Message#send_raw to send the packet with an untouched header.
    # Use Message#do_caching to tell dnsruby whether to check the cache before
    # sending, and update the cache upon receiving a response.
    # Use Message#do_validation to tell dnsruby whether or not to do DNSSEC
    # validation for this particular packet (assuming SingleResolver#dnssec == true)
    # Note that these options should not normally be used!
    def send_async(*args) # msg, client_queue, client_query_id, use_tcp=@use_tcp)
      #  @TODO@ Need to select a good Header ID here - see forgery-resilience RFC draft for details
      msg = args[0]
      client_query_id = nil
      client_queue = nil
      use_tcp = @use_tcp
      if (msg.kind_of? String)
        msg = Message.new(msg)
        if (@dnssec)
          msg.header.cd = @dnssec # we'll do our own validation by default
          if (Dnssec.no_keys?)
            msg.header.cd = false
          end
        end
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
      # Keep the request MAC for response verification (RFC 8945 section 4.3.1).
      if (!client_query_id)
        client_query_id = Time.now + rand(10000) # is this safe?!
      end
      response_settings = response_query_settings(client_query_id)
      disable_edns = args[4] || (response_settings && response_settings.disable_edns)

      begin
        query_packet = make_query_packet(msg, use_tcp, disable_edns)
        check_message_size(query_packet)
      rescue EncodeError => err
        Dnsruby.log.error { "#{err}" }
        st = SelectThread.instance
        if response_settings
          st.fail_query_if_current(client_query_id, client_queue, response_settings, err)
        else
          st.push_exception_to_select(client_query_id, client_queue, err, nil)
        end
        return
      end

      if (msg.do_caching && (msg.class != Update) && !@tsig && !msg.tsig && !msg.signed?)
        #  Check the cache!!
        cachedanswer = nil
        if (msg.header.rd)
          cachedanswer = @@recursive_cache.find(msg.question()[0].qname, msg.question()[0].type, msg.question()[0].qclass)
        else
          cachedanswer = @@authoritative_cache.find(msg.question()[0].qname, msg.question()[0].type, msg.question()[0].qclass)
        end
        if (cachedanswer)
          TheLog.debug("Sending cached answer to client\n")
          #  @TODO@ Fix up the header - ID and flags
          cachedanswer.header.id = msg.header.id
          #  If we can find the answer, send it to the client straight away
          #  Post the result to the client using SelectThread
          st = SelectThread.instance
          if response_settings
            st.push_response_for_query(response_settings, cachedanswer, msg, self)
          else
            st.push_response_to_select(client_query_id, client_queue, cachedanswer, msg, self)
          end
          return client_query_id
        end
      end
      #  Otherwise, run the query
      if (udp_packet_size < query_packet.length)
        if (@no_tcp)
          #  Can't send the message - abort!
          err=IOError.new("Can't send message - too big for UDP and no_tcp=true")
          Dnsruby.log.error { "#{err}" }
          st = SelectThread.instance
          if response_settings
            st.fail_query_if_current(client_query_id, client_queue, response_settings, err)
          else
            st.push_exception_to_select(client_query_id, client_queue, err, nil)
          end
          return
        end
        Dnsruby.log.debug { "Query packet length exceeds max UDP packet size - using TCP" }
        use_tcp = true
      end
      send_dnsruby(query_packet, msg, client_query_id, client_queue, use_tcp, disable_edns)
      return client_query_id
      #       end
    end

    #  This method returns the current tcp socket for pipelining
    #  If this is the first time the method is called then the socket is bound to
    #  @src_address:@src_port and connected to the remote dns server @server:@port.
    #  If the connection has been closed because of an EOF on recv_nonblock (closed by server)
    #  the function will recreate of the socket (since @pipeline_socket.connect will result in a IOError
    #  exception)
    #  In general, every subsequent call the function will either return the current tcp
    #  pipeline socket or a new connected socket if the current one was closed by the server
    def tcp_pipeline_socket(src_port)
      Dnsruby.log.debug("Using tcp_pipeline_socket")
      # A live connection retains its endpoint and source binding. Compare the
      # configured source-port pool, not each randomly selected candidate port.
      configuration = [@server.dup, @port, (@ipv6 ? @src_address6 : @src_address).dup,
        @src_port.dup, @ipv6]
      sockaddr = Socket.sockaddr_in(configuration[1], configuration[0])

      reuse_pipeline_socket = -> do
        begin
          max = @pipeline_socket_max_queries
          use_count = @use_counts[@pipeline_socket]
          if !SelectThread.instance.reusable_socket?(@pipeline_socket) ||
              max != @tcp_pipelining_max_queries ||
              @pipeline_socket_configuration != configuration ||
              (use_count && max != :infinite && use_count >= max)
            # Capacity and endpoint belong to a connection. Outstanding peers
            # keep their old stream and drain before it closes.
            SelectThread.instance.retire_socket(@pipeline_socket)
            @use_counts.delete(@pipeline_socket)
            @pipeline_socket = nil
            Dnsruby.log.debug("Max queries per connection attained - creating new socket")
          else
            @pipeline_socket.connect(sockaddr)
          end
        rescue Errno::EISCONN
          #already connected, do nothing and reuse!
        rescue IOError, Errno::ECONNRESET #close by remote host, reconnect
          @use_counts.delete(@pipeline_socket)
          @pipeline_socket = nil
          Dnsruby.log.debug("Connection closed - recreating socket")
        end
      end

      create_pipeline_socket = -> do
        @tcp_pipeline_local_port = src_port
        src_address = configuration[2]
        begin
          @pipeline_socket_max_queries = @tcp_pipelining_max_queries
          @pipeline_socket_configuration = configuration
          deadline, token = @pipeline_connect_context ||
            [TransportClock.now + @packet_timeout, SelectThread::SendToken.new]
          @pipeline_socket = connect_tcp(configuration[0], configuration[1], src_address, src_port,
            deadline, token)
          Dnsruby.log.debug("Creating socket #{src_address}:#{src_port}")
          @use_counts[@pipeline_socket] = 0
        rescue Exception => e
          # A failed bind/connect never reaches the select thread, which would
          # otherwise own closing the socket (for example, an unusable zone).
          @pipeline_socket.close rescue nil
          @pipeline_socket = nil
          raise e
        end
      end

      # Don't combine the following 2 statements; the reuse lambda can set the
      # socket to nil and if so we'd want to call the create lambda to recreate it.
      reuse_pipeline_socket.() if @pipeline_socket
      new_socket = @pipeline_socket.nil?
      create_pipeline_socket.() unless @pipeline_socket

      @use_counts[@pipeline_socket] += 1

      [@pipeline_socket, new_socket]
    end

    #  This method sends the packet using the built-in pure Ruby event loop, with no dependencies.
    def send_dnsruby(query_bytes, query, client_query_id, client_queue, use_tcp, disable_edns = false) #:nodoc: all
      st = @selector = SelectThread.instance
      response_settings = response_query_settings(client_query_id)
      begin
        check_message_size(query_bytes)
      rescue EncodeError => error
        if response_settings
          st.fail_query_if_current(client_query_id, client_queue, response_settings, error)
        else
          st.push_exception_to_select(client_query_id, client_queue, error, nil)
        end
        return
      end
      # A Resolver reservation already started this attempt's packet deadline.
      # A protocol retry (which has bytes) receives a fresh packet deadline.
      endtime = response_settings && response_settings.query_bytes.nil? ?
        response_settings.endtime : TransportClock.now + @packet_timeout
      previous_settings = response_settings ||
        (st.query_settings_for_id(client_query_id) if use_tcp && @tcp_pipelining)
      pending = SelectThread::QuerySettings.new(query_bytes, query,
        @ignore_truncation, client_queue, client_query_id, nil, @server, @port,
        endtime, udp_receive_size(query), self)
      pending.send_token = previous_settings.send_token if previous_settings
      pending.disable_edns = disable_edns || (previous_settings && previous_settings.disable_edns)
      # A protocol retry starts its own packet deadline at dispatch, including
      # time queued for a worker. Retire the old socket membership atomically.
      return unless st.reserve_send(pending, previous_settings)
      previous_settings = pending
      operation = -> do
        send_dnsruby_with_socket(query_bytes, query, client_query_id, client_queue,
          use_tcp, endtime, previous_settings)
      end
      send_operation = operation
      if use_tcp && @tcp_pipelining
        # Configuration-only senders remain Marshal-compatible. Allocate the
        # writer mutex only on first use, including senders loaded from storage.
        pipeline_mutex = PIPELINE_MUTEX_CREATION.synchronize { @pipeline_mutex ||= Mutex.new }
        send_operation = -> do
          locked = false
          begin
            until (locked = pipeline_mutex.try_lock)
              break if TransportClock.now >= endtime || !st.query_settings_for_id(client_query_id).equal?(previous_settings)
              sleep 0.005
            end
            if locked && TransportClock.now < endtime
              operation.call
            else
              st.fail_query_if_current(client_query_id, client_queue, previous_settings,
                ResolvTimeout.new("Query timed out waiting for TCP pipeline"))
            end
          ensure
            pipeline_mutex.unlock if locked
          end
        end
      end
      guarded_operation = -> do
        send_operation.call
      rescue StandardError => error
        # Deferred callers do not read SendTask#value. Failures before socket
        # registration still belong to this exact reserved attempt.
        st.fail_query_if_current(client_query_id, client_queue, pending, error)
      end
      if use_tcp && st.selector_thread?
        begin
          st.defer_send(@tcp_pipelining ? self : nil, &guarded_operation)
        rescue ThreadError => error
          st.fail_query_if_current(client_query_id, client_queue, previous_settings,
            ResolvTimeout.new("Cannot queue TCP send: #{error.message}"))
        end
      else
        # Only the selector delegates I/O. Public caller sends remain synchronous.
        guarded_operation.call
      end
    end

    def check_message_size(query_bytes)
      if query_bytes.bytesize > 65_535
        raise EncodeError, "DNS message exceeds the 65535-byte wire limit (#{query_bytes.bytesize} bytes)"
      end
    end
    private :check_message_size

    class SendCancelled < StandardError; end
    private_constant :SendCancelled

    # Config has already resolved the server address. Check cancellation while
    # connecting so an unresponsive peer cannot hold up a sender worker.
    def connect_tcp(server, port, source, source_port, deadline, token)
      socket = nil
      connected = false
      begin
        raise SendCancelled if token.cancelled?
        raise ResolvTimeout, 'Query timed out before TCP connect' if TransportClock.now >= deadline
        socket = Socket.new(@ipv6 ? Socket::AF_INET6 : Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket.bind(Socket.sockaddr_in(source_port, source))
        result = socket.connect_nonblock(Socket.sockaddr_in(port, server), exception: false)
        while result == :wait_writable || result == :wait_readable
          raise SendCancelled if token.cancelled?
          remaining = deadline - TransportClock.now
          raise ResolvTimeout, 'Query timed out connecting TCP' if remaining <= 0
          readers, writers = result == :wait_readable ? [[socket], nil] : [nil, [socket]]
          next unless IO.select(readers, writers, nil, [remaining, 0.05].min)
          error = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
          raise SystemCallError.new('TCP connect', error) unless error.zero?
          result = 0
        end
        raise SendCancelled if token.cancelled?
        raise ResolvTimeout, 'Query timed out connecting TCP' if TransportClock.now >= deadline
        connected = true
        socket
      ensure
        socket.close if socket && !connected && !socket.closed?
      end
    end
    private :connect_tcp

    # Socket#send may write only a prefix of a TCP frame. Nonblocking writes keep
    # a stalled peer from holding the pipeline writer past the packet deadline.
    def write_tcp_frame(socket, query_bytes, endtime, send_token)
      check_message_size(query_bytes)
      frame = [query_bytes.bytesize].pack('n') + query_bytes
      offset = 0
      while offset < frame.bytesize
        remaining = endtime - TransportClock.now
        begin
          written = send_token.write do
            raise ResolvTimeout, "Query timed out writing TCP frame" if remaining <= 0
            socket.write_nonblock(frame.byteslice(offset, frame.bytesize - offset))
          end
          return offset if written == false # Cancelled between partial writes.
          raise IOError, "TCP write made no progress" unless written && written > 0
          offset += written
        rescue IO::WaitWritable
          # A canceled pipeline may still have peers and remain open. Bound the
          # wait so cancellation releases the worker even if it never becomes
          # writable; the next iteration retires any incomplete frame.
          IO.select(nil, [socket], nil, [remaining, 0.05].min)
        end
      end
      true
    end

    # A datagram is sent atomically. Order the actual write with cancellation,
    # as for TCP, without holding the token while waiting for a writable socket.
    def write_udp_packet(socket, query_bytes, endtime, send_token, wait_for_writable)
      loop do
        remaining = endtime - TransportClock.now
        begin
          written = send_token.write do
            raise ResolvTimeout, "Query timed out writing UDP packet" if remaining <= 0
            socket.write_nonblock(query_bytes)
          end
          return false if written == false
          raise IOError, "Incomplete UDP datagram write" unless written == query_bytes.bytesize
          return true
        rescue IO::WaitWritable
          raise unless wait_for_writable
          IO.select(nil, [socket], nil, [remaining, 0.05].min)
        end
      end
    end

    def response_query_settings(client_query_id)
      settings = Thread.current[:dnsruby_response_query]
      settings if settings && settings.client_query_id == client_query_id &&
        settings.single_resolver.equal?(self)
    end

    def send_dnsruby_with_socket(query_bytes, query, client_query_id, client_queue,
        use_tcp, endtime, previous_settings)
      #  First send the query (synchronously)
      st = SelectThread.instance
      report_error = ->(error) do
        st.fail_query_if_current(client_query_id, client_queue, previous_settings, error)
      end
      socket = nil
      runnextportloop = true
      numtries = 0
      src_address = @src_address
      if (@ipv6)
        src_address = @src_address6
      end
      while (runnextportloop) do
        # A pre-close reservation gets a one-use socket. Recheck on every
        # admission retry without changing ownership or extending its deadline.
        pipeline = use_tcp && @tcp_pipelining && !previous_settings.retire_connection
        return unless st.query_settings_for_id(client_query_id).equal?(previous_settings)
        begin
          if TransportClock.now >= endtime
            report_error.call(ResolvTimeout.new("Query timed out before connect"))
            return
          end
          numtries += 1
          src_port = get_next_src_port
          if (use_tcp)
            begin
              if pipeline
                begin
                  # RFC 7766 requires unique outstanding IDs on a connection.
                  # Moving a collision to a fresh stream preserves caller IDs,
                  # including raw messages and bytes covered by TSIG.
                  if @pipeline_socket && st.query_id_in_use?(@pipeline_socket, query.header.id)
                    st.retire_socket(@pipeline_socket)
                    @use_counts.delete(@pipeline_socket)
                    @pipeline_socket = nil
                  end
                  @pipeline_connect_context = [endtime, previous_settings.send_token]
                  socket, new_socket = tcp_pipeline_socket(src_port)
                ensure
                  remove_instance_variable(:@pipeline_connect_context)
                end
                src_port = @tcp_pipeline_local_port
              else
                socket = connect_tcp(@server, @port, src_address, src_port,
                  endtime, previous_settings.send_token)
                new_socket = true
              end
            rescue Errno::EBADF, Errno::ENETUNREACH => e
              #  Can't create a connection
              err=IOError.new("TCP connection error to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e}")
              Dnsruby.log.error { "#{err}" }
              report_error.call(err)
              return
            end
          else
            socket = nil
            #  JRuby UDPSocket only takes 0 parameters - no IPv6 support in JRuby...
            if (/java/ =~ RUBY_PLATFORM)
              socket = UDPSocket.new()
            else
              #               ipv6 = @src_address =~ /:/
              socket = UDPSocket.new(@ipv6 ? Socket::AF_INET6 : Socket::AF_INET)
            end
            new_socket = true
            socket.bind(src_address, src_port)
            socket.connect(@server, @port)
          end
        rescue SendCancelled
          return
        rescue Exception => e
          if (socket!=nil)
            begin
              #let the select thread close the socket if tcp_pipeli
              socket.close unless @tcp_pipelining && !new_socket
            rescue Exception
            end
          end
          #  Try again if the error was EADDRINUSE and a random source port is used
          #  Maybe try a max number of times?
          if ((e.class != Errno::EADDRINUSE) || (numtries > 50) ||
              ((e.class == Errno::EADDRINUSE) && (src_port == @src_port[0])))
            err_msg = "dnsruby can't connect to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception = #{e.class}, #{e} #{e.backtrace}"
            err=IOError.new(err_msg)
            Dnsruby.log.error( "#{err}")
            Dnsruby.log.error(e.backtrace)
            if e.kind_of?(Errno::ETIMEDOUT) || e.kind_of?(ResolvTimeout)
              report_error.call(ResolvTimeout.new(err_msg))
            elsif @tcp_pipelining
              report_error.call(SocketEofResolvError.new(err_msg))
            else
              report_error.call(err)
            end
            return
          end
          next # Retry a random source-port collision before registration.
        end
        if (socket==nil)
          err=IOError.new("dnsruby can't connect to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}")
          Dnsruby.log.error { "#{err}" }
          report_error.call(err)
          return
        end
        Dnsruby.log.debug { "Sending packet to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp} : #{query.question()[0].qname}, #{query.question()[0].qtype}" }
        # A reused pipeline is already readable by the selector. Publish its new
        # query before writing so an immediate answer always has an owner.
        query_settings = SelectThread::QuerySettings.new(query_bytes, query, @ignore_truncation, client_queue, client_query_id, socket, @server, @port, endtime, previous_settings.udp_packet_size, self)
        query_settings.send_token = previous_settings.send_token
        query_settings.disable_edns = previous_settings.disable_edns
        query_settings.is_persistent_socket = pipeline
        query_settings.tcp_pipelining_max_queries = (@pipeline_socket_max_queries || @tcp_pipelining_max_queries) if pipeline
        if use_tcp
          registered = st.register_query_if_current(query_settings, previous_settings)
          if registered == :retry_connection
            # No bytes were written and the original reservation still owns the
            # attempt. Peers on the retiring stream keep their registrations.
            @use_counts.delete(socket)
            @pipeline_socket = nil if @pipeline_socket == socket
            next
          end
          unless registered
            # Completion can win during connect. Release only this unused socket
            # reservation; other queries may still own an existing pipeline.
            @use_counts[socket] -= 1 if pipeline && @use_counts[socket]
            socket.close if new_socket && !socket.closed?
            if pipeline && socket.closed?
              @use_counts.delete(socket)
              @pipeline_socket = nil if @pipeline_socket == socket
            end
            return
          end
          previous_settings = query_settings
        elsif !st.query_settings_for_id(client_query_id).equal?(previous_settings)
          socket.close
          return
        end
        runnextportloop = false
      end
      send_packet = -> do
        begin
          if use_tcp
            completed = write_tcp_frame(socket, query_bytes, endtime, query_settings.send_token)
            # Cancellation of a partially written frame retires its whole stream;
            # otherwise another frame could be appended to a corrupt prefix.
            unless completed == true
              if pipeline && completed > 0
                st.fail_tcp_send(query_settings, SocketEofResolvError.new("TCP send cancelled"))
                @use_counts.delete(socket)
                @pipeline_socket = nil if @pipeline_socket == socket
              elsif !pipeline
                socket.close rescue nil
              end
              return
            end
          else
            unless write_udp_packet(socket, query_bytes, endtime, query_settings.send_token, !st.selector_thread?)
              socket.close
              return
            end
            socket.close unless st.register_query_if_current(query_settings, previous_settings)
          end
        rescue IO::WaitWritable
          # Only a congested UDP send reaches this branch on the selector. Keep
          # ordinary UDP traffic independent of the pool's blocked TCP writers.
          return st.defer_send { send_packet.call }
        rescue Exception => e
          err_msg = "Send failed to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp}, exception : #{e}"
          err=IOError.new(err_msg)
          Dnsruby.log.error { "#{err}" }
          Dnsruby.log.error(e.backtrace)
          if pipeline
            error = e.kind_of?(ResolvTimeout) ? e : SocketEofResolvError.new(err_msg)
            st.fail_tcp_send(query_settings, error)
            @use_counts.delete(socket)
            @pipeline_socket = nil if @pipeline_socket == socket
          elsif e.kind_of?(ResolvTimeout)
            report_error.call(e)
          elsif @tcp_pipelining
            report_error.call(SocketEofResolvError.new(err_msg))
          else
            report_error.call(err)
          end
          begin
            #we let the select_thread close the socket when doing tcp
            #pipelining
            socket.close unless @tcp_pipelining && !new_socket
          rescue Exception
          end
          return
        end

        Dnsruby.log.debug { "Packet sent to #{@server}:#{@port} from #{src_address}:#{src_port}, use_tcp=#{use_tcp} : #{query.question()[0].qname}, #{query.question()[0].qtype}" }
      end
      send_packet.call
    rescue StandardError => error
      # Errors outside the expected connect/write failures must not disappear in
      # a worker's result queue. Do not consume a replacement protocol attempt.
      st.fail_query_if_current(client_query_id, client_queue, previous_settings, error)
      # A failure between connect and registration has no selector-owned socket
      # yet. Release that new descriptor here; reused streams retain their peers.
      socket.close if socket && new_socket && !socket.closed?
    end

    #  The source port to send queries from
    #  Returns either a single Integer or an Array
    #  e.g. "0", or "[60001, 60002, 60007]"
    # 
    #  Defaults to 0 - random port
    def src_port
      if (@src_port.length == 1)
        return @src_port[0]
      end
      return @src_port
    end

    #  Can be a single Integer or a Range or an Array
    #  If an invalid port is selected (one reserved by
    #  IANA), then an ArgumentError will be raised.
    # 
    #         res.src_port=0
    #         res.src_port=[60001,60005,60010]
    #         res.src_port=60015..60115
    # 
    def src_port=(p)
      @src_port=[]
      add_src_port(p)
    end

    #  Can be a single Integer or a Range or an Array
    #  If an invalid port is selected (one reserved by
    #  IANA), then an ArgumentError will be raised.
    #  "0" means "any valid port" - this is only a viable
    #  option if it is the only port in the list.
    #  An ArgumentError will be raised if "0" is added to
    #  an existing set of source ports.
    # 
    #         res.add_src_port(60000)
    #         res.add_src_port([60001,60005,60010])
    #         res.add_src_port(60015..60115)
    # 
    def add_src_port(p)
      if (Resolver.check_port(p, @src_port))
        a = Resolver.get_ports_from(p)
        a.each do |x|
          if ((@src_port.length > 0) && (x == 0))
            raise ArgumentError.new("src_port of 0 only allowed as only src_port value (currently #{@src_port.length} values")
          end
          @src_port.push(x)
        end
      end
    end


    def get_next_src_port
      # Preserve the existing high-port range and configured pools, using
      # unpredictable choices for the source-port contribution to DNS IDs.
      if (@src_port[0] == 0)
        return 50_000 + SecureRandom.random_number(15_536)
      end
      @src_port[SecureRandom.random_number(@src_port.length)]
    end

    def check_response(response, response_bytes, query, client_queue, client_query_id, tcp)
      #  @TODO@ Should send_raw avoid this?
      if (!query.send_raw)
        # Reject unrelated packet headers before TSIG verification mutates the
        # response or an error/truncation triggers another transport attempt.
        unless response.header.qr && response.header.opcode == query.header.opcode &&
            response.header.id == query.header.id
          return false
        end
        checking_signature = query.tsig && response.tsig
        sig_value = check_tsig(query, response, response_bytes)
        authenticated_tsig_error = checking_signature && sig_value.kind_of?(TsigError) && response.verified? &&
          response.header.get_header_rcode == RCode.NOTAUTH && [18, 22].include?(response.tsigerror)
        if (sig_value != :okay) && !authenticated_tsig_error
          # Keep waiting for a signed response without extending the deadline
          # (RFC 8945 section 5.4). Save the error in case the query times out.
          settings = response_query_settings(client_query_id)
          settings.authentication_error = sig_value if settings
          return false
        end
        # Match the question when one is present. TCP error replies may omit
        # it (RFC 7766 section 7); UDP replies must match (RFC 5452 section 9.1).
        if (query.class == Update)
          # TODO: Validate the zone section for UPDATE replies.
        elsif !(tcp && response.question.empty? && response.header.get_header_rcode != RCode.NOERROR)
          if ((response.question.size == 0) ||
              (response.question[0].qname.labels != query.question[0].qname.labels) ||
              (response.question[0].qtype != query.question[0].qtype) ||
              (response.question[0].qclass != query.question[0].qclass) ||
              (response.question.length != query.question.length) ||
              (response.header.id != query.header.id))
            TheLog.info("Incorrect packet returned : #{response.to_s}")
            return false
          end
        end
        return sig_value if authenticated_tsig_error
        # Retry a FORMERR without optional EDNS (RFC 6891 section 6.2.2).
        # Queries requiring DNSSEC validation must keep EDNS and DO.
        if ((response.header.get_header_rcode == RCode.FORMERR) &&
            query.get_opt && !(@dnssec && query.do_validation))
          # EDNS negotiation belongs to this attempt, not to the caller's raw
          # mode or Message (which may also be in use by another nameserver).
          retry_query = query.dup
          retry_query.header = query.header.dup
          retry_query.remove_additional
          query.additional.each do |rr|
            retry_query.add_additional(rr) unless rr.type == Types.OPT || rr.type == Types.TSIG
          end
          if query.tsig
            return TsigError.new unless query.tsig.key
            retry_query.tsigstate = :Unsigned
            retry_query.set_tsig(query.tsig.dup)
          end
          send_async(retry_query, client_queue, client_query_id, tcp, true)
          return false
        end
        if (response.header.tc && !tcp && !@ignore_truncation)
          if (@no_tcp)
            Dnsruby.log.debug { "Truncated response - not resending over TCP as no_tcp==true" }
          else
            #  Try to resend over tcp
            Dnsruby.log.debug { "Truncated - resending over TCP" }
            #  @TODO@ Are the query options used correctly here? DNSSEC in particular...
            #         query.send_raw = true # Make sure that the packet is not messed with.
            send_async(query, client_queue, client_query_id, true)
            return false
          end
        end
      end
      return true
    end

    def check_tsig(query, response, response_bytes)
      if (query.tsig)
        if (response_signature = response.tsig)
          if !query.tsig.verify(query, response, response_bytes)
            if response.verified? && response.header.get_header_rcode == RCode.NOTAUTH
              description = {18 => 'BADTIME', 22 => 'BADTRUNC'}[response.tsigerror]
              if description
                diagnostic = "Authenticated TSIG #{description} (#{response.tsigerror})"
                if response.tsigerror == RCode.BADTIME
                  high, low = response_signature.other_data.unpack('nN')
                  diagnostic += "; server time #{(high << 32) | low} seconds since Unix epoch"
                end
                Dnsruby.log.error { diagnostic }
                return TsigError.new(diagnostic)
              end
            end
            #  Discard packet and wait for correctly signed response
            Dnsruby.log.error { "TSIG authentication failed!" }
            return TsigError.new
          end
        else
          # A missing signature is a format error (RFC 8945 section 5.4).
          # Keep a distinct exception so callers can diagnose unsigned peers.
          response.tsigstate = :Failed
          response.tsigerror = RCode.FORMERR
          Dnsruby.log.error { "Expecting TSIG signed response, but got unsigned response - discarding" }
          return TsigNotSignedResponseError.new
        end
      elsif (response.tsig)
        #  Error - signed response to unsigned query
        Dnsruby.log.error { "Signed response to unsigned query" }
        return TsigError.new
      end
      return :okay
    end

    def make_query(name, type = Types::A, klass = Classes::IN, set_cd=@dnssec)
      msg = Message.new
      msg.header.rd = 1
      msg.add_question(name, type, klass)
      if (@dnssec)
        msg.header.cd = set_cd # We do our own validation by default
      end
      return msg
    end

    #  Prepare the packet for sending
    def make_query_packet(packet, use_tcp = @use_tcp, disable_edns = false) #:nodoc: all
      packet.tsig.warn_if_legacy_algorithm if packet.tsig
      # TSIG signs the header and every section, so leave signed messages intact.
      # Decoded messages may have a TSIG without a signing state.
      prepared = packet.signed? || packet.tsig
      if !packet.send_raw && !prepared
        if (packet.header.opcode == OpCode.QUERY || @recurse)
          packet.header.rd=@recurse
        end

        if @dnssec && !disable_edns
          prepare_for_dnssec(packet)
        elsif !disable_edns && (udp_packet_size > 512) && !use_tcp
          add_opt_rr(packet)
        end
      end

      # Prepare the whole message before encoding, which may sign it.
      # Use the resolver's key if the Message has none.
      encoded = packet.encode
      if @tsig && !packet.signed? && !packet.tsig
        packet.set_tsig(@tsig)
        encoded = packet.encode
      end
      encoded
    end

    def add_opt_rr(packet)
      Dnsruby.log.debug { ";; Adding EDNS extension with UDP packetsize  #{udp_packet_size}.\n" }
      # Find OPT by type: its class field stores the payload size. Reuse it and
      # its options, since only one OPT is allowed (RFC 6891 section 6.1.1).
      packet.add_additional(RR::OPT.new(udp_packet_size)) unless packet.get_opt
      packet.get_opt
    end

    def prepare_for_dnssec(packet)
      # Request DNSSEC records with DO (RFC 4035 section 4.1).
      Dnsruby.log.debug { ";; Adding EDNS extension with UDP packetsize #{udp_packet_size} and DNS OK bit set\n" }
      optrr = add_opt_rr(packet)
      optrr.dnssec_ok=true

      # We use DO to request DNSSEC records and leave AD clear
      # (RFC 6840 section 5.7).
      packet.header.ad = false

      # Local validation needs the original data, even if the server rejects it.
      if (packet.do_validation)
        packet.header.cd = true
      end
      if (Dnssec.no_keys?)
        packet.header.cd = false
      end

    end

    #  Return the packet size to use for UDP
    def udp_packet_size
      # Values below 512 mean 512 in EDNS (RFC 6891 section 6.2.3).
      [@udp_size, 512].max
    end

    # Match the receive buffer to this query's OPT so a valid reply isn't
    # cut short when the caller advertises more than the resolver default.
    def udp_receive_size(query)
      opt = query.get_opt
      opt ? [opt.payloadsize, 512].max : udp_packet_size
    end
    private :udp_receive_size
  end
end
