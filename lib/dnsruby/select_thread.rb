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
require 'socket'
# require 'thread'
begin
  require 'fastthread'
rescue LoadError
  require 'thread'
end
require 'set'
require 'singleton'
require 'dnsruby/validator_thread.rb'
module Dnsruby
  class SelectThread #:nodoc: all
    class SelectWakeup < RuntimeError; end
    include Singleton
    #  This singleton class runs a continuous select loop which
    #  listens for responses on all of the in-use sockets.
    #  When a new query is sent, the thread is woken up, and
    #  the socket is added to the select loop (and the new timeout
    #  calculated).
    #  Note that a combination of the socket and the packet ID is
    #  sufficient to uniquely identify the query to the select thread.
    # 
    #  But how do we find the response queue for a particular query?
    #  Hash of client_id->[query, client_queue, socket]
    #  and socket->[client_id]
    # 
    #  @todo@ should we implement some of cancel function?

    def initialize
      @@mutex = Mutex.new
      @@mutex.synchronize {
        @@in_select=false
        #         @@notifier,@@notified=IO.pipe
        @@sockets = Set.new
        @@timeouts = Hash.new
        #     @@mutex.synchronize do
        @@query_hash = Hash.new
        @@socket_hash = Hash.new
        @@socket_is_persistent = Hash.new
        @@socket_owners = Hash.new
        @@retiring_sockets = Set.new
        @@observers = Hash.new
        @@tcp_buffers=Hash.new
        @@socket_remaining_queries = Hash.new
        @@tick_observers = []
        @@queued_exceptions=[]
        @@queued_responses=[]
        @@queued_validation_responses=[]
        @@wakeup_sockets = get_socket_pair
        @@sockets << @@wakeup_sockets[1]

        #  Suppress reverse lookups
        BasicSocket.do_not_reverse_lookup = true
        #     end
        #  Now start the select thread
        @@select_thread = Thread.new { do_select }

        #         # Start the validator thread
        #         @@validator = ValidatorThread.instance
      }
    end

    def get_socket_pair
      #  Emulate socketpair on platforms which don't support it
      srv = nil
      begin
        srv = TCPServer.new('localhost', 0)
      rescue Errno::EADDRNOTAVAIL, SocketError # OSX Snow Leopard issue - need to use explicit IP
        begin
          srv = TCPServer.new('127.0.0.1', 0)
        rescue Error # Try IPv6
          srv = TCPServer.new('::1', 0)
        end
      end
      rsock = TCPSocket.new(srv.addr[3], srv.addr[1])
      lsock = srv.accept
      srv.close
      return [lsock, rsock]
    end

    class QuerySettings
      attr_accessor :query_bytes, :query, :ignore_truncation, :client_queue,
        :client_query_id, :socket, :dest_server, :dest_port, :endtime, :udp_packet_size,
        :single_resolver, :is_persistent_socket, :tcp_pipelining_max_queries, :send_token,
        :retire_connection
      #  new(query_bytes, query, ignore_truncation, client_queue, client_query_id,
      #      socket, dest_server, dest_port, endtime, , udp_packet_size, single_resolver)
      def initialize(*args)
        @query_bytes = args[0]
        @query = args[1]
        @ignore_truncation=args[2]
        @client_queue = args[3]
        @client_query_id = args[4]
        @socket = args[5]
        @dest_server = args[6]
        @dest_port=args[7]
        @endtime = args[8]
        @udp_packet_size = args[9]
        @single_resolver = args[10]
        @is_persistent_socket = false
        @tcp_pipelining_max_queries = nil
        @send_token = SendToken.new
        @retire_connection = false
      end
    end

    # Cancellation and each nonblocking write are ordered without holding the
    # selector mutex during I/O. Waiting for a connect or a writable socket never
    # holds this lock, so closing a Resolver remains responsive.
    class SendToken
      def initialize
        @mutex = Mutex.new
        @cancelled = false
      end

      def cancel
        @mutex.synchronize { @cancelled = true }
      end

      def write
        @mutex.synchronize do
          return false if @cancelled
          yield
        end
      end
    end

    # Register ownership before work leaves the selector, including attempts
    # which have not acquired a socket yet. Nil is never a live attempt token.
    def reserve_send(settings, previous_settings = nil)
      @@mutex.synchronize do
        return false unless @@query_hash[settings.client_query_id].equal?(previous_settings)
        if previous_settings
          settings.retire_connection = previous_settings.retire_connection
          remove_id_from_mutex_synchronized_block(settings.client_query_id, settings.send_token)
        end
        @@query_hash[settings.client_query_id] = settings
        @@timeouts[settings.client_query_id] = settings.endtime
        check_select_thread_synchronized
      end
      wake_up_select_thread
      true
    end

    class SendTask
      def initialize(&operation)
        @operation = operation
        @result = Queue.new
      end

      def run
        @result << [@operation.call, nil]
      rescue Exception => error
        @result << [nil, error]
      end

      def value
        result, error = @result.pop
        raise error if error
        result
      end
    end

    # A finite pool keeps slow connects/writes off the selector without creating
    # an unbounded number of threads. Already-owned attempts can queue without
    # introducing a new admission limit; each retains its original deadline.
    def defer_send(sender = nil, &operation)
      task = SendTask.new(&operation)
      @@mutex.synchronize do
        unless @send_queue && @send_workers.any?(&:alive?)
          queue = Queue.new
          workers = []
          begin
            4.times { workers << Thread.new { while (work = queue.pop); work.run; end } }
          rescue ThreadError
            workers.length.times { queue << nil }
            raise
          end
          @send_queue = queue
          @send_workers = workers
          @send_groups = {}
        end
        if sender
          group = @send_groups[sender]
          if group
            group << task
          else
            @send_groups[sender] = [task]
            # One worker owns each sender's FIFO. Other tasks for the same
            # pipeline do not occupy workers just to wait for its writer lock.
            @send_queue << SendTask.new { run_send_group(sender) }
          end
        else
          @send_queue << task
        end
      end
      task
    end

    def run_send_group(sender)
      task = @@mutex.synchronize { @send_groups[sender].shift }
      task.run
      @@mutex.synchronize do
        if @send_groups[sender].empty?
          @send_groups.delete(sender)
        else
          # Give another sender a turn without allowing two workers to send on
          # this sender concurrently. A continuously busy pipeline cannot starve
          # a different server's connection behind its entire backlog.
          @send_queue << SendTask.new { run_send_group(sender) }
        end
      end
    end
    private :run_send_group

    def tcp?(socket)
      type = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE)
      [Socket::SOCK_STREAM].pack("i") == type.data
    end

    def udp?(socket)
      type = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE)
      [Socket::SOCK_DGRAM].pack("i") == type.data
    end

    def add_to_select(query_settings)
      #  Add the query to sockets, and then wake the select thread up
      @@mutex.synchronize {
        check_select_thread_synchronized
        add_query_from_mutex_synchronized_block(query_settings)
      }
      wake_up_select_thread
    end

    def query_settings_for_id(client_query_id)
      @@mutex.synchronize { @@query_hash[client_query_id] }
    end

    def selector_thread?
      @@mutex.synchronize { @@select_thread.equal?(Thread.current) }
    end

    # Reserve a pipeline query before writing, or replace a protocol retry.
    # A deferred retry must not replace an attempt already completed or replaced.
    def register_query_if_current(query_settings, previous_settings)
      registered = @@mutex.synchronize do
        return false unless @@query_hash[query_settings.client_query_id].equal?(previous_settings)
        query_settings.retire_connection = previous_settings.retire_connection if previous_settings
        check_select_thread_synchronized
        add_query_from_mutex_synchronized_block(query_settings)
      end
      wake_up_select_thread
      registered
    end

    # Called only with @@mutex held. Retrying a client ID also retires its old
    # socket membership, so stale EOF/timeout work cannot consume the retry.
    def add_query_from_mutex_synchronized_block(settings)
      id = settings.client_query_id
      remove_id_from_mutex_synchronized_block(id, settings.send_token) if @@query_hash[id]
      if settings.socket.closed?
        @@queued_exceptions << [id, settings.client_queue,
          SocketEofResolvError.new("TCP socket closed before all answers received"), nil]
        return false
      end
      @@query_hash[id] = settings
      (@@socket_hash[settings.socket] ||= []) << id
      if settings.tcp_pipelining_max_queries != :infinite
        @@socket_remaining_queries[settings.socket] ||= settings.tcp_pipelining_max_queries
      end
      @@timeouts[id] = settings.endtime
      @@sockets << settings.socket
      @@socket_is_persistent[settings.socket] = settings.is_persistent_socket
      (@@socket_owners ||= {})[settings.socket] = settings.single_resolver
      (@@retiring_sockets ||= Set.new) << settings.socket if settings.retire_connection
      true
    end

    # Explicit close retires streams owned by this sender, including idle and
    # rolled-over pipelines. Other logical queries sharing a sender may finish,
    # but future sends must choose a fresh connection.
    def retire_sender(sender)
      @@mutex.synchronize do
        # A connect can be in progress without a socket in our read set yet.
        # Carry retirement through reservation replacements so its eventual
        # registration drains and closes, while later fresh sends can reuse.
        @@query_hash.each_value do |settings|
          settings.retire_connection = true if settings.single_resolver.equal?(sender)
        end
        (@@socket_owners ||= {}).select { |_, owner| owner.equal?(sender) }.each_key do |socket|
          mark_socket_for_retirement(socket)
        end
      end
      wake_up_select_thread
    end

    def retire_socket(socket)
      @@mutex.synchronize { mark_socket_for_retirement(socket) }
      wake_up_select_thread
    end

    def mark_socket_for_retirement(socket)
      (@@retiring_sockets ||= Set.new) << socket
      if (@@socket_hash[socket] || []).empty?
        socket.close rescue nil
        retire_socket_from_mutex_synchronized_block(socket)
      end
    end
    private :mark_socket_for_retirement

    def query_id_in_use?(socket, header_id)
      @@mutex.synchronize do
        (@@socket_hash[socket] || []).any? do |id|
          settings = @@query_hash[id]
          settings && settings.query.header.id == header_id
        end
      end
    end

    def reusable_socket?(socket)
      @@mutex.synchronize do
        !socket.closed? && !(@@retiring_sockets ||= Set.new).include?(socket)
      end
    end

    # A partial TCP frame makes the whole connection unusable. Atomically claim
    # its outstanding queries, then let the selector deliver their errors.
    # Sender threads must never invoke resolver callbacks themselves.
    def fail_tcp_send(settings, error)
      @@mutex.synchronize do
        settings.socket.close rescue nil
        exceptions = retire_socket_from_mutex_synchronized_block(settings.socket)
        exceptions.each do |eof, socket, id|
          current = @@query_hash[id]
          next unless current && current.socket == socket
          remove_id_from_mutex_synchronized_block(id)
          @@queued_exceptions << [id, current.client_queue,
            current.equal?(settings) ? error : eof, nil]
        end
        check_select_thread_synchronized unless @@queued_exceptions.empty?
      end
      wake_up_select_thread
    end

    # A send waiting for the pipeline writer has no new socket registration yet.
    # Its original attempt may have expired or been replaced in the meantime.
    def fail_query_if_current(id, queue, previous_settings, error)
      @@mutex.synchronize do
        return unless @@query_hash[id].equal?(previous_settings)
        remove_id_from_mutex_synchronized_block(id) if previous_settings
        @@queued_exceptions << [id, queue, error, nil]
        check_select_thread_synchronized
      end
      wake_up_select_thread
    end

    # Cache lookup can satisfy a protocol retry before it reaches the sender.
    # Claim that exact attempt before publishing a result, just like a wire reply.
    def push_response_for_query(settings, msg, query, resolver)
      return unless claim_query(settings)
      push_response_to_select(settings.client_query_id, settings.client_queue, msg, query, resolver)
    end

    def claim_query(settings)
      @@mutex.synchronize do
        return false unless @@query_hash[settings.client_query_id].equal?(settings)
        remove_id_from_mutex_synchronized_block(settings.client_query_id)
        true
      end
    end

    def wake_up_select_thread
      # One unread byte is sufficient: a full socket already guarantees that
      # select will wake. Never let notification block a producer or the selector
      # itself (cache hits and protocol retries also produce notifications).
      @@wakeup_sockets[0].write_nonblock(".")
    rescue IO::WaitWritable, IOError, SystemCallError
      nil
    end

    def check_select_thread_synchronized
      if !@@select_thread || !@@select_thread.alive?
        Dnsruby.log.debug{"Restarting select thread"}
        @@select_thread = Thread.new {
          do_select
        }
      end
    end

    def select_thread_alive?
      ret=true
      @@mutex.synchronize{
        ret = !!(@@select_thread && @@select_thread.alive?)
      }
      return ret
    end

    def do_select
      unused_loop_count = 0
      last_tick_time = Time.now - 10
      while true do
        if (last_tick_time < (Time.now - 0.5))
          send_tick_to_observers # ONLY NEED TO SEND THIS TWICE A SECOND - NOT EVERY SELECT!!!
          last_tick_time = Time.now
        end
        send_queued_exceptions
        send_queued_responses
        send_queued_validation_responses
        timeout = tick_time = 0.1 # We provide a timer service to various Dnsruby classes
        sockets, timeouts, has_observer = @@mutex.synchronize { [@@sockets.to_a, @@timeouts.values, !@@observers.empty?] }
        if (timeouts.length > 0)
          timeouts.sort!
          timeout = timeouts[0] - Time.now
          if (timeout <= 0)
            process_timeouts
            timeout = 0
            next
          end
        end
        ready=nil
        if (has_observer && (timeout > tick_time))
          timeout = tick_time
        end
        #         next if (timeout < 0)
        begin
          ready, _write, _errors = IO.select(sockets, nil, nil, timeout)
        rescue SelectWakeup
          #  If SelectWakeup, then just restart this loop - the select call will be made with the new data
          next
        rescue IOError, Errno::EBADF, EncodeError
          # A pipeline writer can close a socket after this loop snapshots its
          # read set, or while native select is waiting on its descriptor.
          exceptions = clean_up_closed_sockets
          exceptions.each { |exception| send_exception_to_client(*exception) }

          next
        end
        if ready && ready.include?(@@wakeup_sockets[1])
          ready.delete(@@wakeup_sockets[1])
          begin
            # Bound draining so continuously arriving notifications cannot starve
            # responses and timeouts. Any remainder wakes the next select.
            @@wakeup_sockets[1].recv_nonblock(4096)
          rescue IO::WaitReadable, IOError, SystemCallError
          end
        end
        if (ready == nil)
          #  process the timeouts
          process_timeouts
          unused_loop_count+=1
        else
          process_ready(ready)
          unused_loop_count=0
          # process_error(errors)
        end
        @@mutex.synchronize do
          if (unused_loop_count > 10 && @@query_hash.empty? && @@observers.empty? &&
              @@queued_exceptions.empty? && @@queued_responses.empty? &&
              @@queued_validation_responses.empty?)
            Dnsruby.log.debug("Try stop select loop")

            # We leave the @@wakeup_sockets here, but remove everything else
            non_persistent_sockets = @@sockets.select { |s| ! @@socket_is_persistent[s] }
            non_persistent_sockets.each do |socket|
              if socket != @@wakeup_sockets[1]
                socket.close rescue nil
                @@sockets.delete(socket)
              end
            end

            Dnsruby.log.debug("Deleted #{non_persistent_sockets.size - 1} non-persistent sockets," +
                              " #{@@sockets.count - 1} persistent sockets remain.")
            @@socket_hash.clear

            if @@sockets.size == 1
              Dnsruby.log.debug("Stopping select loop")
              # A producer acquiring the mutex after this decision must start a
              # replacement, even while the old Ruby thread is still returning.
              @@select_thread = nil
              return
            end
          end
        end
        #               }
      end
    end

    # Detach closed sockets before notifying clients. Callbacks can register
    # other queries, and must never run while holding the selector mutex.
    def clean_up_closed_sockets
      @@mutex.synchronize do
        @@sockets.select(&:closed?).flat_map do |socket|
          retire_socket_from_mutex_synchronized_block(socket)
        end
      end
    end

    # Called only with @@mutex held and after the socket has been closed.
    def retire_socket_from_mutex_synchronized_block(socket)
      ids = @@socket_hash.delete(socket) || []
      @@sockets.delete(socket)
      @@tcp_buffers.delete(socket)
      @@socket_remaining_queries.delete(socket)
      @@socket_is_persistent.delete(socket)
      (@@socket_owners ||= {}).delete(socket)
      (@@retiring_sockets ||= Set.new).delete(socket)
      ids.map do |client_id|
        [SocketEofResolvError.new("TCP socket closed before all answers received"), socket, client_id]
      end
    end

    def process_error(errors)
      Dnsruby.log.debug{"Error! #{errors.inspect}"}
      #  @todo@ Process errors [can we do this in single socket environment?]
    end

    # Retained for callers of this helper; response delivery now matches only
    # queries registered on the receiving socket instead of scanning every ID.
    def get_active_ids(queries, id)
      queries.keys.select { |client_query_id| client_query_id[1].header.id == id }
    end

    #         @@query_hash[query_settings.client_query_id]=query_settings
    def process_ready(ready)
      persistent_sockets, nonpersistent_sockets = @@mutex.synchronize { ready.partition { |socket| persistent?(socket) } }

      nonpersistent_sockets.each do |socket|
        query_settings = @@mutex.synchronize { @@query_hash[(@@socket_hash[socket] || []).first] }
        next if !query_settings

        udp_packet_size = query_settings.udp_packet_size
        msg, bytes = get_incoming_data(socket, udp_packet_size)

        process_message(msg, bytes, socket) if msg

        ready.delete(socket)
      end

      persistent_sockets.each do |socket|
        msg, bytes = get_incoming_data(socket, 0)
        process_message(msg, bytes, socket) if msg
        ready.delete(socket)
      end
    end

    def process_message(msg, bytes, socket)
      # Delivery looks up IDs only on this connected socket, then checks the
      # question and TSIG through PacketSender#check_response.
      send_response_to_client(msg, bytes, socket)
    end

    def send_response_to_client(msg, bytes, socket)
      #  Figure out which client_ids we were expecting on this socket, then see if any header ids match up
      #  @TODO@ Can get rid of this, as we only have one query per socket.
      client_ids=[]
      @@mutex.synchronize{
        client_ids = (@@socket_hash[socket] || []).dup
      }
      #  get the queries associated with them
      client_ids.each do |id|
        settings = @@mutex.synchronize { @@query_hash[id] }
        next unless settings && settings.socket == socket
        query_header_id = settings.query.header.id
        if (query_header_id == msg.header.id)
          # IDs can collide on a pipeline. Select the matching question before
          # query-specific TSIG checks or retries, which may consume the attempt.
          # Preserve raw/update responses and questionless FORMERR handling.
          query = settings.query
          unless query.send_raw || query.kind_of?(Update) || msg.question.empty?
            next unless msg.question.length == query.question.length &&
              msg.question.zip(query.question).all? do |answer, request|
                answer.qname.labels == request.qname.labels &&
                  answer.qtype == request.qtype && answer.qclass == request.qclass
              end
          end
          #  process the response
          client_queue = settings.client_queue
          res = settings.single_resolver
          query = settings.query
          begin
            tcp = settings.is_persistent_socket || tcp?(socket)
          rescue IOError, SystemCallError
            return if socket.closed?
            raise
          end
          #  At this point, we should check if the response is OK
          previous_context = Thread.current[:dnsruby_response_query]
          begin
            # check_response may synchronously retry (FORMERR or truncation).
            # Carry this attempt's identity through that unchanged public API.
            Thread.current[:dnsruby_response_query] = settings
            ret = res.check_response(msg, bytes, query, client_queue, id, tcp)
          ensure
            Thread.current[:dnsruby_response_query] = previous_context
          end
          if ret
            # A writer failure or a retry can replace/remove settings while
            # check_response runs. Only one path may claim this attempt.
            return unless claim_query(settings)
            exception = msg.get_exception
            if (ret.kind_of?TsigError)
              exception = ret
            end
            Dnsruby.log.debug{"Pushing response to client queue"}
            push_to_client(id, client_queue, msg, exception, query, res)
            #             client_queue.push([id, msg, exception])
            #             notify_queue_observers(client_queue, id)
          else
            #  Sending query again - don't return response
          end
          return
        end
      end
      #  If not, then we have an error
      Dnsruby.log.error{"Stray packet - " + msg.inspect + "\n from " + socket.inspect}
    end

    def persistent?(socket)
      @@socket_is_persistent[socket]
    end

    def remove_id(id)
      @@mutex.synchronize do
        remove_id_from_mutex_synchronized_block(id)
      end
    end

    # THIS MUST BE CALLED FROM INSIDE A @@mutex SYNCHRONISED BLOCK!
    def remove_id_from_mutex_synchronized_block(id, preserved_token = nil)
      settings = @@query_hash.delete(id)
      return unless settings
      settings.send_token.cancel unless settings.send_token.equal?(preserved_token)
      @@timeouts.delete(id)
      socket = settings.socket
      return unless socket # A queued send may not have acquired a socket yet.
      (@@socket_hash[socket] || []).delete(id)

      decrement_remaining_queries(socket) if persistent?(socket)

      retiring = (@@retiring_sockets ||= Set.new).include?(socket) &&
        (@@socket_hash[socket] || []).empty?
      if !persistent?(socket) || max_attained?(socket) || retiring
        @@sockets.delete(socket)
        @@socket_hash.delete(socket)
        @@socket_remaining_queries.delete(socket)
        @@socket_is_persistent.delete(socket)
        @@tcp_buffers.delete(socket)
        (@@socket_owners ||= {}).delete(socket)
        @@retiring_sockets.delete(socket)
        Dnsruby.log.debug("Closing socket #{socket}")
        socket.close rescue nil
      end
    end

    def decrement_remaining_queries(socket)
      if @@socket_remaining_queries[socket]
        @@socket_remaining_queries[socket] -= 1
      end
    end

    def max_attained?(socket)
      remaining = @@socket_remaining_queries[socket]
      attained = persistent?(socket) && remaining && remaining <= 0
      Dnsruby.log.debug("Max queries per conn attained") if attained
      attained
    end

    def process_timeouts
      # NOTE: It's @@timeouts we need to protect; after the clone we're ok
      timeouts = @@mutex.synchronize do
        @@timeouts.map { |id, timeout| [@@query_hash[id], timeout] }
      end
      time_now = Time.now
      timeouts.each do |settings, timeout|
        if timeout < time_now && settings && claim_query(settings)
          settings.client_queue.push([settings.client_query_id, Resolver::EventType::ERROR,
            nil, ResolvTimeout.new("Query timed out")])
          notify_queue_observers(settings.client_queue, settings.client_query_id)
        end
      end
    end

    def tcp_read(socket)
      #  Keep buffer for all TCP sockets, and return
      #  to select after reading available data. Once all data has been received,
      #  then process message.
      buf = +""
      expected_length = 0
      reading_length = nil
      @@mutex.synchronize {
        return false if socket.closed?
        buf, expected_length, reading_length = @@tcp_buffers[socket]
        if (!buf)
          buf = +""
          expected_length = 2
          reading_length = true
          @@tcp_buffers[socket]=[buf, expected_length, reading_length]
        end
      }
      if (buf.length() < expected_length)
        begin
          input, = socket.recv_nonblock(expected_length-buf.length)
          # Depending on the Ruby version, EOF is nil or an empty string.
          if input.nil? || input.empty?
            Dnsruby.log.debug("EOF from server - no bytes read - closing socket")
            exceptions = @@mutex.synchronize do
              socket.close
              retire_socket_from_mutex_synchronized_block(socket)
            end
            exceptions.each { |exception| send_exception_to_client(*exception) }

            return false
          end
          buf << input if input
        rescue
          #  Oh well - better luck next time!
          return false
        end
      end
      #  If data is complete, then return it.
      if (buf.length == expected_length)
        if reading_length
          #  We just read the data_length field. Now we need to start reading that many bytes.
          @@mutex.synchronize {
            return false if socket.closed?
            answersize = buf.unpack('n')[0]
            @@tcp_buffers[socket] = [+"", answersize, false]
          }
          return tcp_read(socket)
        else
          #  We just read the data - now return it
          @@mutex.synchronize {
            @@tcp_buffers.delete(socket)
          }
          return buf
        end
      else
        @@mutex.synchronize {
          return false if socket.closed?
          @@tcp_buffers[socket]=[buf, expected_length, reading_length]
        }
        return false
      end
    end

    def get_incoming_data(socket, packet_size)
      answerfrom,answerip,answerport,answersize=nil
      ans,buf = nil
      begin
        is_tcp = tcp?(socket)
      rescue IOError, SystemCallError
        # A concurrent pipeline writer can retire this socket after IO.select
        # returned it. It has already queued errors for its outstanding queries.
        return if socket.closed?
        raise
      end

      begin
        if is_tcp
          #  Call TCP read here - that will take care of reading the 2 byte length,
          #  and then the full packet - without blocking select.
          buf = tcp_read(socket)
          if (!buf) # Wait for the buffer to comletely fill
            #             handle_recvfrom_failure(socket, "")
            return
          end
        else
          #  @TODO@ Can we get recvfrom to stop issuing PTR queries when we already
          #  know both the FQDN and the IP address?
          if (ret = socket.recvfrom(packet_size))
            buf = ret[0]
            answerport=ret[1][1]
            answerfrom=ret[1][2]
            answerip=ret[1][3]
            answersize=(buf.length)
          else
            #  recvfrom failed - why?
            Dnsruby.log.error{"Error - recvfrom failed from #{socket}"}
            handle_recvfrom_failure(socket, "")
            return
          end
        end
      rescue Exception => e
        Dnsruby.log.error{"Error - recvfrom failed from #{socket}, exception : #{e}"}
        handle_recvfrom_failure(socket, e)
        return
      end
      Dnsruby.log.debug{";; answer from #{answerfrom} : #{answersize} bytes\n"}

      begin
        ans = Message.decode(buf)

      rescue Exception => e
        Dnsruby.log.error("Decode error! #{e.class}, #{e}\nfor msg (length=#{buf.length}) : #{buf}")
        # A partial Message has a newly allocated, random header if decoding
        # failed before the complete header. Only the bytes identify its ID.
        header_id = buf.unpack('n').first if buf.bytesize >= 2
        client_id=get_client_id_from_answerfrom(socket, answerip, answerport, header_id)
        if (client_id == nil)
          Dnsruby.log.error{"Decode error from #{answerip} but can't determine packet id"}
          return
        end
        # Truncation permits a UDP-to-TCP fallback, never another TCP attempt.
        # Repeating malformed TCP replies must not renew the packet deadline.
        settings = nil
        if !is_tcp && (DecodeError === e) && e.partial_message && e.partial_message.header.tc
          settings = @@mutex.synchronize do
            current = @@query_hash[client_id]
            if current && current.socket == socket && !current.ignore_truncation && !current.single_resolver.no_tcp
              current
            end
          end
        end
        if settings
          Dnsruby.log.error{"Decode error (from #{answerip})! Header shows truncation, so trying again over TCP"}
          previous_context = Thread.current[:dnsruby_response_query]
          begin
            Thread.current[:dnsruby_response_query] = settings
            settings.single_resolver.send_async(settings.query, settings.client_queue, client_id, true)
          ensure
            Thread.current[:dnsruby_response_query] = previous_context
          end
        else
          send_exception_to_client(e, socket, client_id)
        end
        return
      end

      if is_tcp
        # This supplies peer metadata only. Normal response checks below still
        # validate the question and TSIG, including sequential duplicate IDs.
        settings = @@mutex.synchronize do
          ids = @@socket_hash[socket] || []
          id = ids.find do |candidate|
            current = @@query_hash[candidate]
            current && current.socket == socket && current.query.header.id == ans.header.id
          end
          @@query_hash[id]
        end
        unless settings
          Dnsruby.log.debug { "Ignoring TCP response with no matching query on this socket" }
          return
        end
        answerfrom = settings.dest_server
        answerip = answerfrom
        answerport = settings.dest_port
      end

      if (ans!= nil)
        Dnsruby.log.debug{"#{ans}"}
        ans.answerfrom=(answerfrom)
        ans.answersize=(answersize)
        ans.answerip =(answerip)
      end
      return ans, buf
    end

    def handle_recvfrom_failure(socket, exception)
      #   No way to notify the client about this error, unless there was only one connection on the socket
      #  Not a problem, as there only will ever be one connection on the socket (Kaminsky attack mitigation)
      ids_for_socket = []
      @@mutex.synchronize{
        ids_for_socket = (@@socket_hash[socket] || []).dup
      }
      return if ids_for_socket.empty?
      if (ids_for_socket.length == 1)
        answerfrom=nil
        @@mutex.synchronize{
          query_settings = @@query_hash[ids_for_socket[0]]
          answerfrom=query_settings.dest_server if query_settings
        }
        send_exception_to_client(OtherResolvError.new("recvfrom failed from #{answerfrom}; #{exception}"), socket, ids_for_socket[0])
      else
        Dnsruby.log.fatal{"Recvfrom failed from #{socket}, no way to tell query id"}
      end
    end

    def get_client_id_from_answerfrom(socket, answerip, answerport, header_id=nil)
      #  A pipelined socket can have several outstanding queries.
      client_id=nil
      #  Figure out client id from answerfrom
      @@mutex.synchronize{
        ids = (@@socket_hash[socket] || []).select { |id| @@query_hash[id] }
        # TCP decoding can fail before the peer address has been assigned. The
        # socket and partial header identify its query, including pipeline use.
        if answerip.nil?
          if header_id
            matching = ids.select { |id| @@query_hash[id].query.header.id == header_id }
            return matching.first if matching.length == 1
            return nil
          end
          return ids.first if ids.length == 1
          return nil
        end
        ids.each do |id|
          #  Does this id speak to this dest_server?
          query_settings = @@query_hash[id]
          next if header_id && query_settings.query.header.id != header_id
          # recvfrom may spell a numeric zone as an interface name. The socket
          # is already connected to the scoped peer, so compare address bytes.
          source = IPAddr.new(answerip.split('%', 2).first)
          destination = IPAddr.new(query_settings.dest_server.to_s.split('%', 2).first)
          if (source == destination && answerport == query_settings.dest_port)
            #  We have a match
            client_id = id
            break
          end
        end
      }
      return client_id
    end

    def send_exception_to_client(err, socket, client_id, msg=nil)
      #  find the client response queue
      client_queue = nil
      @@mutex.synchronize {
        settings = @@query_hash[client_id]
        return unless settings && (!socket || settings.socket == socket)
        client_queue = settings.client_queue
        remove_id_from_mutex_synchronized_block(client_id)
      }
      #       push_to_client(client_id, client_queue, msg, err)
      client_queue.push([client_id, Resolver::EventType::ERROR, msg, err])
      notify_queue_observers(client_queue, client_id)
    end

    def push_exception_to_select(client_id, client_queue, err, msg)
      @@mutex.synchronize{
        @@queued_exceptions.push([client_id, client_queue, err, msg])
        check_select_thread_synchronized
      }
      wake_up_select_thread
    end

    def push_response_to_select(client_id, client_queue, msg, query, res)
      #  This needs to queue the response TO THE SELECT THREAD, which then needs
      #  to send it out from its normal loop.
      Dnsruby.log.debug{"Pushing response to client queue direct from resolver or validator"}
      @@mutex.synchronize{
        err = nil
        if (msg.rcode == RCode.NXDOMAIN)
          err = NXDomain.new
        end
        @@queued_responses.push([client_id, client_queue, msg, err, query, res])
        check_select_thread_synchronized
      }
      wake_up_select_thread
    end

    def push_validation_response_to_select(client_id, client_queue, msg, err, query, res)
      #  This needs to queue the response TO THE SELECT THREAD, which then needs
      #  to send it out from its normal loop.
      Dnsruby.log.debug{"Pushing response to client queue direct from resolver or validator"}
      @@mutex.synchronize{
        @@queued_validation_responses.push([client_id, client_queue, msg, err, query, res])
        check_select_thread_synchronized
      }
      wake_up_select_thread
    end

    def send_queued_exceptions
      exceptions = []
      @@mutex.synchronize{
        exceptions = @@queued_exceptions
        @@queued_exceptions = []
      }

      exceptions.each do |item|
        client_id, client_queue, err, msg = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::ERROR, msg, err])
        notify_queue_observers(client_queue, client_id)
      end
    end

    def send_queued_responses
      responses = []
      @@mutex.synchronize{
        responses = @@queued_responses
        @@queued_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, query, res = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::RECEIVED, msg, err])
        notify_queue_observers(client_queue, client_id)
        #  Do we need to validate this? The response has come from the cache -
        #  validate it only if it has not been validated already
        #  So, if we need to validate it, send it to the validation thread
        #  Otherwise, send VALIDATED to the requester.
        if (((msg.security_level == Message::SecurityLevel.UNCHECKED) ||
                (msg.security_level == Message::SecurityLevel.INDETERMINATE)) &&
              (ValidatorThread.requires_validation?(query, msg, err, res)))
          validator = ValidatorThread.new(client_id, client_queue, msg, err, query ,self, res)
          validator.run
        else
          PacketSender.cache(query, msg) # The validator won't cache it, so we'd better do it now
          client_queue.push([client_id, Resolver::EventType::VALIDATED, msg, err])
          notify_queue_observers(client_queue, client_id)
        end
      end
    end

    def send_queued_validation_responses
      responses = []
      @@mutex.synchronize{
        responses = @@queued_validation_responses
        @@queued_validation_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, _query, _res = item
        #         push_to_client(client_id, client_queue, msg, err)
        client_queue.push([client_id, Resolver::EventType::VALIDATED, msg, err])
        notify_queue_observers(client_queue, client_id)
      end
    end

    def push_to_client(client_id, client_queue, msg, err, query, res)
      #  @TODO@ Really need to let the client know that we have received a valid response!
      #  Can do that by calling notify_observers here, but with an identifier which
      #  defines the response to be a "Response received - validating. Please stop sending"
      #  type of response.
      client_queue.push([client_id, Resolver::EventType::RECEIVED, msg, err])
      notify_queue_observers(client_queue, client_id)

      if (!err || (err.instance_of?(NXDomain)))
        # 
        #  This method now needs to push the response to the validator,
        #  which will then take responsibility for delivering it to the client.
        #  The validator will need access to the queue observers -
        validator = ValidatorThread.new(client_id, client_queue, msg, err, query ,self, res)
        validator.run
        #       @@validator.add_to_queue([client_id, client_queue, msg, err, query, self, res])
      end
    end

    def add_observer(client_queue, observer)
      @@mutex.synchronize {
        @@observers[client_queue]=observer
        check_select_thread_synchronized # Is this really necessary? The client should start the thread by sending a query, really...
        if (!@@tick_observers.include?observer)
          @@tick_observers.push(observer)
        end
      }
    end

    def remove_observer(client_queue, observer)
      @@mutex.synchronize {
        if (@@observers[client_queue]==observer)
          #           @@observers.delete(observer)
          @@observers.delete(client_queue)
          # Resolver completion/close owns every packet attempt for this queue,
          # including queued sends which have not opened a socket yet.
          @@query_hash.values.select { |settings| settings.client_queue.equal?(client_queue) }.each do |settings|
            remove_id_from_mutex_synchronized_block(settings.client_query_id)
          end
        else
          if (@@observers[client_queue] == nil)
          end
          Dnsruby.log.error{"remove_observer called with wrong observer for queue"}
          raise ArgumentError.new("remove_observer called with wrong observer for queue")
        end
        if (!@@observers.values.include?observer)
          @@tick_observers.delete(observer)
        end
      }
    end

    def notify_queue_observers(client_queue, client_query_id)
      #  If any observers are known for this query queue then notify them
      observer=nil
      @@mutex.synchronize {
        observer = @@observers[client_queue]
      }
      if (observer)
        observer.handle_queue_event(client_queue, client_query_id)
      end
    end

    def send_tick_to_observers
      #  If any observers are known then send them a tick
      tick_observers=nil
      @@mutex.synchronize {
        tick_observers = @@tick_observers.dup
      }
      tick_observers.each do |observer|
        observer.tick
      end
    end
  end
end
