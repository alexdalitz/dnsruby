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
require 'dnsruby/transport_clock'
module Dnsruby
  class SelectThread #:nodoc: all
    class SelectWakeup < RuntimeError; end
    include Singleton

    class << self
      alias_method :instance_without_fork_check, :instance
      private :instance_without_fork_check

      def instance
        instance_without_fork_check.tap { |selector| selector.send(:ensure_current_process) }
      end
    end
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
    #  and socket->[client_ids], including multiple queries per TCP pipeline.
    #
    # @@mutex owns the attempt, queue and socket indexes. Cancellation may take
    # a SendToken lock while holding @@mutex; a token-protected write must not
    # acquire @@mutex. The selector never waits for a pipeline writer mutex.
    # Blocking I/O and client callbacks run outside @@mutex.

    def initialize
      @process_mutex ||= Mutex.new
      @send_queue = @send_workers = @send_groups = nil
      @created_sockets = ObjectSpace::WeakMap.new
      @@mutex = Mutex.new
      @@mutex.synchronize {
        @@in_select=false
        @@sockets = Set.new
        @@timeouts = Hash.new
        @@query_hash = Hash.new
        @@queries_by_queue = {}.compare_by_identity
        @@queries_by_sender = {}.compare_by_identity
        @@socket_hash = Hash.new
        @@socket_is_persistent = Hash.new
        @@socket_owners = Hash.new
        @@sockets_by_sender = {}.compare_by_identity
        @@retiring_sockets = Set.new
        @@observers = Hash.new
        @@observer_queue_counts = {}.compare_by_identity
        @@observed_queues = ObjectSpace::WeakMap.new
        @@validation_pid = Process.pid
        @@validations = []
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
        #  Now start the select thread
        @process_pid = Process.pid
        @@select_thread = Thread.new { do_select }
      }
    end

    # Only the calling thread survives fork. Discard all parent transactions
    # before restarting any workers, and close the child's descriptor copies
    # without shutting down the connections still used by the parent.
    def ensure_current_process
      return unless @process_pid && @process_pid != Process.pid
      @process_mutex.synchronize do
        if @process_pid != Process.pid
          sockets = @@sockets.to_a + @@socket_hash.keys + @@wakeup_sockets + @created_sockets.keys
          sockets.uniq.each do |socket|
            begin
              socket.close unless socket.closed?
            rescue IOError, SystemCallError
            end
          end
          Thread.current[:dnsruby_response_query] = nil
          initialize
        end
      end
    end
    private :ensure_current_process

    # Also protect callers retaining a selector reference across fork.
    def state_mutex
      ensure_current_process
      @@mutex
    end
    private :state_mutex

    # Keep weak references from allocation through connect/write, before a
    # socket joins the read set. A fork must close those descriptor copies too.
    def track_socket(socket)
      state_mutex.synchronize { (@created_sockets ||= ObjectSpace::WeakMap.new)[socket] = true }
      socket
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
        :retire_connection, :disable_edns, :authentication_error
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
        @disable_edns = false
      end
    end

    # Look up client queries by socket and DNS message ID. Helper callers may
    # register several queries with the same DNS ID; normal TCP sends keep IDs
    # unique per connection. Hold @@mutex when updating the index.
    class SocketQueries < Set
      def initialize
        super
        @by_header_id = {}
        @header_ids = {}
      end

      def add_query(settings)
        id, header_id = settings.client_query_id, settings.query.header.id
        add(id)
        @header_ids[id] = header_id
        (@by_header_id[header_id] ||= Set.new).add(id)
      end

      def matching(header_id)
        (@by_header_id[header_id] || []).to_a
      end

      def delete(id)
        header_id = @header_ids.delete(id)
        if (ids = @by_header_id[header_id])
          ids.delete(id)
          @by_header_id.delete(header_id) if ids.empty?
        end
        super
      end
    end
    private_constant :SocketQueries

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

      def cancelled?
        @mutex.synchronize { @cancelled }
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
      state_mutex.synchronize do
        return false unless @@query_hash[settings.client_query_id].equal?(previous_settings)
        if previous_settings
          settings.retire_connection = previous_settings.retire_connection
          remove_id_from_mutex_synchronized_block(settings.client_query_id, settings.send_token)
        end
        @@query_hash[settings.client_query_id] = settings
        (@@queries_by_queue[settings.client_queue] ||= Set.new) << settings.client_query_id
        ((@@queries_by_sender ||= {}.compare_by_identity)[settings.single_resolver] ||= Set.new) << settings.client_query_id
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
      state_mutex.synchronize do
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
      task = state_mutex.synchronize { @send_groups[sender].shift }
      task.run
      state_mutex.synchronize do
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
      state_mutex.synchronize {
        check_select_thread_synchronized
        add_query_from_mutex_synchronized_block(query_settings)
      }
      wake_up_select_thread
    end

    def query_settings_for_id(client_query_id)
      state_mutex.synchronize { @@query_hash[client_query_id] }
    end

    def selector_thread?
      state_mutex.synchronize { @@select_thread.equal?(Thread.current) }
    end

    # Reserve a pipeline query before writing, or replace a protocol retry.
    # A deferred retry must not replace an attempt already completed or replaced.
    def register_query_if_current(query_settings, previous_settings)
      registered = state_mutex.synchronize do
        return false unless @@query_hash[query_settings.client_query_id].equal?(previous_settings)
        # Selection happens outside this mutex. A timeout or close may retire
        # that stream before admission, so leave the reservation untouched and
        # let the sender choose a new connection under the original deadline.
        if query_settings.is_persistent_socket &&
            (query_settings.socket.closed? || (@@retiring_sockets ||= Set.new).include?(query_settings.socket))
          return :retry_connection
        end
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
      (@@queries_by_queue[settings.client_queue] ||= Set.new) << id
      ((@@queries_by_sender ||= {}.compare_by_identity)[settings.single_resolver] ||= Set.new) << id
      membership = @@socket_hash[settings.socket]
      unless membership.is_a?(SocketQueries)
        indexed = SocketQueries.new
        (membership || []).each { |member| indexed.add_query(@@query_hash[member]) if @@query_hash[member] }
        membership = @@socket_hash[settings.socket] = indexed
      end
      membership.add_query(settings)
      if settings.tcp_pipelining_max_queries != :infinite
        @@socket_remaining_queries[settings.socket] ||= settings.tcp_pipelining_max_queries
      end
      @@timeouts[id] = settings.endtime
      @@sockets << settings.socket
      @@socket_is_persistent[settings.socket] = settings.is_persistent_socket
      previous_owner = (@@socket_owners ||= {})[settings.socket]
      if previous_owner && !previous_owner.equal?(settings.single_resolver) &&
          (previous_sockets = (@@sockets_by_sender ||= {}.compare_by_identity)[previous_owner])
        previous_sockets.delete(settings.socket)
        @@sockets_by_sender.delete(previous_owner) if previous_sockets.empty?
      end
      (@@socket_owners ||= {})[settings.socket] = settings.single_resolver
      ((@@sockets_by_sender ||= {}.compare_by_identity)[settings.single_resolver] ||= Set.new) << settings.socket
      (@@retiring_sockets ||= Set.new) << settings.socket if settings.retire_connection
      true
    end

    # Explicit close retires streams owned by this sender, including idle and
    # rolled-over pipelines. Other logical queries sharing a sender may finish,
    # but future sends must choose a fresh connection.
    def retire_sender(sender)
      state_mutex.synchronize do
        refresh_validation_process
        # A connect can be in progress without a socket in our read set yet.
        # Carry retirement through reservation replacements so its eventual
        # registration drains and closes, while later fresh sends can reuse.
        ((@@queries_by_sender ||= {}.compare_by_identity)[sender] || []).each do |id|
          settings = @@query_hash[id]
          settings.retire_connection = true if settings
        end
        ((@@sockets_by_sender ||= {}.compare_by_identity)[sender] || []).to_a.each do |socket|
          mark_socket_for_retirement(socket)
        end
        @@validations.each do |queue, owner, control|
          # A Resolver owns its validation through the queue observer. Removing
          # that observer cancels its work; retiring a shared or reconfigured
          # sender must let other accepted responses finish. Direct PacketSender
          # callers have no observer, so their sender's close still cancels them.
          control.cancel if owner.equal?(sender) && !@@observers[queue]
        end
      end
      wake_up_select_thread
    end

    def retire_socket(socket)
      state_mutex.synchronize { mark_socket_for_retirement(socket) }
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
      state_mutex.synchronize do
        !socket_ids_for_header(socket, header_id).empty?
      end
    end

    # Helper callers may supply a plain array; add_to_select uses SocketQueries.
    # Call with @@mutex held.
    def socket_ids_for_header(socket, header_id)
      ids = @@socket_hash[socket]
      return [] unless ids
      return ids.matching(header_id) if ids.is_a?(SocketQueries)
      ids.select { |id| (settings = @@query_hash[id]) && settings.query.header.id == header_id }
    end
    private :socket_ids_for_header

    def reusable_socket?(socket)
      state_mutex.synchronize do
        !socket.closed? && !(@@retiring_sockets ||= Set.new).include?(socket)
      end
    end

    # A partial TCP frame makes the whole connection unusable. Atomically claim
    # its outstanding queries, then let the selector deliver their errors.
    # Sender threads must never invoke resolver callbacks themselves.
    def fail_tcp_send(settings, error)
      state_mutex.synchronize do
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
      state_mutex.synchronize do
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

    def claim_query(settings, response_received = false)
      state_mutex.synchronize do
        return false unless @@query_hash[settings.client_query_id].equal?(settings)
        remove_id_from_mutex_synchronized_block(settings.client_query_id, nil, response_received)
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
      state_mutex.synchronize{
        ret = !!(@@select_thread && @@select_thread.alive?)
      }
      return ret
    end

    def do_select
      unused_loop_count = 0
      last_tick_time = TransportClock.now - 10
      while true do
        if (last_tick_time < (TransportClock.now - 0.5))
          send_tick_to_observers # ONLY NEED TO SEND THIS TWICE A SECOND - NOT EVERY SELECT!!!
          last_tick_time = TransportClock.now
        end
        send_queued_exceptions
        send_queued_responses
        send_queued_validation_responses
        timeout = tick_time = 0.1 # We provide a timer service to various Dnsruby classes
        sockets, timeouts, has_observer = state_mutex.synchronize { [@@sockets.to_a, @@timeouts.values, !@@observers.empty?] }
        if (timeouts.length > 0)
          timeout = timeouts.min - TransportClock.now
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
        state_mutex.synchronize do
          if (unused_loop_count > 10 && @@query_hash.empty? && @@observers.empty? &&
              @@queued_exceptions.empty? && @@queued_responses.empty? &&
              @@queued_validation_responses.empty?)
            Dnsruby.log.debug("Try stop select loop")

            # We leave the @@wakeup_sockets here, but remove everything else
            non_persistent_sockets = @@sockets.select { |s| ! @@socket_is_persistent[s] }
            non_persistent_sockets.each do |socket|
              if socket != @@wakeup_sockets[1]
                socket.close rescue nil
                retire_socket_from_mutex_synchronized_block(socket)
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
      end
    end

    # Detach closed sockets before notifying clients. Callbacks can register
    # other queries, and must never run while holding the selector mutex.
    def clean_up_closed_sockets
      state_mutex.synchronize do
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
      owner = (@@socket_owners ||= {}).delete(socket)
      if (sockets = (@@sockets_by_sender ||= {}.compare_by_identity)[owner])
        sockets.delete(socket)
        @@sockets_by_sender.delete(owner) if sockets.empty?
      end
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

    def process_ready(ready)
      persistent_sockets, nonpersistent_sockets = state_mutex.synchronize { ready.partition { |socket| persistent?(socket) } }

      nonpersistent_sockets.each do |socket|
        query_settings = state_mutex.synchronize { @@query_hash[(@@socket_hash[socket] || []).first] }
        next if !query_settings

        udp_packet_size = query_settings.udp_packet_size
        msg, bytes = get_incoming_data(socket, udp_packet_size)

        process_message(msg, bytes, socket) if msg
      end

      persistent_sockets.each do |socket|
        msg, bytes = get_incoming_data(socket, 0)
        process_message(msg, bytes, socket) if msg
      end
    end

    def process_message(msg, bytes, socket)
      # Delivery looks up IDs only on this connected socket, then checks the
      # question and TSIG through PacketSender#check_response.
      send_response_to_client(msg, bytes, socket)
    end

    def matching_questions?(response, query)
      response.question.length == query.question.length &&
        response.question.zip(query.question).all? do |answer, request|
          answer.qname.labels == request.qname.labels &&
            answer.qtype == request.qtype && answer.qclass == request.qclass
        end
    end
    private :matching_questions?

    def send_response_to_client(msg, bytes, socket)
      # Match the header ID against queries outstanding on this connection.
      client_ids=[]
      state_mutex.synchronize{
        client_ids = socket_ids_for_header(socket, msg.header.id)
      }
      #  get the queries associated with them
      client_ids.each do |id|
        settings = state_mutex.synchronize { @@query_hash[id] }
        next unless settings && settings.socket == socket
        query_header_id = settings.query.header.id
        if (query_header_id == msg.header.id)
          # IDs can collide on a pipeline. Select the matching question before
          # query-specific TSIG checks or retries, which may consume the attempt.
          # Preserve raw/update responses and questionless FORMERR handling.
          query = settings.query
          unless query.send_raw || query.kind_of?(Update) || msg.question.empty?
            next unless matching_questions?(msg, query)
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
            return unless claim_query(settings, true)
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
      state_mutex.synchronize do
        remove_id_from_mutex_synchronized_block(id)
      end
    end

    # THIS MUST BE CALLED FROM INSIDE A @@mutex SYNCHRONISED BLOCK!
    def remove_id_from_mutex_synchronized_block(id, preserved_token = nil, response_received = false)
      settings = @@query_hash.delete(id)
      return unless settings
      ids = @@queries_by_queue[settings.client_queue]
      if ids
        ids.delete(id)
        @@queries_by_queue.delete(settings.client_queue) if ids.empty?
      end
      if (sender_ids = (@@queries_by_sender ||= {}.compare_by_identity)[settings.single_resolver])
        sender_ids.delete(id)
        @@queries_by_sender.delete(settings.single_resolver) if sender_ids.empty?
      end
      settings.send_token.cancel unless settings.send_token.equal?(preserved_token)
      @@timeouts.delete(id)
      socket = settings.socket
      return unless socket # A queued send may not have acquired a socket yet.
      (@@socket_hash[socket] || []).delete(id)

      if persistent?(socket)
        decrement_remaining_queries(socket)
        # An unanswered query can still produce a late reply, or leave an
        # incomplete frame in the reader. Drain existing peers, but never admit
        # another query on this stream after its ownership has been cancelled.
        (@@retiring_sockets ||= Set.new) << socket unless response_received
      end

      retiring = (@@retiring_sockets ||= Set.new).include?(socket) &&
        (@@socket_hash[socket] || []).empty?
      if !persistent?(socket) || retiring ||
          (max_attained?(socket) && (@@socket_hash[socket] || []).empty?)
        Dnsruby.log.debug("Closing socket #{socket}")
        socket.close rescue nil
        retire_socket_from_mutex_synchronized_block(socket)
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
      timeouts = state_mutex.synchronize do
        @@timeouts.map { |id, timeout| [@@query_hash[id], timeout] }
      end
      time_now = TransportClock.now
      timeouts.each do |settings, timeout|
        if timeout < time_now && settings && claim_query(settings)
          deliver_queue_event(settings.client_queue, [settings.client_query_id, Resolver::EventType::ERROR,
            nil, settings.authentication_error || ResolvTimeout.new("Query timed out")])
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
      state_mutex.synchronize {
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
            exceptions = state_mutex.synchronize do
              socket.close
              retire_socket_from_mutex_synchronized_block(socket)
            end
            exceptions.each { |exception| send_exception_to_client(*exception) }

            return false
          end
          buf << input if input
        rescue IO::WaitReadable, Errno::EINTR
          return false
        rescue IOError, SystemCallError => error
          # A reset or fatal read failure cannot become readable again. Retire
          # every owner once, without invoking resolver callbacks under our lock.
          exceptions = state_mutex.synchronize do
            socket.close rescue nil
            retire_socket_from_mutex_synchronized_block(socket)
          end
          exceptions.each { |exception| send_exception_to_client(*exception) }
          Dnsruby.log.debug { "TCP read failed: #{error.class}: #{error.message}" }
          return false
        end
      end
      #  If data is complete, then return it.
      if (buf.length == expected_length)
        if reading_length
          #  We just read the data_length field. Now we need to start reading that many bytes.
          state_mutex.synchronize {
            return false if socket.closed?
            answersize = buf.unpack('n')[0]
            @@tcp_buffers[socket] = [+"", answersize, false]
          }
          return tcp_read(socket)
        else
          #  We just read the data - now return it
          state_mutex.synchronize {
            @@tcp_buffers.delete(socket)
          }
          return buf
        end
      else
        state_mutex.synchronize {
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
        unless is_tcp
          matches_question = state_mutex.synchronize do
            current = @@query_hash[client_id]
            partial = e.partial_message if e.is_a?(DecodeError)
            current && current.socket == socket && (current.query.send_raw ||
              (buf.bytesize >= 12 && partial &&
                (current.query.kind_of?(Update) ||
                  (!partial.question.empty? && partial.header.qdcount == partial.question.length &&
                    matching_questions?(partial, current.query)))))
          end
          # A truncated answer can justify TCP fallback only after its question
          # identifies this query (RFC 5452 section 9.1). Incomplete headers or
          # questions and unrelated questions cannot end the UDP transaction.
          return unless matches_question
        end
        # Decoding may fail after a complete header. Such a packet must match
        # the response direction and opcode before it can retry or fail its
        # owner, just as a successfully decoded response must. Use wire bytes:
        # an incomplete decoded Message can still contain a default header.
        if buf.bytesize >= 12
          flags = buf.unpack('n2').last
          matches_header = state_mutex.synchronize do
            current = @@query_hash[client_id]
            current && current.socket == socket && (current.query.send_raw ||
              ((flags & 0x8000) != 0 && ((flags >> 11) & 15) == current.query.header.opcode.code))
          end
          return unless matches_header
        end
        # No undecodable packet can authenticate its TSIG. Discard it before
        # either failing the transaction or acting on an untrusted TC bit, just
        # as check_response discards unsigned or incorrectly signed replies.
        unauthenticated = state_mutex.synchronize do
          current = @@query_hash[client_id]
          if current && current.socket == socket && current.query.tsig && !current.query.send_raw
            current.authentication_error ||= TsigError.new('Cannot authenticate malformed response')
            true
          end
        end
        return if unauthenticated
        # Truncation permits a UDP-to-TCP fallback, never another TCP attempt.
        # Repeating malformed TCP replies must not renew the packet deadline.
        settings = nil
        if !is_tcp && (DecodeError === e) && e.partial_message && e.partial_message.header.tc
          settings = state_mutex.synchronize do
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
        settings = state_mutex.synchronize do
          id = socket_ids_for_header(socket, ans.header.id).first
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
      state_mutex.synchronize{
        ids_for_socket = (@@socket_hash[socket] || []).to_a
      }
      return if ids_for_socket.empty?
      if (ids_for_socket.length == 1)
        answerfrom=nil
        state_mutex.synchronize{
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
      state_mutex.synchronize{
        ids = (header_id ? socket_ids_for_header(socket, header_id) :
          (@@socket_hash[socket] || [])).select { |id| @@query_hash[id] }
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
      state_mutex.synchronize {
        settings = @@query_hash[client_id]
        return unless settings && (!socket || settings.socket == socket)
        client_queue = settings.client_queue
        remove_id_from_mutex_synchronized_block(client_id)
      }
      #       push_to_client(client_id, client_queue, msg, err)
      deliver_queue_event(client_queue, [client_id, Resolver::EventType::ERROR, msg, err])
    end

    def push_exception_to_select(client_id, client_queue, err, msg)
      state_mutex.synchronize{
        @@queued_exceptions.push([client_id, client_queue, err, msg])
        check_select_thread_synchronized
      }
      wake_up_select_thread
    end

    def push_response_to_select(client_id, client_queue, msg, query, res)
      #  This needs to queue the response TO THE SELECT THREAD, which then needs
      #  to send it out from its normal loop.
      Dnsruby.log.debug{"Pushing response to client queue direct from resolver or validator"}
      state_mutex.synchronize{
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
      state_mutex.synchronize{
        @@queued_validation_responses.push([client_id, client_queue, msg, err, query, res])
        check_select_thread_synchronized
      }
      wake_up_select_thread
    end

    def send_queued_exceptions
      exceptions = []
      state_mutex.synchronize{
        exceptions = @@queued_exceptions
        @@queued_exceptions = []
      }

      exceptions.each do |item|
        client_id, client_queue, err, msg = item
        #         push_to_client(client_id, client_queue, msg, err)
        deliver_queue_event(client_queue, [client_id, Resolver::EventType::ERROR, msg, err])
      end
    end

    def send_queued_responses
      responses = []
      state_mutex.synchronize{
        responses = @@queued_responses
        @@queued_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, query, res = item
        #         push_to_client(client_id, client_queue, msg, err)
        next unless deliver_queue_event(client_queue, [client_id, Resolver::EventType::RECEIVED, msg, err])
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
          deliver_queue_event(client_queue, [client_id, Resolver::EventType::VALIDATED, msg, err])
        end
      end
    end

    def send_queued_validation_responses
      responses = []
      state_mutex.synchronize{
        responses = @@queued_validation_responses
        @@queued_validation_responses = []
      }

      responses.each do |item|
        client_id, client_queue, msg, err, _query, _res = item
        #         push_to_client(client_id, client_queue, msg, err)
        deliver_queue_event(client_queue, [client_id, Resolver::EventType::VALIDATED, msg, err])
      end
    end

    def push_to_client(client_id, client_queue, msg, err, query, res)
      # Notify the resolver before validation so it stops competing attempts
      # while retaining the logical query's total deadline.
      return unless deliver_queue_event(client_queue, [client_id, Resolver::EventType::RECEIVED, msg, err])

      if (!err || (err.instance_of?(NXDomain)))
        # The validator owns delivery of the validation result.
        validator = ValidatorThread.new(client_id, client_queue, msg, err, query ,self, res)
        validator.run
      end
    end

    def add_observer(client_queue, observer)
      state_mutex.synchronize {
        (@@observed_queues ||= ObjectSpace::WeakMap.new)[client_queue] = true
        previous = @@observers[client_queue]
        unless previous.equal?(observer)
          remove_observer_queue_count(previous) if previous
          @@observers[client_queue] = observer
          count = (@@observer_queue_counts[observer] || 0) + 1
          @@observer_queue_counts[observer] = count
          @@tick_observers.push(observer) if count == 1
        end
        check_select_thread_synchronized # Is this really necessary? The client should start the thread by sending a query, really...
      }
    end

    # Take the observer snapshot before acquiring its Resolver lock: Resolver
    # completion acquires these locks in the opposite direction.
    def validation_deadline(client_queue, client_query_id)
      observer = state_mutex.synchronize { @@observers[client_queue] }
      observer.validation_deadline(client_queue, client_query_id) if observer.respond_to?(:validation_deadline)
    end

    def register_validation(client_queue, sender, control)
      state_mutex.synchronize do
        refresh_validation_process
        # A response may have been accepted just before close or its total
        # deadline. Remember prior observers weakly so rejected registrations
        # cannot keep completed client queues alive.
        if client_queue.closed? ||
            ((@@observed_queues ||= ObjectSpace::WeakMap.new)[client_queue] && !@@observers[client_queue])
          control.cancel
          return false
        end
        # The validation pool is small and bounded. Keep one registration list
        # rather than maintaining separate indexes for queues and senders.
        unless @@validations.any? { |queue, owner, token|
            queue.equal?(client_queue) && owner.equal?(sender) && token.equal?(control) }
          @@validations << [client_queue, sender, control]
        end
        true
      end
    end

    def unregister_validation(client_queue, sender, control)
      state_mutex.synchronize do
        refresh_validation_process
        @@validations.delete_if do |queue, owner, token|
          queue.equal?(client_queue) && owner.equal?(sender) && token.equal?(control)
        end
      end
    end

    # Caller holds @@mutex. Parent workers do not survive fork, so they cannot
    # unregister their inherited entries in the child. Refresh before adding a
    # child registration, independently of the validation worker pool restart.
    def refresh_validation_process
      pid = Process.pid
      return if defined?(@@validation_pid) && @@validation_pid == pid
      @@validation_pid = pid
      @@validations = []
    end
    private :refresh_validation_process

    def cancel_validations_for_queue_synchronized(client_queue)
      refresh_validation_process
      @@validations.each do |queue, _sender, control|
        control.cancel if queue.equal?(client_queue)
      end
    end
    private :cancel_validations_for_queue_synchronized

    # Stop packet attempts without removing the logical query's observer. A
    # received response can still need validation and its overall deadline.
    def cancel_queries_for_queue(client_queue)
      state_mutex.synchronize { cancel_queries_for_queue_synchronized(client_queue) }
      wake_up_select_thread
    end

    def cancel_queries_for_queue_synchronized(client_queue)
      ids = @@queries_by_queue[client_queue]
      ids.to_a.each { |id| remove_id_from_mutex_synchronized_block(id) } if ids
    end
    private :cancel_queries_for_queue_synchronized

    def remove_observer_queue_count(observer)
      count = @@observer_queue_counts[observer] - 1
      if count == 0
        @@observer_queue_counts.delete(observer)
        @@tick_observers.delete(observer)
      else
        @@observer_queue_counts[observer] = count
      end
    end
    private :remove_observer_queue_count

    def remove_observer(client_queue, observer)
      state_mutex.synchronize {
        if (@@observers[client_queue]==observer)
          registered_observer = @@observers.delete(client_queue)
          # Resolver completion/close owns every packet attempt for this queue,
          # including queued sends which have not opened a socket yet.
          cancel_queries_for_queue_synchronized(client_queue)
          cancel_validations_for_queue_synchronized(client_queue)
          remove_observer_queue_count(registered_observer)
        else
          Dnsruby.log.error{"remove_observer called with wrong observer for queue"}
          raise ArgumentError.new("remove_observer called with wrong observer for queue")
        end
      }
    end

    def notify_queue_observers(client_queue, client_query_id)
      #  If any observers are known for this query queue then notify them
      observer=nil
      state_mutex.synchronize {
        observer = @@observers[client_queue]
      }
      if (observer)
        observer.handle_queue_event(client_queue, client_query_id)
      end
    rescue ClosedQueueError
      Dnsruby.log.debug { 'Observer could not deliver to a closed client queue' }
    end

    def deliver_queue_event(client_queue, event)
      client_queue.push(event)
      notify_queue_observers(client_queue, event.first)
      true
    rescue ClosedQueueError
      # A direct PacketSender caller can close its queue while queries are
      # pending. Cancel those queries so other clients can keep running.
      state_mutex.synchronize do
        cancel_queries_for_queue_synchronized(client_queue)
        cancel_validations_for_queue_synchronized(client_queue)
        observer = @@observers.delete(client_queue)
        remove_observer_queue_count(observer) if observer
      end
      Dnsruby.log.debug { 'Discarding event for closed client queue' }
      false
    end
    private :deliver_queue_event

    def send_tick_to_observers
      #  If any observers are known then send them a tick
      tick_observers=nil
      state_mutex.synchronize {
        tick_observers = @@tick_observers.dup
      }
      tick_observers.each do |observer|
        begin
          observer.tick
        rescue ClosedQueueError
          Dnsruby.log.debug { 'Observer tick could not deliver to a closed client queue' }
        end
      end
    end
  end
end
