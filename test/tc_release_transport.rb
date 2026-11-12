require_relative 'tc_pipeline_send'

class TestReleaseTransport < Minitest::Test
  def test_initial_connect_does_not_hold_resolver_lock_and_close_cancels_it
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
        use_tcp: true, tcp_pipelining: true)
      socket = FrameSocket.new
      entered, release = Queue.new, Queue.new
      resolver.single_resolvers.first.define_singleton_method(:tcp_pipeline_socket) do |_|
        entered << true
        release.pop
        [socket, true]
      end
      queue = Queue.new
      sending = Thread.new { resolver.send_async(query, queue, :slow) }
      entered.pop
      # This is the actual callback entry used by the global selector.
      Timeout.timeout(1) { SELECTOR.send_tick_to_observers }
      Timeout.timeout(1) { resolver.close }
      raise 'close did not complete exactly once' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::OtherResolvError)
      release << true
      sending.value
      drain_errors
      raise 'cancelled connect sent bytes' unless socket.written.empty?
      raise 'cancelled connect retained socket' unless socket.closed?
      raise 'cancelled connect recreated query' unless K.class_variable_get(:@@query_hash).empty?
      raise 'duplicate completion' unless queue.empty?
    RUBY
  end

  def test_close_before_initial_dispatch_cancels_reserved_attempt
    isolated(<<~'RUBY')
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      writer = resolver.single_resolvers.first
      original = writer.method(:prepare_send_async)
      entered, release = Queue.new, Queue.new
      writer.define_singleton_method(:prepare_send_async) do |*args|
        operation = original.call(*args)
        -> { entered << true; release.pop; operation.call }
      end
      writer.define_singleton_method(:send_async) { |*| raise 'dispatched after close' }
      queue = Queue.new
      sending = Thread.new { resolver.send_async(query, queue, :cancelled) }
      entered.pop
      resolver.close
      release << true
      sending.value
      raise 'missing close completion' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::OtherResolvError)
      raise 'retained reservation' unless K.class_variable_get(:@@query_hash).empty?
    RUBY
  end

  def test_nonpipeline_connects_use_independent_workers
    isolated(<<~'RUBY')
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: false,
        packet_timeout: 2, dnssec: false)
      entered, release, connected = Queue.new, Queue.new, Queue.new
      first_socket, second_socket = FrameSocket.new, FrameSocket.new
      calls = 0
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        calls += 1
        if calls == 1
          entered << true
          release.pop
          first_socket
        else
          connected << true
          second_socket
        end
      end
      K.class_variable_set(:@@select_thread, Thread.current)
      first = query('slow.example.')
      task1 = writer.send_dnsruby(first.encode, first, :first, Queue.new, true)
      entered.pop
      second = query('healthy.example.')
      task2 = writer.send_dnsruby(second.encode, second, :second, Queue.new, true)
      Timeout.timeout(1) { connected.pop; task2.value }
      raise 'healthy independent send never wrote' if second_socket.written.empty?
      release << true
      task1.value
      [:first, :second].each { |id| SELECTOR.remove_id(id) }
    RUBY
  end

  def test_explicit_close_retires_idle_streams_but_allows_shared_queries_to_finish
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      socket = FrameSocket.new
      writer = sender(socket)
      writer.use_tcp = true
      first, second = 2.times.map { Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false, use_tcp: true) }
      [first, second].each { |resolver| resolver.single_resolvers = [writer] }
      a, b = query('first.example.'), query('second.example.')
      a.header.id, b.header.id = 123, 124
      qa, qb = Queue.new, Queue.new
      first.send_async(a, qa, :first)
      second.send_async(b, qb, :second)
      first.close
      raise 'shared live query socket closed' if socket.closed?
      raise 'retiring stream remains reusable' if SELECTOR.reusable_socket?(socket)
      response = b.clone
      response.header.qr = true
      SELECTOR.process_message(response, response.encode, socket)
      SELECTOR.send_queued_validation_responses
      raise 'shared query failed' unless qb.size == 1 && qb.pop.last.nil?
      raise 'retired stream stayed open' unless socket.closed?
      assert_clean(socket)
      second.close
      raise 'first close did not complete once' unless qa.size == 1
    RUBY
  end

  def test_pipeline_collision_rotates_stream_without_modifying_raw_signed_requests
    isolated(<<~'RUBY')
      sockets = []
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        FrameSocket.new.tap do |socket|
          socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
          sockets << socket
        end
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: true,
        use_tcp: true, dnssec: false)
      # Identical question and ID, but different TSIG identities. Question-only
      # demultiplexing cannot safely choose between these on the same stream.
      requests = ['one', 'two'].map do |key_name|
        query('same.example.').tap do |request|
          request.header.id = 12345
          request.sign!(key_name, 'MTIzNA==')
          request.send_raw = true
        end
      end
      wires = requests.map(&:encode)
      requests.each_with_index { |request, index| writer.send_async(request, Queue.new, index) }
      raise 'ID collision reused the same stream' unless sockets.size == 2
      sockets.each_with_index do |socket, index|
        raise 'signed/raw bytes changed' unless socket.written == [wires[index].bytesize].pack('n') + wires[index]
      end
      raise 'old stream closed before completion' if sockets.first.closed?
      SELECTOR.remove_id(0)
      raise 'collision stream not retired after completion' unless sockets.first.closed?
      SELECTOR.remove_id(1)
      writer.close
      sockets.each { |socket| raise 'idle stream retained' unless socket.closed?; assert_clean(socket) }
    RUBY
  end

  def test_close_marks_a_shared_pending_connect_for_retirement
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      entered, release = Queue.new, Queue.new
      sockets = []
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        socket = FrameSocket.new
        socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
        sockets << socket
        if sockets.size == 1
          entered << true
          release.pop
        end
        socket
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true, tcp_pipelining: true, dnssec: false)
      first, second = 2.times.map { Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false) }
      [first, second].each { |resolver| resolver.single_resolvers = [writer] }
      queue = Queue.new
      before = query('before-close.example.')
      sending = Thread.new { second.send_async(before, queue, :before) }
      entered.pop
      first.close
      release << true
      sending.value
      answer = before.clone
      answer.header.qr = true
      SELECTOR.process_message(answer, answer.encode, sockets.first)
      SELECTOR.send_queued_validation_responses
      raise 'shared pre-close query failed' unless queue.size == 1 && queue.pop.last.nil?
      raise 'pending connect escaped retirement' unless sockets.first.closed?
      assert_clean(sockets.first)
      after = query('after-close.example.')
      second.send_async(after, queue, :after)
      answer = after.clone
      answer.header.qr = true
      SELECTOR.process_message(answer, answer.encode, sockets.last)
      SELECTOR.send_queued_validation_responses
      raise 'fresh query failed' unless queue.size == 1 && queue.pop.last.nil?
      raise 'fresh connection is not reusable' unless sockets.size == 2 && SELECTOR.reusable_socket?(sockets.last)
      second.close
      sockets.each { |socket| assert_clean(socket) }
    RUBY
  end

  def test_pre_close_reservation_does_not_retire_a_newer_shared_pipeline
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      sockets = []
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        FrameSocket.new.tap do |socket|
          socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
          sockets << socket
        end
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true, tcp_pipelining: true, dnssec: false)
      original = writer.method(:prepare_send_async)
      entered, release = Queue.new, Queue.new
      paused = false
      writer.define_singleton_method(:prepare_send_async) do |*args|
        operation = original.call(*args)
        unless paused
          paused = true
          reserved = operation
          operation = -> { entered << true; release.pop; reserved.call }
        end
        operation
      end
      first, second = 2.times.map { Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false) }
      [first, second].each { |resolver| resolver.single_resolvers = [writer] }
      queue = Queue.new
      old = query('reserved-before-close.example.')
      sending = Thread.new { second.send_async(old, queue, :old) }
      entered.pop
      first.close
      fresh = query('created-after-close.example.')
      second.send_async(fresh, queue, :fresh)
      SELECTOR.send_tick_to_observers
      release << true
      sending.value
      raise 'retired reservation reused fresh stream' unless sockets.size == 2
      [fresh, old].zip(sockets).each do |request, socket|
        answer = request.clone
        answer.header.qr = true
        SELECTOR.process_message(answer, answer.encode, socket)
      end
      SELECTOR.send_queued_validation_responses
      raise 'shared queries did not finish' unless queue.size == 2 && 2.times.all? { queue.pop.last.nil? }
      raise 'old one-use connection retained' unless sockets.last.closed?
      raise 'new pipeline was retired' unless SELECTOR.reusable_socket?(sockets.first)
      second.close
      sockets.each { |socket| assert_clean(socket) }
    RUBY
  end

  def test_closed_pipeline_accounting_stays_bounded
    isolated(<<~'RUBY')
      Socket.define_singleton_method(:tcp) { |*args, **kwargs| FrameSocket.new }
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', tcp_pipelining: true)
      100.times do
        socket, fresh = writer.tcp_pipeline_socket(0)
        raise 'closed connection reused' unless fresh
        socket.close
      end
      raise 'closed sockets accumulated' unless writer.instance_variable_get(:@use_counts).size == 1
    RUBY
  end

  def test_single_resolver_constructor_and_replacement_keep_pipeline_options
    isolated(<<~'RUBY')
      options = {tcp_pipelining: true, tcp_pipelining_max_queries: 5, server: '127.0.0.1'}.freeze
      resolver = Dnsruby::SingleResolver.new(options)
      2.times do
        writer = resolver.single_resolvers.first
        raise 'pipeline option not forwarded' unless writer.tcp_pipelining && writer.tcp_pipelining_max_queries == 5
        resolver.server = '127.0.0.2'
      end
      defaults = Dnsruby::SingleResolver.new(server: '127.0.0.1')
      raise 'incorrect pipeline defaults' unless defaults.tcp_pipelining == false && defaults.tcp_pipelining_max_queries == :infinite
    RUBY
  end

  def test_packet_timeout_does_not_create_nil_sender_and_close_is_safe
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false, retry_times: 1)
      writer = resolver.single_resolvers.first
      writer.define_singleton_method(:send_async) { |*| }
      queue = Queue.new
      resolver.send_async(query, queue, :timeout)
      K.class_variable_get(:@@timeouts).transform_values! { Dnsruby::TransportClock.now - 1 }
      SELECTOR.process_timeouts
      raise 'packet timeout was not delivered' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'last sender moved beyond end of list' unless resolver.single_resolvers == [writer]
      resolver.close
      # Be tolerant of legacy callers holding or supplying the exposed array.
      resolver.single_resolvers << nil
      resolver.close
    RUBY
  end

  def test_late_success_timeout_and_error_do_not_restore_replaced_sender
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [:success, :timeout, :error].each do |outcome|
        resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false, retry_times: 1)
        writer = resolver.single_resolvers.first
        writer.define_singleton_method(:send_async) { |*| }
        queue = Queue.new
        resolver.send_async(query, queue, outcome)
        pending = K.class_variable_get(:@@query_hash).values.find { |settings| settings.single_resolver.equal?(writer) }
        resolver.nameserver = '127.0.0.2'
        replacement = resolver.single_resolvers.first
        case outcome
        when :success
          answer = pending.query.clone
          answer.header.qr = true
          SELECTOR.push_response_for_query(pending, answer, pending.query, writer)
          SELECTOR.send_queued_responses
          SELECTOR.send_queued_validation_responses
        when :timeout
          K.class_variable_get(:@@timeouts)[pending.client_query_id] = Dnsruby::TransportClock.now - 1
          SELECTOR.process_timeouts
        when :error
          SELECTOR.fail_query_if_current(pending.client_query_id, pending.client_queue, pending,
            Dnsruby::OtherResolvError.new('old server failed'))
          SELECTOR.send_queued_exceptions
        end
        raise "#{outcome}: no completion" unless queue.size == 1
        result = queue.pop
        raise 'successful old response lost' if outcome == :success && result.last
        raise "#{outcome}: stale sender restored" unless resolver.single_resolvers == [replacement]
        raise "#{outcome}: config changed" unless resolver.config.nameserver == ['127.0.0.2']
        resolver.close
      end
    RUBY
  end

  def test_timed_out_stream_cannot_accept_new_queries_and_existing_peers_drain
    isolated(<<~'RUBY')
      socket = FrameSocket.new
      writer = sender(socket)
      expired = settings(socket, :expired, query('expired.example.'), writer)
      peer = settings(socket, :peer, query('peer.example.'), writer)
      expired.query.header.id, peer.query.header.id = 7, 8
      [expired, peer].each { |item| SELECTOR.add_to_select(item) }
      # Both a partial prefix and a partial body must remain owned by this
      # retiring stream until its already outstanding queries finish.
      K.class_variable_get(:@@tcp_buffers)[socket] = [+"\0", 2, true]
      K.class_variable_get(:@@timeouts)[:expired] = Dnsruby::TransportClock.now - 1
      SELECTOR.process_timeouts
      raise 'timeout missing' unless expired.client_queue.size == 1 &&
        expired.client_queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      raise 'timeout killed unrelated peer' if socket.closed?
      raise 'timed-out stream reusable' if SELECTOR.reusable_socket?(socket)
      raise 'peer ownership lost' unless SELECTOR.query_settings_for_id(:peer).equal?(peer)
      # Once the late frame has been consumed, a valid peer response can finish.
      K.class_variable_get(:@@tcp_buffers).delete(socket)
      response = peer.query.clone
      response.header.qr = true
      SELECTOR.process_message(response, response.encode, socket)
      SELECTOR.send_queued_validation_responses
      raise 'peer response lost' unless peer.client_queue.size == 2 &&
        2.times.all? { peer.client_queue.pop.last.nil? }
      raise 'drained stream stayed open' unless socket.closed?
      assert_clean(socket)
    RUBY
  end

  def test_retirement_between_socket_selection_and_registration_retries_admission
    isolated(<<~'RUBY')
      [true, false].each do |keep_peer|
        sockets = []
        Socket.define_singleton_method(:tcp) do |*args, **kwargs|
          FrameSocket.new.tap do |socket|
            socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
            sockets << socket
          end
        end
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true,
          tcp_pipelining: true, dnssec: false, packet_timeout: 5)
        requests = 3.times.map { |i| query("admission#{i}.example.").tap { |q| q.header.id = i } }
        queues = 3.times.map { Queue.new }
        writer.send_async(requests[0], queues[0], 0)
        writer.send_async(requests[1], queues[1], 1) if keep_peer
        old = sockets.first
        selected, release = Queue.new, Queue.new
        choose = writer.method(:tcp_pipeline_socket)
        writer.define_singleton_method(:tcp_pipeline_socket) do |port|
          result = choose.call(port)
          if result.first.equal?(old)
            selected << true
            release.pop
          end
          result
        end
        sending = Thread.new { writer.send_async(requests[2], queues[2], 2) }
        selected.pop
        pending = SELECTOR.query_settings_for_id(2)
        original_deadline = pending.endtime
        old_size = old.written.bytesize
        K.class_variable_get(:@@tcp_buffers)[old] = [+'partial', 1000, false]
        K.class_variable_get(:@@timeouts)[0] = Dnsruby::TransportClock.now - 1
        SELECTOR.process_timeouts
        raise 'incorrect old stream lifetime' unless old.closed? == !keep_peer
        release << true
        sending.value
        current = SELECTOR.query_settings_for_id(2)
        raise 'registration used retired or closed stream' unless sockets.size == 2 &&
          current.socket.equal?(sockets.last) && old.written.bytesize == old_size
        raise 'admission retry replaced ownership or deadline' unless
          current.send_token.equal?(pending.send_token) && current.endtime == original_deadline
        raise 'admission retry delivered a premature error' unless queues[2].empty?
        raise 'retirement lost existing peer' if keep_peer && !SELECTOR.query_settings_for_id(1)
        [2, (1 if keep_peer)].compact.each do |id|
          item = SELECTOR.query_settings_for_id(id)
          response = requests[id].clone
          response.header.qr = true
          SELECTOR.process_message(response, response.encode, item.socket)
        end
        SELECTOR.send_queued_validation_responses
        raise 'fresh query did not complete' unless queues[2].size == 2 &&
          2.times.all? { queues[2].pop.last.nil? }
        writer.close
        sockets.each { |socket| raise 'socket retained' unless socket.closed?; assert_clean(socket) }
      end
    RUBY
  end

  def test_timeout_without_partial_bytes_rotates_before_reusing_a_header_id
    isolated(<<~'RUBY')
      sockets = []
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        FrameSocket.new.tap do |socket|
          socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
          sockets << socket
        end
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true,
        tcp_pipelining: true, dnssec: false)
      request = query
      request.header.id = 123
      writer.send_async(request, Queue.new, :old)
      K.class_variable_get(:@@timeouts)[:old] = Dnsruby::TransportClock.now - 1
      SELECTOR.process_timeouts
      writer.send_async(request, Queue.new, :new)
      raise 'late reply could reach reused ID' unless sockets.size == 2 && sockets.first.closed?
      SELECTOR.remove_id(:new)
      writer.close
      sockets.each { |socket| assert_clean(socket) }
    RUBY
  end

  def test_removed_sender_retries_use_connections_that_close_after_the_answer
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      sockets = []
      Socket.define_singleton_method(:tcp) do |*args, **kwargs|
        FrameSocket.new.tap do |socket|
          socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
          sockets << socket
        end
      end
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', use_tcp: true,
        tcp_pipelining: true, dnssec: false, retry_times: 2, retry_delay: 10)
      queue, request = Queue.new, query
      resolver.send_async(request, queue, :retry)
      old_writer = resolver.single_resolvers.first
      resolver.nameserver = '127.0.0.2'
      original = K.class_variable_get(:@@query_hash).values.first
      K.class_variable_get(:@@timeouts)[original.client_query_id] = Dnsruby::TransportClock.now - 1
      SELECTOR.process_timeouts
      engine = resolver.instance_variable_get(:@resolver_ruby)
      retry_plan = engine.instance_variable_get(:@timeouts)[:retry][1]
      entry = retry_plan.values.first
      raise 'original retry plan replaced' unless entry.first.equal?(old_writer)
      retry_plan.clear
      retry_plan[Dnsruby::TransportClock.now - 1] = entry
      engine.tick
      raise 'retry did not make a new connection' unless sockets.size == 2
      response = request.clone
      response.header.qr = true
      SELECTOR.process_message(response, response.encode, sockets.last)
      SELECTOR.send_queued_validation_responses
      raise 'retry response lost' unless queue.size == 1 && queue.pop.last.nil?
      raise 'old retry left an idle socket' unless sockets.all?(&:closed?)
      resolver.close
      sockets.each { |socket| assert_clean(socket) }
    RUBY
  end

  def test_pipeline_capacity_changes_rotate_connections_and_preserve_every_peer
    isolated(<<~'RUBY')
      [[2, 3], [3, 2], [:infinite, 2], [2, :infinite], [3, 1]].each do |before, after|
        sockets = []
        Socket.define_singleton_method(:tcp) do |*args, **kwargs|
          FrameSocket.new.tap do |socket|
            socket.define_singleton_method(:connect) { |_| raise Errno::EISCONN }
            sockets << socket
          end
        end
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true,
          tcp_pipelining: true, tcp_pipelining_max_queries: before, dnssec: false)
        requests = 3.times.map { |i| query("capacity#{i}.example.").tap { |q| q.header.id = i } }
        queues = 3.times.map { Queue.new }
        writer.send_async(requests[0], queues[0], 0)
        original = sockets.first
        writer.tcp_pipelining_max_queries = after
        [1, 2].each { |i| writer.send_async(requests[i], queues[i], i) }
        raise 'old connection reused after capacity change' unless sockets.size >= 2 &&
          !SELECTOR.reusable_socket?(original) && !original.closed?
        # Out-of-order responses also exercise draining the retired generation.
        [2, 0, 1].each do |id|
          current = SELECTOR.query_settings_for_id(id)
          response = requests[id].clone
          response.header.qr = true
          SELECTOR.process_message(response, response.encode, current.socket)
        end
        SELECTOR.send_queued_validation_responses
        raise 'capacity change lost a response' unless queues.all? do |queue|
          queue.size == 2 && 2.times.all? { queue.pop.last.nil? }
        end
        writer.close
        sockets.each { |socket| raise 'socket open' unless socket.closed?; assert_clean(socket) }
      end
    RUBY
  end

  def test_tcp_read_waits_only_for_transient_errors_and_retires_fatal_errors
    isolated(<<~'RUBY')
      [IO::EAGAINWaitReadable, Errno::EINTR, Errno::ECONNRESET, IOError].each do |kind|
        socket = FrameSocket.new
        requests = 2.times.map { |i| settings(socket, i) }
        requests.each { |item| SELECTOR.add_to_select(item) }
        socket.define_singleton_method(:recv_nonblock) { |_| raise kind, 'injected read failure' }
        raise 'unexpected bytes' unless SELECTOR.tcp_read(socket) == false
        if [IO::EAGAINWaitReadable, Errno::EINTR].include?(kind)
          raise 'transient read failed owners' if socket.closed? || requests.any? { |s| !s.client_queue.empty? }
          requests.each { |item| SELECTOR.remove_id(item.client_query_id) }
        else
          raise 'fatal read left stream open' unless socket.closed?
          requests.each do |item|
            raise 'fatal read did not fail each owner once' unless item.client_queue.size == 1 &&
              item.client_queue.pop.last.is_a?(Dnsruby::SocketEofResolvError)
          end
          assert_clean(socket)
        end
      end
    RUBY
  end

  def test_random_source_port_collision_retries_before_registering_a_socket
    isolated(<<~'RUBY')
      [true, false].each do |pipeline|
        calls = 0
        socket = FrameSocket.new
        Socket.define_singleton_method(:tcp) do |*args, **kwargs|
          calls += 1
          raise Errno::EADDRINUSE if calls == 1
          socket
        end
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true,
          tcp_pipelining: pipeline, dnssec: false)
        writer.define_singleton_method(:get_next_src_port) { 40000 + calls }
        queue, request = Queue.new, query
        writer.send_async(request, queue, :collision)
        raise 'source port collision did not retry' unless calls == 2
        raise 'retry did not send the complete frame' unless
          socket.written == [request.encode.bytesize].pack('n') + request.encode
        drain_errors
        raise 'source port collision delivered an error' unless queue.empty?
        SELECTOR.remove_id(:collision)
        writer.close
        assert_clean(socket)
      end
    RUBY
  end

  def test_random_udp_source_port_collision_retries_with_a_new_socket
    isolated(<<~'RUBY')
      sockets = []
      UDPSocket.define_singleton_method(:new) do |*|
        FrameSocket.new.tap do |socket|
          first = sockets.empty?
          socket.define_singleton_method(:bind) { |*| raise Errno::EADDRINUSE if first }
          socket.define_singleton_method(:connect) { |*| }
          sockets << socket
        end
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
      writer.define_singleton_method(:get_next_src_port) { 40000 + sockets.size }
      queue, request = Queue.new, query
      writer.send_async(request, queue, :collision)
      raise 'failed UDP bind was not closed and retried' unless
        sockets.size == 2 && sockets.first.closed? && sockets.first.written.empty?
      raise 'UDP retry did not send the query' unless sockets.last.written == request.encode
      drain_errors
      raise 'UDP source port collision delivered an error' unless queue.empty?
      SELECTOR.remove_id(:collision)
      writer.close
      sockets.each { |socket| assert_clean(socket) }
    RUBY
  end

  def test_connect_timeouts_preserve_scheduled_retries_for_both_tcp_modes
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [true, false].each do |pipeline|
        calls = 0
        Socket.define_singleton_method(:tcp) { |*args, **kwargs| calls += 1; raise Errno::ETIMEDOUT }
        resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', use_tcp: true,
          tcp_pipelining: pipeline, dnssec: false, retry_times: 2, retry_delay: 10)
        queue = Queue.new
        resolver.send_async(query, queue, :connect)
        drain_errors
        engine = resolver.instance_variable_get(:@resolver_ruby)
        plan = engine.instance_variable_get(:@timeouts)[:connect][1]
        raise 'connect timeout discarded scheduled retry' if plan.empty?
        entry = plan.values.first
        plan.clear
        plan[Dnsruby::TransportClock.now - 1] = entry
        engine.tick
        drain_errors
        raise 'connect timeout did not retry' unless calls == 2
        raise 'wrong final connect error' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
        resolver.close
      end
    RUBY
  end

  def test_worker_exceptions_reach_owner_without_reading_task_value
    isolated(<<~'RUBY')
      writer = sender(FrameSocket.new)
      failure = RuntimeError.new('unexpected worker failure')
      writer.define_singleton_method(:send_dnsruby_with_socket) { |*| raise failure }
      K.class_variable_set(:@@select_thread, Thread.current)
      queue = Queue.new
      writer.send_dnsruby(query.encode, query, :worker, queue, true)
      Timeout.timeout(1) do
        Thread.pass while SELECTOR.query_settings_for_id(:worker)
      end
      drain_errors
      raise 'worker error was swallowed' unless queue.size == 1 && queue.pop.last.equal?(failure)
      raise 'worker error retained deadline' if K.class_variable_get(:@@timeouts).key?(:worker)
    RUBY
  end

  def test_worker_failure_after_connect_releases_an_unregistered_socket
    isolated(<<~'RUBY')
      socket = FrameSocket.new
      Socket.define_singleton_method(:tcp) { |*args, **kwargs| socket }
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true, dnssec: false)
      failure = RuntimeError.new('unexpected registration failure')
      construct = K::QuerySettings.method(:new)
      K::QuerySettings.define_singleton_method(:new) do |*args|
        raise failure if args[5] # A connected socket, after the initial reservation.
        construct.call(*args)
      end
      K.class_variable_set(:@@select_thread, Thread.current)
      queue = Queue.new
      writer.send_dnsruby(query.encode, query, :worker, queue, true)
      Timeout.timeout(1) do
        Thread.pass until socket.closed?
      end
      drain_errors
      raise 'worker error was swallowed' unless queue.size == 1 && queue.pop.last.equal?(failure)
      raise 'worker retained ownership' if SELECTOR.query_settings_for_id(:worker)
      assert_clean(socket)
    RUBY
  end

  def test_wall_clock_jumps_do_not_change_query_packet_retry_or_write_deadlines
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      clock = 1000.0
      Dnsruby::TransportClock.define_singleton_method(:now) { clock }
      original_time = Time.method(:now)
      socket = FrameSocket.new
      writer = sender(socket)
      writer.use_tcp = true
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', use_tcp: true,
        dnssec: false, packet_timeout: 5, query_timeout: 10, retry_times: 2, retry_delay: 3)
      resolver.single_resolvers = [writer]
      queue = Queue.new
      resolver.send_async(query, queue, :clock)
      # Initial retry keys precede tick only after monotonic time advances.
      clock += 0.1
      engine = resolver.instance_variable_get(:@resolver_ruby)
      engine.tick
      pending = K.class_variable_get(:@@query_hash).values.first
      raise 'packet deadline used wall time' unless pending.endtime < 1010
      engine_deadline, retries = engine.instance_variable_get(:@timeouts)[:clock]
      raise 'query or retry deadline used wall time' unless engine_deadline == 1010 && retries.keys.all? { |t| t < 1010 }
      [-86400, 86400].each do |jump|
        Time.define_singleton_method(:now) { original_time.call + jump }
        SELECTOR.process_timeouts
        raise 'wall jump expired query' unless queue.empty?
        extra = FrameSocket.new
        writer.write_tcp_frame(extra, 'abc', clock + 1, K::SendToken.new)
        raise 'wall jump prevented write' unless extra.written == "\0\3abc".b
      end
      clock = 1011
      engine.tick
      raise 'monotonic query deadline ignored' unless queue.size == 1 && queue.pop.last.is_a?(Dnsruby::ResolvTimeout)
      resolver.close
    RUBY
  end

  private

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
