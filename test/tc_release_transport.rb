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
      K.class_variable_get(:@@timeouts).transform_values! { Time.now - 1 }
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
          K.class_variable_get(:@@timeouts)[pending.client_query_id] = Time.now - 1
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

  private

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend")
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
