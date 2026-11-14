require_relative 'tc_pipeline_send'

class ReleaseReviewTransportTest < Minitest::Test
  def test_malformed_tsig_responses_preserve_the_attempt_until_an_authenticated_answer
    isolated(<<~'RUBY')
      [false, true].product([:short_header, :bad_rdata, :truncated]).each do |tcp, malformed|
        socket = FrameSocket.new
        unless tcp
          socket.define_singleton_method(:getsockopt) { |*| Struct.new(:data).new([Socket::SOCK_DGRAM].pack('i')) }
          socket.define_singleton_method(:recvfrom) do |*|
            [incoming, ['AF_INET', 53, '127.0.0.1', '127.0.0.1']]
          end
        end
        writer = sender(socket)
        writer.define_singleton_method(:send_async) { |*| raise 'unauthenticated TC triggered a retry' }
        request = query
        key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
          key: 'c2VjcmV0', algorithm: 'hmac-sha256')
        key.apply(request)
        live = settings(socket, [tcp, malformed], request, writer)
        live.is_persistent_socket = tcp
        SELECTOR.add_to_select(live)
        original_deadline = live.endtime
        reply = query
        reply.header.id, reply.header.qr = request.header.id, true
        reply.header.tc = true if malformed == :truncated
        bytes = if malformed == :short_header
          [request.header.id].pack('n')
        else
          reply.encode.tap { |wire| wire.setbyte(7, 1) } # Claims a missing answer RR.
        end
        socket.incoming = tcp ? [bytes.bytesize].pack('n') + bytes : bytes
        raise 'malformed response was returned' if SELECTOR.get_incoming_data(socket, 512)
        raise 'malformed reply consumed the query' unless SELECTOR.query_settings_for_id(live.client_query_id).equal?(live)
        raise 'malformed reply completed the query' unless live.client_queue.empty?
        raise 'malformed reply extended the deadline' unless live.endtime == original_deadline
        reply.header.tc = false
        key.apply(reply, request)
        bytes = reply.encode
        socket.incoming = tcp ? [bytes.bytesize].pack('n') + bytes : bytes
        decoded = SELECTOR.get_incoming_data(socket, 512)
        SELECTOR.process_message(*decoded, socket)
        SELECTOR.send_queued_validation_responses
        raise 'valid signed reply lost' unless live.client_queue.size == 2 &&
          2.times.map { live.client_queue.pop }.all? { |event| event.last.nil? && event[2].verified? }
        SELECTOR.retire_sender(writer)
        assert_clean(socket)
      end
    RUBY
  end

  def test_tcp_eof_keeps_only_configured_retries_and_the_original_query_deadline
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [false, true].product([:success, :failure, :deadline, :update]).each do |pipeline, outcome|
        sockets = []
        Dnsruby::PacketSender.define_method(:connect_tcp) do |*|
          FrameSocket.new.tap do |socket|
            socket.define_singleton_method(:recv_nonblock) { |*| ''.b }
            sockets << socket
          end
        end
        resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
          use_tcp: true, tcp_pipelining: pipeline, packet_timeout: 30,
          query_timeout: 30, retry_times: 2, retry_delay: 10)
        request, completion = query, Queue.new
        if outcome == :update
          request = Dnsruby::Update.new('example.')
          request.do_validation = request.do_caching = false
        end
        resolver.send_async(request, completion, :eof)
        engine = resolver.instance_variable_get(:@resolver_ruby)
        plan = engine.instance_variable_get(:@timeouts)[:eof]
        deadline = plan.first
        raise 'initial attempt missing' unless sockets.size == 1
        SELECTOR.get_incoming_data(sockets.first, 0)
        if outcome == :update
          raise 'UPDATE did not report ambiguous EOF' unless completion.size == 1 &&
            completion.pop.last.is_a?(Dnsruby::SocketEofResolvError)
          engine.tick
          raise 'UPDATE was replayed' unless sockets.size == 1 && engine.instance_variable_get(:@timeouts).empty?
          resolver.close
          assert_clean(sockets.first)
          next
        end
        raise 'EOF completed a retryable query' unless completion.empty? && plan[1].size == 1
        raise 'EOF changed the deadline' unless plan.first == deadline
        if outcome == :deadline
          plan[0] = Dnsruby::TransportClock.now - 1
          engine.tick
          raise 'expired query reconnected' unless sockets.size == 1
          raise 'wrong deadline completion' unless completion.size == 1 && completion.pop.last.is_a?(Dnsruby::ResolvTimeout)
        else
          retry_value = plan[1].values.first
          plan[1].clear
          plan[1][Dnsruby::TransportClock.now - 1] = retry_value
          engine.tick
          raise 'retry did not reconnect' unless sockets.size == 2 && !sockets.last.equal?(sockets.first)
          raise 'retry changed logical deadline' unless plan.first == deadline
          if outcome == :success
            reply = request.clone
            reply.header.qr = true
            SELECTOR.process_message(reply, reply.encode, sockets.last)
            SELECTOR.send_queued_validation_responses
            raise 'retry answer lost' unless completion.size == 1 && completion.pop.last.nil?
          else
            SELECTOR.get_incoming_data(sockets.last, 0)
            raise 'exhausted EOF query did not finish' unless completion.size == 1 &&
              completion.pop.last.is_a?(Dnsruby::SocketEofResolvError)
          end
        end
        engine.tick
        resolver.close
        raise 'retry plan retained after completion' unless engine.instance_variable_get(:@timeouts).empty?
        raise 'completion repeated' unless completion.empty?
        sockets.each { |socket| assert_clean(socket) }
      end
    RUBY
  end

  def test_ambiguous_update_eof_cancels_other_servers_and_outstanding_attempts
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [false, true].product([false, true]).each do |pipeline, other_already_sent|
        sockets = []
        Dnsruby::PacketSender.define_method(:connect_tcp) do |*|
          FrameSocket.new.tap do |socket|
            socket.define_singleton_method(:recv_nonblock) { |*| ''.b }
            sockets << [server, socket]
          end
        end
        resolver = Dnsruby::Resolver.new(nameserver: ['127.0.0.1', '127.0.0.2'],
          dnssec: false, use_tcp: true, tcp_pipelining: pipeline,
          packet_timeout: 30, query_timeout: 30, retry_times: 2, retry_delay: 10)
        request, completion = Dnsruby::Update.new('example.'), Queue.new
        request.do_validation = request.do_caching = false
        resolver.send_async(request, completion, :update)
        engine = resolver.instance_variable_get(:@resolver_ruby)
        plan = engine.instance_variable_get(:@timeouts)[:update]
        raise 'initial UPDATE missing' unless sockets.map(&:first) == ['127.0.0.1']
        if other_already_sent
          scheduled = plan[1].keys.min
          next_attempt = plan[1].delete(scheduled)
          raise 'unexpected retry ordering' unless next_attempt.first.server == '127.0.0.2'
          plan[1][Dnsruby::TransportClock.now - 1] = next_attempt
          engine.tick
          raise 'second attempt missing' unless sockets.map(&:first) == ['127.0.0.1', '127.0.0.2']
        end
        SELECTOR.get_incoming_data(sockets.first.last, 0)
        raise 'ambiguous UPDATE not terminal' unless completion.size == 1 &&
          completion.pop.last.is_a?(Dnsruby::SocketEofResolvError)
        raise 'UPDATE retries retained' unless engine.instance_variable_get(:@timeouts).empty?
        raise 'UPDATE outstanding ownership retained' unless K.class_variable_get(:@@query_hash).empty?
        engine.tick
        expected_sends = other_already_sent ? 2 : 1
        raise 'UPDATE replayed after ambiguous EOF' unless sockets.length == expected_sends
        resolver.close
        raise 'duplicate UPDATE completion' unless completion.empty?
        sockets.each { |_, socket| assert_clean(socket) }
      end
    RUBY
  end

  def test_sender_retirement_uses_indexes_and_cleans_pending_active_and_idle_ownership
    isolated(<<~'RUBY')
      senders, attempts, sockets = [], [], []
      12.times do |index|
        active, idle = FrameSocket.new, FrameSocket.new
        writer = sender(active)
        senders << writer
        sockets.concat([active, idle])
        live = settings(active, [index, :active], query, writer)
        unused = settings(idle, [index, :idle], query, writer)
        pending = settings(nil, [index, :pending], query, writer)
        SELECTOR.add_to_select(live)
        SELECTOR.add_to_select(unused)
        SELECTOR.claim_query(unused, true)
        SELECTOR.reserve_send(pending)
        attempts << [live, pending]
      end
      # A sender close must never enumerate other senders' global tables.
      [K.class_variable_get(:@@query_hash), K.class_variable_get(:@@socket_owners)].each do |table|
        [:each, :each_value, :select].each do |method|
          table.define_singleton_method(method) { |*| raise 'retirement scanned a global index' }
        end
      end
      SELECTOR.retire_sender(senders.first)
      raise 'active or pending reservation not retired' unless attempts.first.all?(&:retire_connection)
      raise 'another sender was retired' unless attempts.drop(1).flatten.none?(&:retire_connection)
      raise 'idle stream retained' unless sockets[1].closed?
      raise 'active stream closed before draining' if sockets[0].closed?
      attempts.first.each { |attempt| SELECTOR.remove_id(attempt.client_query_id) }
      [:queries_by_sender, :sockets_by_sender].each do |name|
        raise 'retired sender retained' if K.class_variable_get("@@#{name}").key?(senders.first)
      end
      senders.drop(1).each { |writer| SELECTOR.retire_sender(writer) }
      attempts.drop(1).flatten.each { |attempt| SELECTOR.remove_id(attempt.client_query_id) }
      [:queries_by_sender, :sockets_by_sender].each do |name|
        raise 'sender index leaked' unless K.class_variable_get("@@#{name}").empty?
      end
      sockets.each { |socket| assert_clean(socket) }

      # Re-registering a reusable stream under a different helper sender must
      # replace its owner instead of leaving a stale retirement entry.
      shared = FrameSocket.new
      first, second = sender(shared), sender(shared)
      old = settings(shared, :old_owner, query, first)
      SELECTOR.add_to_select(old)
      SELECTOR.claim_query(old, true)
      current = settings(shared, :new_owner, query, second)
      SELECTOR.add_to_select(current)
      raise 'old socket owner retained' if K.class_variable_get(:@@sockets_by_sender).key?(first)
      SELECTOR.retire_sender(first)
      raise 'old owner retired reassigned socket' if K.class_variable_get(:@@retiring_sockets).include?(shared)
      SELECTOR.retire_sender(second)
      SELECTOR.remove_id(:new_owner)
      assert_clean(shared)
      raise 'reassigned sender retained' unless K.class_variable_get(:@@sockets_by_sender).empty?
    RUBY
  end

  def test_validation_registration_obeys_queue_and_sender_cancellation_without_leaking
    isolated(<<~'RUBY')
      budget_class = Class.new do
        attr_accessor :cancelled
        def initialize(cancelled); @cancelled = cancelled; end
        def cancel; @cancelled = true; end
      end
      queue, observer, writer = Queue.new, Object.new, sender(FrameSocket.new)
      other_queue, other_writer = Queue.new, sender(FrameSocket.new)
      other_budget = budget_class.new(false)
      raise 'unrelated validation rejected' unless SELECTOR.register_validation(other_queue, other_writer, other_budget)
      SELECTOR.add_observer(queue, observer)
      active = budget_class.new(false)
      raise 'active validation rejected' unless SELECTOR.register_validation(queue, writer, active)
      SELECTOR.register_validation(queue, writer, active)
      raise 'duplicate registration retained' unless K.class_variable_get(:@@validations).length == 2
      SELECTOR.remove_observer(queue, observer)
      raise 'finished query did not cancel work' unless active.cancelled
      raise 'queue completion cancelled unrelated work' if other_budget.cancelled
      late = budget_class.new(false)
      raise 'completed queue started late validation' if SELECTOR.register_validation(queue, writer, late)
      raise 'late work not cancelled' unless late.cancelled
      SELECTOR.unregister_validation(queue, writer, active)

      # Direct PacketSender queues have no observer and remain supported. A
      # shared budget may be registered with more than one nested query.
      first, second, shared = Queue.new, Queue.new, budget_class.new(false)
      [first, second].each do |direct|
        raise 'direct validation rejected' unless SELECTOR.register_validation(direct, writer, shared)
      end
      SELECTOR.unregister_validation(first, writer, shared)
      SELECTOR.retire_sender(writer)
      raise 'shared remaining validation escaped retirement' unless shared.cancelled
      raise 'sender retirement cancelled unrelated work' if other_budget.cancelled
      SELECTOR.unregister_validation(second, writer, shared)
      SELECTOR.retire_sender(other_writer)
      raise 'unrelated sender lost its registration' unless other_budget.cancelled
      SELECTOR.unregister_validation(other_queue, other_writer, other_budget)
      raise 'validation registration leaked' unless K.class_variable_get(:@@validations).empty?
    RUBY
  end

  def test_sender_retirement_preserves_resolver_validation_but_owner_close_cancels_it
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      [:reconfigure, :other_close, :owner_close].each do |action|
        socket = FrameSocket.new
        writer = sender(socket)
        writer.use_tcp = writer.dnssec = true
        first, second = 2.times.map do
          Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: true, use_tcp: true, do_validation: true)
        end
        [first, second].each { |resolver| resolver.single_resolvers = [writer] }
        entered, release = Queue.new, Queue.new
        Dnsruby::Dnssec.define_singleton_method(:validate_with_query) do |_query, answer|
          entered << true
          release.pop
          answer.security_level = Dnsruby::Message::SecurityLevel::SECURE
        end
        request = query('validating.example.')
        request.do_validation = true
        results = Queue.new
        second.send_async(request, results, :client)
        answer = request.clone
        answer.header.qr = true
        SELECTOR.process_message(answer, answer.encode, socket)
        entered.pop
        case action
        when :reconfigure then second.nameserver = '127.0.0.2'
        when :other_close then first.close
        when :owner_close then second.close
        end
        release << true
        sleep 0.001 until K.class_variable_get(:@@validations).empty?
        SELECTOR.send_queued_validation_responses
        raise "#{action}: missing or duplicate completion" unless results.size == 1
        _id, response, error = results.pop
        if action == :owner_close
          raise 'owner close did not cancel its query' unless error.is_a?(Dnsruby::OtherResolvError)
        else
          raise "#{action}: accepted validation was cancelled: #{error.inspect}" unless
            error.nil? && response.security_level == Dnsruby::Message::SecurityLevel::SECURE
        end
        first.close
        second.close
        SELECTOR.send_queued_validation_responses
        raise 'late validation completed twice' unless results.empty?
        raise 'validation registration leaked' unless K.class_variable_get(:@@validations).empty?
      end
    RUBY
  end

  def test_fork_discards_parent_validation_registrations_without_losing_child_work
    skip 'fork unavailable' unless Process.respond_to?(:fork)
    isolated(<<~'RUBY')
      entered, release = Queue.new, Queue.new
      request = query
      request.do_validation = true
      response = request.clone
      response.header.qr = true
      writer = sender(FrameSocket.new)
      writer.dnssec = true
      parent_queue = Queue.new
      parent = Dnsruby::ValidatorThread.new(:parent, parent_queue, response, nil, request, SELECTOR, writer)
      parent.define_singleton_method(:validate) { |*| entered << true; release.pop; true }
      parent.run
      Timeout.timeout(3) { entered.pop }
      [false, true].each do |retire_first|
        pid = fork do
          SELECTOR.retire_sender(writer) if retire_first
          child_entered, child_release = Queue.new, Queue.new
          child_queue = Queue.new
          child = Dnsruby::ValidatorThread.new(:child, child_queue, response.clone, nil, request, SELECTOR, writer)
          child.define_singleton_method(:validate) { |*| child_entered << true; child_release.pop; true }
          child.run
          Timeout.timeout(3) { child_entered.pop }
          registrations = K.class_variable_get(:@@validations)
          raise 'parent validation retained after fork' if registrations.any? { |queue, _, _| queue.equal?(parent_queue) }
          raise 'child registration lost during pool restart' unless registrations.length == 1 &&
            registrations.first[0].equal?(child_queue) && registrations.first[1].equal?(writer)
          child_release << true
          Timeout.timeout(3) do
            sleep(0.001) until K.class_variable_get(:@@validations).empty?
          end
          exit! 0
        end
        Process.wait(pid)
        raise 'child registration lifecycle failed' unless $?.success?
        raise 'child cleared parent registration' unless K.class_variable_get(:@@validations).any? { |queue, _, _| queue.equal?(parent_queue) }
      end
      release << true
      Timeout.timeout(3) do
        sleep(0.001) until K.class_variable_get(:@@validations).empty?
      end
    RUBY
  end

  private

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    source = "#{TestPipelineSend::FIXTURE}\nTimeout.timeout(12) do\n#{body}\nend"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', source)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
