require_relative 'tc_pipeline_send'

class CancelledSendCapacityTest < Minitest::Test
  def test_cancelled_udp_writes_release_all_workers_and_unregistered_sockets
    isolated(<<~'RUBY')
      sockets = []
      UDPSocket.define_singleton_method(:new) do |*|
        socket = FrameSocket.new
        socket.define_singleton_method(:bind) { |*| }
        socket.define_singleton_method(:connect) { |*| }
        socket.define_singleton_method(:write_nonblock) { |*| raise IO::EAGAINWaitWritable }
        sockets << socket
        socket
      end
      tasks, queues = [], []
      4.times do |id|
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, packet_timeout: 60)
        q, queue = query, Queue.new
        queues << queue
        tasks << writer.send_dnsruby(q.encode, q, id, queue, false)
      end
      4.times { WAITING.pop }
      4.times { |id| SELECTOR.remove_id(id) }
      healthy = Queue.new
      next_task = SELECTOR.defer_send { healthy << true }
      Timeout.timeout(2) do
        healthy.pop
        (tasks + [next_task]).each(&:value)
      end
      drain_errors
      raise 'cancelled UDP socket retained' unless sockets.all?(&:closed?)
      raise 'cancelled attempt still registered' unless K.class_variable_get(:@@query_hash).empty?
      raise 'cancelled UDP wrote bytes' unless sockets.all? { |socket| socket.written.empty? }
      raise 'cancelled owner received another completion' unless queues.all?(&:empty?)
    RUBY
  end

  def test_cancelled_unwritten_tcp_frames_release_workers_without_failing_peers
    tcp_cancellation_scenario(false)
  end

  def test_cancelled_partial_tcp_frames_release_workers_and_retire_corrupt_streams
    tcp_cancellation_scenario(true)
  end

  def test_writable_wait_slices_retain_the_original_tcp_and_udp_deadline
    isolated(<<~'RUBY')
      [:tcp, :udp].each do |transport|
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
        socket = FrameSocket.new
        socket.define_singleton_method(:write_nonblock) { |*| raise IO::EAGAINWaitWritable }
        token = K::SendToken.new
        started = Dnsruby::TransportClock.now
        begin
          if transport == :tcp
            writer.write_tcp_frame(socket, query.encode, started + 0.15, token)
          else
            writer.write_udp_packet(socket, query.encode, started + 0.15, token, true)
          end
          raise 'congested write did not time out'
        rescue Dnsruby::ResolvTimeout
          elapsed = Dnsruby::TransportClock.now - started
          raise 'select slice expired the entire attempt early' if elapsed < 0.14
          raise 'wait extended the packet deadline' if elapsed > 2
        end
      end
    RUBY
  end

  private

  def tcp_cancellation_scenario(partial)
    isolated("partial = #{partial}\n" + <<~'RUBY')
      sockets, tasks, peers, queues = [], [], [], []
      4.times do |id|
        socket = FrameSocket.new
        writer = sender(socket)
        writer.packet_timeout = 60
        peer = settings(socket, [:peer, id], query("peer-#{id}.example."), writer)
        SELECTOR.add_to_select(peer)
        calls = 0
        native_write = socket.method(:write_nonblock)
        socket.define_singleton_method(:write_nonblock) do |bytes|
          calls += 1
          if partial && calls == 1
            native_write.call(bytes.byteslice(0, 2))
          else
            raise IO::EAGAINWaitWritable
          end
        end
        q, queue = query("cancelled-#{id}.example."), Queue.new
        sockets << socket
        peers << peer
        queues << queue
        tasks << writer.send_dnsruby(q.encode, q, id, queue, true)
      end
      4.times { WAITING.pop }
      4.times { |id| SELECTOR.remove_id(id) }
      healthy = Queue.new
      next_task = SELECTOR.defer_send { healthy << true }
      Timeout.timeout(2) do
        healthy.pop
        (tasks + [next_task]).each(&:value)
      end
      drain_errors
      raise 'cancelled owner received another completion' unless queues.all?(&:empty?)
      sockets.zip(peers).each do |socket, peer|
        raise 'canceled frame continued writing' unless socket.written.bytesize == (partial ? 2 : 0)
        if partial
          raise 'corrupt pipeline remained open' unless socket.closed?
          raise 'corrupt stream peer not failed exactly once' unless peer.client_queue.length == 1 &&
            peer.client_queue.pop(true).last.is_a?(Dnsruby::SocketEofResolvError)
        else
          raise 'unwritten cancellation closed peer socket' if socket.closed?
          raise 'unwritten cancellation lost peer' unless SELECTOR.query_settings_for_id(peer.client_query_id).equal?(peer)
          raise 'unwritten cancellation failed peer' unless peer.client_queue.empty?
          response = peer.query.clone
          response.header.qr = true
          SELECTOR.process_message(response, response.encode, socket)
          SELECTOR.send_queued_validation_responses
          events = 2.times.map { peer.client_queue.pop(true) }
          raise 'peer did not complete once' unless peer.client_queue.empty? && events.all? { |event| event.last.nil? }
          raise 'retiring pipeline retained after peer finished' unless socket.closed?
        end
        assert_clean(socket)
      end
      raise 'cancelled TCP attempt retained' unless K.class_variable_get(:@@query_hash).empty?
    RUBY
  end

  WAIT_FIXTURE = <<~'RUBY'
    WAITING = Queue.new
    waiters, waiter_mutex = {}, Mutex.new
    IO.define_singleton_method(:select) do |readers, writers, _, timeout|
      raise 'unexpected writable wait' unless readers.nil? && writers.length == 1
      waiter_mutex.synchronize do
        unless waiters[Thread.current]
          waiters[Thread.current] = true
          WAITING << Thread.current
        end
      end
      # Model a socket that stays congested: honor the supplied timeout rather
      # than artificially waking a canceled writer, which masked the leak.
      sleep(timeout)
      nil
    end
    K.class_variable_set(:@@select_thread, Thread.current)
  RUBY

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    source = "#{TestPipelineSend::FIXTURE}\n#{WAIT_FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', source)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
