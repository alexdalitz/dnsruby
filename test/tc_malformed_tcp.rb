require_relative 'spec_helper'
require 'minitest/mock'
require 'timeout'
require 'socket'

class TestMalformedTcp < Minitest::Test
  # Keep selector fixtures off IO.select: a live resolver in another test may
  # share these tables. Only the dedicated allocated receiver uses the fakes.
  class SocketBuffer
    attr_reader :closed
    attr_accessor :udp_response

    def initialize(bytes = ''.b)
      @bytes = bytes.dup
      @closed = false
    end

    def recv_nonblock(length)
      @bytes.slice!(0, [length, 1].min) # Fragment prefix and body alike.
    end

    def close
      @closed = true
    end

    def recvfrom(_length)
      @udp_response
    end
  end

  def setup
    @selector_class = Dnsruby::SelectThread
    @temporary_variables = []
    { :@@mutex => Mutex.new, :@@query_hash => {}, :@@socket_hash => {},
      :@@timeouts => {}, :@@sockets => Set.new, :@@tcp_buffers => {},
      :@@socket_is_persistent => {}, :@@socket_remaining_queries => {} }.each do |name, value|
      next if @selector_class.class_variable_defined?(name)
      @selector_class.class_variable_set(name, value)
      @temporary_variables << name
    end
    @selector = @selector_class.send(:allocate)
    @selector.define_singleton_method(:tcp?) { |_| true }
    @selector.define_singleton_method(:notify_queue_observers) { |*| }
    @registered = []
  end

  def teardown
    table(:mutex).synchronize do
      @registered.each do |settings|
        table(:query_hash).delete(settings.client_query_id)
        table(:timeouts).delete(settings.client_query_id)
        [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
          table(name).delete(settings.socket)
        end
      end
    end
    @temporary_variables.each { |name| @selector_class.remove_class_variable(name) }
  end

  def test_short_matching_frames_report_only_the_matching_pipeline_query
    [2, 4, 11].each do |length|
      socket = SocketBuffer.new
      first = register(socket, 12_345)
      second = register(socket, 12_346)
      packet = [12_346, 0x8000, 0, 0, 0, 0].pack('n6')[0, length]
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      event = second.client_queue.pop(true)
      assert_equal(second.client_query_id, event[0])
      assert_kind_of(Dnsruby::DecodeError, event.last)
      assert(first.client_queue.empty?)
      assert_same(first, table(:query_hash)[first.client_query_id])
      refute(socket.closed)
    end
  end

  def test_unknown_and_unidentifiable_pipeline_frames_leave_queries_active
    socket = SocketBuffer.new
    first = register(socket, 12_350)
    second = register(socket, 12_351)
    packets = ['', 'x', [12_352].pack('n'),
      [12_352, 0x8000, 1, 0, 0, 0].pack('n6'),
      [12_352, 0x8000, 0, 0, 0, 0].pack('n6')]
    packets.each do |packet|
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      [first, second].each do |settings|
        assert(settings.client_queue.empty?)
        assert_same(settings, table(:query_hash)[settings.client_query_id])
      end
    end
    refute(socket.closed)
  end

  def test_unidentifiable_frame_on_single_query_reports_decode_error
    ['', 'x'].each do |packet|
      settings = register(SocketBuffer.new, 12_355)
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(settings.socket, 0)) }
      assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
    end
  end

  def test_duplicate_ids_on_one_pipeline_socket_are_ambiguous
    socket = SocketBuffer.new
    first = register(socket, 12_356)
    second = register(socket, 12_356)
    [2, 12].each do |length|
      packet = [12_356, 0x8000, 1, 0, 0, 0].pack('n6')[0, length]
      @selector.stub(:tcp_read, packet) { assert_nil(@selector.get_incoming_data(socket, 0)) }
      [first, second].each do |settings|
        assert(settings.client_queue.empty?)
        assert_same(settings, table(:query_hash)[settings.client_query_id])
      end
    end
  end

  def test_valid_in_order_replies_with_duplicate_ids_keep_existing_behavior
    socket = SocketBuffer.new
    first = register(socket, 12_357)
    second = register(socket, 12_357)
    second.query = Dnsruby::Message.new('second.example.')
    second.query.header.id = 12_357
    delivered = []
    @selector.stub(:push_to_client, ->(*args) { delivered << args }) do
      [first, second].each do |settings|
        settings.single_resolver = Dnsruby::PacketSender.allocate
        response = settings.query.clone
        response.header.qr = true
        @selector.stub(:tcp_read, response.encode) do
          decoded, bytes = @selector.get_incoming_data(socket, 0)
          @selector.send_response_to_client(decoded, bytes, socket)
        end
      end
    end
    assert_equal([first.client_query_id, second.client_query_id], delivered.map(&:first))
    assert(delivered.all? { |args| args[3].nil? })
    assert_equal([], table(:socket_hash)[socket])
    refute(socket.closed)
  end

  def test_matching_ids_on_other_sockets_do_not_supply_tcp_peer_metadata
    first = register(SocketBuffer.new, 12_360, '192.0.2.1', 53)
    second = register(SocketBuffer.new, 12_360, '192.0.2.2', 54)
    response = second.query.clone
    response.header.qr = true
    wire = response.encode
    @selector.stub(:tcp_read, wire) do
      decoded, bytes = @selector.get_incoming_data(second.socket, 0)
      assert_equal('192.0.2.2', decoded.answerip)
      assert_equal(wire, bytes)
    end
    # The same ID on another socket does not make an unsolicited frame ours.
    second.query.header.id = 12_361
    @selector.stub(:tcp_read, wire) { assert_nil(@selector.get_incoming_data(second.socket, 0)) }
    assert(first.client_queue.empty?)
    assert(second.client_queue.empty?)
  end

  def test_malformed_udp_requires_matching_id_address_and_port
    socket = SocketBuffer.new
    settings = register(socket, 12_370, '192.0.2.1', 53)
    [
      [12_371, '192.0.2.1', 53],
      [12_370, '192.0.2.2', 53],
      [12_370, '192.0.2.1', 54],
    ].each do |id, source, port|
      socket.udp_response = [[id, 0x8000, 1, 0, 0, 0].pack('n6'), ['AF_INET', port, source, source]]
      @selector.stub(:tcp?, false) { assert_nil(@selector.get_incoming_data(socket, 512)) }
      assert(settings.client_queue.empty?)
      assert_same(settings, table(:query_hash)[settings.client_query_id])
    end
  end

  def test_malformed_truncated_tcp_response_is_terminal_without_retrying
    settings = register(SocketBuffer.new, 12_372)
    sender = Object.new
    sender.define_singleton_method(:send_async) { |*| raise 'Unexpected TCP retry' }
    settings.single_resolver = sender
    packet = [settings.query.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
    @selector.stub(:tcp_read, packet) do
      assert_nil(@selector.get_incoming_data(settings.socket, 0))
      # A second buffered frame after terminal delivery cannot start a retry.
      assert_nil(@selector.get_incoming_data(settings.socket, 0))
    end
    assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
    assert(settings.client_queue.empty?)
    refute(table(:query_hash).key?(settings.client_query_id))
  end

  def test_malformed_truncated_udp_respects_transport_options
    [[true, false], [false, true], [true, true]].each do |no_tcp, ignore_truncation|
      socket = SocketBuffer.new
      settings = register(socket, 12_373)
      settings.ignore_truncation = ignore_truncation
      sender = Object.new
      sender.define_singleton_method(:no_tcp) { no_tcp }
      sender.define_singleton_method(:send_async) { |*| raise 'Unexpected UDP fallback' }
      settings.single_resolver = sender
      packet = [settings.query.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
      socket.udp_response = [packet, ['AF_INET', 53, '127.0.0.1', '127.0.0.1']]
      @selector.stub(:tcp?, false) { assert_nil(@selector.get_incoming_data(socket, 512)) }
      assert_kind_of(Dnsruby::DecodeError, settings.client_queue.pop(true).last)
      refute(table(:query_hash).key?(settings.client_query_id))
    end
  end

  def test_fragmented_zero_one_and_two_byte_frames_do_not_consume_next_frame
    [0, 1, 2].each do |length|
      short = 'x' * length
      valid = Dnsruby::Message.new('following.example.').encode
      socket = SocketBuffer.new([short.bytesize].pack('n') + short + [valid.bytesize].pack('n') + valid)
      # Register only for fixture cleanup; tcp_read itself does not decode.
      register(socket, 12_380 + length)
      frames = []
      (short.bytesize + valid.bytesize + 8).times do
        frame = @selector.tcp_read(socket)
        frames << frame if frame
        break if frames.length == 2
      end
      assert_equal([short, valid], frames)
      refute(socket.closed)
      refute(table(:tcp_buffers).key?(socket))
    end
  end

  def test_error_for_removed_query_is_harmless
    socket = SocketBuffer.new
    assert_nil(@selector.send_exception_to_client(Dnsruby::DecodeError.new, socket, Object.new))
    @selector.stub(:tcp_read, Dnsruby::Message.new.encode) do
      assert_nil(@selector.get_incoming_data(socket, 0))
    end
  end

  def test_eof_after_fragment_fails_all_pending_queries_and_clears_framing
    socket = SocketBuffer.new("\x00".b)
    first = register(socket, 12_390)
    second = register(socket, 12_391)
    assert_equal(false, @selector.tcp_read(socket))
    assert_equal(false, @selector.tcp_read(socket))
    [first, second].each do |settings|
      assert_kind_of(Dnsruby::SocketEofResolvError, settings.client_queue.pop(true).last)
      refute(table(:query_hash).key?(settings.client_query_id))
    end
    assert(socket.closed)
    [:socket_hash, :tcp_buffers, :socket_is_persistent, :socket_remaining_queries].each do |name|
      refute(table(name).key?(socket))
    end
  end

  private

  def table(name)
    @selector_class.class_variable_get("@@#{name}")
  end

  def register(socket, id, destination = '127.0.0.1', port = 53)
    settings = Dnsruby::SelectThread::QuerySettings.new
    settings.query = Dnsruby::Message.new('malformed.example.')
    settings.query.header.id = id
    settings.client_query_id = [Object.new, settings.query]
    settings.client_queue = Queue.new
    settings.socket = socket
    settings.dest_server = destination
    settings.dest_port = port
    table(:mutex).synchronize do
      table(:query_hash)[settings.client_query_id] = settings
      (table(:socket_hash)[socket] ||= []) << settings.client_query_id
      table(:socket_is_persistent)[socket] = true
    end
    @registered << settings
    settings
  end
end

class TestMalformedTcpTransport < Minitest::Test
  def test_malformed_query_does_not_block_an_unrelated_query_or_its_timeout
    [:two_bytes, :four_bytes, :truncated, :unknown_id].each do |kind|
      listener = TCPServer.new('127.0.0.1', 0)
      connections = []
      exchanges = []
      release = Queue.new
      server = Thread.new do
        begin
          # Both queries must already be outstanding when the malformed reply
          # arrives; resolver retry scheduling is separate from selector liveness.
          requests = 2.times.map do
            connection = listener.accept
            connections << connection
            length = connection.read(2).unpack('n').first
            [connection, Dnsruby::Message.decode(connection.read(length))]
          end
          requests.each do |connection, response|
            if response.question.first.qname.to_s == 'broken.example'
              wire = case kind
              when :two_bytes
                [response.header.id].pack('n')
              when :four_bytes
                [response.header.id, 0x8000].pack('n2')
              when :truncated
                [response.header.id, 0x8200, 1, 0, 0, 0].pack('n6')
              when :unknown_id
                [(response.header.id + 1) % 65_536, 0x8000, 0, 0, 0, 0].pack('n6')
              end
            else
              response.header.qr = true
              response.add_answer(Dnsruby::RR.create('healthy.example. 60 IN A 192.0.2.25'))
              wire = response.encode
            end
            exchanges << [response.question.first.qname.to_s, wire.bytesize]
            connection.write([wire.bytesize].pack('n') + wire)
          end
          release.pop # The unanswered query must time out while its peer stays open.
        rescue StandardError => error
          error
        end
      end
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', port: listener.addr[1],
        use_tcp: true, tcp_pipelining: false, do_caching: false, dnssec: false, retry_times: 1,
        # The second async query is sent on the next resolver tick (up to 0.5s).
        packet_timeout: 1, query_timeout: 2)
      queue = Queue.new
      [:broken, :healthy].each do |id|
        query = Dnsruby::Message.new("#{id}.example.")
        query.do_caching = false
        query.do_validation = false
        resolver.send_async(query, queue, id)
      end
      results = Timeout.timeout(5) { 2.times.map { queue.pop } }
      broken = results.find { |item| item.first == :broken }
      healthy = results.find { |item| item.first == :healthy }
      assert_kind_of(kind == :unknown_id ? Dnsruby::ResolvTimeout : Dnsruby::DecodeError, broken.last)
      assert_nil(healthy.last, "#{kind}: #{exchanges.inspect}, server status: #{server.status.inspect}")
      assert_equal(['192.0.2.25'], healthy[1].answer.map { |rr| rr.address.to_s })
      assert(Dnsruby::SelectThread.instance.select_thread_alive?)
      release << true
      server_result = Timeout.timeout(5) { server.value }
      raise server_result if server_result.is_a?(StandardError)
    ensure
      resolver.close if resolver
      server.kill.join if server
      connections.each { |connection| connection.close unless connection.closed? } if connections
      listener.close if listener && !listener.closed?
    end
  end
end
