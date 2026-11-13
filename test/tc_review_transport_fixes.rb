require_relative 'tc_pipeline_send'

class ReviewTransportFixesTest < Minitest::Test
  def test_resolver_early_errors_keep_the_public_completion_protocol
    isolated(<<~'CODE')
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
      invalid = query
      rr = Dnsruby::RR.get_class(62001, 1).new('x'.b * 65_536)
      rr.name, rr.ttl, rr.type, rr.klass = 'size.example.', 0, 62001, 1
      invalid.add_additional(rr)
      [invalid, sized_message(65_536)].each do |message|
        begin
          resolver.send_message(message)
          raise 'encoding error returned as a successful Message'
        rescue Dnsruby::EncodeError
        end
        reply, error = resolver.send_message!(message)
        raise 'bang response tuple lost encoding error' unless reply.nil? && error.is_a?(Dnsruby::EncodeError)
        queue = Queue.new
        resolver.send_async(message, queue, :invalid)
        tuple = queue.pop(true)
        raise 'malformed async encode tuple' unless tuple.length == 3 && tuple[0] == :invalid &&
          tuple[1].nil? && tuple[2].is_a?(Dnsruby::EncodeError)
        raise 'duplicate early completion' unless queue.empty?
      end
      queue = Queue.new
      resolver.send_async(Object.new, queue, :wrong_type)
      tuple = queue.pop(true)
      raise 'malformed wrong-type tuple' unless tuple.length == 3 && tuple[0] == :wrong_type &&
        tuple[1].nil? && tuple[2].is_a?(ArgumentError)
      raise 'early error acquired transport state' unless K.class_variable_get(:@@query_hash).empty?
      resolver.close
    CODE
  end

  def test_duplicate_id_error_leaves_the_original_query_owned
    isolated(<<~'CODE')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false, use_tcp: true)
      socket = FrameSocket.new
      Dnsruby::PacketSender.define_method(:connect_tcp) { |*args, **options| socket }
      first, duplicate = Queue.new, Queue.new
      resolver.send_async(query('first.example.'), first, :same)
      written = socket.written.dup
      resolver.send_async(query('second.example.'), duplicate, :same)
      tuple = duplicate.pop(true)
      raise 'malformed duplicate tuple' unless tuple.length == 3 && tuple[0] == :same &&
        tuple[1].nil? && tuple[2].is_a?(ArgumentError)
      raise 'duplicate query wrote bytes' unless socket.written == written
      raise 'duplicate query completed the original' unless first.empty?
      resolver.close
      tuple = first.pop(true)
      raise 'original query lost after duplicate' unless tuple == [:same, nil, tuple.last] &&
        tuple.last.is_a?(Dnsruby::OtherResolvError)
      drain_errors
      raise 'duplicate completion' unless first.empty? && duplicate.empty?
      raise 'query state retained' unless K.class_variable_get(:@@query_hash).empty?
    CODE
  end

  def test_pipeline_configuration_changes_rotate_streams_while_peers_drain
    isolated(<<~'CODE')
      created = []
      Dnsruby::PacketSender.define_method(:connect_tcp) do |*args, **options|
        socket = FrameSocket.new
        socket.define_singleton_method(:connect) { |*| raise Errno::EISCONN }
        created << [socket, args]
        socket
      end
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', port: 5301,
        use_tcp: true, tcp_pipelining: true, dnssec: false)
      send_query = ->(id) do
        q = query("configuration-#{id}.example.")
        q.header.id = id + 100
        writer.send_dnsruby(q.encode, q, id, Queue.new, true)
      end
      send_query.call(0)
      original = created.last.first
      send_query.call(1)
      raise 'random source port selection rotated a reusable stream' unless created.length == 1
      changes = [
        -> { writer.port = 5302 },
        -> { writer.server = '127.0.0.2' },
        -> { writer.src_address = '127.0.0.3' },
        -> { writer.src_port = [61_001, 61_002] },
        -> { writer.src_port << 61_003 },
        -> { writer.server = '::1'; writer.src_address6 = '::1' }
      ]
      changes.each_with_index do |change, index|
        previous = created.last.first
        change.call
        send_query.call(index + 2)
        raise 'configuration reused old endpoint or binding' unless created.length == index + 2
        raise 'rotation closed pending peer' if previous.closed?
        raise 'new stream was already closed' if created.last.first.closed?
      end
      raise 'changed port not used' unless created[1][1][1] == 5302
      raise 'changed server not used' unless created[2][1][0] == '127.0.0.2'
      raise 'changed source not used' unless created[3][1][2] == '127.0.0.3'
      raise 'changed IPv6 source not used' unless created.last[1][0, 3] == ['::1', 5302, '::1']
      SELECTOR.remove_id(0)
      raise 'first stream closed before last peer drained' if original.closed?
      SELECTOR.remove_id(1)
      raise 'retired stream remained open after last peer' unless original.closed?
      (2..7).each { |id| SELECTOR.remove_id(id) }
      writer.close
    CODE
  end

  def test_single_resolver_server_change_keeps_the_configured_port
    resolver = Dnsruby::SingleResolver.new(server: '127.0.0.1', port: 5301)
    resolver.server = '127.0.0.2'
    assert_equal(5301, resolver.port)
    assert_equal(5301, resolver.single_resolvers.first.port)
  ensure
    resolver.close if resolver
  end

  def test_total_wire_limit_rejects_before_pipeline_admission_and_preserves_peers
    isolated(<<~'CODE')
      socket = FrameSocket.new
      writer = sender(socket)
      ordinary, queue = query('peer.example.'), Queue.new
      ordinary.header.id = 100
      writer.send_dnsruby(ordinary.encode, ordinary, :peer, queue, true)
      peer = SELECTOR.query_settings_for_id(:peer)
      boundary = sized_message(65_535)
      boundary.header.id = 101
      writer.send_dnsruby(boundary.encode, boundary, :boundary, Queue.new, true)
      before = socket.written.dup
      rejected = sized_message(65_536)
      rejected.header.id = 102
      errors = Queue.new
      writer.send_dnsruby(rejected.encode, rejected, :oversized, errors, true)
      drain_errors
      event = errors.pop(true)
      raise 'total size did not produce EncodeError' unless event[0] == :oversized && event.last.is_a?(Dnsruby::EncodeError)
      raise 'oversized frame wrote or closed the pipeline' unless socket.written == before && !socket.closed?
      raise 'oversized query acquired registration' if SELECTOR.query_settings_for_id(:oversized)
      raise 'oversized query displaced peer' unless SELECTOR.query_settings_for_id(:peer).equal?(peer)
      last = query('last.example.')
      last.header.id = 103
      writer.send_dnsruby(last.encode, last, :last, Queue.new, true)
      expected = [ordinary, boundary, last].map { |q| [q.encode.bytesize].pack('n') + q.encode }.join
      raise 'pipeline frames corrupted at wire boundary' unless socket.written == expected
      raise 'duplicate encode error' unless errors.empty?
      [:peer, :boundary, :last].each { |id| SELECTOR.remove_id(id) }
    CODE
  end

  def test_tsig_growth_is_checked_after_packet_preparation
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    isolated(<<~'CODE')
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', use_tcp: true, dnssec: false)
      writer.tsig = ['key.example.', ['secret'].pack('m0')]
      message = sized_message(65_520)
      raise 'fixture must fit before signing' unless message.encode.bytesize == 65_520
      queue = Queue.new
      Dnsruby::PacketSender.define_method(:connect_tcp) { |*args, **options| raise 'oversized signed packet opened a socket' }
      writer.send_async(message, queue, :signed)
      drain_errors
      event = queue.pop(true)
      raise 'signed packet size error lost' unless event[0] == :signed && event.last.is_a?(Dnsruby::EncodeError)
      raise 'oversized signed packet acquired query state' unless K.class_variable_get(:@@query_hash).empty?
    CODE
  end

  private

  SIZE_FIXTURE = <<~'CODE'
    def sized_message(size)
      q = query('size.example.')
      q.send_raw = true
      rr = Dnsruby::RR.get_class(62001, 1).new('')
      rr.name, rr.ttl, rr.type, rr.klass = 'size.example.', 0, 62001, 1
      q.add_additional(rr)
      padding = size - q.encode.bytesize
      full = Dnsruby::RR.get_class(62001, 1).new('x'.b * padding)
      full.name, full.ttl, full.type, full.klass = 'size.example.', 0, 62001, 1
      q.remove_additional
      q.add_additional(full)
      raise 'wrong fixture wire length' unless q.encode.bytesize == size
      q
    end
  CODE

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    source = "#{TestPipelineSend::FIXTURE}\n#{SIZE_FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', source)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
