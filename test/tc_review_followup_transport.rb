require_relative 'tc_pipeline_send'

class ReviewFollowupTransportTest < Minitest::Test
  def test_cancelled_connects_release_all_workers_in_both_tcp_modes
    [false, true].each do |pipeline|
      [:close, :deadline].each do |cancellation|
        isolated("pipeline = #{pipeline}; cancellation = #{cancellation.inspect}\n" + <<~'RUBY')
          SELECTOR.singleton_class.remove_method(:notify_queue_observers)
          K.class_variable_set(:@@select_thread, Thread.current)
          waiting, wrote = Queue.new, Queue.new
          sockets, resolvers, queues = [], [], []
          socket_mutex = Mutex.new
          Socket.define_singleton_method(:new) do |*|
            socket = FrameSocket.new
            blocked = socket_mutex.synchronize { sockets << socket; sockets.size <= 4 }
            socket.define_singleton_method(:bind) { |*| 0 }
            socket.define_singleton_method(:connect_nonblock) do |*, **|
              waiting << true if blocked
              blocked ? :wait_writable : 0
            end
            socket.on_write = ->(*) { wrote << socket }
            socket
          end
          IO.define_singleton_method(:select) do |readers, writers, _, duration|
            raise 'invalid connect wait' unless readers.nil? && writers.length == 1 && duration <= 0.05
            sleep(duration)
            nil
          end
          4.times do |id|
            resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
              use_tcp: true, tcp_pipelining: pipeline, packet_timeout: 60,
              query_timeout: 60, retry_times: 1)
            queue = Queue.new
            resolvers << resolver
            queues << queue
            resolver.send_async(query("cancelled-#{id}.example."), queue, id)
          end
          4.times { waiting.pop }
          resolvers.each_with_index do |resolver, id|
            if cancellation == :close
              resolver.close
            else
              engine = resolver.instance_variable_get(:@resolver_ruby)
              engine.instance_variable_get(:@timeouts)[id][0] = Dnsruby::TransportClock.now - 1
              engine.tick
            end
          end
          healthy = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
            use_tcp: true, tcp_pipelining: pipeline, packet_timeout: 1,
            query_timeout: 2, retry_times: 1)
          request, completion = query('healthy.example.'), Queue.new
          healthy.send_async(request, completion, :healthy)
          socket = Timeout.timeout(2) { wrote.pop }
          Timeout.timeout(2) { Thread.pass until sockets.first(4).all?(&:closed?) }
          raise 'canceled connection wrote bytes' unless sockets.first(4).all? { |s| s.written.empty? }
          response = request.clone
          response.header.qr = true
          SELECTOR.process_message(response, response.encode, socket)
          SELECTOR.send_queued_validation_responses
          raise 'healthy query did not finish' unless completion.size == 1 && completion.pop.last.nil?
          expected = cancellation == :close ? Dnsruby::OtherResolvError : Dnsruby::ResolvTimeout
          queues.each do |queue|
            raise 'cancellation did not complete exactly once' unless queue.size == 1 && queue.pop.last.is_a?(expected)
          end
          (resolvers + [healthy]).each(&:close)
          drain_errors
          raise 'canceled attempt resurrected' unless K.class_variable_get(:@@query_hash).empty?
          raise 'late canceled completion' unless queues.all?(&:empty?)
          sockets.each { |s| assert_clean(s) }
        RUBY
      end
    end
  end

  def test_nonblocking_connector_checks_error_deadline_binding_and_cancellation
    isolated(<<~'RUBY')
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1')
      [:refused, :deadline, :cancelled, :bound_error, :success].each do |mode|
        socket, bound, target = FrameSocket.new, nil, nil
        socket.define_singleton_method(:bind) do |address|
          bound = Socket.unpack_sockaddr_in(address)
          raise Errno::EADDRINUSE if mode == :bound_error
        end
        socket.define_singleton_method(:connect_nonblock) do |address, **options|
          target = Socket.unpack_sockaddr_in(address)
          raise 'blocking connect requested' unless options[:exception] == false
          :wait_writable
        end
        socket.define_singleton_method(:getsockopt) do |level, option|
          raise 'SO_ERROR not queried' unless level == Socket::SOL_SOCKET && option == Socket::SO_ERROR
          Struct.new(:int).new(mode == :refused ? Errno::ECONNREFUSED::Errno : 0)
        end
        Socket.define_singleton_method(:new) { |family, type, _| raise 'wrong family/type' unless family == Socket::AF_INET && type == Socket::SOCK_STREAM; socket }
        token = K::SendToken.new
        IO.define_singleton_method(:select) do |_, writers, _, duration|
          raise 'unbounded wait' unless duration > 0 && duration <= 0.05 && writers == [socket]
          token.cancel if mode == :cancelled
          if mode == :deadline || mode == :cancelled
            sleep(duration)
            nil
          else
            [[], writers, []]
          end
        end
        started = Dnsruby::TransportClock.now
        begin
          result = writer.send(:connect_tcp, '127.0.0.2', 5300, '127.0.0.3', 55000,
            started + (mode == :cancelled ? 60 : 0.15), token)
          raise 'unexpected connection success' unless mode == :success && result.equal?(socket)
        rescue StandardError => error
          expected = {refused: Errno::ECONNREFUSED, deadline: Dnsruby::ResolvTimeout,
            bound_error: Errno::EADDRINUSE, cancelled: Dnsruby::PacketSender.const_get(:SendCancelled)}[mode]
          raise error unless expected && error.is_a?(expected)
          raise 'failed connection retained descriptor' unless socket.closed?
        end
        raise 'source binding changed' unless bound == [55000, '127.0.0.3']
        raise 'destination changed' unless mode == :bound_error || target == [5300, '127.0.0.2']
        elapsed = Dnsruby::TransportClock.now - started
        raise 'deadline expired early' if mode == :deadline && elapsed < 0.14
        raise 'cancellation waited for deadline' if mode == :cancelled && elapsed >= 2
        socket.close
      end
    RUBY
  end

  def test_closed_completion_queue_does_not_interrupt_other_resolvers
    isolated(<<~'RUBY')
      SELECTOR.singleton_class.remove_method(:notify_queue_observers)
      sockets = []
      Dnsruby::PacketSender.define_method(:connect_tcp) { |*| FrameSocket.new.tap { |s| sockets << s } }
      resolvers = 2.times.map do
        Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false,
          use_tcp: true, do_validation: false, do_caching: false)
      end
      requests, queues = 2.times.map { |id| query("queue-#{id}.example.") }, [Queue.new, Queue.new]
      resolvers.each_with_index { |resolver, id| resolver.send_async(requests[id], queues[id], id) }
      queues.first.close
      sockets.each_with_index do |socket, id|
        response = requests[id].clone
        response.header.qr = true
        SELECTOR.process_message(response, response.encode, socket)
        SELECTOR.send_queued_validation_responses
      end
      raise 'healthy completion lost' unless queues.last.size == 1 && queues.last.pop.last.nil?
      raise 'closed owner retained' unless K.class_variable_get(:@@query_hash).empty? &&
        K.class_variable_get(:@@observers).empty?
      resolvers.each(&:close)
      # Direct PacketSender recipients can also abandon an event queue.
      queue = Queue.new
      queue.close
      SELECTOR.push_exception_to_select(:abandoned, queue, IOError.new('gone'), nil)
      SELECTOR.send_queued_exceptions
      SELECTOR.push_response_to_select(:abandoned, queue, query, query, nil)
      SELECTOR.send_queued_responses
    RUBY
  end

  def test_tsig_discards_unsigned_and_bad_mac_until_valid_response_or_deadline
    isolated(<<~'RUBY')
      [:unsigned, :bad_mac, :timeout].each do |mode|
        socket = FrameSocket.new
        writer = sender(socket)
        request = query
        key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
          key: 'c2VjcmV0', algorithm: 'hmac-sha256')
        key.apply(request)
        live = settings(socket, mode, request, writer)
        SELECTOR.add_to_select(live)
        reply = Dnsruby::Message.new('pipeline.example.')
        reply.header.id, reply.header.qr = request.header.id, true
        if mode == :bad_mac
          wrong = key.dup
          wrong.key = 'd3Jvbmc='
          wrong.apply(reply, request)
        end
        bytes = reply.encode
        SELECTOR.process_message(Dnsruby::Message.decode(bytes), bytes, socket)
        raise 'unauthenticated reply completed query' unless SELECTOR.query_settings_for_id(mode).equal?(live) && live.client_queue.empty?
        if mode == :timeout
          K.class_variable_get(:@@timeouts)[mode] = Dnsruby::TransportClock.now - 1
          SELECTOR.process_timeouts
          raise 'timeout lost TSIG diagnostic' unless live.client_queue.size == 1 &&
            live.client_queue.pop.last.is_a?(Dnsruby::TsigNotSignedResponseError)
        else
          valid = Dnsruby::Message.new('pipeline.example.')
          valid.header.id, valid.header.qr = request.header.id, true
          key.apply(valid, request)
          bytes = valid.encode
          SELECTOR.process_message(Dnsruby::Message.decode(bytes), bytes, socket)
          SELECTOR.send_queued_validation_responses
          raise 'authentic response lost' unless live.client_queue.size == 2 &&
            2.times.map { live.client_queue.pop }.all? { |event| event.last.nil? && event[2].verified? }
          raise 'completed query retained' if SELECTOR.query_settings_for_id(mode)
          writer.close
        end
      end
    RUBY
  end

  def test_authenticated_tsig_errors_complete_but_forged_errors_keep_waiting
    isolated(<<~'RUBY')
      def error_wire(key, request, error_code, variant)
        response = Dnsruby::Message.new(variant == :wrong_question ? 'wrong.example.' : 'pipeline.example.')
        response.header.id, response.header.qr = request.header.id, true
        response.header.rcode = variant == :wrong_rcode ? Dnsruby::RCode::NOERROR : Dnsruby::RCode::NOTAUTH
        signer = key.dup
        signer.error = error_code
        signer.time_signed = request.tsig.time_signed
        if error_code == 18 && variant != :bad_other_data
          signer.other_data = [0, Time.now.to_i + 3600].pack('nN')
          signer.other_size = 6
        end
        signer.name = 'different-key.example.' if variant == :wrong_key
        signer.algorithm = 'hmac-sha1' if variant == :wrong_algorithm
        if variant == :bad_other_data
          signature = signer.dup
          signature.original_id = response.header.id
          input = [request.tsig.mac_size].pack('n') + request.tsig.mac + response.encode +
            signer.sig_data(signer, signer.time_signed)
          signature.mac = signer.calculate_mac(signer.algorithm, input)
          signature.mac_size = signature.mac.bytesize
        else
          signature = signer.generate(response, request)
        end
        if variant == :bad_mac
          signature.mac = signature.mac.dup
          signature.mac.setbyte(0, signature.mac.getbyte(0) ^ 1)
        elsif variant == :unsigned
          signature.mac, signature.mac_size = ''.b, 0
        end
        response.add_additional(signature)
        response.encode
      end

      [18, 22].each do |error_code|
        [:valid, :bad_mac, :unsigned, :wrong_key, :wrong_algorithm, :wrong_rcode, :wrong_question].each do |variant|
          socket = FrameSocket.new
          writer = sender(socket)
          request = query
          key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
            key: 'c2VjcmV0', algorithm: 'hmac-sha256')
          key.apply(request)
          live = settings(socket, [error_code, variant], request, writer)
          SELECTOR.add_to_select(live)
          deadline = live.endtime
          wire = error_wire(key, request, error_code, variant)
          if variant == :valid
            standalone = Dnsruby::Message.decode(wire)
            raise 'TSIG verify changed its error return contract' unless key.verify(request, standalone, wire.dup) == false
            raise 'valid server error was not authenticated' unless standalone.verified? && standalone.tsigerror == error_code
          end
          SELECTOR.process_message(Dnsruby::Message.decode(wire), wire, socket)
          if variant != :valid
            raise 'forged TSIG error claimed query' unless SELECTOR.query_settings_for_id(live.client_query_id).equal?(live)
            raise 'forged TSIG error published event' unless live.client_queue.empty?
            raise 'discard extended the deadline' unless live.endtime == deadline
            wire = error_wire(key, request, error_code, :valid)
            SELECTOR.process_message(Dnsruby::Message.decode(wire), wire, socket)
          end
          raise "authenticated TSIG error #{error_code}/#{variant} completed #{live.client_queue.size} times" unless live.client_queue.size == 1
          event = live.client_queue.pop
          name = error_code == 18 ? 'BADTIME' : 'BADTRUNC'
          raise 'TSIG error diagnostic lost' unless event.last.is_a?(Dnsruby::TsigError) && event.last.message.include?(name)
          raise 'verified server error state lost' unless event[2].verified? && event[2].tsigerror == error_code
          raise 'authenticated error retained attempt' if SELECTOR.query_settings_for_id(live.client_query_id)
          SELECTOR.retire_socket(socket)
          assert_clean(socket)
        end
      end
      # Even a valid MAC cannot make malformed BADTIME Other Data acceptable.
      request = query
      key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY', key: 'c2VjcmV0')
      key.apply(request)
      wire = error_wire(key, request, 18, :bad_other_data)
      decoded = Dnsruby::Message.decode(wire)
      raise 'malformed signed BADTIME accepted' unless key.verify(request, decoded, wire) == false && !decoded.verified?
    RUBY
  end

  def test_edns_preserves_existing_opt_options_payload_and_flags
    [1232, 4096].product([false, true]).each do |payload, dnssec|
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: dnssec, udp_size: 1232)
      request = Dnsruby::Message.new('opt.example.')
      option = Dnsruby::RR::OPT::Option.new(65000, 'opaque'.b)
      opt = Dnsruby::RR::OPT.new(payload, 0x0040, [option])
      request.add_additional(opt)
      writer.make_query_packet(request)
      assert_same(opt, request.get_opt)
      decoded = Dnsruby::Message.decode(request.encode)
      assert_equal(1, decoded.additional.count { |rr| rr.type == Dnsruby::Types::OPT })
      assert_equal(payload, decoded.get_opt.payloadsize)
      assert_equal(0x0040 | (dnssec ? 0x8000 : 0), decoded.get_opt.flags)
      assert_equal([[65000, 'opaque']], decoded.get_opt.options(nil).map { |o| [o.code, o.data] })
    end
  end

  def test_authenticated_notauth_response_remains_a_server_error
    request = Dnsruby::Message.new('authenticated-error.example.')
    key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
      key: 'c2VjcmV0', algorithm: 'hmac-sha256')
    key.apply(request)
    reply = Dnsruby::Message.new('authenticated-error.example.')
    reply.header.id, reply.header.qr, reply.header.rcode = request.header.id, true, Dnsruby::RCode::NOTAUTH
    key.apply(reply, request)
    bytes = reply.encode
    reply = Dnsruby::Message.decode(bytes)
    writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
    assert_equal(true, writer.check_response(reply, bytes, request, Queue.new, :notauth, false))
    assert(reply.verified?)
    assert_instance_of(Dnsruby::NotAuth, reply.get_exception)
  end

  def test_tsig_generate_and_apply_preserve_the_error_fields_covered_by_the_mac
    [18, 22].product([:generate, :apply]).each do |error_code, operation|
      request = Dnsruby::Message.new('signed-error.example.')
      key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
        key: 'c2VjcmV0', algorithm: 'hmac-sha256')
      key.apply(request)
      signer = key.dup
      signer.error = error_code
      signer.time_signed = request.tsig.time_signed
      expected_data = error_code == 18 ? [0, Time.now.to_i + 3600].pack('nN') : ''.b
      signer.other_data, signer.other_size = expected_data, expected_data.bytesize
      reply = Dnsruby::Message.new('signed-error.example.')
      reply.header.id, reply.header.qr, reply.header.rcode = request.header.id, true, Dnsruby::RCode::NOTAUTH
      if operation == :generate
        reply.add_additional(signer.generate(reply, request))
      else
        signer.apply(reply, request)
      end
      wire = reply.encode
      decoded = Dnsruby::Message.decode(wire)
      assert_equal(expected_data.bytesize, decoded.tsig.other_size)
      assert_equal(expected_data, decoded.tsig.other_data)
      assert_equal(false, key.verify(request, decoded, wire))
      assert(decoded.verified?, "#{operation} produced an invalid signed error")
      assert_equal(error_code, decoded.tsigerror)
    end
  end

  def test_rechecking_stripped_tsig_errors_does_not_reuse_the_previous_authentication
    [18, 22].each do |error_code|
      request = Dnsruby::Message.new('signed-error.example.')
      key = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
        key: 'c2VjcmV0', algorithm: 'hmac-sha256')
      key.apply(request)
      signer = key.dup
      signer.error = error_code
      signer.time_signed = request.tsig.time_signed
      signer.other_data = error_code == 18 ? [0, Time.now.to_i + 3600].pack('nN') : ''.b
      signer.other_size = signer.other_data.bytesize
      reply = Dnsruby::Message.new('signed-error.example.')
      reply.header.id, reply.header.qr, reply.header.rcode = request.header.id, true, Dnsruby::RCode::NOTAUTH
      signer.apply(reply, request)
      wire = reply.encode
      decoded = Dnsruby::Message.decode(wire)
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
      queue = Queue.new
      assert_instance_of(Dnsruby::TsigError, writer.check_response(decoded, wire, request, queue, :repeat, false))
      assert(decoded.verified?)
      assert_nil(decoded.tsig)
      assert_equal(false, writer.check_response(decoded, wire, request, queue, :repeat, false))
      refute(decoded.verified?)
      assert_equal(Dnsruby::RCode::FORMERR, decoded.tsigerror)
      assert(queue.empty?)
    end
  end

  def test_udp_receive_capacity_uses_the_opt_advertised_by_each_attempt
    isolated(<<~'RUBY')
      [[1232, 4096], [4096, 1232], [1232, 0]].each do |configured, advertised|
        socket = FrameSocket.new
        socket.define_singleton_method(:bind) { |*| }
        socket.define_singleton_method(:connect) { |*| }
        socket.define_singleton_method(:getsockopt) { |*| Struct.new(:data).new([Socket::SOCK_DGRAM].pack('i')) }
        UDPSocket.define_singleton_method(:new) { |*| socket }
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, udp_size: configured)
        request = query('large-opt.example.')
        request.add_additional(Dnsruby::RR::OPT.new(advertised))
        queue = Queue.new
        writer.send_async(request, queue, :opt)
        live = SELECTOR.query_settings_for_id(:opt)
        raise 'receive capacity disagrees with OPT' unless live.udp_packet_size == [advertised, 512].max
        response = request.clone
        response.header.qr = true
        count = advertised > configured ? 7 : 1
        response.add_answer(Dnsruby::RR.create('large-opt.example. 0 IN TXT ' +
          Array.new(count) { '"' + 'x' * 240 + '"' }.join(' ')))
        wire = response.encode
        raise 'fixture did not exceed configured capacity' if count == 7 && wire.bytesize <= configured
        socket.define_singleton_method(:recvfrom) do |capacity|
          [wire.byteslice(0, capacity), ['AF_INET', 53, '127.0.0.1', '127.0.0.1']]
        end
        incoming = SELECTOR.get_incoming_data(socket, live.udp_packet_size)
        SELECTOR.process_message(*incoming, socket) if incoming
        SELECTOR.send_queued_validation_responses
        raise 'valid advertised-size reply was truncated' unless queue.size == 2 &&
          2.times.map { queue.pop }.all? { |event| event.last.nil? && event[2].answer.first.strings.size == count }
        raise 'completed OPT query retained' if SELECTOR.query_settings_for_id(:opt)
        assert_clean(socket)
      end
    RUBY
  end

  def test_explicit_udp_size_is_honoured_with_dnssec_in_either_option_order
    [Dnsruby::Resolver, Dnsruby::SingleResolver, Dnsruby::PacketSender].each do |klass|
      [{udp_size: 1232, dnssec: true}, {dnssec: true, udp_size: 1232}].each do |settings|
        options = klass == Dnsruby::Resolver ? {nameserver: '127.0.0.1'} : {server: '127.0.0.1'}
        object = klass.new(options.merge(settings))
        assert_equal(1232, object.udp_size)
        writer = object.is_a?(Dnsruby::Resolver) ? object.single_resolvers.first : object
        request = Dnsruby::Message.new('payload.example.')
        assert_equal(1232, writer.udp_packet_size)
        assert_equal(1232, Dnsruby::Message.decode(writer.make_query_packet(request)).get_opt.payloadsize)
      end
    end
    writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, udp_size: 1232)
    assert_equal(1232, Dnsruby::Message.decode(writer.make_query_packet(Dnsruby::Message.new('payload.example.'))).get_opt.payloadsize)
    writer.udp_size = 100
    assert_equal(512, writer.udp_packet_size)
    assert_nil(Dnsruby::Message.decode(writer.make_query_packet(Dnsruby::Message.new('payload.example.'))).get_opt)
  end

  def test_default_and_explicit_udp_sizes_match_the_wire_and_receive_capacity
    assert_equal(1232, Dnsruby::Resolver::DefaultUDPSize)
    assert_equal(1220, Dnsruby::Resolver::AbsoluteMinDnssecUdpSize)
    assert_equal(4096, Dnsruby::Resolver::MinDnssecUdpSize)
    isolated(<<~'RUBY')
      [Dnsruby::Resolver, Dnsruby::SingleResolver, Dnsruby::PacketSender].product(
        [false, true], [nil, 512, 1220, 1232, 4096]).each do |klass, dnssec, configured|
        socket = FrameSocket.new
        socket.define_singleton_method(:bind) { |*| }
        socket.define_singleton_method(:connect) { |*| }
        socket.define_singleton_method(:getsockopt) { |*| Struct.new(:data).new([Socket::SOCK_DGRAM].pack('i')) }
        UDPSocket.define_singleton_method(:new) { |*| socket }
        options = klass == Dnsruby::Resolver ? {nameserver: '127.0.0.1'} : {server: '127.0.0.1'}
        options[:udp_size] = configured if configured
        options[:dnssec] = dnssec
        object = klass.new(options)
        writer = object.is_a?(Dnsruby::Resolver) ? object.single_resolvers.first : object
        expected = configured || 1232
        expected = [expected, 1220].max if dnssec
        raise "wrong configured size for #{klass}" unless object.udp_size == expected && writer.udp_size == expected
        request, queue = query('udp-limit.example.'), Queue.new
        writer.send_async(request, queue, :limit)
        live = SELECTOR.query_settings_for_id(:limit)
        raise 'wrong receive capacity' unless live.udp_packet_size == expected
        sent = Dnsruby::Message.decode(socket.written)
        if expected > 512
          raise 'wrong OPT count' unless sent.additional.count { |rr| rr.type == Dnsruby::Types::OPT } == 1
          raise 'wrong advertised capacity' unless sent.get_opt.payloadsize == expected
          raise 'wrong DNSSEC flag' unless sent.get_opt.dnssec_ok == dnssec
        else
          raise 'classic DNS unexpectedly advertised EDNS' if sent.get_opt
        end
        response = request.clone
        response.header.qr = true
        wire = response.encode
        socket.define_singleton_method(:recvfrom) do |capacity|
          raise 'receive buffer differs from advertisement' unless capacity == expected
          [wire, ['AF_INET', 53, '127.0.0.1', '127.0.0.1']]
        end
        incoming = SELECTOR.get_incoming_data(socket, live.udp_packet_size)
        SELECTOR.process_message(*incoming, socket)
        SELECTOR.send_queued_validation_responses
        raise 'response did not complete' unless queue.size == 2 &&
          2.times.map { queue.pop }.all? { |event| event.last.nil? }
        object.close
        assert_clean(socket)
      end
    RUBY
  end

  def test_questionless_error_matching_is_tcp_only_and_edns_retry_retains_transport
    [false, true].product([false, true]).each do |tcp, edns|
      writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
      retries = []
      writer.define_singleton_method(:send_async) { |*args| retries << args }
      request = Dnsruby::Message.new('error.example.')
      request.add_additional(Dnsruby::RR::OPT.new(1232)) if edns
      error = Dnsruby::Message.new
      error.header.id, error.header.qr, error.header.rcode = request.header.id, true, Dnsruby::RCode::FORMERR
      result = writer.check_response(error, error.encode, request, Queue.new, :error, tcp)
      assert_equal(tcp && !edns, result)
      assert_equal(tcp && edns ? 1 : 0, retries.size)
      if tcp && edns
        assert_equal(true, retries.first[3])
        assert_equal(true, retries.first[4])
        assert_nil(retries.first[0].get_opt)
      end
      error.header.rcode = Dnsruby::RCode::NOERROR
      assert_equal(false, writer.check_response(error, error.encode, request, Queue.new, :error, tcp))
    end
  end

  def test_public_senders_prepare_messages_before_signing_and_preserve_existing_signatures
    isolated(<<~'RUBY')
      captured = []
      Dnsruby::PacketSender.define_method(:send_dnsruby) { |wire, *| captured << wire }
      [Dnsruby::Resolver, Dnsruby::SingleResolver, Dnsruby::PacketSender].product(
        [false, true], [false, true], [false, true], [false, true],
        [:message, :resolver, :both, :signed, :decoded, :raw_message, :raw_unsigned]).each do |klass, dnssec, rd, recurse, tcp, mode|
        message_key = Dnsruby::RR.create(name: 'message-key.example.', type: 'TSIG', klass: 'ANY',
          key: 'c2VjcmV0', algorithm: 'hmac-sha256')
        resolver_key = Dnsruby::RR.create(name: 'resolver-key.example.', type: 'TSIG', klass: 'ANY',
          key: 'b3RoZXI=', algorithm: 'hmac-sha256')
        options = klass == Dnsruby::Resolver ? {nameserver: '127.0.0.1'} : {server: '127.0.0.1'}
        object = klass.new(options.merge(dnssec: dnssec, recurse: recurse, use_tcp: tcp))
        object.tsig = resolver_key unless [:message, :raw_message, :raw_unsigned].include?(mode)
        request = query('signed-query.example.')
        request.header.rd, request.header.ad = rd, true
        request.add_additional(Dnsruby::RR::OPT.new(4096, 0x0040,
          [Dnsruby::RR::OPT::Option.new(65000, 'opaque'.b)]))
        request.send_raw = [:raw_message, :raw_unsigned].include?(mode)
        if [:signed, :decoded].include?(mode)
          message_key.apply(request)
          original_wire = request.encode
          request = Dnsruby::Message.decode(original_wire) if mode == :decoded
        elsif [:message, :both, :raw_message].include?(mode)
          request.set_tsig(message_key)
        end
        request.do_caching = request.do_validation = false
        object.send_async(request, Queue.new, :signed)
        raise "missing send for #{klass}/#{mode}" unless captured.size == 1
        wire = captured.shift
        decoded = Dnsruby::Message.decode(wire)
        if [:signed, :decoded].include?(mode)
          raise 'pre-signed packet was changed' unless wire == original_wire
        end
        protected = [:signed, :decoded, :raw_message, :raw_unsigned].include?(mode)
        raise 'wrong RD policy' unless decoded.header.rd == (protected ? rd : recurse)
        raise 'wrong DO policy' unless decoded.get_opt.dnssec_ok == (!protected && dnssec)
        raise 'caller OPT payload changed' unless decoded.get_opt.payloadsize == 4096
        raise 'caller OPT options changed' unless decoded.get_opt.options(nil).map { |opt| [opt.code, opt.data] } == [[65000, 'opaque']]
        raise 'caller OPT flag lost' unless decoded.get_opt.flags & 0x0040 == 0x0040
        if mode == :raw_unsigned
          raise 'raw unsigned packet was signed' if decoded.tsig
        else
          key = mode == :resolver ? resolver_key : message_key
          signature = decoded.tsig
          raise 'wrong signing key precedence' unless signature && signature.name == key.name
          raise "invalid request MAC for #{klass}/#{mode}/#{dnssec}/#{rd}/#{recurse}/#{tcp}" unless
            key.generate(decoded, nil, '', wire, signature).mac == signature.mac
          raise 'duplicate TSIG' unless decoded.additional.count { |rr| rr.type == Dnsruby::Types::TSIG } == 1
        end
        object.close
      end
    RUBY
  end

  def test_socket_index_retains_duplicate_helper_ids_and_cleans_up_replacements
    isolated(<<~'RUBY')
      first_socket, second_socket = FrameSocket.new, FrameSocket.new
      first = settings(first_socket, :first, query('first.example.'))
      second = settings(first_socket, :second, query('second.example.'))
      first.query.header.id = second.query.header.id = 123
      [first, second].each { |s| SELECTOR.add_to_select(s) }
      raise 'missing collision' unless SELECTOR.query_id_in_use?(first_socket, 123)
      replacement = settings(second_socket, :first, first.query)
      SELECTOR.add_to_select(replacement)
      raise 'peer collision removed' unless SELECTOR.query_id_in_use?(first_socket, 123)
      raise 'replacement collision missing' unless SELECTOR.query_id_in_use?(second_socket, 123)
      SELECTOR.remove_id(:second)
      raise 'old collision retained' if SELECTOR.query_id_in_use?(first_socket, 123)
      SELECTOR.remove_id(:first)
      raise 'replacement collision retained' if SELECTOR.query_id_in_use?(second_socket, 123)
      [first_socket, second_socket].each { |socket| assert_clean(socket) }
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
