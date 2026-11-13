require_relative 'tc_pipeline_send'

class ReviewPacketContractsTest < Minitest::Test
  def test_both_caches_match_query_class_and_keep_ordinary_cache_hits
    isolated(<<~'RUBY')
      [true, false].each do |recursive|
        Dnsruby::PacketSender.clear_caches
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, recurse: recursive)
        sent = []
        writer.define_singleton_method(:send_dnsruby) { |*args| sent << args }
        internet = cache_query('IN')
        internet.header.rd = recursive
        Dnsruby::PacketSender.cache(internet, answer(internet, 'internet'))
        chaos = cache_query('CH')
        chaos.header.rd = recursive
        writer.send_async(chaos, Queue.new, :miss)
        raise 'wrong class hit cached IN answer' unless sent.length == 1
        Dnsruby::PacketSender.cache(chaos, answer(chaos, 'chaos'))
        [['CH', 'chaos'], ['IN', 'internet']].each do |klass, text|
          queue = Queue.new
          writer.send_async(cache_query(klass), queue, klass)
          SELECTOR.send_queued_responses
          received = queue.pop(true)
          validated = queue.pop(true)
          raise 'cache hit lost' unless received[2].cached && sent.length == 1
          raise 'wrong cached class' unless received[2].question.first.qclass == Dnsruby::Classes.new(klass)
          raise 'wrong cached answer' unless received[2].answer.first.strings == [text]
          raise 'cache completion duplicated' unless validated[1] == Dnsruby::Resolver::EventType::VALIDATED && queue.empty?
        end
      end
    RUBY
  end

  def test_tsig_transactions_bypass_both_cache_reads_and_verified_response_writes
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    isolated(<<~'RUBY')
      [true, false].each do |recursive|
        [:sender_key, :message_key, :presigned].each do |mode|
          Dnsruby::PacketSender.clear_caches
          writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, recurse: recursive)
          sent = []
          writer.define_singleton_method(:send_dnsruby) { |*args| sent << args }
          plain = cache_query('IN')
          plain.header.rd = recursive
          Dnsruby::PacketSender.cache(plain, answer(plain, 'unsigned cache'))
          key = signing_key
          signed = cache_query('IN')
          signed.header.rd = recursive
          if mode == :sender_key
            writer.tsig = key
          elsif mode == :message_key
            signed.set_tsig(key)
          else
            key.apply(signed)
          end
          queue = Queue.new
          writer.send_async(signed, queue, :signed)
          raise 'signed request read shared cache' unless sent.length == 1
          raise 'signed query not sent on wire' unless Dnsruby::Message.decode(sent.first.first).tsig
          raise 'cache response was queued' unless K.class_variable_get(:@@queued_responses).empty?
          unsigned = answer(signed, 'unsigned server')
          result = writer.check_response(unsigned, unsigned.encode, signed, queue, :signed, false)
          raise 'unsigned server answer accepted' unless result.is_a?(Dnsruby::TsigNotSignedResponseError)
          response = answer(signed, 'private signed answer')
          key.apply(response, signed)
          bytes = response.encode
          response = Dnsruby::Message.decode(bytes)
          raise 'signed reply not verified' unless writer.check_response(response, bytes, signed, queue, :signed, false) == true
          raise 'fixture has not exercised TSIG stripping' unless response.verified? && response.tsig.nil?
          Dnsruby::PacketSender.clear_caches
          Dnsruby::PacketSender.cache(signed, response)
          writer.tsig = nil
          writer.send_async(cache_query('IN'), Queue.new, :plain)
          raise 'verified private answer entered shared cache' unless sent.length == 2
          raise 'signed reply produced a cached result' unless K.class_variable_get(:@@queued_responses).empty?
        end
      end
    RUBY
  end

  def test_invalid_headers_are_rejected_before_tsig_mutation_or_retry
    skip('OpenSSL HMAC unavailable') unless defined?(OpenSSL::HMAC)
    isolated(<<~'RUBY')
      [:query_packet, :wrong_opcode, :wrong_id].each do |invalid_header|
        [:ordinary, :formerr, :truncated].each do |kind|
          writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false)
          retries = []
          writer.define_singleton_method(:send_async) { |*args| retries << args }
          q = cache_query('IN')
          q.add_additional(Dnsruby::RR::OPT.new(4096))
          key = signing_key
          key.apply(q)
          reply = answer(q, 'ignored')
          reply.header.qr = false if invalid_header == :query_packet
          reply.header.opcode = Dnsruby::OpCode::Update if invalid_header == :wrong_opcode
          reply.header.rcode = Dnsruby::RCode::FORMERR if kind == :formerr
          reply.header.tc = true if kind == :truncated
          key.apply(reply, q)
          reply.header.id = (q.header.id + 1) % 65_536 if invalid_header == :wrong_id
          bytes = reply.encode
          reply = Dnsruby::Message.decode(bytes)
          signature = reply.tsig
          state = reply.tsigstate
          result = writer.check_response(reply, bytes, q, Queue.new, :ignored, false)
          raise "invalid #{invalid_header}/#{kind} consumed request" unless result == false
          raise 'invalid header mutated TSIG' unless reply.tsig.equal?(signature) && reply.tsigstate == state
          raise 'invalid header caused retry' unless retries.empty?
        end
      end
    RUBY
  end

  def test_invalid_then_valid_packets_preserve_query_and_pipeline_peer_ownership
    isolated(<<~'RUBY')
      [:query_packet, :wrong_opcode].each do |invalid_header|
        socket = FrameSocket.new
        writer = sender(socket)
        q = query('target.example.')
        q.header.id = 100
        target = settings(socket, :target, q, writer)
        peer = settings(socket, :peer, query('peer.example.'), writer)
        peer.query.header.id = 100 # Exercise matching questions before response processing.
        SELECTOR.add_to_select(target)
        SELECTOR.add_to_select(peer)
        invalid = answer(q, 'invalid')
        invalid.header.qr = false if invalid_header == :query_packet
        invalid.header.opcode = Dnsruby::OpCode::Update if invalid_header == :wrong_opcode
        SELECTOR.process_message(invalid, invalid.encode, socket)
        raise 'invalid reply completed target' unless SELECTOR.query_settings_for_id(:target).equal?(target)
        raise 'invalid reply disturbed peer' unless SELECTOR.query_settings_for_id(:peer).equal?(peer)
        raise 'invalid reply was delivered' unless target.client_queue.empty? && peer.client_queue.empty?
        [peer, target].each do |current|
          response = answer(current.query, 'valid')
          SELECTOR.process_message(response, response.encode, socket)
          SELECTOR.send_queued_validation_responses
          events = 2.times.map { current.client_queue.pop(true) }
          raise 'valid response not delivered exactly once' unless current.client_queue.empty? &&
            events.map { |event| event[1] } == [Dnsruby::Resolver::EventType::RECEIVED, Dnsruby::Resolver::EventType::VALIDATED] &&
            events.all? { |event| event.last.nil? && event[2].answer.first.strings == ['valid'] }
        end
        SELECTOR.retire_socket(socket)
        assert_clean(socket)
      end
    RUBY
  end

  def test_edns_fallback_keeps_the_attempt_transport_and_raw_mode_stays_raw
    isolated(<<~'RUBY')
      [true, false].each do |tcp|
        writer = Dnsruby::PacketSender.new(server: '127.0.0.1', dnssec: false, use_tcp: !tcp)
        retries = []
        writer.define_singleton_method(:send_async) { |*args| retries << args }
        q = query
        q.add_additional(Dnsruby::RR::OPT.new(4096))
        original = q.encode
        reply = answer(q, 'formerr')
        reply.header.rcode = Dnsruby::RCode::FORMERR
        raise 'FORMERR was delivered' unless writer.check_response(reply, reply.encode, q, Queue.new, :retry, tcp) == false
        raise 'wrong retry transport' unless retries.length == 1 && retries.first[3] == tcp
        raise 'EDNS not disabled for retry' unless retries.first[4] && retries.first.first.get_opt.nil?
        raise 'caller query was mutated' unless q.encode == original
        q.send_raw = true
        reply.header.qr = false
        reply.header.opcode = Dnsruby::OpCode::Update
        raise 'raw response was filtered' unless writer.check_response(reply, reply.encode, q, Queue.new, :raw, tcp) == true
        raise 'raw response retried' unless retries.length == 1
      end
    RUBY
  end

  def test_malformed_invalid_headers_leave_udp_and_tcp_owners_active_for_valid_replies
    isolated(<<~'RUBY')
      [false, true].each do |tcp|
        [false, true].each do |truncated|
          [:query_packet, :wrong_opcode].each do |invalid_header|
            socket = FrameSocket.new
            writer = sender(socket)
            retries = []
            writer.define_singleton_method(:send_async) { |*args| retries << args }
            q = query('target.example.')
            q.header.id = 100
            target = settings(socket, :target, q, writer)
            target.is_persistent_socket = tcp
            peer_socket = tcp ? socket : FrameSocket.new
            peer = settings(peer_socket, :peer, query('peer.example.'), writer)
            peer.query.header.id = 101
            SELECTOR.add_to_select(target)
            SELECTOR.add_to_select(peer)
            flags = invalid_header == :query_packet ? 0 : 0xa800
            flags |= 0x0200 if truncated
            malformed = [100, flags, 1, 0, 0, 0].pack('n6') # Question is missing.
            inject_packet(socket, malformed, tcp)
            raise 'malformed packet decoded' if SELECTOR.get_incoming_data(socket, 512)
            raise 'invalid malformed header triggered fallback' unless retries.empty?
            raise 'invalid malformed header completed target' unless SELECTOR.query_settings_for_id(:target).equal?(target)
            raise 'invalid malformed header consumed peer' unless SELECTOR.query_settings_for_id(:peer).equal?(peer)
            raise 'invalid malformed header delivered an error' unless target.client_queue.empty? && peer.client_queue.empty?
            valid = answer(q, 'valid')
            inject_packet(socket, valid.encode, tcp)
            incoming = SELECTOR.get_incoming_data(socket, 512)
            raise 'following valid response was lost' unless incoming
            SELECTOR.process_message(*incoming, socket)
            SELECTOR.send_queued_validation_responses
            events = 2.times.map { target.client_queue.pop(true) }
            raise 'valid response not delivered once' unless target.client_queue.empty? &&
              events.all? { |event| event.last.nil? && event[2].answer.first.strings == ['valid'] }
            raise 'valid target response disturbed peer' unless SELECTOR.query_settings_for_id(:peer).equal?(peer)
            SELECTOR.remove_id(:peer)
            assert_clean(socket)
            assert_clean(peer_socket)
          end
        end
      end
    RUBY
  end

  def test_malformed_matching_and_raw_headers_keep_existing_fallback_and_error_behavior
    isolated(<<~'RUBY')
      [false, true].each do |tcp|
        [false, true].each do |truncated|
          [false, true].each do |raw|
            socket = FrameSocket.new
            writer = sender(socket)
            retries = []
            writer.define_singleton_method(:send_async) { |*args| retries << args }
            q = query
            q.header.id = 100
            q.send_raw = raw
            current = settings(socket, :current, q, writer)
            current.is_persistent_socket = tcp
            SELECTOR.add_to_select(current)
            # Raw queries intentionally retain permissive header handling.
            flags = raw ? 0x2800 : 0x8000
            flags |= 0x0200 if truncated
            inject_packet(socket, [100, flags, 1, 0, 0, 0].pack('n6'), tcp)
            raise 'malformed packet decoded' if SELECTOR.get_incoming_data(socket, 512)
            if truncated && !tcp
              raise 'valid/raw truncated UDP lost TCP fallback' unless retries.length == 1 && retries.first[3] == true
              raise 'fallback emitted a premature error' unless current.client_queue.empty?
              SELECTOR.remove_id(:current)
            else
              raise 'malformed TCP/nontruncated packet unexpectedly retried' unless retries.empty?
              raise 'malformed packet did not report one decode error' unless current.client_queue.length == 1 &&
                current.client_queue.pop(true).last.is_a?(Dnsruby::DecodeError)
              raise 'terminal decode error retained owner' if SELECTOR.query_settings_for_id(:current)
            end
            assert_clean(socket)
          end
        end
      end
    RUBY
  end

  def test_short_malformed_headers_keep_existing_decode_error_delivery
    isolated(<<~'RUBY')
      [false, true].each do |tcp|
        [2, 4, 11].each do |length|
          socket = FrameSocket.new
          writer = sender(socket)
          writer.define_singleton_method(:send_async) { |*| raise 'incomplete header triggered retry' }
          q = query
          q.header.id = 100
          current = settings(socket, :current, q, writer)
          current.is_persistent_socket = tcp
          SELECTOR.add_to_select(current)
          inject_packet(socket, [100, 0x2800, 1, 0, 0, 0].pack('n6').byteslice(0, length), tcp)
          raise 'incomplete header decoded' if SELECTOR.get_incoming_data(socket, 512)
          raise 'incomplete header error was suppressed' unless current.client_queue.length == 1 &&
            current.client_queue.pop(true).last.is_a?(Dnsruby::DecodeError)
          raise 'incomplete header retained owner' if SELECTOR.query_settings_for_id(:current)
          assert_clean(socket)
        end
      end
    RUBY
  end

  private

  CONTRACT_FIXTURE = <<~'RUBY'
    def cache_query(klass)
      Dnsruby::Message.new('contract.example.', Dnsruby::Types::TXT, klass).tap do |message|
        message.do_validation = false
      end
    end
    def answer(query, text)
      question = query.question.first
      Dnsruby::Message.new(question.qname, question.qtype, question.qclass).tap do |reply|
        reply.header.id = query.header.id
        reply.header.qr = reply.header.aa = true
        reply.add_answer(Dnsruby::RR.create("#{question.qname} 60 #{question.qclass} TXT \"#{text}\""))
      end
    end
    def signing_key
      Dnsruby::RR.create(name: 'contract-key.example.', type: 'TSIG', klass: 'ANY',
        key: 'c2VjcmV0', algorithm: 'hmac-sha256')
    end
    def inject_packet(socket, bytes, tcp)
      if tcp
        socket.incoming = [bytes.bytesize].pack('n') + bytes
      else
        socket.define_singleton_method(:getsockopt) { |*| Struct.new(:data).new([Socket::SOCK_DGRAM].pack('i')) }
        socket.define_singleton_method(:recvfrom) { |*| [bytes, ['AF_INET', 53, '127.0.0.1', '127.0.0.1']] }
      end
    end
  RUBY

  def isolated(body)
    options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    source = "#{TestPipelineSend::FIXTURE}\n#{CONTRACT_FIXTURE}\nTimeout.timeout(10) do\n#{body}\nend"
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, *options, '-I',
      File.expand_path('../lib', __dir__), '-e', source)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
