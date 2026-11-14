require_relative 'spec_helper'
require 'open3'
require 'rbconfig'

class TestTransportFork < Minitest::Test
  def test_child_discards_parent_transactions_descriptors_and_worker_state
    skip 'fork unavailable' unless Process.respond_to?(:fork)
    code = <<~'CHILD'
      require 'dnsruby'
      require 'timeout'
      Dnsruby.log.level = Logger::FATAL
      # Own dispatch explicitly: no DNS service or elapsed timeout is needed.
      class Dnsruby::SelectThread
        def get_socket_pair
          Socket.pair(:UNIX, :STREAM, 0)
        end

        def do_select
          sleep
        end
      end
      Timeout.timeout(10) do
        selector = Dnsruby::SelectThread.instance
        klass = Dnsruby::SelectThread
        resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1', dnssec: false)
        sender = resolver.single_resolvers.first
        sender.define_singleton_method(:send_async) { |*| }
        request = Dnsruby::Message.new('fork.example.')
        request.do_caching = request.do_validation = false
        results = Queue.new
        resolver.send_async(request, results, :reused)
        engine = resolver.instance_variable_get(:@resolver_ruby)
        inherited_attempt = engine.instance_variable_get(:@query_list)[:reused][3].first
        socket, peer = Socket.pair(:UNIX, :STREAM, 0)
        pending_socket, pending_peer = Socket.pair(:UNIX, :STREAM, 0)
        selector.track_socket(pending_socket) # A socket still connecting/writing.
        settings = klass::QuerySettings.new(request.encode, request, false, Queue.new,
          :parent_stream, socket, '127.0.0.1', 53, Dnsruby::TransportClock.now + 60, 512, sender)
        settings.is_persistent_socket = true
        settings.tcp_pipelining_max_queries = :infinite
        selector.add_to_select(settings)
        sender.instance_variable_set(:@pipeline_socket, socket)
        sender.instance_variable_set(:@use_counts, { socket => 1 })
        writer_lock = Mutex.new
        writer_lock.lock
        sender.instance_variable_set(:@pipeline_mutex, writer_lock)
        wakeups = klass.class_variable_get(:@@wakeup_sockets).dup
        started, release = Queue.new, Queue.new
        selector.defer_send(sender) { started << true; release.pop }
        started.pop

        pid = fork do
          begin
            # A retained reference must be as safe as fetching the singleton.
            raise 'inherited transaction survived' if selector.query_settings_for_id(:parent_stream)
            raise 'singleton changed' unless Dnsruby::SelectThread.instance.equal?(selector)
            raise 'inherited descriptors open' unless ([socket, pending_socket] + wakeups).all?(&:closed?)
            [:query_hash, :socket_hash, :timeouts, :observers, :observer_queue_counts,
              :tcp_buffers, :socket_owners, :socket_remaining_queries,
              :queued_exceptions, :queued_responses, :queued_validation_responses,
              :validations, :tick_observers].each do |name|
              raise "inherited #{name}" unless klass.class_variable_get("@@#{name}").empty?
            end
            raise 'inherited sockets still selected' unless klass.class_variable_get(:@@sockets).size == 1
            raise 'new wakeup pair unavailable' unless klass.class_variable_get(:@@wakeup_sockets).none?(&:closed?)
            raise 'inherited workers retained' if selector.instance_variable_get(:@send_workers)
            selector.defer_send(sender) { :child_work }.value == :child_work or raise 'new worker failed'

            # A real pipeline send must choose a child-owned connection before
            # taking the writer lock that the parent held when it forked.
            child_socket, child_peer = Socket.pair(:UNIX, :STREAM, 0)
            sender.tcp_pipelining = true
            sender.define_singleton_method(:connect_tcp) do |*|
              selector.track_socket(child_socket)
            end
            direct_results = Queue.new
            sender.send_dnsruby(request.encode, request, :child_stream, direct_results, true)
            raise 'child did not open its own pipeline' unless sender.instance_variable_get(:@pipeline_socket).equal?(child_socket)
            raise 'inherited writer mutex retained' if sender.instance_variable_get(:@pipeline_mutex).equal?(writer_lock)
            raise 'inherited use counts retained' if sender.instance_variable_get(:@use_counts).key?(socket)
            frame_size = child_peer.read(2).unpack1('n')
            child_request = Dnsruby::Message.decode(child_peer.read(frame_size))
            raise 'child frame incorrect' unless child_request.question == request.question
            direct_answer = request.clone
            direct_answer.header.qr = true
            selector.process_message(direct_answer, direct_answer.encode, child_socket)
            selector.send_queued_validation_responses
            raise 'child pipeline response failed' unless direct_results.size == 2 &&
              2.times.map { direct_results.pop }.all? { |event| event.last.nil? }
            sender.close
            child_peer.close

            # Resolver IDs also belong to the parent and can be reused by child
            # transactions without delivering a spurious duplicate-ID failure.
            resolver.send_async(request.clone, results, :reused)
            current = engine.instance_variable_get(:@query_list)[:reused]
            raise 'child query rejected' unless current && results.empty?
            pending = selector.query_settings_for_id(current[3].first)
            raise 'child attempt absent' unless pending
            answer = request.clone
            answer.header.qr = true
            answer.add_answer(Dnsruby::RR.create('fork.example. 60 IN A 192.0.2.1'))
            selector.push_response_for_query(pending, answer, pending.query, sender)
            selector.send_queued_responses
            raise 'child completion failed' unless results.size == 1 && results.pop.last.nil?
            resolver.close
            exit! 0
          rescue Exception => error
            warn error.full_message
            exit! 1
          end
        end
        Process.wait(pid)
        raise 'fork child failed' unless $?.success?
        raise 'parent descriptor closed' if ([socket, pending_socket] + wakeups).any?(&:closed?)
        raise 'parent transaction discarded' unless selector.query_settings_for_id(inherited_attempt)
        raise 'parent observer discarded' unless klass.class_variable_get(:@@observers).size == 1
        raise 'parent received child result' unless results.empty?
        peer.write('parent')
        raise 'parent connection damaged' unless socket.read(6) == 'parent'
        release << true
        writer_lock.unlock
        resolver.close
        [socket, peer, pending_socket, pending_peer].each { |io| io.close unless io.closed? }
      end
    CHILD
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I',
      File.expand_path('../lib', __dir__), '-e', code)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
