# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'soak_server'

# Defaults preserve the historical workload: 81,512 queries in eight cases.
# Increase the counts for a longer run. SOAK_TIMEOUT bounds each complete case.
class TestSingleResolverSoak < Minitest::Test
  SINGLE_RESOLVER_QUERY_TIMES = Integer(ENV.fetch('SOAK_ASYNC_ROUNDS', '63'))
  THREAD_COUNT = Integer(ENV.fetch('SOAK_THREADS', RUBY_PLATFORM.include?('java') ? '50' : '250'))
  ROUNDS = Integer(ENV.fetch('SOAK_ROUNDS', '40'))
  CASE_TIMEOUT = Float(ENV.fetch('SOAK_TIMEOUT', '120'))

  def setup
    @resolvers = []
    @workers = []
    @queues = []
    raise ArgumentError, 'Soak counts and timeout must be positive' unless
      [SINGLE_RESOLVER_QUERY_TIMES, THREAD_COUNT, ROUNDS, CASE_TIMEOUT].all?(&:positive?)
    @server = SoakServer.new
  end

  def teardown
    @workers.each { |worker| worker.kill if worker.alive? }
    @workers.each(&:join)
    @resolvers.each(&:close)
    @server&.stop
    @queues.each { |queue| assert(queue.empty?, 'Unexpected extra/duplicate completion') }
  end

  def test_many_asynchronous_queries_one_single_resolver
    run_many_asynch_queries_test_single_res(1)
  end

  def test_many_asynchronous_queries_many_single_resolvers
    run_many_asynch_queries_test_single_res(50)
  end

  def test_many_asynchronous_queries_one_single_resolver_tcp
    run_many_asynch_queries_test_single_res(1, true)
  end

  def test_many_asynchronous_queries_many_single_resolvers_tcp
    run_many_asynch_queries_test_single_res(50, true)
  end

  def test_many_asynchronous_queries_one_single_resolver_tcp_pipelining
    run_many_asynch_queries_test_single_res(1, true, true)
  end

  def test_many_asynchronous_queries_many_single_resolvers_tcp_pipelining
    run_many_asynch_queries_test_single_res(50, true, true)
  end

  def run_many_asynch_queries_test_single_res(num_resolvers, tcp = false, pipelining = false)
    queue = tracked_queue
    resolvers = Array.new(num_resolvers) { create_resolver(tcp, pipelining) }
    count = SINGLE_RESOLVER_QUERY_TIMES * SoakServer::TYPES.length
    timed_case(count) do
      count.times { |id| resolvers[id % num_resolvers].send_async(request_for(id), queue, id) }
      receive_all(queue, count)
    end
  end

  def test_many_threads_on_one_single_resolver_synchronous
    resolver = create_resolver
    run_threaded_queries do |id, _queue|
      [id, resolver.query(query_name(id), query_type(id)), nil]
    end
  end

  def test_many_threads_on_many_single_resolvers
    resolvers = Array.new(THREAD_COUNT) { create_resolver }
    run_threaded_queries do |id, queue|
      resolver = resolvers[id / (ROUNDS * SoakServer::TYPES.length)]
      resolver.send_async(request_for(id), queue, id)
      completion = queue.pop
      raise "Wrong completion ID: expected #{id}, got #{completion[0].inspect}" unless completion[0] == id
      completion
    end
  end

  private

  def tracked_queue
    queue = Queue.new
    @queues << queue
    queue
  end

  def create_resolver(tcp = false, pipelining = false)
    resolver = Dnsruby::SingleResolver.new(server: SoakServer::IP,
      port: @server.port, do_caching: false, do_validation: false,
      dnssec: false, use_tcp: tcp, packet_timeout: 10,
      tcp_pipelining: pipelining, tcp_pipelining_max_queries: 5)
    assert_equal(pipelining, resolver.single_resolvers.first.tcp_pipelining)
    @resolvers << resolver
    resolver
  end

  def query_name(id)
    "q#{id}.soak.test."
  end

  def query_type(id)
    SoakServer::TYPES[id % SoakServer::TYPES.length]
  end

  def request_for(id)
    request = Dnsruby::Message.new(query_name(id), query_type(id))
    request.do_caching = false
    request.do_validation = false
    request
  end

  def timed_case(count)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Timeout.timeout(CASE_TIMEOUT) { yield }
    @server.check!
    puts "Verified #{count} responses in #{(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3)}s"
  rescue Timeout::Error
    @server.check!
    flunk "Soak case exceeded #{CASE_TIMEOUT}s; a query or worker did not complete"
  end

  def run_threaded_queries
    per_thread = ROUNDS * SoakServer::TYPES.length
    completions = tracked_queue
    queues = Array.new(THREAD_COUNT) { tracked_queue }
    timed_case(THREAD_COUNT * per_thread) do
      THREAD_COUNT.times do |worker_id|
        @workers << Thread.new do
          Thread.current.abort_on_exception = false
          Thread.current.report_on_exception = false
          begin
            per_thread.times do |iteration|
              id = worker_id * per_thread + iteration
              completions << yield(id, queues[worker_id])
            end
          rescue StandardError => error
            completions << [nil, nil, error]
          end
        end
      end
      receive_all(completions, THREAD_COUNT * per_thread)
      @workers.each(&:join)
    end
  end

  def receive_all(queue, count)
    seen = {}
    count.times do
      id, response, error = queue.pop
      assert_nil(error, "Query #{id.inspect}: #{error.class}: #{error}")
      assert(id.is_a?(Integer) && id >= 0 && id < count, "Unexpected query ID #{id.inspect}")
      refute(seen.key?(id), "Duplicate completion #{id}")
      seen[id] = true
      assert_instance_of(Dnsruby::Message, response)
      assert_equal('NOERROR', response.rcode.to_s)
      assert_equal(1, response.question.length)
      question = response.question.first
      assert_equal([query_name(id), query_type(id), 'IN'],
        [question.qname.to_s(true), question.qtype.to_s, question.qclass.to_s])
      assert_equal(1, response.answer.length)
      answer = response.answer.first
      assert_equal([query_name(id), query_type(id), 'IN'],
        [answer.name.to_s(true), answer.type.to_s, answer.klass.to_s])
      case query_type(id)
      when 'A' then assert_equal(SoakServer::ADDRESS, answer.address.to_s)
      when 'MX' then assert_equal([10, SoakServer::EXCHANGE], [answer.preference, answer.exchange.to_s(true)])
      when 'CNAME' then assert_equal(SoakServer::ALIAS, answer.domainname.to_s(true))
      when 'TXT' then assert_equal([SoakServer::TEXT], answer.strings)
      end
    end
    assert_equal(count, seen.length)
    assert(queue.empty?, 'Extra/duplicate completion after the expected count')
  end
end
