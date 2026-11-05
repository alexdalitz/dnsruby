# --
# Copyright 2015 Verisign
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'
require_relative 'tcp_pipelining_server'
require 'timeout'

class TestTCPPipelining < Minitest::Test
  WAIT_TIMEOUT = 5

  def setup
    @server = PipelineTest::Server.new
    @query_id = 0
    @resolver = Dnsruby::Resolver.new(
      use_tcp: true,
      do_caching: false,
      tcp_pipelining: true,
      dnssec: false,
      retry_times: 1,
      packet_timeout: WAIT_TIMEOUT,
      query_timeout: WAIT_TIMEOUT,
      tcp_pipelining_max_queries: 10,
      nameserver: PipelineTest::Server::IP,
      port: @server.port
    )
  end

  def teardown
    @resolver.close if @resolver
  ensure
    @server.stop if @server
    wait_for_client_close if @resolver
  end

  def send_async_messages(count, queue)
    Array.new(count) do
      id = @query_id
      @query_id += 1
      message = Dnsruby::Message.new("pipeline-#{id}.example.invalid")
      message.do_caching = false
      message.do_validation = false
      @resolver.send_async(message, queue, id)
      id
    end
  end

  def responses_for(ids, queue)
    responses = Timeout.timeout(WAIT_TIMEOUT + 1) do
      Array.new(ids.length) { queue.pop }
    end
    @server.stats # Propagate any exception in the server thread.
    assert_equal ids.sort, responses.map(&:first).sort
    responses.sort_by(&:first)
  end

  def verify_responses(ids, queue)
    responses_for(ids, queue).each do |id, response, exception|
      assert_nil exception
      assert_instance_of Dnsruby::Message, response
      assert_equal "pipeline-#{id}.example.invalid", response.question.first.qname.to_s
      assert_equal PipelineTest::Server::ANSWER, response.answer.first.address.to_s
    end
  end

  def wait_for_timeouts(count)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + WAIT_TIMEOUT
    until @server.stats[:timeouts] == count && @server.stats[:connections].zero?
      flunk "Timed out waiting for #{count} connection expiry/expiries: #{@server.stats}" if
        Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.01
    end
    # A server-side close does not mean the client's select thread has seen
    # the FIN yet. Reconnect only after it has processed EOF.
    wait_for_client_close
  end

  def wait_for_client_close
    sender = @resolver.single_resolvers.first
    socket = sender.instance_variable_get(:@pipeline_socket)
    Timeout.timeout(WAIT_TIMEOUT) do
      sleep 0.01 while socket && !socket.closed?
    end
  end

  # Multiple outstanding queries share one TCP connection; after it expires,
  # the next batch must use a new connection.
  def test_TCP_pipelining_timeout
    queue = Queue.new
    verify_responses(send_async_messages(3, queue), queue)
    assert_equal 1, @server.stats[:accepts]
    wait_for_timeouts(1)

    verify_responses(send_async_messages(3, queue), queue)
    assert_equal 2, @server.stats[:accepts]
    wait_for_timeouts(2)
    assert_equal 2, @server.stats[:timeouts]
  end

  # The server closes the pipeline between sends, and a single subsequent
  # query must reconnect successfully.
  def test_TCP_pipelining_timeout_in_send
    queue = Queue.new
    verify_responses(send_async_messages(2, queue), queue)
    assert_equal 1, @server.stats[:accepts]
    wait_for_timeouts(1)

    verify_responses(send_async_messages(1, queue), queue)
    assert_equal 2, @server.stats[:accepts]
    wait_for_timeouts(2)
    assert_equal 2, @server.stats[:timeouts]
  end

  # The peer answers only four of six outstanding queries before closing.
  # Each unanswered query must receive EOF, rather than a resolver timeout.
  def test_TCP_pipelining_socket_eof
    queue = Queue.new
    ids = send_async_messages(6, queue)
    responses_for(ids, queue).each do |id, response, exception|
      if id < PipelineTest::Server::MAX_REQUESTS
        assert_nil exception
        assert_instance_of Dnsruby::Message, response
        assert_equal "pipeline-#{id}.example.invalid", response.question.first.qname.to_s
        assert_equal PipelineTest::Server::ANSWER, response.answer.first.address.to_s
      else
        assert_instance_of Dnsruby::SocketEofResolvError, exception
        assert_nil response
      end
    end
    wait_for_timeouts(1)
    assert_equal 1, @server.stats[:accepts]
    assert_equal 1, @server.stats[:limits]
  end
end
