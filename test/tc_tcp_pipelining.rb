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
require_relative 'test_dnsserver'

# The TCPPipeliningServer links our TCPPipeliningHandler on
# the loopback interface.
class TCPPipeliningServer < RubyDNS::RuleBasedServer

  PORT = 53937
  IP   = '127.0.0.1'

  @@stats = Stats.new

  def self.stats
    @@stats
  end

  def run
    fire(:setup)

    link TCPPipeliningHandler.new(self,
                                  IP,
                                  PORT,
                                  TCPPipeliningHandler::DEFAULT_MAX_REQUESTS,
                                  TCPPipeliningHandler::DEFAULT_TIMEOUT)

    fire(:start)
  end
end

class TestTCPPipelining < Minitest::Test

  QUERIES = %w(psi.net  passport.net  verisigninc.com  google.com  yahoo.com  apple.com)

  class << self
    attr_accessor :query_id
  end

  def self.init
    unless @initialized
      Celluloid.boot
      # By default, Celluloid logs output to console. Use Dnsruby.log instead
      Celluloid.logger = Dnsruby.log
      @initialized = true
      @query_id = 0
    end
  end

  def setup
    self.class.init
    @@upstream ||= RubyDNS::Resolver.new([
        [:udp, '193.0.14.129', 53],
        [:tcp, '193.0.14.129', 53]])

    # Instantiate a new server that uses our tcp pipelining handler
    # For each query the server sends the query upstream (193.0.14.129)
    options = {
        server_class: TCPPipeliningServer,
        asynchronous: true
    }

    @@supervisor ||= RubyDNS::run_server(options) do
      otherwise do |transaction|
        transaction.passthrough!(@@upstream)
      end
    end

    # Instantiate our resolver. The resolver will use the same pipeline as much as possible.
    # If a timeout occurs or max_request_per_connection a new connection should be initiated
    @@resolver ||= Dnsruby::Resolver.new(
        use_tcp:                    true,
        do_caching:                 false,
        tcp_pipelining:             true,
        dnssec:                     false,
        packet_timeout:             10,
        tcp_pipelining_max_queries: 10,
        nameserver:                 TCPPipeliningServer::IP,
        port:                       TCPPipeliningServer::PORT)
  end

  # Send a x number of queries asynchronously to our resolver

  # NOTE: Since durations can be in different units, this name is clearer.

  def send_async_messages(number_of_messages, queue, wait_seconds = 0)
    query_cycler = QUERIES.cycle
    number_of_messages.times do
      message = Dnsruby::Message.new(query_cycler.next)
      # self.class.query_id identifies our query, must be different for each message
      @@resolver.send_async(message, queue, self.class.query_id)
      self.class.query_id += 1

      # Note: For 0, we don't sleep at all instead of sleeping 0 since sleeping 0
      # involves yielding the CPU.
      sleep wait_seconds unless wait_seconds == 0
    end
  end

  # Verify x responses with no exception
  def verify_responses(number_of_messages, queue)
    number_of_messages.times do
      # NOTE: Leading '_' indicates it's unused.
      _response_id, response, exception = queue.pop
      assert_nil(exception)
      assert(response.is_a?(Dnsruby::Message))
    end
  end

  # This test initiates multiple asynchronous requests and verifies they go on the same tcp
  # pipeline or a new one depending on timeouts
  def test_TCP_pipelining_timeout
    accept_count  = TCPPipeliningServer.stats.accept_count
    timeout_count = TCPPipeliningServer.stats.timeout_count

    # This is the main queue used to communicate between Dnsruby in async mode and the client
    query_queue = Queue.new

    # Test basic pipelining. All request should go on the same tcp connection.
    # TCPPipeliningServer.stats.accept_count should be 1.
    send_async_messages(3, query_queue)
    verify_responses(3, query_queue)

    assert_equal(accept_count + 1, TCPPipeliningServer.stats.accept_count)

    # Wait for the timeout to occur (5s) and check timeout_count
    sleep TCPPipeliningHandler::DEFAULT_TIMEOUT + 0.5

    assert_equal(timeout_count + 1, TCPPipeliningServer.stats.timeout_count)

    # Initiate another 3 queries, check accept_count and timeout_count
    send_async_messages(3, query_queue)
    verify_responses(3, query_queue)

    assert_equal(accept_count + 2, TCPPipeliningServer.stats.accept_count)

    # Wait for the timeout to occur and check timeout_count
    sleep TCPPipeliningHandler::DEFAULT_TIMEOUT + 0.5

    assert_equal(timeout_count + 2, TCPPipeliningServer.stats.timeout_count)
  end

  # Test timeout occurs and new connection is initiated inbetween 2 sends
  def test_TCP_pipelining_timeout_in_send
    accept_count  = TCPPipeliningServer.stats.accept_count
    timeout_count = TCPPipeliningServer.stats.timeout_count

    query_queue = Queue.new

    # Initiate another 3 queries but wait 3s after each query.
    # Check accept_count. Wait for timeout and verify we got 2 additional timeouts.
    send_async_messages(3, query_queue, TCPPipeliningHandler::DEFAULT_TIMEOUT / 2.0 + 0.5)
    verify_responses(3, query_queue)

    assert_equal(accept_count + 2, TCPPipeliningServer.stats.accept_count)

    sleep TCPPipeliningHandler::DEFAULT_TIMEOUT + 0.5

    assert_equal(timeout_count + 2, TCPPipeliningServer.stats.timeout_count)
  end

  # Test that we get a SocketEofResolvError if the servers closes the socket before
  # all queries are answered
  def test_TCP_pipelining_socket_eof
    accept_count  = TCPPipeliningServer.stats.accept_count
    timeout_count = TCPPipeliningServer.stats.timeout_count
    max_count     = TCPPipeliningServer.stats.max_count

    query_queue = Queue.new

    # Issue 6 queries. Only 4 should be replied since max_request_per_connection = 4
    # Verify we get Dnsruby::SocketEofResolvError on the last 2.
    # Verify we got max_count was incremented
    send_async_messages(6, query_queue)

    step = 0
    6.times do
      _response_id, response, exception = query_queue.pop
      if step < TCPPipeliningHandler::DEFAULT_MAX_REQUESTS
        assert_nil(exception)
        assert(response.is_a?(Dnsruby::Message))
      else
        assert_equal(Dnsruby::SocketEofResolvError, exception.class)
        assert_nil(response)
      end
      step += 1
    end

    assert_equal(accept_count + 1, TCPPipeliningServer.stats.accept_count)
    assert_equal(timeout_count,    TCPPipeliningServer.stats.timeout_count)
    assert_equal(max_count + 1,    TCPPipeliningServer.stats.max_count)
  end
end
