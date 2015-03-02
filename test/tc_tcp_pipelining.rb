# --
# Copyright 2007 Nominet UK
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
require 'rubydns'

# TCPPipeliningHandler accepts new tcp connection and reads data from the sockets until
# either the client closes the connection, @max_request_per_connection is reached
# or @timeout is attained
class TCPPipeliningHandler < RubyDNS::GenericHandler
  DEFAULT_MAX_REQUESTS = 4
  DEFAULT_TIMEOUT = 3.0

  def initialize(server, host, port, max_request = DEFAULT_MAX_REQUESTS, timeout = DEFAULT_TIMEOUT)
    super(server)
    @timeout = timeout
    @max_request_per_connection = max_request
    @socket = TCPServer.new(host, port)

    async.run
  end

  finalizer :finalize

  def finalize
    @socket.close if @socket
  end

  def run
    loop { async.handle_connection(@socket.accept) }
  end

  def handle_connection(socket)
    _, remote_port, remote_host = socket.peeraddr
    options = { peer: remote_host }

    @logger.debug "New connection"
    TCPPipeliningServer.stats.increment_connection

    timeout = @timeout
    msg_count = 0

    loop do
      start_time = Time.now
      @logger.debug "Waiting for #{timeout} max"
      sockets = ::IO.select([socket], nil , nil, timeout)
      duration = Time.now - start_time

      @logger.debug "Slept for #{duration}"

      timeout -= duration

      if sockets
        input_data = RubyDNS::StreamTransport.read_chunk(socket)
        response = process_query(input_data, options)
        RubyDNS::StreamTransport.write_message(socket, response)

        msg_count += 1
        @logger.debug "Responded to message #{msg_count}"
      else
        @logger.debug "TCP session timeout!"
        TCPPipeliningServer.stats.increment_timeout
        break
      end

      if msg_count >= @max_request_per_connection
        @logger.debug "Max number of requests attained (#{@max_request_per_connection})"
        TCPPipeliningServer.stats.increment_max
        break
      end

    end
  rescue EOFError => error
    @logger.warn "TCP session ended (closed by client)"
  rescue DecodeError
    @logger.warn "Could not decode incoming TCP data!"
  ensure
    socket.close
  end
end

# Stats collects statistics from our tcp handler
class Stats
  def initialize()
    @mutex = Mutex.new
    @accept_count = 0
    @timeout_count = 0
    @max_count = 0
  end

  def increment_max;        @mutex.synchronize { @max_count     += 1 } end
  def increment_timeout;    @mutex.synchronize { @timeout_count += 1 } end
  def increment_connection; @mutex.synchronize { @accept_count  += 1 } end

  def accept_count
    @mutex.synchronize { @accept_count  }
  end

  def timeout_count
    @mutex.synchronize { @timeout_count }
  end

  def max_count
    @mutex.synchronize { @max_count }
  end

end

# The TCPPipeliningServer links our TCPPipeliningHandler on
# the loopback interface
class TCPPipeliningServer < RubyDNS::RuleBasedServer
  PORT = 53937
  IP   = "127.0.0.1"

  @@stats = Stats.new

  def self.stats
    @@stats
  end

  def run
    fire(:setup)

    link TCPPipeliningHandler.new(self, IP, PORT)

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
      #default Celluloid log outputs to console. Use Dnsruby.log instead
      Celluloid.logger = Dnsruby.log
      @initialized = true
      @query_id = 0
    end
  end

  def initialize(arg)
    super(arg)
    self.class.init
  end

  def setup
    # @@celluloid_initialized ||= init_celluloid
    @@upstream ||= RubyDNS::Resolver.new([[:udp, "193.0.14.129", 53], [:tcp, "193.0.14.129", 53]])

    # Instantiate a new server that uses our tcp pipelining handler
    # For each query the server sends the query upstream (193.0.14.129)
    options = {}
    options[:server_class] = TCPPipeliningServer
    options[:asynchronous] = true

    @@supervisor ||= RubyDNS::run_server(options) do
      otherwise do |transaction|
        transaction.passthrough!(@@upstream)
      end
    end

    # Instantiate our resolver. The resolver will use the same pipeline as much as possible.
    # If a timeout occurs or max_request_per_connection a new connection should be initiated
    @@resolver ||= Dnsruby::Resolver.new(:use_tcp => true,
                                        :do_caching => false,
                                        :tcp_pipelining => true,
                                        :dnssec => false,
                                        :packet_timeout => 10,
                                        :nameserver => TCPPipeliningServer::IP,
                                        :port => TCPPipeliningServer::PORT)
  end

  # Send a x number of queries asynchronously to our resolver
  def send_async_messages(number_of_messages, queue, wait=nil)
    number_of_messages.times do
      message = Dnsruby::Message.new(QUERIES[self.class.query_id % QUERIES.count])
      # self.class.query_id identifies our query, must be different for each message
      @@resolver.send_async(message, queue, self.class.query_id)
      self.class.query_id += 1
      sleep wait if wait
    end
  end

  # Verify x responses with no exception
  def verify_responses(number_of_messages, queue)
    number_of_messages.times do
      response_id, response, exception = queue.pop
      assert_equal(nil, exception)
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
    verify_responses(3,query_queue)

    assert_equal(accept_count + 1, TCPPipeliningServer.stats.accept_count)

    # Wait for the timeout to occur (5s) and check timeout_count
    sleep TCPPipeliningHandler::DEFAULT_TIMEOUT + 0.5

    assert_equal(timeout_count + 1, TCPPipeliningServer.stats.timeout_count)

    # Initiate another 3 queries, check accept_count and timeout_count
    send_async_messages(3, query_queue)
    verify_responses(3,query_queue)

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
    send_async_messages(3, query_queue, TCPPipeliningHandler::DEFAULT_TIMEOUT/2.0 + 0.5)
    verify_responses(3,query_queue)

    assert_equal(accept_count + 2, TCPPipeliningServer.stats.accept_count)

    sleep TCPPipeliningHandler::DEFAULT_TIMEOUT + 0.5

    assert_equal(timeout_count + 2,TCPPipeliningServer.stats.timeout_count)
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
      response_id, response, exception = query_queue.pop
      if step < TCPPipeliningHandler::DEFAULT_MAX_REQUESTS
        assert_equal(exception, nil)
        assert(response.is_a?(Dnsruby::Message))
      else
        assert_equal(Dnsruby::SocketEofResolvError, exception.class)
        assert_equal(response, nil)
      end
      step += 1
    end

    assert_equal(accept_count + 1, TCPPipeliningServer.stats.accept_count)
    assert_equal(timeout_count,    TCPPipeliningServer.stats.timeout_count)
    assert_equal(max_count + 1,    TCPPipeliningServer.stats.max_count)
  end
end
