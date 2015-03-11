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

require 'rubydns'
require 'nio'
require 'socket'

# TCPPipeliningHandler accepts new tcp connection and reads data from the sockets until
# either the client closes the connection, @max_request_per_connection is reached
# or @timeout is attained

class NioTcpPipeliningHandler < RubyDNS::GenericHandler
  DEFAULT_MAX_REQUESTS = 4

  # TODO Add timeout
  def initialize(server, host, port, max_request = DEFAULT_MAX_REQUESTS)
    super(server)
    @max_request_per_connection = max_request
    @socket = TCPServer.new(host, port)
    @count = {}

    @selector = NIO::Selector.new
    monitor = @selector.register(@socket, :r)
    monitor.value = proc { accept }

    async.run
  end

  finalizer :finalize

  def finalize
    @socket.close if @socket
    @selector.close
    @rcv_thread.join
  end

  def run
    @logger.debug "Running selector thread"
    selector_thread
  end

  def accept
    handle_connection(@socket.accept)
  end

  def process_socket(socket)
    @logger.debug "Processing socket"
    _, remote_port, remote_host = socket.peeraddr
    options = { peer: remote_host }

    input_data = RubyDNS::StreamTransport.read_chunk(socket)
    response = process_query(input_data, options)
    RubyDNS::StreamTransport.write_message(socket, response)

    @count[socket] ||= 0
    @count[socket]  += 1

    if @count[socket] >= @max_request_per_connection
      _, port, host = socket.peeraddr
      @logger.debug("*** max request for #{host}:#{port}")
      remove(socket)
    end
  rescue EOFError
      _, port, host = socket.peeraddr
    @logger.debug("*** #{host}:#{port} disconnected")

    remove(socket)
  end

  def remove(socket)
    @logger.debug("Removing soket from selector")
    socket.close rescue nil
    @selector.deregister(socket)
    @count.delete(socket)
  end

  def selector_thread
    @rcv_thread = Thread.new do
      loop do
        begin
          @selector.select { |monitor| monitor.value.call(monitor) }
          if @selector.closed?
            break
          end
        rescue Exception => e
          @logger.log.debug(e)
        end
      end
    end
  end

  def handle_connection(socket)
    _, remote_port, remote_host = socket.peeraddr
    options = { peer: remote_host }

    @logger.debug "New connection"
    @server.class.stats.increment_connection

    @logger.debug "Add socket to @selector"
    monitor = @selector.register(socket, :r)
    monitor.value = proc { process_socket(socket) }
  end
end

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
    @server.class.stats.increment_connection

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
        @server.class.stats.increment_timeout
        break
      end

      if msg_count >= @max_request_per_connection
        @logger.debug "Max number of requests attained (#{@max_request_per_connection})"
        @server.class.stats.increment_max
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
