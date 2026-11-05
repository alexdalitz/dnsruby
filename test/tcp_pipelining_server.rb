# frozen_string_literal: true

require 'socket'
require 'resolv'
require 'thread'

module PipelineTest
  # A deliberately small DNS-over-TCP peer. Using the stdlib codec keeps these
  # transport tests independent of both Dnsruby's codec and RubyDNS's server API.
  class Server
    IP = '127.0.0.1'
    ANSWER = '192.0.2.155'
    MAX_REQUESTS = 4
    IDLE_TIMEOUT = 1

    attr_reader :port

    def initialize
      @listener = TCPServer.new(IP, 0)
      @port = @listener.addr[1]
      @wake_read, @wake_write = IO.pipe
      @clients = {}
      @mutex = Mutex.new
      @stats = { accepts: 0, connections: 0, timeouts: 0, limits: 0 }
      @worker = Thread.new do
        Thread.current.abort_on_exception = false
        Thread.current.report_on_exception = false
        begin
          run
        rescue StandardError => error
          # Other suites enable Thread.abort_on_exception globally. Capture
          # errors here so those settings cannot abort the test process.
          @error = error
        end
      end
    end

    def stats
      # Surface fixture failures in the test thread instead of hiding them
      # behind a resolver timeout or aborting the entire suite.
      @worker.value unless @worker.alive?
      raise @error if @error
      @mutex.synchronize { @stats.dup }
    end

    def stop
      @wake_write.close unless @wake_write.closed?
      unless @worker.join(5)
        @worker.kill
        @worker.join
        raise 'TCP pipelining server did not stop'
      end
      @worker.value
      raise @error if @error
    end

    private

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def run
      loop do
        deadline = @clients.values.map { |client| client[:deadline] }.min
        wait = deadline ? [deadline - now, 0].max : nil
        readable = IO.select([@wake_read, @listener] + @clients.keys, nil, nil, wait)
        if readable
          break if readable.first.include?(@wake_read)
          readable.first.each do |socket|
            socket == @listener ? accept : receive(socket)
          end
        end
        @clients.keys.each do |socket|
          disconnect(socket, :timeouts) if @clients.fetch(socket)[:deadline] <= now
        end
      end
    ensure
      @clients.keys.each { |socket| disconnect(socket) }
      @listener.close
      @wake_read.close
    end

    def accept
      socket = @listener.accept_nonblock(exception: false)
      return if socket == :wait_readable

      @clients[socket] = { buffer: ''.b, requests: 0, deadline: now + IDLE_TIMEOUT }
      @mutex.synchronize do
        @stats[:accepts] += 1
        @stats[:connections] += 1
      end
    end

    def receive(socket)
      data = socket.read_nonblock(65_535, exception: false)
      return if data == :wait_readable
      return disconnect(socket) if data.nil?

      client = @clients.fetch(socket)
      client[:deadline] = now + IDLE_TIMEOUT
      client[:buffer] << data

      # TCP can split a length prefix or combine several DNS messages in a read.
      while client[:buffer].bytesize >= 2
        length = client[:buffer].unpack1('n')
        break if client[:buffer].bytesize < length + 2

        client[:buffer].slice!(0, 2)
        query = client[:buffer].slice!(0, length)
        client[:requests] += 1
        if client[:requests] <= MAX_REQUESTS
          response = answer(query)
          socket.write([response.bytesize].pack('n') + response)
          if client[:requests] == MAX_REQUESTS
            @mutex.synchronize { @stats[:limits] += 1 }
          end
        end
        # Drain excess requests before closing on timeout. Closing with unread
        # input can cause a TCP reset instead of the EOF being tested.
      end
    rescue Errno::ECONNRESET, Errno::EPIPE
      disconnect(socket)
    end

    def answer(bytes)
      query = ::Resolv::DNS::Message.decode(bytes)
      response = ::Resolv::DNS::Message.new(query.id)
      response.qr = 1
      response.aa = 1
      response.rd = query.rd
      response.ra = 1
      query.each_question do |name, type|
        response.add_question(name, type)
        response.add_answer(name, 60, ::Resolv::DNS::Resource::IN::A.new(ANSWER))
      end
      response.encode
    end

    def disconnect(socket, reason = nil)
      return unless @clients.delete(socket)

      socket.close
      @mutex.synchronize do
        @stats[:connections] -= 1
        @stats[reason] += 1 if reason
      end
    end
  end
end
