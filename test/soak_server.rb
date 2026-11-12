# frozen_string_literal: true

require 'socket'
require 'resolv'
require 'thread'
require 'timeout'

# Local, independent DNS peer. No public DNS traffic, fixed port, privileged
# service, RubyDNS API or subprocess is required.
class SoakServer
  IP = '127.0.0.1'
  ADDRESS = '192.0.2.155'
  EXCHANGE = 'mail.soak.test.'
  ALIAS = 'alias.soak.test.'
  TEXT = 'dnsruby-soak'
  TYPES = %w[A MX CNAME TXT].freeze

  attr_reader :port

  def initialize
    @listener = TCPServer.new(IP, 0)
    @port = @listener.addr[1]
    @udp = UDPSocket.new
    @udp.bind(IP, @port)
    @wake_read, @wake_write = IO.pipe
    @clients = {}
    ready = Queue.new
    @worker = Thread.new do
      Thread.current.abort_on_exception = false
      Thread.current.report_on_exception = false
      begin
        ready << true
        run
      rescue StandardError => error
        @error = error
      end
    end
    Timeout.timeout(5) { ready.pop }
    check!
  rescue Exception
    if @worker
      @worker.kill
      @worker.join
    end
    [@listener, @udp, @wake_read, @wake_write].compact.each { |io| io.close unless io.closed? }
    raise
  end

  def check!
    raise @error if @error
  end

  def stop
    @wake_write.close unless @wake_write.closed?
    unless @worker.join(5)
      @worker.kill
      @worker.join
      raise 'Soak server did not stop within five seconds'
    end
    check!
  end

  private

  def run
    loop do
      writers = @clients.select { |_, buffers| !buffers[:output].empty? }.keys
      readable, writable = IO.select([@wake_read, @listener, @udp] + @clients.keys, writers)
      break if readable.include?(@wake_read)
      readable.each do |socket|
        if socket == @listener
          accept
        elsif socket == @udp
          receive_udp
        else
          receive_tcp(socket)
        end
      end
      writable.each { |socket| write_tcp(socket) if @clients.key?(socket) }
    end
  ensure
    @clients.keys.each { |socket| disconnect(socket) }
    [@listener, @udp, @wake_read].each { |io| io.close unless io.closed? }
  end

  def accept
    socket = @listener.accept_nonblock(exception: false)
    return if socket == :wait_readable
    socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    @clients[socket] = { input: ''.b, output: ''.b }
  end

  def receive_udp
    packet = @udp.recvfrom_nonblock(65_535, exception: false)
    return if packet == :wait_readable
    bytes, peer = packet
    @udp.send(answer(bytes), 0, peer[3], peer[1])
  end

  def receive_tcp(socket)
    bytes = socket.read_nonblock(65_535, exception: false)
    return if bytes == :wait_readable
    return disconnect(socket) if bytes.nil?
    buffers = @clients.fetch(socket)
    buffers[:input] << bytes
    while buffers[:input].bytesize >= 2
      length = buffers[:input].unpack1('n')
      break if buffers[:input].bytesize < length + 2
      buffers[:input].slice!(0, 2)
      response = answer(buffers[:input].slice!(0, length))
      buffers[:output] << [response.bytesize].pack('n') << response
    end
    write_tcp(socket)
  rescue Errno::ECONNRESET, Errno::EPIPE
    disconnect(socket)
  end

  def write_tcp(socket)
    output = @clients.fetch(socket)[:output]
    return if output.empty?
    written = socket.write_nonblock(output, exception: false)
    output.slice!(0, written) if written.is_a?(Integer)
  rescue Errno::ECONNRESET, Errno::EPIPE
    disconnect(socket)
  end

  def disconnect(socket)
    @clients.delete(socket)
    socket.close unless socket.closed?
  end

  def answer(bytes)
    query = ::Resolv::DNS::Message.decode(bytes)
    response = ::Resolv::DNS::Message.new(query.id)
    response.qr = 1
    response.aa = 1
    response.rd = query.rd
    response.ra = 1
    query.each_question do |name, type|
      raise "Unsupported soak class: #{type}" unless type::ClassValue == 1
      resource = case type::TypeValue
                 when 1 then type.new(ADDRESS)
                 when 15 then type.new(10, ::Resolv::DNS::Name.create(EXCHANGE))
                 when 5 then type.new(::Resolv::DNS::Name.create(ALIAS))
                 when 16 then type.new(TEXT)
                 else raise "Unsupported soak question: #{type}"
                 end
      response.add_question(name, type)
      response.add_answer(name, 60, resource)
    end
    response.encode
  end
end
