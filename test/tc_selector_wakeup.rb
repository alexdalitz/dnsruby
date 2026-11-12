require_relative 'spec_helper'
require 'open3'
require 'rbconfig'

class TestSelectorWakeup < Minitest::Test
  def test_a_saturated_native_notification_socket_cannot_block_the_selector
    script = <<~'RUBY'
      require 'dnsruby'
      require 'fcntl'
      require 'timeout'
      selector = Dnsruby::SelectThread.send(:allocate)
      writer, reader = selector.get_socket_pair
      Dnsruby::SelectThread.class_variable_set(:@@wakeup_sockets, [writer, reader])
      writer.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 1024)
      reader.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 1024)
      flags = writer.fcntl(Fcntl::F_GETFL, 0)
      begin
        # Fill both kernel buffers; allow already-enqueued data to move across
        # the connection, then refill until no further transfer creates space.
        20.times do
          begin
            loop { writer.write_nonblock('x' * 4096) }
          rescue IO::WaitWritable
          end
          sleep 0.005
        end
        # Filling through write_nonblock can change the descriptor flags. Restore
        # blocking mode so the old Socket#send implementation really would block.
        writer.fcntl(Fcntl::F_SETFL, flags & ~Fcntl::O_NONBLOCK)
        Timeout.timeout(1) { 1000.times { selector.wake_up_select_thread } }
        raise 'notification disappeared' unless IO.select([reader], nil, nil, 0)
      ensure
        writer.close
        reader.close
      end
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I',
      File.expand_path('../lib', __dir__), '-e', script)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end
end
