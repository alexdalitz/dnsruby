require 'dnsruby/transport_clock'

module Dnsruby
  # A deadline and cancellation signal shared by related lookups. This carries
  # no DNSSEC policy; the caller decides how a stopped operation is reported.
  class QueryControl # :nodoc: all
    # These must bypass ordinary lookup and verification fallback handlers.
    class Stopped < StandardError; end
    class Cancelled < Stopped; end
    class DeadlineExceeded < Stopped; end

    # A normal Queue whose producers also wake deadline/cancellation waiters.
    # Keeping the notification alongside push avoids polling and works on Ruby
    # versions which do not support Queue#pop(timeout:).
    class Queue < ::Queue
      def initialize
        super
        @wait_mutex = Mutex.new
        @condition = ConditionVariable.new
      end

      def push(value)
        @wait_mutex.synchronize do
          super
          @condition.broadcast
        end
        self
      end
      alias << push
      alias enq push

      def close
        @wait_mutex.synchronize do
          super
          @condition.broadcast
        end
        self
      end

      def wake_waiters
        @wait_mutex.synchronize { @condition.broadcast }
      end

      def pop_with_control(control)
        control.add_waiter(self)
        @wait_mutex.synchronize do
          loop do
            control.check!
            begin
              return pop(true)
            rescue ThreadError
              return nil if closed?
              remaining = control.deadline && control.deadline - TransportClock.now
              @condition.wait(@wait_mutex, remaining && [remaining, 0].max)
            end
          end
        end
      ensure
        control.remove_waiter(self)
      end
    end

    attr_reader :deadline

    def self.current
      Thread.current[:dnsruby_query_control]
    end

    def self.with(control)
      previous = current
      Thread.current[:dnsruby_query_control] = control
      control.check!
      result = yield
      control.check!
      result
    ensure
      Thread.current[:dnsruby_query_control] = previous
    end

    def initialize(deadline: nil, parent: nil)
      @parent = parent
      @deadline = [deadline, parent&.deadline].compact.min
      @cancelled = false
      @mutex = Mutex.new
      @waiters = []
    end

    def cancel
      waiters = @mutex.synchronize do
        @cancelled = true
        @waiters.dup
      end
      waiters.each(&:wake_waiters)
      true
    end

    def check!
      @parent&.check!
      raise Cancelled, 'Query cancelled' if @mutex.synchronize { @cancelled }
      raise DeadlineExceeded, 'Query deadline exceeded' if @deadline && TransportClock.now >= @deadline
      true
    end

    def add_waiter(queue)
      @parent&.add_waiter(queue)
      @mutex.synchronize { @waiters << queue }
    end

    def remove_waiter(queue)
      @mutex.synchronize do
        index = @waiters.index(queue)
        @waiters.delete_at(index) if index
      end
      @parent&.remove_waiter(queue)
    end

    def pop(queue)
      return queue.pop_with_control(self) if queue.is_a?(Queue)

      # Preserve support for caller-supplied ordinary queues, whose producers
      # cannot notify this control. Internal lookups use the queue above.
      loop do
        check!
        begin
          return queue.pop(true)
        rescue ThreadError
          sleep(@deadline ? (@deadline - TransportClock.now).clamp(0, 0.01) : 0.01)
        end
      end
    end
  end
end
