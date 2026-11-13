require 'dnsruby/transport_clock'

module Dnsruby
  # A deadline and cancellation signal shared by related lookups. This carries
  # no DNSSEC policy; the caller decides how a stopped operation is reported.
  class QueryControl # :nodoc: all
    # These must bypass ordinary lookup and verification fallback handlers.
    class Stopped < StandardError; end
    class Cancelled < Stopped; end
    class DeadlineExceeded < Stopped; end

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
    end

    def cancel
      @cancelled = true
    end

    def check!
      @parent&.check!
      raise Cancelled, 'Query cancelled' if @cancelled
      raise DeadlineExceeded, 'Query deadline exceeded' if @deadline && TransportClock.now >= @deadline
      true
    end

    # Queue#pop(timeout:) is unavailable on some supported Ruby versions.
    def pop(queue)
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
