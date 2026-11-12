module Dnsruby
  # Packet, query, retry, and I/O deadlines share one clock unaffected by wall
  # clock corrections. DNS TTLs and signatures continue to use civil time.
  module TransportClock #:nodoc:
    def self.now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
