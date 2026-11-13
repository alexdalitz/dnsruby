require 'dnsruby/query_control'

module Dnsruby
  # Resource limits are verification failures, never evidence that a zone is
  # insecure. Keep this distinction through trust-anchor and algorithm fallbacks.
  class ValidationLimitError < VerifyError; end
  class ValidationCancelled < ValidationLimitError; end

  # One budget counts DNSSEC work across nested validation calls. Supporting
  # lookups share its deadline and cancellation signal through QueryControl.
  class ValidationBudget # :nodoc: all
    # Ordinary verification and lookup failures can select another key or
    # anchor. Exhaustion must cross those fallbacks unchanged, then become the
    # public verification error when the outermost validation returns.
    class Abort < StandardError
      attr_reader :public_error

      def initialize(public_error)
        @public_error = public_error
        super(public_error.message)
      end
    end
    private_constant :Abort

    DEFAULT_LIMITS = {
      max_signature_verifications: 64,
      max_work: 100_000,
      timeout: 5.0
    }.freeze

    attr_reader :control

    def self.current
      Thread.current[:dnsruby_validation_budget]
    end

    def self.with(budget = nil)
      previous = current
      budget = previous || budget || new
      Thread.current[:dnsruby_validation_budget] = budget
      QueryControl.with(budget.control) do
        budget.check!
        result = yield budget
        budget.check!
        result
      end
    rescue Abort, QueryControl::Stopped => error
      raise if previous
      raise public_error(error), cause: error
    ensure
      Thread.current[:dnsruby_validation_budget] = previous
    end

    def initialize(deadline: nil, limits: Dnssec.validation_limits)
      @limits = limits
      deadline = [deadline, TransportClock.now + limits[:timeout]].compact.min
      @control = QueryControl.new(deadline: deadline, parent: QueryControl.current)
      @signature_verifications = 0
      @work = 0
    end

    def deadline
      @control.deadline
    end

    def cancel
      @control.cancel
    end

    def check!(work = 0)
      @control.check!
      if @signature_verifications > @limits[:max_signature_verifications]
        fail_with(ValidationLimitError, 'DNSSEC signature verification limit exceeded')
      end
      @work += work
      fail_with(ValidationLimitError, 'DNSSEC validation work limit exceeded') if @work > @limits[:max_work]
      true
    rescue QueryControl::Stopped => error
      raise if self.class.current
      raise self.class.public_error(error), cause: error
    end

    def self.public_error(error)
      public_error = case error
      when Abort then error.public_error
      when QueryControl::Cancelled then ValidationCancelled.new('DNSSEC validation cancelled')
      else ValidationLimitError.new('DNSSEC validation deadline exceeded')
      end
      public_error.set_backtrace(error.backtrace)
      public_error
    end

    def fail_with(error_class, message)
      error = error_class.new(message)
      raise(self.class.current ? Abort.new(error) : error)
    end
    private :fail_with

    def signature!
      check!
      @signature_verifications += 1
      check!
    end

  end
end
