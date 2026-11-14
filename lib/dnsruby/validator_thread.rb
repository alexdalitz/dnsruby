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

module Dnsruby
  # Runs local DNSSEC validation outside SelectThread, using a bounded pool.
  # Nested trust discovery shares the original validation budget.
  class ValidatorThread # :nodoc: all
    WORKER_COUNT = 4
    QUEUE_CAPACITY = 64
    @worker_mutex = Mutex.new

    # Chain discovery performs synchronous queries, so validation must run away
    # from the selector. Bound both threads and queued responses under load.
    def self.enqueue(validator)
      rejected = []
      accepted = @worker_mutex.synchronize do
        # Threads do not survive fork. Parent work belongs to the parent, while
        # the child's first admission must start its own pool.
        if @worker_pid != Process.pid
          @worker_pid = Process.pid
          @work_queue = SizedQueue.new(QUEUE_CAPACITY)
          @workers = []
        end
        @workers.select!(&:alive?)
        begin
          (WORKER_COUNT - @workers.length).times do
            queue = @work_queue
            @workers << Thread.new do
              loop do
                work = queue.pop
                begin
                  work.do_validate
                rescue StandardError => error
                  Dnsruby.log.error { "DNSSEC validation worker: #{error}" }
                end
              end
            end
          end
        rescue ThreadError
          # A partial pool remains usable and is replenished on later admission.
          # If no worker could start, fail queued work rather than strand it.
        end
        if @workers.empty?
          begin
            loop { rejected << @work_queue.pop(true) }
          rescue ThreadError
          end
          false
        else
          begin
            @work_queue.push(validator, true)
            true
          rescue ThreadError
            false
          end
        end
      end
      rejected.each(&:reject_capacity)
      accepted
    end

    def initialize(*args)
      @client_id, @client_queue, @response, @error, @query, @st, @res = args
      @registered = false
      prepare_budget if should_validate
    end

    def prepare_budget
      return @budget if @budget
      deadline = @st.validation_deadline(@client_queue, @client_id) if @st.respond_to?(:validation_deadline)
      @budget = ValidationBudget.new(deadline: deadline)
    end
    private :prepare_budget

    def register
      return true if @registered
      prepare_budget
      return false unless @st.register_validation(@client_queue, @res, @budget.control)
      @registered = true
    end
    private :register

    def run
      if should_validate
        return unless register
        unless self.class.enqueue(self)
          reject_capacity
        end
      else
        do_validate
      end
    end

    def do_validate
      needs_validation = should_validate
      return if needs_validation && !register
      validated_ok = if needs_validation
        ValidationBudget.with(@budget) { validate(@query, @response, @res) }
      else
        validate(@query, @response, @res)
      end
      validated_ok = false if @error && !@error.is_a?(NXDomain)
      if @response.security_level == Message::SecurityLevel.BOGUS
        detail = @response.security_error.to_s
        raise VerifyError, detail.empty? ? 'DNSSEC validation failed' : detail
      end
      @budget.check! if needs_validation
      cache_if_valid(@query, @response) if validated_ok
      @st.push_validation_response_to_select(@client_id, @client_queue, @response,
        validated_ok ? nil : @response.security_error, @query, @res)
    rescue StandardError => error
      # Resolver observers ignore late completions; direct PacketSender callers
      # still need a terminal error after cancellation or their sender closing.
      error = VerifyError.new("DNSSEC validation failed: #{error.message}") unless error.is_a?(VerifyError)
      finish_error(error)
    ensure
      unregister
    end

    def finish_error(error)
      @response.security_error = error
      @response.security_level = Message::SecurityLevel.BOGUS
      @st.push_validation_response_to_select(@client_id, @client_queue, @response,
        error, @query, @res)
    end
    private :finish_error

    def unregister
      @st.unregister_validation(@client_queue, @res, @budget.control) if @registered
      @registered = false
    end
    private :unregister

    def reject_capacity
      finish_error(ValidationLimitError.new('DNSSEC validation capacity exceeded'))
    ensure
      unregister
    end

    def should_validate
      return ValidatorThread.requires_validation?(@query, @response, @error, @res)
    end

    def ValidatorThread.requires_validation?(query, response, error, res)
      #  @error will be nil for DNS RCODE errors - it will be true for TsigError. really?!
      if ((!error || (error.instance_of?NXDomain)) && query.do_validation)
        if (res.dnssec)
          if (response.security_level != Message::SecurityLevel.SECURE)
            return true
          end
        end
      end
      return false

    end

    def validate(query, response, res)
      return true unless should_validate
      ValidationBudget.with do
        begin
          validated = Dnssec.validate_with_query(query, response)
          if !validated || response.security_level == Message::SecurityLevel.BOGUS
            error = response.security_error
            error = VerifyError.new(error.to_s.empty? ? 'DNSSEC validation failed' : error.to_s) unless error.is_a?(VerifyError)
            response.security_error = error
            response.security_level = Message::SecurityLevel.BOGUS
            return false
          end
          true
        rescue VerifyError => e
          response.security_error = e
          response.security_level = Message::SecurityLevel.BOGUS
          #  Response security_level should already be set
          false
        end
      end
    end

    def cache_if_valid(query, response)
      return if @error
      PacketSender.cache(query, response)
    end
  end
end
