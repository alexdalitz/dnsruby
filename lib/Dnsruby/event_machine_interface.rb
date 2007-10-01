require 'eventmachine'
#require 'singleton'
module Dnsruby
  class EventMachineInterface
    #    include Singleton
    @@started_em_here = false
    @@outstanding_sends = []
    @@em_thread=nil
    # We want to have one EM loop running continuously in this class.
    # Remember to use stop_event_loop inside of EM callback in order to stop the event machine
    
    # Queue interface still used here, to allow any client to call.
    # @TODO@ Should we bother using Queue interface still?

    def EventMachineInterface::start_eventmachine
      if (!eventmachine_running?)
        TheLog.debug("Starting EventMachine")
        @@started_em_here = true
        @@em_thread = Thread.new {
          EM.run {
          }
        }
      end
    end
    
    def EventMachineInterface::eventmachine_running?
      return (@@em_thread!=nil)
    end
    
    def EventMachineInterface::stop_eventmachine
      if (@@started_em_here)
        if (@@outstanding_sends.size==0)
          if (@@em_thread)
            TheLog.debug("Stopping EventMachine")
            @@em_thread.kill
            @@started_em_here = false
          end
        end
      end
    end

    def EventMachineInterface::send(args={})#msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
      # Is the EventMachine loop running? If not, we need to start it (and mark that we started it)
      puts "Send with EM"
      begin
        if (!EventMachine.reactor_running?)
          start_eventmachine
        end
      rescue Exception
        #@TODO@ reactor_running? only introduced in EM v0.9.0 - if it's not there, we simply don't know what to do...
        TheLog.error("EventMachine::reactor_running? not available.")
        if Resolver.start_eventmachine_loop?
          #          TheLog.debug("Trying to start event loop - may prove fatal...")
          start_eventmachine
        else
          TheLog.debug("Not trying to start event loop.")
        end
      end
      df = nil
      if (args[:use_tcp])
        df = send_tcp(args)
      else
        df = send_udp(args)
      end 
      # Need to add this send to the list of outstanding sends
      @@outstanding_sends.push(df)
      return df
    end

    def EventMachineInterface::send_tcp(args={})#msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
    end
    
    def EventMachineInterface::send_udp(args={})# msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_cp)
      connection = EventMachine::open_datagram_socket(args[:src_addr], args[:src_port], EmUdpHandler) { |c|
        c.instance_eval {@args = args}
        #c.set_comm_inactivity_timeout(args[:timeout])
        c.send_datagram args[:msg], args[:server], args[:port]
        TheLog.debug"EventMachine : Sent datagram to #{args[:server]}:#{args[:port]} from #{args[:src_addr]}:#{args[:src_port]}, timeout=#{args[:timeout]}"
        c.timeout_time=Time.now + args[:timeout]
        EM::Timer.new(args[:timeout]) {
          # Cancel the send
          c.closing=true
          c.close_connection
          c.send_timeout
        }
      }
      return connection # allows clients to set callback, errback, etc., if desired
    end
    
    def EventMachineInterface::remove_from_outstanding(df)
      @@outstanding_sends.delete(df)
      # If we explicitly started the EM loop, and there are no more outstanding sends, then stop the EM loop
      stop_eventmachine
    end
    
    
    class EmUdpHandler < EventMachine::Connection
      include EM::Deferrable
      attr_accessor :closing, :timeout_time
      def post_init
        @closing=false
      end
      def receive_data(dgm)
        TheLog.debug("receive_data called in thread #{Thread.current}")
        ans=nil
        begin
          ans = Message.decode(dgm)
        rescue Exception => e
          TheLog.error("Decode error! #{e.class}, #{e}\nfor msg (length=#{dgm.length}) : #{dgm}")
          send_to_client(@args[:client_queue], @args[:client_query_id], nil, e)
          # @TODO@ Resend or close?
          @closing=true
          close_connection
          return
        end
        TheLog.debug("#{ans}")
        ans.answerfrom=(@args[:server])
        ans.answersize=(dgm.length)
        exception = ans.header.getException
        send_to_client(@args[:client_queue], @args[:client_query_id], ans, exception)
        @closing=true
        close_connection
      end
        
      def unbind
        TheLog.debug("Unbind called in thread #{Thread.current}")
        if (!@closing)
          if (@timeout_time <= Time.now)
            send_timeout
          else
            #@TODO@ RAISE OTHER NETWORK ERROR!
            TheLog.debug("Sending IOError to client")
            send_to_client(@args[:client_queue], @args[:client_query_id], nil, IOError.new("Network error"))
          end
        end
        @closing=false
        # Take the last send off the list of outstanding sends
        EventMachineInterface.remove_from_outstanding(self)
      end
      def send_timeout
        TheLog.debug("Sending timeout to client")
        send_to_client(@args[:client_queue], @args[:client_query_id], nil, ResolvTimeout.new("Query timed out"))
      end
      def send_to_client(q, id, msg, err)
        q.push([id, msg, err])
        #  We call set_defered_status when done
        if (err != nil)
          set_deferred_status :failed, id, msg, err
        else
          set_deferred_status :succeeded, id, msg
        end
      end
    
    end
  end
end