require 'eventmachine'
#require 'singleton'
module Dnsruby
  class EventMachineInterface
    #    include Singleton
    @@started_em_here = false
    @@running_clients=[]
    @@outstanding_sends = []
    @@em_thread=nil
    # We want to have one EM loop running continuously in this class.
    # Remember to use stop_event_loop inside of EM callback in order to stop the event machine
    
    def EventMachineInterface::start_eventmachine
      if (!eventmachine_running?)
        if Resolver.start_eventmachine_loop?
          TheLog.debug("Starting EventMachine")
          @@started_em_here = true
          @@em_thread = Thread.new {
            EM.run {
              @@df = EventMachine::DefaultDeferrable.new
              @@df.callback{
                TheLog.debug("Stopping EventMachine")
                EM.stop              
                @@em_thread=nil
              }
            }
          }
        else
          TheLog.debug("Not trying to start event loop")
        end
      end
    end
    
    def EventMachineInterface::start_em_for_resolver(res)
      @@running_clients.push(res)
      start_eventmachine
    end
    
    def EventMachineInterface::stop_em_for_resolver(res)
      @@running_clients.each_index do |i|
        if (@@running_clients[i]==res)
          @@running_clients.delete_at(i)
        end
      end
      stop_eventmachine
    end
    
    def EventMachineInterface::eventmachine_running?
      return (@@em_thread!=nil)
    end
    
    def EventMachineInterface::stop_eventmachine
      if (@@started_em_here)
        if (@@outstanding_sends.size==0)
          if (@@running_clients.length == 0)
            if (@@em_thread)
              @@df.set_deferred_status :succeeded
              @@started_em_here = false
              #              @@em_thread = nil
            end
          end
        end
      end
    end

    def EventMachineInterface::send(args={})#msg, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
      # Is the EventMachine loop running? If not, we need to start it (and mark that we started it)
      begin
        if (!EventMachine.reactor_running?)
          start_eventmachine
        end
      rescue Exception
        #@TODO@ EM::reactor_running? only introduced in EM v0.9.0 - if it's not there, we simply don't know what to do...
        TheLog.error("EventMachine::reactor_running? not available.")
        #        if Resolver.start_eventmachine_loop?
        #          TheLog.debug("Trying to start event loop - may prove fatal...")
        start_eventmachine
        #        else
        #          TheLog.debug("Not trying to start event loop.")
        #        end
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

    def EventMachineInterface::send_tcp(args={})#msg, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
      #      connection = EventMachine::connect(args[:src_addr], args[:src_port], EmTcpHandler) { |c|
      connection = EventMachine::connect(args[:server], args[:port], EmTcpHandler) { |c|
        #@TODO SRC_PORT FOR TCP!!!
        c.timeout_time=Time.now + args[:timeout]
        #        c.comm_inactivity_timeout = args[:timeout]
        c.instance_eval {@args = args}
        lenmsg = [args[:msg].length].pack('n')
        c.send_data(lenmsg)
        c.send_data args[:msg] # , args[:server], args[:port]
        TheLog.debug"EventMachine : Sent TCP packet to #{args[:server]}:#{args[:port]}" + # from #{args[:src_addr]}:#{args[:src_port]}, timeout=#{args[:timeout]}"
        ", timeout=#{args[:timeout]}"
        # @TODO@ Timers max out at 1000 - use another system
        c.timer = EventMachine::Timer.new(args[:timeout]) {
          # Cancel the send
          c.closing=true
          c.close_connection
          c.send_timeout
        }
      }
      return connection # allows clients to set callback, errback, etc., if desired
    end
    
    def EventMachineInterface::send_udp(args={})# msg, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_cp)
      connection = EventMachine::open_datagram_socket(args[:src_addr], args[:src_port], EmUdpHandler) { |c|
        c.timeout_time=Time.now + args[:timeout]
        #       c.comm_inactivity_timeout = args[:timeout]
        c.instance_eval {@args = args}
        c.send_datagram args[:msg], args[:server], args[:port]
        TheLog.debug"EventMachine : Sent datagram to #{args[:server]}:#{args[:port]} from #{args[:src_addr]}:#{args[:src_port]}, timeout=#{args[:timeout]}"
        # @TODO@ Timers max out at 1000 - use another system
        c.timer = EventMachine::Timer.new(args[:timeout]) {
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
      attr_accessor :closing, :timeout_time, :timer
      def post_init
        @closing=false
      end
      def receive_data(dgm)
        TheLog.debug("UDP receive_data called")
        process_incoming_message(dgm)
      end
      
      def process_incoming_message(data)
        TheLog.debug("Processing incoming message, #{data.length} bytes")
        ans=nil
        begin
          ans = Message.decode(data)
        rescue Exception => e
          TheLog.error("Decode error! #{e.class}, #{e}\nfor msg (length=#{data.length}) : #{data}")
          send_to_client(nil, e)
          @closing=true
          close_connection
          return
        end
        TheLog.debug("#{ans}")
        ans.answerfrom=(@args[:server])
        ans.answersize=(data.length)
        exception = ans.header.getException
        @closing=true
        send_to_client(ans, exception)
        close_connection
      end
        
      def unbind
        TheLog.debug("Unbind called")
        if (!@closing)
          if (@timeout_time <= Time.now + 1)
            send_timeout
          else
            #@TODO@ RAISE OTHER NETWORK ERROR!
            TheLog.debug("Sending IOError to client")
            send_to_client(nil, IOError.new("Network error"))
          end
        end
        @closing=false
        # Take the last send off the list of outstanding sends
        EventMachineInterface.remove_from_outstanding(self)
      end
      def send_timeout
        TheLog.debug("Sending timeout to client")
        send_to_client(nil, ResolvTimeout.new("Query timed out"))
      end
      def send_to_client(msg, err)
        #  We call set_defered_status when done
        if (err != nil)
          set_deferred_status :failed, msg, err
        else
          set_deferred_status :succeeded, msg
        end
        if (@timer)
          @timer.cancel
        end
      end
    end


    class EmTcpHandler < EmUdpHandler
      def post_init
        super
        @data=""
        @answersize = 0
      end
      def receive_data(data)
        TheLog.debug("TCP receive_data called")
        #Buffer up the incoming data until we have a complete packet
        @data << data
        if (@data.length >= 2)
          if (@answersize == 0)
            @answersize = @data[0..1].unpack('n')[0]
            TheLog.debug("TCP - expecting #{@answersize} bytes")
          end
          if (@answersize == @data.length - 2)
            TheLog.debug("TCP - got all #{@answersize} bytes ")
            process_incoming_message(@data[2..@data.length])
          else
            TheLog.debug("TCP - got #{@data.length-2} message bytes")
          end
        end
      end      
    end
    
  end
end