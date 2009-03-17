# Support for EventMachine has been deprecated.
#require 'eventmachine'
#module Dnsruby
#  class EventMachineInterface#:nodoc: all
#    @@started_em_here = false
#    @@running_clients=[]
#    @@outstanding_sends = []
#    @@em_thread=nil
#    # We want to have one EM loop running continuously in this class.
#    # Remember to use stop_event_loop inside of EM callback in order to stop the event machine
#
#    # Timers - can't use EM timers as they max out at 1000.
#    # Instead, while queries are outstanding, call next_tick to manage our own list of timers.
#
#    @@timer_procs={} # timeout=>[proc
#    @@timer_keys_sorted=[]
#    TIMER_PERIOD = 0.1
#
#    def EventMachineInterface::process_timers
#      # Go through list of timers
#      now = Time.now
#      @@timer_keys_sorted.each do |timeout|
#        if (timeout > now)
#          break
#        end
#        c, proc = @@timer_procs[timeout]
#        @@timer_procs.delete(timeout)
#        @@timer_keys_sorted.delete(timeout)
#        proc.call
#      end
#
#      if (!@@outstanding_sends.empty?)
#        EventMachine::add_timer(TIMER_PERIOD) {process_timers}
#      end
#    end
#
#    def EventMachineInterface::remove_timer(c)
#      # Remove from timer structures - if still there!
#      @@timer_procs.each do |timeout, value|
#        conn, proc = value
#        if (c==conn)
#          @@timer_procs.delete(timeout)
#          @@timer_keys_sorted.delete(timeout)
#        end
#      end
#    end
#
#    def EventMachineInterface::add_to_outstanding(c, timeout)
#      # Add to timer structures
#      @@timer_procs[Time.now+timeout]=[c, Proc.new {
#          # Cancel the send
#          c.closing=true
#          c.close_connection
#          c.send_timeout
#        }]
#      @@timer_keys_sorted=@@timer_procs.keys.sort
#      @@outstanding_sends.push(c)
##      puts "#{@@outstanding_sends.length} outstanding connections"
#      if (@@outstanding_sends.length==1)
#        EventMachine::add_timer(0) {process_timers}
#      end
#    end
#
#    def EventMachineInterface::remove_from_outstanding(c)
#      @@outstanding_sends.delete(c)
##      puts "#{@@outstanding_sends.length} outstanding connections"
#      remove_timer(c)
#      # If we explicitly started the EM loop, and there are no more outstanding sends, then stop the EM loop
#      stop_eventmachine
#    end
#
#    def EventMachineInterface::start_eventmachine
#      if (!eventmachine_running?)
#        if Resolver.start_eventmachine_loop?
#          Dnsruby.log.debug("Starting EventMachine")
#          @@started_em_here = true
#          @@em_thread = Thread.new {
#            EM.run {
##              EventMachine::add_periodic_timer(0.1) {EventMachineInterface::process_timers}
#              EventMachine::add_timer(0.1) {EventMachineInterface::process_timers}
#              @@df = EventMachine::DefaultDeferrable.new
#              @@df.callback{
#                Dnsruby.log.debug("Stopping EventMachine")
#                EM.stop
#                @@em_thread=nil
#              }
#            }
#          }
#        else
#          Dnsruby.log.debug("Not trying to start event loop")
#        end
#      end
#    end
#
#    def EventMachineInterface::start_em_for_resolver(res)
#      @@running_clients.push(res)
#      start_eventmachine
#    end
#
#    def EventMachineInterface::stop_em_for_resolver(res)
#      @@running_clients.each_index do |i|
#        if (@@running_clients[i]==res)
#          @@running_clients.delete_at(i)
#        end
#      end
#      stop_eventmachine
#    end
#
#    def EventMachineInterface::eventmachine_running?
#      return (@@em_thread!=nil)
#    end
#
#    def EventMachineInterface::stop_eventmachine
#      if (@@started_em_here)
#        if (@@outstanding_sends.size==0)
#          if (@@running_clients.length == 0)
#            if (@@em_thread)
#              @@df.set_deferred_status :succeeded
#              @@started_em_here = false
#              #              @@em_thread = nil
#            end
#          end
#        end
#      end
#    end
#
#    def EventMachineInterface::send(args={})#msg, timeout, server, port, src_add, src_port, use_tcp)
#      # Is the EventMachine loop running? If not, we need to start it (and mark that we started it)
#      begin
#        if (!EventMachine.reactor_running?)
#          start_eventmachine
#        end
#      rescue Exception
#        #@TODO@ EM::reactor_running? only introduced in EM v0.9.0 - if it's not there, we simply don't know what to do...
#        Dnsruby.log.error("EventMachine::reactor_running? not available.")
#        #        if Resolver.start_eventmachine_loop?
#        #          Dnsruby.log.debug("Trying to start event loop - may prove fatal...")
#        start_eventmachine
#        #        else
#        #          Dnsruby.log.debug("Not trying to start event loop.")
#        #        end
#      end
#      df = nil
#      if (args[:use_tcp])
#        df = send_tcp(args)
#      else
#        df = send_udp(args)
#      end
#      # Need to add this send to the list of outstanding sends
#      add_to_outstanding(df, args[:timeout])
#      return df
#    end
#
#    def EventMachineInterface::send_tcp(args={})#msg, timeout, server, port, src_add, src_port, use_tcp)
#      connection = EventMachine::connect(args[:server], args[:port], EmTcpHandler) { |c|
#        #@TODO SRC_PORT FOR TCP!!!
#        c.timeout_time=Time.now + args[:timeout]
#        c.instance_eval {@args = args}
#        lenmsg = [args[:msg].length].pack('n')
#        c.send_data(lenmsg)
#        c.send_data args[:msg] # , args[:server], args[:port]
#        Dnsruby.log.debug {"EventMachine : Sent TCP packet to #{args[:server]}:#{args[:port]}" + # from #{args[:src_address]}:#{args[:src_port]}, timeout=#{args[:timeout]}"
#        ", timeout=#{args[:timeout]}"}
#      }
#      return connection # allows clients to set callback, errback, etc., if desired
#    end
#
#    def EventMachineInterface::send_udp(args={})# msg, timeout, server, port, src_add, src_port, use_tcp)
#      connection = EventMachine::open_datagram_socket(args[:src_address], args[:src_port], EmUdpHandler) { |c|
#        c.timeout_time=Time.now + args[:timeout]
#        c.instance_eval {@args = args}
#        c.send_datagram args[:msg], args[:server], args[:port]
#        Dnsruby.log.debug{"EventMachine : Sent datagram to #{args[:server]}:#{args[:port]} from #{args[:src_address]}:#{args[:src_port]}, timeout=#{args[:timeout]}"}
#      }
#      return connection # allows clients to set callback, errback, etc., if desired
#    end
#
#
#    class EmUdpHandler < EventMachine::Connection #:nodoc: all
#      include EM::Deferrable
#      attr_accessor :closing, :timeout_time
#      def post_init
#        @closing=false
#      end
#      def receive_data(dgm)
#        Dnsruby.log.debug{"UDP receive_data called"}
#        process_incoming_message(dgm)
#      end
#
#      def process_incoming_message(data)
#        Dnsruby.log.debug{"Processing incoming message, #{data.length} bytes"}
#        ans=nil
#        begin
#          ans = Message.decode(data)
#        rescue Exception => e
#          Dnsruby.log.error{"Decode error! #{e.class}, #{e}\nfor msg (length=#{data.length}) : #{data}"}
#          @closing=true
#          close_connection
#          send_to_client(nil, nil, e)
#          return
#        end
#        Dnsruby.log.debug{"#{ans}"}
#        ans.answerfrom=(@args[:server])
#        ans.answersize=(data.length)
#        exception = ans.header.get_exception
#        @closing=true
#        close_connection
#        send_to_client(ans, data, exception)
#      end
#
#      def unbind
#        Dnsruby.log.debug{"Unbind called"}
#        if (!@closing)
#          if (@timeout_time <= Time.now + 1)
#            send_timeout
#          else
#            Dnsruby.log.debug{"Sending IOError to client"}
#            send_to_client(nil, nil, IOError.new("Network error"))
#          end
#        end
#        @closing=false
#        # Take the last send off the list of outstanding sends
#        EventMachineInterface.remove_from_outstanding(self)
#      end
#      def send_timeout
#        Dnsruby.log.debug{"Sending timeout to client"}
#        send_to_client(nil, nil, ResolvTimeout.new("Query timed out"))
#      end
#      def send_to_client(msg, bytes, err)
#        #  We call set_defered_status when done
#        if (err != nil)
#          set_deferred_status :failed, msg, err
#        else
#          set_deferred_status :succeeded, msg, bytes
#        end
#      end
#    end
#
#
#    class EmTcpHandler < EmUdpHandler #:nodoc: all
#      def post_init
#        super
#        @data=""
#        @answersize = 0
#      end
#      def receive_data(data)
#        Dnsruby.log.debug{"TCP receive_data called"}
#        #Buffer up the incoming data until we have a complete packet
#        @data << data
#        if (@data.length >= 2)
#          if (@answersize == 0)
#            @answersize = @data[0..1].unpack('n')[0]
#            Dnsruby.log.debug{"TCP - expecting #{@answersize} bytes"}
#          end
#          if (@answersize == @data.length - 2)
#            Dnsruby.log.debug{"TCP - got all #{@answersize} bytes "}
#            process_incoming_message(@data[2..@data.length])
#          else
#            Dnsruby.log.debug{"TCP - got #{@data.length-2} message bytes"}
#          end
#        end
#      end
#    end
#
#  end
#end