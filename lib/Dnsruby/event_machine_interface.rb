require 'eventmachine'
require 'singleton'
module Dnsruby
  class EventMachineInterface
    include Singleton
    include EM::Deferrable
    # We want to have one EM loop running continuously in this class.
    # Remember to use stop_event_loop inside of EM callback in order to stop the event machine
    
    # Queue interface still used here, to allow any client to call.
    # @TODO@ ALSO SUPPORT DEFERRABLE INTERFACE! So - 
    #   Client adds callback and errback to returned connection
    #   @TODO@ We call set_defered_status when done

    def initialize
      @@em_thread = Thread.new {
        EM.run {
        }
      }
    end
    
    def send(args={})#msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
      if (args[:use_tcp])
        send_tcp(args)
      else
        send_udp(args)
      end 
    end

    def send_tcp(args={})#msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_tcp)
    end
    
    def send_udp(args={})# msg, client_query_id, client_queue, timeout, server, port, src_add, src_port, tsig_key, ignore_truncation, use_cp)
      connection = EventMachine::open_datagram_socket(args[:src_addr], args[:src_port], EmUdpHandler) { |c|
        c.instance_eval {@args = args}
        #c.set_comm_inactivity_timeout(args[:timeout])
        c.send_datagram args[:msg], args[:server], args[:port]
        TheLog.debug"EventMachine : Sent datagram to #{args[:server]}:#{args[:port]} from #{args[:src_addr]}:#{args[:src_port]}"
        EM::Timer.new(args[:timeout]) {
          # Cancel the send
          c.closing=true
          c.close_connection
          c.send_timeout
        }
      }
      return connection # allows clients to set callback, errback, etc., if desired
    end
    
    class EmUdpHandler < EventMachine::Connection
      attr_accessor :closing
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
          send_timeout
        end
        @closing=false
      end
      def send_timeout
        TheLog.debug("Sending timeout to client")
        send_to_client(@args[:client_queue], @args[:client_query_id], nil, ResolvTimeout.new("Query timed out"))
      end
      def send_to_client(q, id, msg, err)
        q.push([id, msg, err])
        #   @TODO@ We call set_defered_status when done
      end
    
    end
  end
end