#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require "Dnsruby/SingleResolver"
module Dnsruby
  #== Description
  # This class uses a set of SingleResolvers to perform queries with retries across multiple nameservers.
  #
  # The retry policy is a combination of the Net::DNS and dnsjava approach, and has the option of :
  #* A total timeout for the query (defaults to 0, meaning "no total timeout")
  #* A retransmission system that targets the namervers concurrently once the first query round is 
  #  complete, but in which the total time per query round is split between the number of nameservers 
  #  targetted for the first round. and total time for query round is doubled for each query round
  #   
  #  Note that, if a total timeout is specified, then that will apply regardless of the retry policy 
  #  (i.e. it may cut retries short).
  #  
  #  Note also that these timeouts are distinct from the SingleResolver's packet_timeout
  #
  #== Methods
  # 
  #=== Synchronous
  #These methods raise an exception or return a response message with rcode==NOERROR
  #
  #*  Dnsruby::Resolver#send_message(msg)
  #*  Dnsruby::Resolver#query(name [, type [, klass]])
  #
  #=== Asynchronous
  #These methods use a response queue to return the response and the error
  #
  #*  Dnsruby::Resolver#send_async(msg, query_id, response_queue)
  #
  
  class Resolver
    @@event_machine_available=false
    begin
      require 'Dnsruby/event_machine_interface'
      @@event_machine_available=true
      TheLog.debug("EventMachine loaded")
    rescue LoadError
      TheLog.error("EventMachine not found")
    end
    DefaultQueryTimeout = 0 
    DefaultPacketTimeout = 10
    DefaultRetryTimes = 4
    DefaultRetryDelay = 5
    DefaultPort = 53
    DefaultUDPSize = 512
    # The port to send queries to on the resolver
    attr_reader :port
    
    # Should TCP be used as a transport rather than UDP?
    attr_reader :use_tcp
    
    
    attr_reader :tsig_key
    
    # Should truncation be ignored?
    # i.e. the TC bit is ignored and thus the resolver will not requery over TCP if TC is set
    attr_reader :ignore_truncation
    
    # The source address to send queries from
    attr_reader :src_address
    # The source port to send queries from
    attr_reader :src_port
    
    # Should TCP queries be sent on a persistent socket?
    attr_reader :persistent_tcp
    # Should UDP queries be sent on a persistent socket?
    attr_reader :persistent_udp
    
    # Should the Recursion Desired bit be set?
    attr_reader :recurse
    
    # The maximum UDP size to be used
    attr_reader :udp_size
    
    # The current Config
    attr_reader :config
    
    # The array of SingleResolvers used for sending query messages
    attr_reader :single_resolvers
    
    #The timeout for any individual packet. This is the timeout used by SingleResolver
    attr_reader :packet_timeout
    
    # Note that this timeout represents the total time a query may run for - multiple packets
    # can be sent to multiple nameservers in this time.
    # This is distinct from the SingleResolver per-packet timeout
    # The query_timeout is not required - it will default to 0, which means "do not use query_timeout".
    # If this is the case then the timeout will be dictated by the retry_times and retry_delay attributes
    attr_accessor :query_timeout
    
    # The query will be tried across nameservers retry_times times, with a delay of retry_delay seconds
    # between each retry. The first time round, retry_delay will be divided by the number of nameservers
    # being targetted, and a new nameserver will be queried with the resultant delay.
    attr_accessor :retry_times, :retry_delay
    
    @@use_eventmachine=false
    @@start_eventmachine_loop=true
    
    #--
    #@TODO@ add load_balance? i.e. Target nameservers in a random, rather than pre-determined, order?
    #++
    
    # Query for a n. If a valid Message is received, then it is returned 
    # to the caller. Otherwise an exception (a Dnsruby::ResolvError or Dnsruby::ResolvTimeout) is raised.
    #
    #   require 'Dnsruby'
    #   res = Dnsruby::Resolver.new
    #   response = res.query("example.com") # defaults to Types.A, Classes.IN
    #   response = res.query("example.com", Types.MX)
    #   response = res.query("208.77.188.166") # IPv4 address so PTR query will be made
    #   response = res.query("208.77.188.166", Types.PTR)
    def query(name, type=Types.A, klass=Classes.IN)
      msg = Message.new
      msg.header.rd = 1
      msg.add_question(name, type, klass)
      return send_message(msg)
    end
    
    # Send a message, and wait for the response. If a valid Message is received, then it is returned 
    # to the caller. Otherwise an exception (a Dnsruby::ResolvError or Dnsruby::ResolvTimeout) is raised.
    # 
    # send_async is called internally.
    # 
    # example :
    # 
    #   require 'Dnsruby'
    #   res = Dnsruby::Resolver.new
    #   begin
    #   response = res.send_message(Message.new("example.com", Types.MX))
    #   rescue ResolvError
    #     # ...
    #   rescue ResolvTimeout
    #     # ...
    #   end
    def send_message(message)
      TheLog.debug("Resolver : sending message")
      q = Queue.new
      send_async(message, q, q)
      id, result, error = q.pop
      TheLog.debug("Resolver : result received")
      if (error != nil)
        raise error
      else
        return result
      end
      #      case result
      #      when Exception
      #        # Pass them on
      #        raise result
      #      when Message
      #        return result
      #      else
      #        TheLog.error("Unknown result returned : #{result}")
      #        raise ResolvError.new("Unknown error, return : #{result}")
      #      end 
    end
    
    
    # Asynchronously sends a DNS packet (Dnsruby::Message). The client must pass in the 
    # Message to be sent, a client_query_id to identify the message and a client_queue (of 
    # class Queue) to pass the response back in. 
    # 
    # A tuple of (query_id, response_message, exception) will be added to the client_queue.
    #
    # 
    # example :
    # 
    #   require 'Dnsruby'
    #   res = Dnsruby::Resolver.new
    #   query_id = 10 # can be any object you like
    #   query_queue = Queue.new
    #   res.send_async(Message.new("example.com", Types.MX), query_id,  query_queue)
    #   query_id += 1
    #   res.send_async(Message.new("example.com", Types.A), query_id,  query_queue)
    #   # ...do a load of other stuff here...
    #   2.times do 
    #     response_id, response, exception = query_queue.pop
    #     # You can check the ID to see which query has been answered
    #     if (exception == nil)
    #         # deal with good response
    #     else
    #         # deal with problem
    #     end
    #   end
    def send_async(msg, client_query_id, client_queue)
      # This is the whole point of the Resolver class.
      # We want to use multiple SingleResolvers to run a query.
      # So we kick off a system with select_thread where we send
      # a query with a queue, but log ourselves as observers for that
      # queue. When a new response is pushed on to the queue, then the
      # select thread will call this class' handler method IN THAT THREAD.
      # When the final response is known, this class then sticks it in
      # to the client queue.
      
      q = Queue.new
      
      if (!client_queue.kind_of?Queue)
        TheLog.error("Wrong type for client_queue in Resolver#send_async")
        client_queue.push([client_query_id, ArgumentError.new("Wrong type of client_queue passed to Dnsruby::Resolver#send_async - should have been Queue, was #{client_queue.class}")])
        return
      end
      
      if (!msg.kind_of?Message)
        TheLog.error("Wrong type for msg in Resolver#send_async")
        client_queue.push([client_query_id, ArgumentError.new("Wrong type of msg passed to Dnsruby::Resolver#send_async - should have been Message, was #{msg.class}")])
        return
      end
      
      tick_needed=false
      # add to our data structures
      @mutex.synchronize{
        tick_needed = true if @query_list.empty?
        if (@query_list.has_key?client_query_id)
          TheLog.error("Duplicate query id requested (#{client_query_id}")
          client_queue.push([client_query_id, ArgumentError.new("Client query ID already in use")])
          return
        end
        outstanding = []
        @query_list[client_query_id]=[msg, client_queue, q, outstanding]
        
        query_timeout = Time.now+@query_timeout
        if (@query_timeout == 0)
          query_timeout = Time.now+31536000 # a year from now
        end
        @timeouts[client_query_id]=[query_timeout, generate_timeouts()]
      }
      
      # Now do querying stuff using SingleResolver
      # All this will be handled by the tick method (if we have 0 as the first timeout)
      st = SelectThread.instance
      st.add_observer(q, self)
      tick if tick_needed
    end
    
    def generate_timeouts() #:nodoc: all
      # Create the timeouts for the query from the retry_times and retry_delay attributes. 
      # These are created at the same time in case the parameters change during the life of the query.
      # 
      # These should be absolute, rather than relative
      # The first value should be Time.now
      time_now = Time.now
      timeouts={}
      #These should be be pegged to the single_resolver they are targetting :
      #  e.g. timeouts[timeout1]=nameserver
      retry_delay = @retry_delay
      @retry_times.times do |retry_count|
        if (retry_count>0)
          retry_delay *= 2
        end
        servers=[]
        @single_resolvers.each do |r| servers.push(r.server) end
        @single_resolvers.each_index do |i|
          res= @single_resolvers[i]
          offset = (i*@retry_delay.to_f/@single_resolvers.length)
          if (retry_count==0)
            timeouts[time_now+offset]=[res, retry_count]
          else
            if (timeouts.has_key?(time_now+retry_delay+offset))
              TheLog.error("Duplicate timeout key!")
              raise RuntimeError.new("Duplicate timeout key!")
            end
            timeouts[time_now+retry_delay+offset]=[res, retry_count]
          end
        end
      end
      return timeouts      
    end
    
    # Close the Resolver. Unfinished queries are terminated with OtherResolError.
    def close
      @mutex.synchronize {
        @query_list.each do |client_query_id, values|
          msg, client_queue, q, outstanding = values
          send_result_and_close(client_queue, client_query_id, q, nil, OtherResolvError.new("Resolver closing!"))
        end
      }
    end
    
    # MUST BE CALLED IN A SYNCHRONIZED BLOCK!    
    # 
    # Send the result back to the client, and close the socket for that query by removing 
    # the query from the select thread.
    def send_result_and_close(client_queue, client_query_id, select_queue, msg, error) #:nodoc: all
      TheLog.debug("Sending result #{error} to client")
      # We might still get some callbacks, which we should ignore
      st = SelectThread.instance
      st.remove_observer(select_queue, self)
      #      @mutex.synchronize{
      # Remove the query from all of the data structures
      @timeouts.delete(client_query_id)
      @query_list.delete(client_query_id)
      #      }
      # Return the response to the client
      client_queue.push([client_query_id, msg, error])
    end
    
    # This method is called ten times a second from the select loop, in the select thread. 
    # It should arguably be called from another worker thread... 
    # Each tick, we check if any timeouts have occurred. If so, we take the appropriate action : 
    # Return a timeout to the client, or send a new query
    def tick #:nodoc: all
      # Handle the tick
      # Do we have any retries due to be sent yet?
      @mutex.synchronize{
        time_now = Time.now
        @timeouts.keys.each do |client_query_id|
          msg, client_queue, select_queue, outstanding = @query_list[client_query_id]
          query_timeout, timeouts = @timeouts[client_query_id]
          if (query_timeout < Time.now)
            #Time the query out
            send_result_and_close(client_queue, client_query_id, select_queue, nil, ResolvTimeout.new("Query timed out"))
            next
          end
          timeouts_done = []
          timeouts.keys.sort.each do |timeout|
            if (timeout < time_now)
              # Send the next query
              res, retry_count = timeouts[timeout]
              id = [res, msg, client_query_id, retry_count]
              TheLog.debug("Sending msg to #{res.server}")
              # We should keep a list of the queries which are outstanding
              outstanding.push(id)
              timeouts_done.push(timeout)
              timeouts.delete(timeout)
              res.send_async(msg, id, select_queue)
            else
              break
            end
          end
          timeouts_done.each do |t|
            timeouts.delete(t)
          end
        end
      }
    end
    
    # This method is called by the SelectThread (in the select thread) when the queue has a new item on it.
    # The queue interface is used to separate producer/consumer threads, but we're using it here in one thread. 
    # It's probably a good idea to create a new "worker thread" to take items from the select thread queue and 
    # call this method in the worker thread.
    # 
    # Time to process a new queue event.
    def handle_queue_event(queue, id) #:nodoc: all
      # If we get a callback for an ID we don't know about, don't worry -
      # just ignore it. It may be for a query we've already completed.
      # 
      # So, get the next response from the queue (presuming there is one!)
      #
      # @TODO@ Tick could poll the queue and then call this method if needed - no need for observer interface.
      # @TODO@ Currently, tick and handle_queue_event called from select_thread - could have thread chuck events in to tick_queue. But then, clients would have to call in on other thread!
      #
      if (queue.empty?)
        TheLog.fatal("Queue empty in handle_queue_event!")
        raise RuntimeError.new("Severe internal error - Queue empty in handle_queue_event")
      end
      event_id, response, error = queue.pop
      # We should remove this packet from the list of outstanding packets for this query
      resolver, msg, client_query_id, retry_count = id
      if (id != event_id)
        TheLog.error("Serious internal error!! #{id} expected, #{event_id} received")
        raise RuntimeError.new("Serious internal error!! #{id} expected, #{event_id} received")
      end
      @mutex.synchronize{
        if (@query_list[client_query_id]==nil)
          TheLog.debug("Ignoring response for dead query")
          return
        end
        msg, client_queue, select_queue, outstanding = @query_list[client_query_id]
        if (!outstanding.include?id)
          TheLog.error("Query id not on outstanding list! #{outstanding.length} items. #{id} not on #{outstanding}")
          raise RuntimeError.new("Query id not on outstanding!")
        end
        outstanding.delete(id)
      }
      #      if (event.kind_of?(Exception))
      if (error != nil)
        handle_error_response(queue, event_id, error, response)
      else # if (event.kind_of?(Message))
        handle_response(queue, event_id, response)
        #      else
        #        TheLog.error("Random object #{event.class} returned through queue to Resolver")
      end
    end
    
    def handle_error_response(select_queue, query_id, error, response) #:nodoc: all
      #Handle an error
      @mutex.synchronize{
        TheLog.debug("handling error #{error.class}, #{error}")
        # Check what sort of error it was :
        resolver, msg, client_query_id, retry_count = query_id
        msg, client_queue, select_queue, outstanding = @query_list[client_query_id]
        if (error.kind_of?(ResolvTimeout))
          #   - if it was a timeout, then check which number it was, and how many retries are expected on that server
          #       - if it was the last retry, on the last server, then return a timeout to the client (and clean up)
          #       - otherwise, continue
          # Do we have any more packets to send to this resolver?
          timeouts = @timeouts[client_query_id]
          if (outstanding.empty? && timeouts[1].values.empty?)
            TheLog.debug("Sending timeout to client")
            send_result_and_close(client_queue, client_query_id, select_queue, response, error)
          end
        elsif (error.kind_of?NXDomain)
          #   - if it was an NXDomain, then return that to the client, and stop all new queries (and clean up)
          send_result_and_close(client_queue, client_query_id, select_queue, response, error)
        else
          #   - if it was any other error, then remove that server from the list for that query
          #   If a Too Many Open Files error, then don't remove, but let retry work.
          timeouts = @timeouts[client_query_id]
          if (!(error.to_s=~/Errno::EMFILE/))
            TheLog.debug("Removing #{resolver.server} from resolver list for this query")
            timeouts[1].each do |key, value|
              res = value[0]
              if (res == resolver)
                timeouts[1].delete(key)
              end
            end
          else
            TheLog.debug("NOT Removing #{resolver.server} due to Errno::EMFILE")          
          end
          #        - if it was the last server, then return an error to the client (and clean up)
          if (outstanding.empty? && timeouts[1].values.empty?)
            #          if (outstanding.empty?)
            TheLog.debug("Sending error to client")
            send_result_and_close(client_queue, client_query_id, select_queue, response, error)
          end
        end
        #@TODO@ If we're still sending packets for this query, but none are outstanding, then 
        #jumpstart the next query?
      }
    end
    
    def handle_response(select_queue, query_id, response) #:nodoc: all
      # Handle a good response
      TheLog.debug("Handling good response")
      resolver, msg, client_query_id, retry_count = query_id
      @mutex.synchronize{
        query, client_queue, s_queue, outstanding = @query_list[client_query_id]
        if (s_queue != select_queue)
          TheLog.error("Serious internal error : expected select queue #{s_queue}, got #{select_queue}")
          raise RuntimeError.new("Serious internal error : expected select queue #{s_queue}, got #{select_queue}")
        end
        send_result_and_close(client_queue, client_query_id, select_queue, response, nil)
      }
    end
    
    # Create a new Resolver object. If no parameters are passed in, then the default 
    # system configuration will be used. Otherwise, a Hash may be passed in with the 
    # following optional elements : 
    # 
    # 
    # * :port
    # * :use_tcp
    # * :tsig_key
    # * :ignore_truncation
    # * :src_address
    # * :src_port
    # * :persistent_tcp
    # * :persistent_udp
    # * :recurse
    # * :udp_size
    # * :config_info - see Config
    # * :nameserver - can be either a String or an array of Strings
    # * :packet_timeout
    # * :query_timeout
    # * :retry_times
    # * :retry_delay
    def initialize(*args)
      reset_attributes
      
      # Process args
      if (args.length==1)
        if (args[0].class == Hash)
          args[0].keys.each do |key|
            begin
              if (key == :config_info)
                @config.set_config_info(args[0][:config_info])
              elsif (key==:nameserver)
                set_config_nameserver(args[0][:nameserver])
              else
                send(key.to_s+"=", args[0][key])
              end
            rescue Exception
              TheLog.error("Argument #{key} not valid\n")
            end
          end
        elsif (args[0].class == Config)
          # also accepts a Config object from Dnsruby::Resolv
          @config = args[0]
        end
      else
        #@TODO@ ?
      end
      if (@single_resolvers==[])
        add_config_nameservers
      end
      update
    end
    
    def add_config_nameservers
      # Add the Config nameservers
      @config.nameserver.each do |ns|
        @single_resolvers.push(SingleResolver.new({:server=>ns}))
      end
    end
    
    def set_config_nameserver(n)
      if (n).kind_of?String
        @config.nameserver=[n]
      else
        @config.nameserver=n
      end
    end    
    
    def reset_attributes #:nodoc: all
      # data structures
      @mutex=Mutex.new
      @query_list = {}
      
      # Attributes
      @timeouts = {}
      @query_timeout = DefaultQueryTimeout
      @retry_delay = DefaultRetryDelay
      @retry_times = DefaultRetryTimes
      @packet_timeout = DefaultPacketTimeout
      @port = DefaultPort
      @udp_size = DefaultUDPSize
      @use_tcp = false
      @tsig_key = nil
      @ignore_truncation = false
      @config = Config.new()
      @src_addr        = '0.0.0.0'
      @src_port        = 0
      @recurse = true
      @persistent_udp = false
      @persistent_tcp = false
      @single_resolvers=[]
    end
    
    def update #:nodoc: all
      #Update any resolvers we have with the latest config
      @single_resolvers.each do |res|
        [:port, :use_tcp, :tsig_key, :ignore_truncation, :packet_timeout, 
          :src_address, :src_port, :persistent_tcp, :persistent_udp, :recurse, 
          :udp_size].each do |param|
          
          res.send(param.to_s+"=", instance_variable_get("@"+param.to_s))
        end
      end
    end
    
    # Add a new SingleResolver to the list of resolvers this Resolver object will 
    # query.
    def add_resolver(single)
      @single_resolvers.push(single)
    end
    
    def nameserver=(n)
      @single_resolvers=[]
      set_config_nameserver(n)
      add_config_nameservers
    end
    
    def packet_timeout=(t)
      @packet_timeout = t
      update
    end
    
    def port=(p)
      @port = p
      update
    end
    
    def use_tcp=(on)
      @use_tcp = on
      update
    end
    
    def tsig_key=(t)
      @tsig_key = t
      update
    end
    
    def ignore_truncation=(on)
      @ignore_truncation = on
      update
    end
    
    def src_address=(a)
      @src_address = a
      update
    end
    
    def src_port=(a)
      @src_port = a
      update
    end
    
    def persistent_tcp=(on)
      @persistent_tcp = on
      update
    end
    
    def persistent_udp=(on)
      @persistent_udp = on
      update
    end
    
    def recurse=(a)
      @recurse = a
      update
    end
    
    def udp_size=(s)
      @udp_size = s
      update
    end
    def Resolver.use_eventmachine(on=true)
      if (!@@event_machine_available)
        raise RuntimeError.new("EventMachine is not available in this environment!")
      end
      @@use_eventmachine = on
    end
    def Resolver.eventmachine?
      return @@use_eventmachine
    end
    def Resolver.start_eventmachine_loop(on=true)
      @@start_eventmachine_loop=on
    end
    def Resolver.start_eventmachine_loop?
      return @@start_eventmachine_loop
    end
  end
end