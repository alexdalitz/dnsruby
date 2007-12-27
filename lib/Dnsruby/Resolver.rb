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
  #Dnsruby::Resolver is a DNS stub resolver.
  #This class uses a set of SingleResolvers to perform queries with retries across multiple nameservers.
  #
  #The retry policy is a combination of the Net::DNS and dnsjava approach, and has the option of :
  #* A total timeout for the query (defaults to 0, meaning "no total timeout")
  #* A retransmission system that targets the namervers concurrently once the first query round is 
  #  complete, but in which the total time per query round is split between the number of nameservers 
  #  targetted for the first round. and total time for query round is doubled for each query round
  #   
  # Note that, if a total timeout is specified, then that will apply regardless of the retry policy 
  #(i.e. it may cut retries short).
  #  
  # Note also that these timeouts are distinct from the SingleResolver's packet_timeout
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
  #*  Dnsruby::Resolver#send_async(msg, response_queue, query_id)
  #
  #== Event Loop
  #Dnsruby runs a pure Ruby event loop to handle I/O in a single thread.
  #It is also possible to configure Dnsruby to use EventMachine instead.
  #See the Dnsruby::Resolver::use_eventmachine method for details.
  #
  #Note that, if using Dnsruby from an EventMachine loop, you will need to tell
  #Dnsruby not to start the event loop itself :
  #
  #   Dnsruby::Resolver::use_eventmachine(true)
  #   Dnsruby::Resolver::start_eventmachine_loop(false)
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
    
    
    attr_reader :tsig
    
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
    
    # Use DNSSEC for this Resolver
    attr_reader :dnssec
    
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
      send_async(message, q)
      id, result, error = q.pop
      TheLog.debug("Resolver : result received")
      if (error != nil)
        raise error
      else
        return result
      end
    end
    
    
    #Asynchronously send a Message to the server. The send can be done using just
    #Dnsruby, or using EventMachine.
    # 
    #== Dnsruby pure Ruby event loop :
    # 
    #A client_queue is supplied by the client, 
    #along with an optional client_query_id to identify the response. The client_query_id
    #is generated, if not supplied, and returned to the client.
    #When the response is known, 
    #a tuple of (query_id, response_message, exception) will be added to the client_queue.
    # 
    #The query is sent synchronously in the caller's thread. The select thread is then used to 
    #listen for and process the response (up to pushing it to the client_queue). The client thread 
    #is then used to retrieve the response and deal with it.
    # 
    #Takes :
    # 
    #* msg - the message to send
    #* client_queue - a Queue to push the response to, when it arrives
    #* client_query_id - an optional ID to identify the query to the client
    #* use_tcp - whether to use TCP (defaults to SingleResolver.use_tcp)
    #
    #Returns :
    # 
    #* client_query_id - to identify the query response to the client. This ID is
    #generated if it is not passed in by the client
    # 
    #=== Example invocations :
    #
    #    id = res.send_async(msg, queue)
    #    NOT SUPPORTED : id = res.send_async(msg, queue, use_tcp)
    #    id = res.send_async(msg, queue, id)
    #    id = res.send_async(msg, queue, id, use_tcp)
    #    
    #=== Example code :
    #
    #   require 'Dnsruby'
    #   res = Dnsruby::Resolver.new
    #   query_id = 10 # can be any object you like
    #   query_queue = Queue.new
    #   res.send_async(Message.new("example.com", Types.MX),  query_queue, query_id)
    #   query_id_2 = res.send_async(Message.new("example.com", Types.A), query_queue)
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
    #
    #== If EventMachine is being used :
    # 
    #If EventMachine is being used (see Dnsruby::Resolver::use_eventmachine, then this method returns
    #an EM::Deferrable object. When the response is known, then the Deferrable will complete.
    #If a queue (and ID) is passed in, then the response will also be 
    #pushed to the Queue. Note that an ID is not automatically generated by this version.
    # 
    #=== Example invocations :
    #
    #    deferrable = res.send_async(msg)
    #    deferrable = res.send_async(msg, use_tcp)
    #    deferrable = res.send_async(msg, q, id, use_tcp)
    #    
    #=== Example code  
    #* Here is an example of using the code in an EventMachine style :
    #
    #    require 'Dnsruby'
    #    require 'eventmachine'
    #    res = Dnsruby::Resolver.new
    #    Dnsruby::Resolver.use_eventmachine
    #    Dnsruby::Resolver.start_eventmachine_loop(false)
    #    EventMachine::run {
    #      df = res.send_async(Dnsruby::Message.new("example.com"))
    #      df.callback {|msg|
    #         puts "Response : #{msg}"
    #         EM.stop}
    #      df.errback {|msg, err|
    #         puts "Response : #{msg}"
    #         puts "Error: #{err}"
    #         EM.stop}
    #    }
    #
    #* And an example in a normal Dnsruby style :
    #
    #    require 'Dnsruby'
    #    res = Dnsruby::Resolver.new
    #    Dnsruby::Resolver.use_eventmachine
    #    Dnsruby::Resolver.start_eventmachine_loop(true) # default
    #    q = Queue.new
    #    id = res.send_async(Dnsruby::Message.new("example.com"),q)
    #    id, response, error = q.pop
    #
    def send_async(*args) # msg, client_queue, client_query_id)
      if (Resolver.eventmachine?)
        if (!@resolver_em)
          @resolver_em = ResolverEM.new(self)
        end
        return @resolver_em.send_async(*args)
      else
        if (!@resolver_ruby) # @TODO@ Synchronize this?
          @resolver_ruby = ResolverRuby.new(self)
        end
        return @resolver_ruby.send_async(*args)
      end
    end
    
    # Close the Resolver. Unfinished queries are terminated with OtherResolvError.
    def close
      [@resolver_em, @resolver_ruby].each do |r| r.close if r end
    end

    # Create a new Resolver object. If no parameters are passed in, then the default 
    # system configuration will be used. Otherwise, a Hash may be passed in with the 
    # following optional elements : 
    # 
    # 
    # * :port
    # * :use_tcp
    # * :tsig
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
      @resolver_em = nil
      @resolver_ruby = nil
      @src_address = nil
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
        elsif (args[0].class == String)
          set_config_nameserver(args[0])          
        elsif (args[0].class == Config)
          # also accepts a Config object from Dnsruby::Resolv
          @config = args[0]
        end
      else
        # Anything to do?
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
      if (@resolver_em)
        @resolver_em.reset_attributes
      end
      if (@resolver_ruby)
        @resolver_ruby.reset_attributes
      end
     
      # Attributes
      @query_timeout = DefaultQueryTimeout
      @retry_delay = DefaultRetryDelay
      @retry_times = DefaultRetryTimes
      @packet_timeout = DefaultPacketTimeout
      @port = DefaultPort
      @udp_size = DefaultUDPSize
      @use_tcp = false
      @tsig = nil
      @ignore_truncation = false
      @config = Config.new()
      @src_addr        = '0.0.0.0'
      @src_port        = 0
      @recurse = true
      @persistent_udp = false
      @persistent_tcp = false
      @single_resolvers=[]
      @dnssec = true
    end
    
    def update #:nodoc: all
      #Update any resolvers we have with the latest config
      @single_resolvers.each do |res|
        [:port, :use_tcp, :tsig, :ignore_truncation, :packet_timeout, 
          :src_address, :src_port, :persistent_tcp, :persistent_udp, :recurse, 
          :udp_size, :dnssec].each do |param|
          
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
    
    #--
    #@TODO@ Should really auto-generate these methods.
    #Also, any way to tie them up with SingleResolver RDoc?
    #++
    
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
    
    #Sets the TSIG to sign outgoing messages with.
    #Pass in either a Dnsruby::RR::TSIG, or a key_name and key (or just a key)
    #Pass in nil to stop tsig signing.
    #* res.tsig=(tsig_rr)
    #* res.tsig=(key_name, key)
    #* res.tsig=nil # Stop the resolver from signing
    def tsig=(t)
      @tsig=t
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
    
    def dnssec=(d)
      @dnssec = d
      update
    end
    
    def udp_size=(s)
      @udp_size = s
      update
    end
    #Tell Dnsruby to use EventMachine for I/O. 
    #
    #If EventMachine is not used, then the pure Ruby event loop in Dnsruby will
    #be used instead.
    #
    #If EventMachine is not available on the platform, then a RuntimeError will be raised.
    #
    #Takes a bool to say whether or not to use EventMachine.
    def Resolver.use_eventmachine(on=true)
      if (on && !@@event_machine_available)
        raise RuntimeError.new("EventMachine is not available in this environment!")
      end
      @@use_eventmachine = on
      if (on)
        TheLog.info("EventMachine will be used for IO")
      else
        TheLog.info("EventMachine will not be used for IO")
      end
    end
    #Check whether EventMachine will be used by Dnsruby
    def Resolver.eventmachine?
      return @@use_eventmachine
    end
    #If EventMachine is being used, then this method tells Dnsruby whether or not
    #to start the EventMachine loop. If you want to use Dnsruby client code as 
    #is, but using EventMachine for I/O, then Dnsruby must start the EventMachine
    #loop for you. This is the default behaviour.
    #If you want to use EventMachine-style code, where everything is wrapped
    #up in an EventMachine::run{} call, then this method should be called with
    #false as the parameter.
    #
    #Takes a bool argument to say whether or not to start the event loop when required.
    def Resolver.start_eventmachine_loop(on=true)
      @@start_eventmachine_loop=on
      if (on)
        TheLog.info("EventMachine loop will be started by Dnsruby")
      else
        TheLog.info("EventMachine loop will not be started by Dnsruby")
      end
    end
    #Checks whether Dnsruby will start the EventMachine loop when required.
    def Resolver.start_eventmachine_loop?
      return @@start_eventmachine_loop
    end
    def generate_timeouts(base=0) #:nodoc: all
      #These should be be pegged to the single_resolver they are targetting :
      #  e.g. timeouts[timeout1]=nameserver
      timeouts = {}
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
            timeouts[base+offset]=[res, retry_count]
          else
            if (timeouts.has_key?(base+retry_delay+offset))
              TheLog.error("Duplicate timeout key!")
              raise RuntimeError.new("Duplicate timeout key!")
            end
            timeouts[base+retry_delay+offset]=[res, retry_count]
          end
        end
      end
      return timeouts      
    end
  end
  
  # This class implements the I/O using EventMachine.
  # This is the preferred implementation. 
  # NOTE - EM does not work properly on Windows with version 0.8.1 - do not use!
  class ResolverEM #:nodoc: all
    TIMER_PERIOD = 0.1
    def initialize(parent)
      @parent=parent
    end
    def reset_attributes #:nodoc: all
    end
    class PersistentData
      attr_accessor :outstanding, :deferrable, :to_send, :timeouts, :timer_procs, :timer_keys_sorted, :finish
    end
    def send_async(*args) #msg, client_queue=nil, client_query_id=nil)
      msg=args[0]
      client_queue=nil
      client_query_id=nil
      if (args.length>1)
        client_queue=args[1]
        if (args.length > 2)
          client_query_id = args[2]
        end
      end
      # We want to send the query to the first resolver.
      # We then want to set up all the timers for all of the events which might happen
      #   (first round timers, retry timers, etc.)
      # The callbacks for these should be able to cancel any of the rest (including any for broken resolvers)
      # We can then forget about the query, as all the callbacks will be lodged with EventMachine.
      
      EventMachineInterface::start_em_for_resolver(self)
      persistent_data = PersistentData.new
      persistent_data.deferrable = EM::DefaultDeferrable.new
      persistent_data.outstanding = []
      persistent_data.to_send = 0
      persistent_data.timeouts=@parent.generate_timeouts(Time.now)
      persistent_data.timer_procs = {}
      persistent_data.finish = false
      persistent_data.timeouts.keys.sort.each do |timeout|
        value = persistent_data.timeouts[timeout]
        #        timeout = timeout.round
        single_resolver, retry_count = value
        persistent_data.to_send+=1
        df = nil
        if (timeout == 0) 
          # Send immediately
          TheLog.debug("Sending first EM query")
          df = send_new_em_query(single_resolver, msg, client_queue, client_query_id, persistent_data)
          persistent_data.outstanding.push(df)
        else
          # Send later
          persistent_data.timer_procs[timeout]=Proc.new{
            TheLog.debug("Sending #{timeout} delayed EM query")
            df = send_new_em_query(single_resolver, msg, client_queue, client_query_id, persistent_data)
            persistent_data.outstanding.push(df)
          }
        end
      end
      query_timeout = @parent.query_timeout
      if (query_timeout > 0)
        persistent_data.timer_procs[Time.now+query_timeout]=Proc.new{
          cancel_queries(persistent_data)
          return_to_client(persistent_data.deferrable, client_queue, client_query_id, nil, ResolvTimeout.new("Query timed out after query_timeout=#{query_timeout.round} seconds"))
        }
      end
      persistent_data.timer_keys_sorted = persistent_data.timer_procs.keys.sort
      EventMachine::add_timer(0) {process_eventmachine_timers(persistent_data)}
      return persistent_data.deferrable
    end
    
    # Close the Resolver. Unfinished queries are terminated with OtherResolvError.
    def close
      # @TODO@ We need a list of open deferrables so that we can complete them
    end
    
    def process_eventmachine_timers(persistent_data)
      if (persistent_data.finish)
        return
      end
      now = Time.now
      persistent_data.timer_keys_sorted.each do |timeout|
        if (timeout > now)
          break
        end
        persistent_data.timer_procs[timeout].call
        persistent_data.timer_procs.delete(timeout)
        persistent_data.timer_keys_sorted.delete(timeout)
      end
      EventMachine::add_timer(TIMER_PERIOD) {process_eventmachine_timers(persistent_data)}
    end
    
    def send_new_em_query(single_resolver, msg, client_queue, client_query_id, persistent_data)
      df = single_resolver.send_async(msg) # client_queue, client_query_id)
      persistent_data.to_send-=1
      df.callback { |answer|
        TheLog.debug("Response returned")
        persistent_data.outstanding.delete(df)
        cancel_queries(persistent_data)
        return_to_client(persistent_data.deferrable, client_queue, client_query_id, answer, nil)
      }  
      df.errback { |response, error|
        TheLog.debug("Error #{error} returned")
        persistent_data.outstanding.delete(df)
        if (response!="cancelling")

          if (error.kind_of?(ResolvTimeout))
            #   - if it was a timeout, then check which number it was, and how many retries are expected on that server
            #       - if it was the last retry, on the last server, then return a timeout to the client (and clean up)
            #       - otherwise, continue
            # Do we have any more packets to send to this resolver?
            if (persistent_data.outstanding.empty? && persistent_data.to_send==0)
              TheLog.debug("Sending timeout to client")
              return_to_client(persistent_data.deferrable, client_queue, client_query_id, response, error)
            end
          elsif (error.kind_of?NXDomain)
            #   - if it was an NXDomain, then return that to the client, and stop all new queries (and clean up)
            TheLog.debug("NXDomain - returning to client")
            cancel_queries(persistent_data)
            return_to_client(persistent_data.deferrable, client_queue, client_query_id, response, error)
          elsif (error.kind_of?FormErr)
            #   - if it was a FormErr, then return that to the client, and stop all new queries (and clean up)
            TheLog.debug("FormErr - returning to client")
            cancel_queries(persistent_data)
            return_to_client(persistent_data.deferrable, client_queue, client_query_id, response, error)
          else
            #   - if it was any other error, then remove that server from the list for that query
            #   If a Too Many Open Files error, then don't remove, but let retry work.
            if (!(error.to_s=~/Errno::EMFILE/))
              remove_server(single_resolver, persistent_data)
              TheLog.debug("Removing #{single_resolver.server} from resolver list for this query")
            else
              TheLog.debug("NOT Removing #{single_resolver.server} due to Errno::EMFILE")          
            end
            #        - if it was the last server, then return an error to the client (and clean up)
            if (persistent_data.outstanding.empty? && persistent_data.to_send==0)
              #          if (outstanding.empty?)
              TheLog.debug("Sending error to client")
              return_to_client(persistent_data.deferrable, client_queue, client_query_id, response, error)
            end
          end
        end
      }  
      return df
    end
    
    def remove_server(server, persistent_data)
      # Go through persistent_data.timeouts and check all the values for that resolver
      persistent_data.timeouts.each do |key, value|
        if (value[0] == server)
          # Remove the server from the list
          persistent_data.timer_procs.delete(key)
          persistent_data.timer_keys_sorted.delete(key)
        end
      end      
    end
    
    def cancel_queries(persistent_data)
      TheLog.debug("Cancelling EM queries")
      persistent_data.outstanding.each do |df|
        df.set_deferred_status :failed, "cancelling", "cancelling"
      end
      # Cancel the next tick
      persistent_data.finish = true
    end
    
    def return_to_client(deferrable, client_queue, client_query_id, answer, error)
      if (client_queue)
        client_queue.push([client_query_id, answer, error])
      end
      #  We call set_defered_status when done
      if (error != nil)
        deferrable.set_deferred_status :failed, answer, error
      else
        deferrable.set_deferred_status :succeeded, answer
      end
      EventMachineInterface::stop_em_for_resolver(self)
    end
  end

  # This class implements the I/O using pure Ruby, with no dependencies.
  class ResolverRuby #:nodoc: all
    def initialize(parent)
      reset_attributes
      @parent=parent
    end
    def reset_attributes #:nodoc: all
      # data structures
      @mutex=Mutex.new
      @query_list = {}
      @timeouts = {}
    end
    def send_async(*args) # msg, client_queue, client_query_id=nil)
      msg=args[0]
      client_queue=nil
      client_query_id=nil
      client_queue=args[1]
      if (args.length > 2)
        client_query_id = args[2]
      end

      
      # This is the whole point of the Resolver class.
      # We want to use multiple SingleResolvers to run a query.
      # So we kick off a system with select_thread where we send
      # a query with a queue, but log ourselves as observers for that
      # queue. When a new response is pushed on to the queue, then the
      # select thread will call this class' handler method IN THAT THREAD.
      # When the final response is known, this class then sticks it in
      # to the client queue.
      
      q = Queue.new
      if (client_query_id==nil)
        client_query_id = Time.now + rand(10000)
      end
      
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
        
        query_timeout = Time.now+@parent.query_timeout
        if (@parent.query_timeout == 0)
          query_timeout = Time.now+31536000 # a year from now
        end
        @timeouts[client_query_id]=[query_timeout, generate_timeouts()]
      }
      
      # Now do querying stuff using SingleResolver
      # All this will be handled by the tick method (if we have 0 as the first timeout)
      st = SelectThread.instance
      st.add_observer(q, self)
      tick if tick_needed
      return client_query_id
    end
    
    def generate_timeouts() #:nodoc: all
      # Create the timeouts for the query from the retry_times and retry_delay attributes. 
      # These are created at the same time in case the parameters change during the life of the query.
      # 
      # These should be absolute, rather than relative
      # The first value should be Time.now[      
      time_now = Time.now
      timeouts=@parent.generate_timeouts(time_now)
      return timeouts
    end
    
    # Close the Resolver. Unfinished queries are terminated with OtherResolvError.
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
              res.send_async(msg, select_queue, id)
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
  end   
end