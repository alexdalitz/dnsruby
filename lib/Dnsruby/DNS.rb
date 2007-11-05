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
require 'Dnsruby/Hosts'
require 'Dnsruby/Config'
require "Dnsruby/Resolver"
module Dnsruby
  #--
  #@TODO@ Asynchronous interface. Do we want a callback (in a new thread) or a queue system?
  #Is there any point in taking a block? May as well...
  #e.g. getaddresses_async(name, Queue|Proc)
  #Could we make the final argument optional to all the standard calls? So they are either sync or async?
  #e.g. getaddresses(name{, Queue|Proc})
  #Yes to all but each_resource - would have to make a new each_resource_async or something...
  #@TODO@ BUT - need to pass in an ID as well as a queue to identify correct response
  #Proc can keep track of query ID itself
  #++

  #== Dnsruby::DNS class
  #DNS stub resolver.
  #
  #=== class methods
  #* Dnsruby::DNS.new(config_info=nil)
  #
  #    ((|config_info|)) should be nil, a string or a hash.
  #    If nil is given, /etc/resolv.conf and platform specific information is used.
  #    If a string is given, it should be a filename which format is same as /etc/resolv.conf.
  #    If a hash is given, it may contains information for nameserver, search and ndots as follows.
  #
  #      Dnsruby::DNS.new({:nameserver=>["210.251.121.21"], :search=>["ruby-lang.org"], :ndots=>1})
  #
  #* Dnsruby::DNS.open(config_info=nil)
  #* Dnsruby::Resolv::DNS.open(config_info=nil) {|dns| ...}
  #
  #=== methods
  #* Dnsruby::DNS#close
  #
  #* Dnsruby::DNS#getaddress(name)
  #* Dnsruby::DNS#getaddresses(name)
  #* Dnsruby::DNS#each_address(name) {|address| ...}
  #    address lookup methods.
  #
  #    ((|name|)) must be an instance of Dnsruby::Name or String.  Resultant
  #    address is represented as an instance of Dnsruby::IPv4 or Dnsruby::IPv6.
  #
  #* Dnsruby::DNS#getname(address)
  #* Dnsruby::DNS#getnames(address)
  #* Dnsruby::DNS#each_name(address) {|name| ...}
  #    These methods lookup hostnames .
  #
  #    ((|address|)) must be an instance of Dnsruby::IPv4, Dnsruby::IPv6 or String.
  #    Resultant name is represented as an instance of Dnsruby::Name.
  #
  #* Dnsruby::DNS#getresource(name, type, class)
  #* Dnsruby::DNS#getresources(name, type, class)
  #* Dnsruby::DNS#each_resource(name, type, class) {|resource| ...}
  #    These methods lookup DNS resources of ((|name|)).
  #    ((|name|)) must be a instance of Dnsruby::Name or String.
  #
  #    ((|type|)) must be a member of Dnsruby::Types
  #    ((|class|)) must be a member of Dnsruby::Classes
  #
  #    Resultant resource is represented as an instance of (a subclass of)
  #    Dnsruby::RR. 
  #    (Dnsruby::RR::IN::A, etc.)
  #
  #The searchlist and other Config info is applied to the domain name if appropriate. All the nameservers
  #are tried (if there is no timely answer from the first).
  #
  #This class uses Resolver to perform the queries.
  class DNS
    # STD0013 (RFC 1035, etc.)
    # ftp://ftp.isi.edu/in-notes/iana/assignments/dns-parameters
    
    def self.open(*args)
      dns = new(*args)
      return dns unless block_given?
      begin
        yield dns
      ensure
        dns.close
      end
    end
    
    def close
      @resolver.close
    end
    
    
    def to_s
      return "DNS : " + @config.to_s
    end
    
    def initialize(config_info=nil)
      @config = Config.new()
      @config.set_config_info(config_info)
      @resolver = Resolver.new(@config)
    end
    
    attr_reader :config    
    
    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("DNS result has no information for #{name}")
    end
    
    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end
    
    def each_address(name)
      each_resource(name) {|resource| yield resource.address}
    end
    
    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("DNS result has no information for #{address}")
    end
    
    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end
    
    def each_name(address)
      case address
      when Name
        ptr = address
      when IPv4::Regex
        ptr = IPv4.create(address).to_name
      when IPv6::Regex
        ptr = IPv6.create(address).to_name
      else
        raise ResolvError.new("cannot interpret as address: #{address}")
      end
      each_resource(ptr, Types.PTR, Classes.IN) {|resource| yield resource.domainname}
    end
    
    def getresource(name, type=Types.A, klass=Classes.IN)
      each_resource(name, type, klass) {|resource| return resource}
      raise ResolvError.new("DNS result has no information for #{name}")
    end
    
    def getresources(name, type=Types.A, klass=Classes.IN)
      ret = []
      each_resource(name, type, klass) {|resource| ret << resource}
      return ret
    end
    
    def send_query(name, type=Types.A, klass=Classes.IN)
      candidates = @config.generate_candidates(name)
      exception = nil
      candidates.each do |candidate|
        q = Queue.new
        msg = Message.new
        msg.header.rd = 1
        msg.add_question(candidate, type, klass)
        @resolver.send_async(msg, q, id)
        id, ret, exception = q.pop
        if (exception == nil && ret.header.rcode == RCode.NOERROR)
          return ret, ret.question[0].qname
        end
      end
      raise exception
    end
    
    def each_resource(name, type=Types.A, klass=Classes.IN, &proc)
      type = Types.new(type)
      klass = Classes.new(klass)
      reply, reply_name = send_query(name, type, klass)
      case reply.header.rcode.code
      when RCode::NOERROR
        extract_resources(reply, reply_name, type, klass, &proc)
        return
        #      when RCode::NXDomain
        #        TheLog.debug("RCode::NXDomain returned - raising error")
        #        raise Config::NXDomain.new(reply_name.to_s)
      else
        TheLog.error("Unexpected rcode : #{reply.header.rcode.string}")
        raise Config::OtherResolvError.new(reply_name.to_s)
      end
      
    end
    
    def extract_resources(msg, name, type, klass)
      #      if type < Types.ANY
      if type == Types.ANY
        n0 = Name.create(name)
        msg.each_answer {|rec|
          yield rec if n0 == rec.name
        }
      end
      yielded = false
      n0 = Name.create(name)
      msg.each_answer {|rec|
        if n0 == rec.name
          case rec.type
          when type
            if (rec.klass == klass)
              yield rec
              yielded = true
            end
          when Types.CNAME
            n0 = rec.domainname
          end
        end
      }
      return if yielded
      msg.each_answer {|rec|
        if n0 == rec.name
          case rec.type
          when type
            if (rec.klass == klass)
              yield rec
            end
          end
        end
      }
    end
    
    class DecodeError < StandardError
    end

    class EncodeError < StandardError
    end

  end
end