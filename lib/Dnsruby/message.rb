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
require 'Dnsruby/name'
require 'Dnsruby/resource/resource'
module Dnsruby
  #===Defines a DNS packet.
  # 
  #RFC 1035 Section 4.1, RFC 2136 Section 2, RFC 2845
  #
  #===Sections
  #Message objects have five sections:
  #
  #* The header section, a Dnsruby::Header object.
  # 
  #      msg.header=Header.new(...)
  #      header = msg.header
  #
  #* The question section, an array of Dnsruby::Question objects.
  # 
  #      msg.add_question(Question.new(domain, type, klass))
  #      msg.each_question do |question|  ....   end
  #
  #* The answer section, an array of Dnsruby::RR objects.
  #
  #      msg.add_answer(RR.create({:name    => "a2.example.com",
  #		      :type    => "A", :address => "10.0.0.2"}))
  #      msg.each_answer {|answer| ... }
  #
  #* The authority section, an array of Dnsruby::RR objects.
  #
  #      msg.add_authority(rr)
  #      msg.each_authority {|rr| ... }
  #
  #* The additional section, an array of Dnsruby::RR objects.
  # 
  #      msg.add_additional(rr)
  #      msg.each_additional {|rr| ... }
  # 
  #In addition, each_resource iterates the answer, additional
  #and authority sections :
  #
  #      msg.each_resource {|rr| ... }
  #
  #===Packet format encoding
  #
  #      Dnsruby::Message#encode
  #      Dnsruby::Message::decode(data)
  #
  #===Additional information
  #security_level records the current DNSSEC status of this Message.
  #answerfrom records the server which this Message was received from.
  #cached records whether this response came from the cache.
  #
  class Message
    # The security level (see RFC 4035 section 4.3)
    class SecurityLevel < CodeMapper
      INDETERMINATE = -2
      BOGUS = -1
      UNCHECKED = 0
      INSECURE = 1
      SECURE = 2
      update()
    end
    # If dnssec is set on, then each message will have the security level set
    # To find the precise error (if any), call Dnsruby::Dnssec::validate(msg) -
    # the resultant exception will define the error.
    attr_accessor :security_level
    # If there was a problem verifying this message with DNSSEC, then securiy_error
    # will hold a description of the problem. It defaults to ""
    attr_accessor :security_error

    # If the Message was returned from the cache, the cached flag will be set
    # true. It will be false otherwise.
    attr_accessor :cached


    class Section < Array
      def initialize(msg = nil)
        @msg = msg
        super(0)
      end
      # Return the rrset of the specified type in this section
      def rrset(name, type=Types.A, klass=Classes::IN)
        rrs = select{|rr| 
          type_ok = (rr.type==type)
          if (rr.type == Types::RRSIG)
            type_ok = (rr.type_covered == type)
          end
          if (!(/\.\z/ =~ name.to_s))
            name = name.to_s + "."
          end
          type_ok && (rr.klass == klass) && (rr.name.to_s(true).downcase == name.to_s().downcase)
        }
        rrset = RRSet.new()
        rrs.each do |rr|
          rrset.add(rr)
        end
        return rrset
      end
      
      # Return an array of all the rrsets in the section
      def rrsets(type = nil, include_opt = false)
        if (type && !(Types === type))
          type = Types.new(type)
        end
        ret = []
        each do |rr|
          next if (!include_opt && (rr.type == Types::OPT))
          #          if (type)
          #            next if ((rr.type == Types.RRSIG) && (type != Types.RRSIG) && (rr.type_covered != type))
          #            next if (rr.type != type)
          #          end
          if (type)
            # if this is an rrsig type, then :
            #    only include it if the type_covered is the type requested,
            #    OR if the type requested is an RRSIG
            if (rr.type == Types::RRSIG)
              if ((rr.type_covered == type) || (type == Types::RRSIG))
              else
                next
              end
              #              next if ((rr.type_covered != type) || (type != Types.RRSIG))
            elsif (rr.type != type)
              next
            end
          end

          found_rrset = false
          ret.each do |rrset|
            found_rrset = rrset.add(rr)
            break if found_rrset
          end
          if (!found_rrset)
            ret.push(RRSet.new(rr))
          end
        end
        return ret        
      end
      def ==(other)
        return false unless (other.instance_of?Message::Section)
        return false if (other.rrsets(nil, true).length != self.rrsets(nil, true).length)
        otherrrsets = other.rrsets(nil, true)
        self.rrsets(nil, true).each {|rrset|
          return false unless otherrrsets.include?rrset
        }
        return true
      end

      def remove_rrset(name, type)
        # Remove all RRs with the name and type from the section.
        # Need to worry about header counts here - can we get Message to
        # update the counts itself, rather than the section worrying about it?
        rrs_to_delete = []
        each do |rr|
          next if rr.rr_type == Types::OPT
          if ((rr.name.to_s.downcase == name.to_s.downcase) &&
                ((rr.type == type) ||
                  ((rr.type == Types::RRSIG) && (rr.type_covered == type)) ))
            rrs_to_delete.push(rr)
          end
        end
        rrs_to_delete.each {|rr|
          delete(rr)
        }
        @msg.update_counts if @msg
      end
    end
    #Create a new Message. Takes optional name, type and class
    #
    #type defaults to A, and klass defaults to IN
    #
    #*  Dnsruby::Message.new("example.com") # defaults to A, IN
    #*  Dnsruby::Message.new("example.com", 'AAAA')
    #*  Dnsruby::Message.new("example.com", Dnsruby::Types.PTR, "HS")
    #
    def initialize(*args)
      @header = Header.new()
      #      @question = Section.new(self)
      @question = []
      @answer = Section.new(self)
      @authority = Section.new(self)
      @additional = Section.new(self)
      @tsigstate = :Unsigned
      @signing = false
      @tsigkey = nil
      @answerfrom = nil
      @answerip = nil
      @send_raw = false
      @do_validation = true
      @do_caching = true
      @security_level = SecurityLevel.UNCHECKED
      @security_error = nil
      @cached = false
      type = Types::A
      klass = Classes::IN
      if (args.length > 0)
        name = args[0]
        if (args.length > 1)
          type = Types.new(args[1])
          if (args.length > 2)
            klass = Classes.new(args[2])
          end
        end
        add_question(name, type, klass)
      end
    end
    
    #The question section, an array of Dnsruby::Question objects.
    attr_reader :question
    
    #The answer section, an array of Dnsruby::RR objects.
    attr_reader :answer
    #The authority section, an array of Dnsruby::RR objects.
    attr_reader :authority
    #The additional section, an array of Dnsruby::RR objects.
    attr_reader :additional
    #The header section, a Dnsruby::Header object.
    attr_accessor :header
    
    #If this Message is a response from a server, then answerfrom contains the address of the server
    attr_accessor :answerfrom
    
    #If this Message is a response from a server, then answerfrom contains the IP address of the server
    attr_accessor :answerip
    
    #If this Message is a response from a server, then answersize contains the size of the response
    attr_accessor :answersize
    
    #If this message has been verified using a TSIG RR then tsigerror contains
    #the error code returned by the TSIG verification. The error will be an RCode
    attr_accessor :tsigerror
    
    #Can be
    #* :Unsigned - the default state
    #* :Signed - the outgoing message has been signed
    #* :Verified - the incoming message has been verified by TSIG
    #* :Intermediate - the incoming message is an intermediate envelope in a TCP session
    #in which only every 100th envelope must be signed
    #* :Failed - the incoming response failed verification
    attr_accessor :tsigstate
    
    #--
    attr_accessor :tsigstart
    #++
    
    #Set send_raw if you wish to send and receive the response to this Message
    #with no additional processing. In other words, if set, then Dnsruby will
    #not touch the Header of the outgoing Message. This option does not affect
    #caching or dnssec validation
    #
    #This option should not normally be set.
    attr_accessor :send_raw

    #do_validation is set by default. If you do not wish dnsruby to validate
    #this message (on a Resolver with @dnssec==true), then set do_validation
    #to false. This option does not affect caching, or the header options
    attr_accessor :do_validation

    #do_caching is set by default. If you do not wish dnsruby to inspect the
    #cache before sending the query, nor cache the result of the query, then
    #set do_caching to false.
    attr_accessor :do_caching

    def get_exception
      exception = nil
      if (rcode==RCode.NXDOMAIN)
        exception = NXDomain.new
      elsif (rcode==RCode.SERVFAIL)
        exception = ServFail.new
      elsif (rcode==RCode.FORMERR)
        exception = FormErr.new
      elsif (rcode==RCode.NOTIMP)
        exception = NotImp.new
      elsif (rcode==RCode.REFUSED)
        exception = Refused.new
      elsif (rcode==RCode.NOTZONE)
        exception = NotZone.new
      elsif (rcode==RCode.NOTAUTH)
        exception = NotAuth.new
      elsif (rcode==RCode.NXRRSET)
        exception = NXRRSet.new
      elsif (rcode==RCode.YXRRSET)
        exception = YXRRSet.new
      elsif (rcode==RCode.YXDOMAIN)
        exception = YXDomain.new
      elsif (rcode >= RCode.BADSIG && rcode <= RCode.BADALG)
        return VerifyError.new # @TODO@
      end
      return exception
    end

    def ==(other)
      ret = false
      if (other.kind_of?Message)
        ret = @header == other.header &&
          @question[0] == other.question[0] &&
          @answer == other.answer &&
          @authority == other.authority &&
          @additional == other.additional
      end
      return ret
    end

    # Return the first rrset of the specified attributes in the message
    def rrset(name, type, klass = Classes::IN)
      [@answer, @authority, @additional].each do |section|
        if ((rrset = section.rrset(name, type, klass)).length > 0)
          return rrset
        end
      end
      return RRSet.new
    end
    
    # Return the rrsets of the specified type in the message
    def rrsets(type, klass=Classes::IN)
      rrsetss = []
      [@answer, @authority, @additional].each do |section|
        if ((rrsets = section.rrsets(type, klass)).length > 0)
          rrsets.each {|rrset|
            rrsetss.push(rrset)
          }
        end
      end
      return rrsetss
    end
    
    # Return a hash, with the section as key, and the RRSets in that
    # section as the data : {section => section_rrs}
    def section_rrsets(type = nil, include_opt = false)
      ret = {}
      ["answer", "authority", "additional"].each do |section|
        ret[section] = self.send(section).rrsets(type, include_opt)
      end
      return ret
    end
    
    #Add a new Question to the Message. Takes either a Question,
    #or a name, and an optional type and class.
    #
    #* msg.add_question(Question.new("example.com", 'MX'))
    #* msg.add_question("example.com") # defaults to Types.A, Classes.IN
    #* msg.add_question("example.com", Types.LOC)
    def add_question(question, type=Types.A, klass=Classes.IN)
      if (!question.kind_of?Question)
        question = Question.new(question, type, klass)
      end
      @question << question
      update_counts
    end
    
    def each_question
      @question.each {|rec|
        yield rec
      }
    end

    def update_counts # :nodoc:all
      @header.ancount = @answer.length
      @header.arcount = @additional.length
      @header.qdcount = @question.length
      @header.nscount = @authority.length
    end
    
    
    def add_answer(rr) #:nodoc: all
      if (!@answer.include?rr)
        @answer << rr
        update_counts
      end
    end
    
    def each_answer
      @answer.each {|rec|
        yield rec
      }
    end
    
    def add_authority(rr) #:nodoc: all
      if (!@authority.include?rr)
        @authority << rr
        update_counts
      end
    end
    
    def each_authority
      @authority.each {|rec|
        yield rec
      }
    end
    
    def add_additional(rr) #:nodoc: all
      if (!@additional.include?rr)
        @additional << rr
        update_counts
      end
    end
    
    def each_additional
      @additional.each {|rec|
        yield rec
      }
    end
    
    #Yields each section (question, answer, authority, additional)
    def each_section
      [@answer, @authority, @additional].each {|section| yield section}
    end
    
    #Calls each_answer, each_authority, each_additional
    def each_resource
      each_answer {|rec| yield rec}
      each_authority {|rec| yield rec}
      each_additional {|rec| yield rec}
    end

    # Returns the TSIG record from the ADDITIONAL section, if one is present.
    def tsig
      if (@additional.last)
        if (@additional.last.rr_type == Types.TSIG)
          return @additional.last
        end
      end
      return nil
    end
    
    #Sets the TSIG to sign this message with. Can either be a Dnsruby::RR::TSIG
    #object, or it can be a (name, key) tuple, or it can be a hash which takes
    #Dnsruby::RR::TSIG attributes (e.g. name, key, fudge, etc.)
    def set_tsig(*args)
      if (args.length == 1)
        if (args[0].instance_of?RR::TSIG)
          @tsigkey = args[0]
        elsif (args[0].instance_of?Hash)
          @tsigkey = RR.create({:type=>'TSIG', :klass=>'ANY'}.merge(args[0]))
        else
          raise ArgumentError.new("Wrong type of argument to Dnsruby::Message#set_tsig - should be TSIG or Hash")
        end
      elsif (args.length == 2)
        @tsigkey = RR.create({:type=>'TSIG', :klass=>'ANY', :name=>args[0], :key=>args[1]})
      else
        raise ArgumentError.new("Wrong number of arguments to Dnsruby::Message#set_tsig")
      end
    end
    
    #Was this message signed by a TSIG?
    def signed?
      return (@tsigstate == :Signed ||
          @tsigstate == :Verified ||
          @tsigstate == :Failed)
    end
    
    #If this message was signed by a TSIG, was the TSIG verified?
    def verified?
      return (@tsigstate == :Verified)
    end
    
    def get_opt
      each_additional do |r|
        if (r.type == Types::OPT)
          return r
        end
      end
      return nil
    end
    
    def rcode
      rcode = @header.get_header_rcode
      opt = get_opt
      if (opt != nil)
        rcode = rcode.code + (opt.xrcode.code << 4)
        rcode = RCode.new(rcode)
      end
      return rcode;
    end

    def to_s
      retval = "";
      
      if (@answerfrom != nil && @answerfrom != "")
        retval = retval + ";; Answer received from #{@answerfrom} (#{@answersize} bytes)\n;;\n";
      end
      retval = retval + ";; Security Level : #{@security_level.string}\n"
      
      retval = retval + ";; HEADER SECTION\n"
      # OPT pseudosection? EDNS flags, udpsize
      opt = get_opt
      if (!opt)
        retval = retval + @header.to_s
      else
        retval = retval + @header.to_s_with_rcode(rcode())
      end
      retval = retval + "\n"
      
      if (opt)
        retval = retval + opt.to_s
        retval = retval + "\n"
      end
            
      section = (@header.opcode == OpCode.UPDATE) ? "ZONE" : "QUESTION";
      retval = retval +  ";; #{section} SECTION (#{@header.qdcount}  record#{@header.qdcount == 1 ? '' : 's'})\n";
      each_question { |qr|
        retval = retval + ";; #{qr.to_s}\n";
      }
      
      if (@answer.size > 0)
        retval = retval + "\n";
        section = (@header.opcode == OpCode.UPDATE) ? "PREREQUISITE" : "ANSWER";
        retval = retval + ";; #{section} SECTION (#{@header.ancount}  record#{@header.ancount == 1 ? '' : 's'})\n";
        each_answer { |rr|
          retval = retval + rr.to_s + "\n";
        }
      end
      
      if (@authority.size > 0)
        retval = retval + "\n";
        section = (@header.opcode == OpCode.UPDATE) ? "UPDATE" : "AUTHORITY";
        retval = retval + ";; #{section} SECTION (#{@header.nscount}  record#{@header.nscount == 1 ? '' : 's'})\n";
        each_authority { |rr|
          retval = retval + rr.to_s + "\n";
        }
      end
      
      if ((@additional.size > 0 && !opt) || (@additional.size > 1))
        retval = retval + "\n";
        retval = retval + ";; ADDITIONAL SECTION (#{@header.arcount}  record#{@header.arcount == 1 ? '' : 's'})\n";
        each_additional { |rr|
          if (rr.type != Types::OPT)
            retval = retval + rr.to_s+ "\n"
          end
        }
      end
      
      return retval;
    end
    
    #Signs the message. If used with no arguments, then the message must have already
    #been set (set_tsig). Otherwise, the arguments can either be a Dnsruby::RR::TSIG
    #object, or a (name, key) tuple, or a hash which takes
    #Dnsruby::RR::TSIG attributes (e.g. name, key, fudge, etc.)
    #
    #NOTE that this method should only be called by the resolver, rather than the
    #client code. To use signing from the client, call Dnsruby::Resolver#tsig=
    def sign!(*args) #:nodoc: all
      if (args.length > 0)
        set_tsig(*args)
        sign!
      else
        if ((@tsigkey) && @tsigstate == :Unsigned)
          @tsigkey.apply(self)
        end
      end
    end
    
    #Return the encoded form of the message
    # If there is a TSIG record present and the record has not been signed
    # then sign it
    def encode
      if ((@tsigkey) && @tsigstate == :Unsigned && !@signing)
        @signing = true
        sign!
        @signing = false
      end
      return MessageEncoder.new {|msg|
        header = @header
        header.encode(msg)
        @question.each {|q|
          msg.put_name(q.qname)
          msg.put_pack('nn', q.qtype.code, q.qclass.code)
        }
        [@answer, @authority, @additional].each {|rr|
          rr.each { |r|
            msg.put_rr(r)
          }
        }
      }.to_s
    end
    
    #Decode the encoded message
    def Message.decode(m)
      o = Message.new()
      begin
        MessageDecoder.new(m) {|msg|
          o.header = Header.new(msg)
          o.header.qdcount.times {
            question = msg.get_question
            o.question << question
          }
          o.header.ancount.times {
            rr = msg.get_rr
            o.answer << rr
          }
          o.header.nscount.times {
            rr = msg.get_rr
            o.authority << rr
          }
          o.header.arcount.times { |count|
            start = msg.index
            rr = msg.get_rr
            if (rr.type == Types::TSIG)
              if (count!=o.header.arcount-1)
                Dnsruby.log.Error("Incoming message has TSIG record before last record")
                raise DecodeError.new("TSIG record present before last record")
              end
              o.tsigstart = start # needed for TSIG verification
            end
            o.additional << rr
          }
        }
      rescue DecodeError => e
        # So we got a decode error
        # However, we might have been able to fill in many parts of the message
        # So let's raise the DecodeError, but add the partially completed message
        e.partial_message = o
        raise e
      end
      return o
    end
    
    #In dynamic update packets, the question section is known as zone and
    #specifies the zone to be updated.
    alias :zone :question
    alias :add_zone :add_question
    alias :each_zone :each_question
    #In dynamic update packets, the answer section is known as pre or
    #prerequisite and specifies the RRs or RRsets which must or
    #must not preexist.
    alias :pre :answer
    alias :add_pre :add_answer
    alias :each_pre :each_answer
    #In dynamic update packets, the answer section is known as pre or
    #prerequisite and specifies the RRs or RRsets which must or
    #must not preexist.
    alias :prerequisite :pre
    alias :add_prerequisite :add_pre
    alias :each_prerequisite :each_pre
    #In dynamic update packets, the authority section is known as update and
    #specifies the RRs or RRsets to be added or delted.
    alias :update :authority
    alias :add_update :add_authority
    alias :each_update :each_authority
    
  end
  
  #The header portion of a DNS packet
  #
  #RFC 1035 Section 4.1.1
  class Header
    MAX_ID = 65535
    
    # The header ID
    attr_accessor :id
    
    #The query response flag
    attr_accessor :qr
    
    #Authoritative answer flag
    attr_accessor :aa
    
    #Truncated flag
    attr_accessor :tc
    
    #Recursion Desired flag
    attr_accessor :rd
    
    #The Checking Disabled flag
    attr_accessor :cd
    
    #The Authenticated Data flag
    #Relevant in DNSSEC context.
    #(The AD bit is only set on answers where signatures have been
    #cryptographically verified or the server is authoritative for the data
    #and is allowed to set the bit by policy.)
    attr_accessor :ad
    
    #The query response flag
    attr_accessor :qr
    
    #Recursion available flag
    attr_accessor :ra
    
    #Query response code
    #deprecated - use Message#rcode
    #    attr_reader :rcode

    # This new get_header_rcode method is intended for use only by the Message class.
    # This is because the Message OPT section may contain an extended rcode (see
    # RFC 2671 section 4.6). Using the header rcode only ignores this extension, and
    # is not recommended.
    def get_header_rcode
      @rcode
    end
    
    # The header opcode
    attr_reader :opcode
    
    #The number of records in the question section of the message
    attr_accessor :qdcount
    #The number of records in the authoriy section of the message
    attr_accessor :nscount
    #The number of records in the answer section of the message
    attr_accessor :ancount
    #The number of records in the additional record section og the message
    attr_accessor :arcount
    
    def initialize(*args)
      if (args.length == 0)
        @id = rand(MAX_ID)
        @qr = false
        @opcode=OpCode.Query
        @aa = false
        @ad=false
        @tc = false
        @rd = false # recursion desired
        @ra = false # recursion available
        @cd=false
        @rcode=RCode.NoError
        @qdcount = 0
        @nscount = 0
        @ancount = 0
        @arcount = 0
      elsif (args.length == 1)
        decode(args[0])
      end
    end
    
    def opcode=(op)
      @opcode = OpCode.new(op)
    end
    
    def rcode=(rcode)
      @rcode = RCode.new(rcode)
    end
    
    def Header.new_from_data(data)
      header = Header.new
      MessageDecoder.new(data) {|msg|
        header.decode(msg)}
      return header
    end
    
    def data
      return MessageEncoder.new {|msg|
        self.encode(msg)
      }.to_s
    end
    
    def encode(msg)
      msg.put_pack('nnnnnn',
        @id,
        (@qr ? 1:0) << 15 |
        (@opcode.code & 15) << 11 |
        (@aa ? 1:0) << 10 |
        (@tc ? 1:0) << 9 |
        (@rd ? 1:0) << 8 |
        (@ra ? 1:0) << 7 |
        (@ad ? 1:0) << 5 |
        (@cd ? 1:0) << 4 |
        (@rcode.code & 15),
        @qdcount,
        @ancount,
        @nscount,
        @arcount)
    end
    
    def Header.decrement_arcount_encoded(bytes)
      header = Header.new
      header_end = 0
      MessageDecoder.new(bytes) {|msg|
        header.decode(msg)
        header_end = msg.index
      }
      header.arcount = header.arcount - 1
      bytes[0,header_end]=MessageEncoder.new {|msg|
        header.encode(msg)}.to_s
      return bytes
    end
    
    def ==(other)
      return @qr == other.qr &&
        @opcode == other.opcode &&
        @aa == other.aa &&
        @tc == other.tc &&
        @rd == other.rd &&
        @ra == other.ra &&
        @cd == other.cd &&
        @ad == other.ad &&
        @rcode == other.get_header_rcode
    end
    
    def to_s
      to_s_with_rcode(@rcode)
    end
      
    def to_s_with_rcode(rcode)
      retval = ";; id = #{@id}\n";
      
      if (@opcode == OpCode::Update)
        retval += ";; qr = #{@qr}    " +\
          "opcode = #{@opcode.string}    "+\
          "rcode = #{@rcode.string}\n";
        
        retval += ";; zocount = #{@qdcount}  "+\
          "prcount = #{@ancount}  " +\
          "upcount = #{@nscount}  "  +\
          "adcount = #{@arcount}\n";
      else
        retval += ";; qr = #{@qr}    "  +\
          "opcode = #{@opcode.string}    " +\
          "aa = #{@aa}    "  +\
          "tc = #{@tc}    " +\
          "rd = #{@rd}\n";
        
        retval += ";; ra = #{@ra}    " +\
          "ad = #{@ad}    "  +\
          "cd = #{@cd}    "  +\
          "rcode  = #{rcode.string}\n";
        
        retval += ";; qdcount = #{@qdcount}  " +\
          "ancount = #{@ancount}  " +\
          "nscount = #{@nscount}  " +\
          "arcount = #{@arcount}\n";
      end
      
      return retval;
    end
    
    def decode(msg)
      @id, flag, @qdcount, @ancount, @nscount, @arcount =
        msg.get_unpack('nnnnnn')
      @qr = (((flag >> 15)&1)==1)?true:false
      @opcode = OpCode.new((flag >> 11) & 15)
      @aa = (((flag >> 10)&1)==1)?true:false
      @tc = (((flag >> 9)&1)==1)?true:false
      @rd = (((flag >> 8)&1)==1)?true:false
      @ra = (((flag >> 7)&1)==1)?true:false
      @ad = (((flag >> 5)&1)==1)?true:false
      @cd = (((flag >> 4)&1)==1)?true:false
      @rcode = RCode.new(flag & 15)
    end
    
    alias zocount qdcount
    alias zocount= qdcount=
    
    alias prcount ancount
    alias prcount= ancount=
    
    alias upcount nscount
    alias upcount= nscount=
    
    alias adcount arcount
    alias adcount= arcount=
    
  end
  
  class MessageDecoder #:nodoc: all
    attr_reader :index
    def initialize(data)
      @data = data
      @index = 0
      @limit = data.length
      yield self
    end
    
    def has_remaining
      return @limit-@index > 0
    end
    
    def get_length16
      len, = self.get_unpack('n')
      save_limit = @limit
      @limit = @index + len
      d = yield(len)
      if @index < @limit
        raise DecodeError.new("junk exists")
      elsif @limit < @index
        raise DecodeError.new("limit exceeded")
      end
      @limit = save_limit
      return d
    end
    
    def get_bytes(len = @limit - @index)
      d = @data[@index, len]
      @index += len
      return d
    end
    
    def get_unpack(template)
      len = 0
      littlec = ?c
      bigc = ?C
      littleh = ?h
      bigh = ?H
      littlen = ?n
      bign = ?N
      star = ?*
      if (littlec.class != Fixnum)
        # We're using Ruby 1.9 - convert the codes
        littlec = littlec.getbyte(0)
        bigc = bigc.getbyte(0)
        littleh = littleh.getbyte(0)
        bigh = bigh.getbyte(0)
        littlen = littlen.getbyte(0)
        bign = bign.getbyte(0)
        star = star.getbyte(0)
      end
      template.each_byte {|byte|
        case byte
        when littlec, bigc
          len += 1
        when littleh, bigh
          len += 1
        when littlen
          len += 2
        when bign
          len += 4
        when star
          len = @limit-@index
        else
          raise StandardError.new("unsupported template: '#{byte.chr}' in '#{template}'")
        end
      }
      raise DecodeError.new("limit exceeded") if @limit < @index + len
      arr = @data.unpack("@#{@index}#{template}")
      @index += len
      return arr
    end
    
    def get_string
      len = @data[@index]
      if (len.class == String)
        len = len.getbyte(0)
      end
      raise DecodeError.new("limit exceeded\nlimit = #{@limit}, index = #{@index}, len = #{len}\n") if @limit < @index + 1 + (len ? len : 0)
      d = @data[@index + 1, len]
      @index += 1 + len
      return d
    end
    
    def get_string_list
      strings = []
      while @index < @limit
        strings << self.get_string
      end
      strings
    end
    
    def get_name
      return Name.new(self.get_labels)
    end
    
    def get_labels(limit=nil)
      limit = @index if !limit || @index < limit
      d = []
      while true
        temp = @data[@index]
        if (temp.class == String)
          temp = (temp.getbyte(0))
        end
        case temp # @data[@index]
        when 0
          @index += 1
          return d
        when 192..255
          idx = self.get_unpack('n')[0] & 0x3fff
          if limit <= idx
            raise DecodeError.new("non-backward name pointer")
          end
          save_index = @index
          @index = idx
          d += self.get_labels(limit)
          @index = save_index
          return d
        else
          d << self.get_label
        end
      end
      return d
    end
    
    def get_label
      begin
        #        label = Name::Label.new(Name::decode(self.get_string))
        label = Name::Label.new(self.get_string)
        return label
        #         return Name::Label::Str.new(self.get_string)
      rescue ResolvError => e
        raise DecodeError.new(e) # Turn it into something more suitable
      end
    end
    
    def get_question
      name = self.get_name
      type, klass = self.get_unpack("nn")
      q = Question.new(name, type, klass)
      return q
    end
    
    def get_rr
      name = self.get_name
      type, klass, ttl = self.get_unpack('nnN')
      klass = Classes.new(klass)
      typeclass = RR.get_class(type, klass)
      # @TODO@ Trap decode errors here, and somehow mark the record as bad.
      # Need some way to represent raw data only
      rec = self.get_length16 {typeclass.decode_rdata(self)}
      rec.name=name
      rec.ttl=ttl
      rec.type = type
      rec.klass = klass
      return rec
    end
  end
  
  class MessageEncoder #:nodoc: all
    def initialize
      @data = ''
      @names = {}
      yield self
    end
    
    def to_s
      return @data
    end
    
    def put_bytes(d)
      @data << d
    end
    
    def put_pack(template, *d)
      @data << d.pack(template)
    end
    
    def put_length16
      length_index = @data.length
      @data << "\0\0"
      data_start = @data.length
      yield
      data_end = @data.length
      @data[length_index, 2] = [data_end - data_start].pack("n")
    end
    
    def put_string(d)
      self.put_pack("C", d.length)
      @data << d
    end
    
    def put_string_list(ds)
      ds.each {|d|
        self.put_string(d)
      }
    end
    
    def put_rr(rr, canonical=false)
      # RFC4034 Section 6.2
      put_name(rr.name, canonical)
      put_pack("nnN", rr.type.code, rr.klass.code, rr.ttl)
      put_length16 {rr.encode_rdata(self, canonical)}
    end

    def put_name(d, canonical=false, downcase = canonical)
      # DNSSEC requires some records (e.g. NSEC, RRSIG) to be canonicalised, but
      # not downcased. YUK!
      if (downcase)
        d = d.downcase
      end
      put_labels(d.to_a, canonical)
    end
    
    def put_labels(d, do_canonical)
      d.each_index {|i|
        domain = d[i..-1].join(".")
        if (!do_canonical && (idx = @names[domain]))
          self.put_pack("n", 0xc000 | idx)
          return
        else
          @names[domain] = @data.length
          self.put_label(d[i])
        end
      }
      @data << "\0"
    end
    
    
    def put_label(d)
      #      s, = Name.encode(d)
      s = d
      raise RuntimeError, "length of #{s} is #{s.string.length} (larger than 63 octets)" if s.string.length > 63
      self.put_string(s.string)
    end
  end
  
  #A Dnsruby::Question object represents a record in the
  #question section of a DNS packet.
  #
  #RFC 1035 Section 4.1.2
  class Question
    # The Question name
    attr_reader :qname
    # The Question type
    attr_reader :qtype
    # The Question class
    attr_reader :qclass
    
    #Creates a question object from the domain, type, and class passed
    #as arguments.
    #
    #If a String is passed in, a Name, IPv4 or IPv6 object is created.
    #
    #If an IPv4 or IPv6 object is used then the type is set to PTR.
    def initialize(*args)
      @qtype = Types::A
      @qclass = Classes::IN
      if (args.length > 0)
        if (args.length > 1)
          @qtype = Types.new(args[1])
          if (args.length > 2)
            @qclass = Classes.new(args[2])
          end
        end
      else
        raise ArgumentError.new("Must pass at least a name!")
      end
      # If the name looks like an IP address then do an appropriate
      # PTR query.
      @qname=args[0]
      case @qname.to_s
      when IPv4::Regex
        @qname = IPv4.create(@qname).to_name
        @qtype = Types.PTR
      when IPv6::Regex
        @qname = IPv6.create(@qname).to_name
        @qtype = Types.PTR
      when Name
      when IPv6
        @qtype = Types.PTR
      when IPv4
        @qtype = Types.PTR
      else
        @qname = Name.create(@qname)
      end
    end
    
    def qtype=(qtype)
      @qtype = Types.new(qtype)
    end
    
    def qclass=(qclass)
      @qclass = Classes.new(qclass)
    end
    
    def qname=(qname)
      case qname
      when IPv4::Regex
        @qname = IPv4.create(qname).to_name
        @qtype = Types.PTR
      when IPv6::Regex
        @qname = IPv6.create(qname).to_name
        @qtype = Types.PTR
      when Name
      when IPv6
        @qtype = Types.PTR
      when IPv4
        @qtype = Types.PTR
      else
        @qname = Name.create(qname)
      end
    end
    
    #Returns a string representation of the question record.
    def to_s
      return "#{@qname}.\t#{@qclass.string}\t#{@qtype.string}";
    end
    
    # For Updates, the qname field is redefined to zname (RFC2136, section 2.3)
    alias zname qname
    # For Updates, the qtype field is redefined to ztype (RFC2136, section 2.3)
    alias ztype qtype
    # For Updates, the qclass field is redefined to zclass (RFC2136, section 2.3)
    alias zclass qclass
    
    alias type qtype
  end
end