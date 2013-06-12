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
require 'Dnsruby/code_mapper'
require 'Dnsruby/ipv4'
require 'Dnsruby/ipv6'
require 'timeout'
require 'Dnsruby/TheLog'
#= Dnsruby library
#Dnsruby is a thread-aware DNS stub resolver library written in Ruby.
#
#It is based on resolv.rb, the standard Ruby DNS implementation, 
#but gives a complete DNS implementation, including DNSSEC.
#
#The Resolv class can be used to resolve addresses using /etc/hosts and /etc/resolv.conf, 
#or the DNS class can be used to make DNS queries. These interfaces will attempt to apply 
#the default domain and searchlist when resolving names.
#
#The Resolver and SingleResolver interfaces allow finer control of individual messages. 
#The Resolver class sends queries to multiple resolvers using various retry mechanisms. 
#The SingleResolver class is used by Resolver to send individual Messages to individual 
#resolvers.
#
#Resolver queries return Dnsruby::Message objects.  Message objects have five
#sections:
#
#* The header section, a Dnsruby::Header object.
#
#* The question section, a list of Dnsruby::Question objects.
#
#* The answer section, a list of Dnsruby::Resource objects.
#
#* The authority section, a list of Dnsruby::Resource objects.
#
#* The additional section, a list of Dnsruby::Resource objects.
#
#
#== example
#  res = Dnsruby::Resolver.new # System default
#  ret = res.query("example.com")
#  print "#{ret.anwer.length} answer records returned, #{ret.answer.rrsets.length} RRSets returned in aswer section\n"
#
#  p Dnsruby::Resolv.getaddress("www.ruby-lang.org")
#  p Dnsruby::Resolv.getname("210.251.121.214")
#
#  Dnsruby::DNS.open {|dns|
#    p dns.getresources("www.ruby-lang.org", Dnsruby::Types.A).collect {|r| r.address}
#    p dns.getresources("ruby-lang.org", 'MX').collect {|r| [r.exchange.to_s, r.preference]}
#  }
#
#== exceptions
#
#* ResolvError < StandardError
#  
#* ResolvTimeout < TimeoutError
# 
#* NXDomain < ResolvError
#  
#* FormErr < ResolvError
#  
#* ServFail < ResolvError
#  
#* NotImp < ResolvError
#  
#* Refused < ResolvError
#
#* NotZone < ResolvError
#
#* YXDomain < ResolvError
#
#* YXRRSet < ResolvError
#  
#* NXRRSet < ResolvError
#
#* NotAuth < ResolvError
#
#* OtherResolvError < ResolvError
#  
#== I/O
#Dnsruby implements a pure Ruby event loop to perform I/O.
#Support for EventMachine has been deprecated.
#
#== DNSSEC
#Dnsruby supports DNSSEC and NSEC(3).
#DNSSEC support is on by default - but no trust anchors are configured by default.
#See Dnsruby::Dnssec for more details.
#
#== Bugs
#* NIS is not supported.
#* /etc/nsswitch.conf is not supported.
#* NSEC3 validation still TBD
module Dnsruby

  # @TODO@ Remember to update version in dnsruby.gemspec!
  VERSION = 1.54
  def Dnsruby.version
    return VERSION
  end
  
  @@logger = Logger.new(STDOUT)
  @@logger.level = Logger::FATAL
  #Get the log for Dnsruby
  #Use this to set the log level
  #e.g. Dnsruby.log.level = Logger::INFO
  def Dnsruby.log
    @@logger
  end
      
  class OpCode < CodeMapper
    Query = 0        # RFC 1035
    IQuery = 1        # RFC 1035
    Status = 2        # RFC 1035
    Notify = 4        # RFC 1996
    Update = 5        # RFC 2136
    
    update()
  end
  
  class RCode < CodeMapper
    NOERROR = 0       # RFC 1035
    FORMERR = 1       # RFC 1035
    SERVFAIL = 2       # RFC 1035
    NXDOMAIN = 3       # RFC 1035
    NOTIMP = 4       # RFC 1035
    REFUSED = 5       # RFC 1035
    YXDOMAIN = 6       # RFC 2136
    YXRRSET = 7       # RFC 2136
    NXRRSET = 8       # RFC 2136
    NOTAUTH = 9       # RFC 2136
    NOTZONE = 10       # RFC 2136
    
#    BADVERS = 16 # an EDNS ExtendedRCode
    BADSIG = 16
    BADKEY = 17
    BADTIME = 18
    BADMODE = 19
    BADNAME = 20
    BADALG = 21
    
    update()    
  end

  class ExtendedRCode < CodeMapper
    BADVERS = 16
    update()
  end
  
  class Classes < CodeMapper
    IN        = 1       # RFC 1035
    CH        = 3       # RFC 1035
    #    CHAOS        = 3       # RFC 1035
    HS        = 4       # RFC 1035
    #    HESIOD        = 4       # RFC 1035
    NONE      = 254     # RFC 2136
    ANY       = 255     # RFC 1035
    update()
    
    def unknown_string(arg)
      if (arg=~/^CLASS/i)
        Classes.add_pair(arg, arg.gsub('CLASS', '').to_i)
        set_string(arg)
      else
        raise ArgumentError.new("String #{arg} not a member of #{self.class}")
      end
    end
    
    def unknown_code(arg)
      Classes.add_pair('CLASS' + arg.to_s, arg)
      set_code(arg)
    end        
    
    # classesbyval and classesbyname functions are wrappers around the
    # similarly named hashes. They are used for 'unknown' DNS RR classess
    # (RFC3597)    
    # See typesbyval and typesbyname, these beasts have the same functionality    
    def Classes.classesbyname(name) #:nodoc: all
      name.upcase!;
      if to_code(name)
        return to_code(name)
      end
      
      if ((name =~/^\s*CLASS(\d+)\s*$/o) == nil)
        raise ArgumentError, "classesbyval() argument is not CLASS### (#{name})"
      end
      
      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'classesbyval() argument larger than ' + 0xffff
      end
      
      return val;
    end
    
    
    
    def Classes.classesbyval(val) #:nodoc: all
      if (val.class == String)
        if ((val =~ /^\s*0*([0-9]+)\s*$/) == nil)
          raise ArgumentError,  "classesbybal() argument is not numeric (#{val})" # unless  val.gsub!("^\s*0*([0-9]+)\s*$", "$1")
          #          val =~ s/^\s*0*([0-9]+)\s*$/$1/o;#
        end
        val = $1.to_i
      end
      
      return to_string(val) if to_string(val)
      
      raise ArgumentError,  'classesbyval() argument larger than ' + 0xffff if val > 0xffff;
      
      return "CLASS#{val}";
    end                
  end
  
  # The RR types explicitly supported by Dnsruby.
  # 
  # New RR types should be added to this set
  class Types < CodeMapper
    SIGZERO   = 0       # RFC2931 consider this a pseudo type
    A         = 1       # RFC 1035, Section 3.4.1
    NS        = 2       # RFC 1035, Section 3.3.11
    MD        = 3       # RFC 1035, Section 3.3.4 (obsolete)
    MF        = 4       # RFC 1035, Section 3.3.5 (obsolete)
    CNAME     = 5       # RFC 1035, Section 3.3.1
    SOA       = 6       # RFC 1035, Section 3.3.13
    MB        = 7       # RFC 1035, Section 3.3.3
    MG        = 8       # RFC 1035, Section 3.3.6
    MR        = 9       # RFC 1035, Section 3.3.8
    NULL      = 10      # RFC 1035, Section 3.3.10
    WKS       = 11      # RFC 1035, Section 3.4.2 (deprecated)
    PTR       = 12      # RFC 1035, Section 3.3.12
    HINFO     = 13      # RFC 1035, Section 3.3.2
    MINFO     = 14      # RFC 1035, Section 3.3.7
    MX        = 15      # RFC 1035, Section 3.3.9
    TXT       = 16      # RFC 1035, Section 3.3.14
    RP        = 17      # RFC 1183, Section 2.2
    AFSDB     = 18      # RFC 1183, Section 1
    X25       = 19      # RFC 1183, Section 3.1
    ISDN      = 20      # RFC 1183, Section 3.2
    RT        = 21      # RFC 1183, Section 3.3
    NSAP      = 22      # RFC 1706, Section 5
    NSAP_PTR  = 23      # RFC 1348 (obsolete)
    SIG       = 24      # RFC 2535, Section 4.1
    KEY       = 25      # RFC 2535, Section 3.1
    PX        = 26      # RFC 2163,
    GPOS      = 27      # RFC 1712 (obsolete)
    AAAA      = 28      # RFC 1886, Section 2.1
    LOC       = 29      # RFC 1876
    NXT       = 30      # RFC 2535, Section 5.2 obsoleted by RFC3755
    EID       = 31      # draft-ietf-nimrod-dns-xx.txt
    NIMLOC    = 32      # draft-ietf-nimrod-dns-xx.txt
    SRV       = 33      # RFC 2052
    ATMA      = 34      # ???
    NAPTR     = 35      # RFC 2168
    KX        = 36      # RFC 2230
    CERT      = 37      # RFC 2538
    DNAME     = 39      # RFC 2672
    OPT       = 41      # RFC 2671
#    APL       = 42      # RFC 3123
    DS        = 43      # RFC 4034
    SSHFP     = 44      # RFC 4255
    IPSECKEY  = 45      # RFC 4025
    RRSIG     = 46      # RFC 4034
    NSEC      = 47      # RFC 4034
    DNSKEY    = 48      # RFC 4034
    DHCID     = 49      # RFC 4701
    NSEC3     = 50      # RFC still pending at time of writing
    NSEC3PARAM= 51      # RFC still pending at time of writing
    HIP       = 55      # RFC 5205
    SPF       = 99      # RFC 4408
    UINFO     = 100     # non-standard
    UID       = 101     # non-standard
    GID       = 102     # non-standard
    UNSPEC    = 103     # non-standard
    TKEY      = 249     # RFC 2930
    TSIG      = 250     # RFC 2931
    IXFR      = 251     # RFC 1995
    AXFR      = 252     # RFC 1035
    MAILB     = 253     # RFC 1035 (MB, MG, MR)
    MAILA     = 254     # RFC 1035 (obsolete - see MX)
    ANY       = 255     # RFC 1035    
    DLV       = 32769   # RFC 4431 (informational)
    update()
    
    def unknown_string(arg) #:nodoc: all
      if (arg=~/^TYPE/i)
        Types.add_pair(arg, arg.gsub('TYPE', '').to_i)
        set_string(arg)
      else
        raise ArgumentError.new("String #{arg} not a member of #{self.class}")
      end
    end
    
    def unknown_code(arg) #:nodoc: all
      Types.add_pair('TYPE' + arg.to_s, arg)
      set_code(arg)
    end        
    
    #--
    # typesbyval and typesbyname functions are wrappers around the similarly named
    # hashes. They are used for 'unknown' DNS RR types (RFC3597)    
    # typesbyname returns they TYPEcode as a function of the TYPE
    # mnemonic. If the TYPE mapping is not specified the generic mnemonic
    # TYPE### is returned.
    def Types.typesbyname(name)  #:nodoc: all
      name.upcase!
      
      if to_code(name)
        return to_code(name)
      end
      
      
      if ((name =~/^\s*TYPE(\d+)\s*$/o)==nil)
        raise ArgumentError, "Net::DNS::typesbyname() argument (#{name}) is not TYPE###"
      end
      
      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'Net::DNS::typesbyname() argument larger than ' + 0xffff
      end
      
      return val;
    end
    
    
    # typesbyval returns they TYPE mnemonic as a function of the TYPE
    # code. If the TYPE mapping is not specified the generic mnemonic
    # TYPE### is returned.
    def Types.typesbyval(val) #:nodoc: all
      if (!defined?val)
        raise ArgumentError,  "Net::DNS::typesbyval() argument is not defined"
      end
      
      if val.class == String
        #      if val.gsub!("^\s*0*(\d+)\s*$", "$1")
        if ((val =~ /^\s*0*(\d+)\s*$", "$1/o) == nil)
          raise ArgumentError,  "Net::DNS::typesbyval() argument (#{val}) is not numeric" 
          #          val =~s/^\s*0*(\d+)\s*$/$1/o;
        end
        
        val = $1.to_i
      end
      
      
      if to_string(val)
        return to_string(val)
      end
      
      raise ArgumentError,  'Net::DNS::typesbyval() argument larger than ' + 0xffff if 
      val > 0xffff;
      
      return "TYPE#{val}";
    end
  end
  
  class QTypes < CodeMapper
    IXFR   = 251  # incremental transfer                [RFC1995]
    AXFR   = 252  # transfer of an entire zone          [RFC1035]
    MAILB  = 253  # mailbox-related RRs (MB, MG or MR)   [RFC1035]
    MAILA  = 254  # mail agent RRs (Obsolete - see MX)   [RFC1035]
    ANY    = 255  # all records                      [RFC1035]
    update()
  end
  
  class MetaTypes < CodeMapper
    TKEY        = 249    # Transaction Key   [RFC2930]
    TSIG        = 250    # Transaction Signature  [RFC2845]
    OPT         = 41     # RFC 2671
  end
  
  # http://www.iana.org/assignments/dns-sec-alg-numbers/
  class Algorithms < CodeMapper
    RESERVED   = 0
    RSAMD5     = 1
    DH         = 2
    DSA        = 3
    ECC        = 4
    RSASHA1    = 5
    RSASHA256  = 8
    RSASHA512  = 10
    INDIRECT   = 252
    PRIVATEDNS = 253
    PRIVATEOID = 254
    update()
    # Referred to as Algorithms.DSA_NSEC3_SHA1
    add_pair("DSA-NSEC3-SHA1", 6)
    # Referred to as Algorithms.RSASHA1_NSEC3_SHA1
    add_pair("RSASHA1-NSEC3-SHA1", 7)
  end  

  # http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
  class Nsec3HashAlgorithms < CodeMapper
    RESERVED = 0
    update()
    add_pair("SHA-1", 1)
  end

  #An error raised while querying for a resource
  class ResolvError < StandardError
  end
  
  #A timeout error raised while querying for a resource
  class ResolvTimeout < TimeoutError
  end
  
  #The requested domain does not exist
  class NXDomain < ResolvError
  end
  
  #A format error in a received DNS message
  class FormErr < ResolvError
  end
  
  #Indicates a failure in the remote resolver
  class ServFail < ResolvError
  end
  
  #The requested operation is not implemented in the remote resolver
  class NotImp < ResolvError
  end
  
  #The requested operation was refused by the remote resolver
  class Refused < ResolvError
  end

  #The update RR is outside the zone (in dynamic update)
  class NotZone < ResolvError
  end

  #Some name that ought to exist, does not exist (in dynamic update)
  class YXDomain < ResolvError
  end

  #Some RRSet that ought to exist, does not exist (in dynamic update)
  class YXRRSet < ResolvError
  end

  #Some RRSet that ought not to exist, does exist (in dynamic update)
  class NXRRSet < ResolvError
  end

  #The nameserver is not responsible for the zone (in dynamic update)
  class NotAuth < ResolvError
  end

  
  #Another kind of resolver error has occurred
  class OtherResolvError < ResolvError
  end

  #An error occurred processing the TSIG
  class TsigError < OtherResolvError
  end
  
  # Sent a signed packet, got an unsigned response
  class TsigNotSignedResponseError < TsigError
  end

  #Indicates an error in decoding an incoming DNS message
  class DecodeError < ResolvError
    attr_accessor :partial_message
  end

  #Indicates an error encoding a DNS message for transmission
  class EncodeError < ResolvError
  end

  #Indicates an error verifying 
  class VerifyError < ResolvError
  end

  #Indicates a zone transfer has failed due to SOA serial mismatch
  class ZoneSerialError < ResolvError
  end

  #The Resolv class can be used to resolve addresses using /etc/hosts and /etc/resolv.conf, 
  #
  #The DNS class may be used to perform more queries. If greater control over the sending 
  #of packets is required, then the Resolver or SingleResolver classes may be used.
  class Resolv
    
    #Looks up the first IP address for +name+
    def self.getaddress(name)
      DefaultResolver.getaddress(name)
    end
    
    #Looks up all IP addresses for +name+
    def self.getaddresses(name)
      DefaultResolver.getaddresses(name)
    end
    
    #Iterates over all IP addresses for +name+
    def self.each_address(name, &block)
      DefaultResolver.each_address(name, &block)
    end
    
    #Looks up the first hostname of +address+
    def self.getname(address)
      DefaultResolver.getname(address)
    end
    
    #Looks up all hostnames of +address+
    def self.getnames(address)
      DefaultResolver.getnames(address)
    end
    
    #Iterates over all hostnames of +address+
    def self.each_name(address, &proc)
      DefaultResolver.each_name(address, &proc)
    end
    
    #Creates a new Resolv using +resolvers+
    def initialize(resolvers=[Hosts.new, DNS.new])
      @resolvers = resolvers
    end
    
    #Looks up the first IP address for +name+
    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("no address for #{name}")
    end
    
    #Looks up all IP addresses for +name+
    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end
    
    #Iterates over all IP addresses for +name+
    def each_address(name)
      if AddressRegex =~ name
        yield name
        return
      end
      yielded = false
      @resolvers.each {|r|
        r.each_address(name) {|address|
          yield address.to_s
          yielded = true
        }
        return if yielded
      }
    end
    
    #Looks up the first hostname of +address+
    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("no name for #{address}")
    end
    
    #Looks up all hostnames of +address+
    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end
    
    #Iterates over all hostnames of +address+
    def each_name(address)
      yielded = false
      @resolvers.each {|r|
        r.each_name(address) {|name|
          yield name.to_s
          yielded = true
        }
        return if yielded
      }
    end
    
    
    require 'Dnsruby/Cache'
    require 'Dnsruby/DNS'
    require 'Dnsruby/Hosts'
    require 'Dnsruby/message'
    require 'Dnsruby/update'
    require 'Dnsruby/zone_transfer'
    require 'Dnsruby/dnssec'
    require 'Dnsruby/zone_reader'
    
    #Default Resolver to use for Dnsruby class methods
    DefaultResolver = self.new
    
    #Address RegExp to use for matching IP addresses
    AddressRegex = /(?:#{IPv4::Regex})|(?:#{IPv6::Regex})/
  end
end
