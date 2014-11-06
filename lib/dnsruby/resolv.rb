# The Resolv class can be used to resolve addresses using /etc/hosts and /etc/resolv.conf,
# 
# The DNS class may be used to perform more queries. If greater control over the sending
# of packets is required, then the Resolver or SingleResolver classes may be used.
module Dnsruby
class Resolv

  # Looks up the first IP address for +name+
  def self.getaddress(name)
    DefaultResolver.getaddress(name)
  end

  # Looks up all IP addresses for +name+
  def self.getaddresses(name)
    DefaultResolver.getaddresses(name)
  end

  # Iterates over all IP addresses for +name+
  def self.each_address(name, &block)
    DefaultResolver.each_address(name, &block)
  end

  # Looks up the first hostname of +address+
  def self.getname(address)
    DefaultResolver.getname(address)
  end

  # Looks up all hostnames of +address+
  def self.getnames(address)
    DefaultResolver.getnames(address)
  end

  # Iterates over all hostnames of +address+
  def self.each_name(address, &proc)
    DefaultResolver.each_name(address, &proc)
  end

  # Creates a new Resolv using +resolvers+
  def initialize(resolvers=[Hosts.new, DNS.new])
    @resolvers = resolvers
  end

  # Looks up the first IP address for +name+
  def getaddress(name)
    each_address(name) {|address| return address}
    raise ResolvError.new("no address for #{name}")
  end

  # Looks up all IP addresses for +name+
  def getaddresses(name)
    ret = []
    each_address(name) {|address| ret << address}
    return ret
  end

  # Iterates over all IP addresses for +name+
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

  # Looks up the first hostname of +address+
  def getname(address)
    each_name(address) {|name| return name}
    raise ResolvError.new("no name for #{address}")
  end

  # Looks up all hostnames of +address+
  def getnames(address)
    ret = []
    each_name(address) {|name| ret << name}
    return ret
  end

  # Iterates over all hostnames of +address+
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


  require 'dnsruby/cache'
  require 'dnsruby/DNS'
  require 'dnsruby/hosts'
  require 'dnsruby/message'
  require 'dnsruby/update'
  require 'dnsruby/zone_transfer'
  require 'dnsruby/dnssec'
  require 'dnsruby/zone_reader'

  # Default Resolver to use for Dnsruby class methods
  DefaultResolver = self.new

  # Address RegExp to use for matching IP addresses
  AddressRegex = /(?:#{IPv4::Regex})|(?:#{IPv6::Regex})/
end
end
