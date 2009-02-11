#@TODO@ Max size for cache?

#This class implements a cache, which stores both RRSets and negative responses. 
#It respects ttl expiration - records are deleted from the cache after they expire
require 'singleton'
module Dnsruby
  class Cache 
    # How do we store the records?
    # How about a hash of domain name -> hash2
    # Each hash2 is type -> [expiration, data] where data is either RRSet or nil
    class Negative
      attr_accessor :type, :name, :soa
    end
    def initialize()
      clear_cache
    end
  
    def clear_cache()
      @rrsets = Hash.new
      @negatives = Hash.new # Store.new # Do these have a ttl? Yes - the SOA minimum field (RFC 2308)
    end
  
    def rrsets_for_domain(d)
      domain = d.to_s.downcase
      return @rrsets[domain]
    end
    def get_rrs_and_exps(domain, type_in)
      type = Types.new(type_in).code
      if (rrsets = rrsets_for_domain(domain))
        if (type_rrs = rrsets[type])
          # Check expiry
          if (type_rrs[0]) < Time.now.to_i
            delete_rrset(domain, type)
            return nil
          end
          return type_rrs
        else
          return nil
        end
      else
        return nil
      end
    end
    def rrsets(domain, type)
      type_rrs = get_rrs_and_exps(domain, type)
      if (type_rrs)
        return type_rrs[1]
      else return nil
      end
    end
    def rrset_expiration(domain, type)
      type_rrs = get_rrs_and_exps(domain, type)
      if (type_rrs)
        return type_rrs[0]
      else return nil
      end
    end
    def delete_rrset(domain, type)
      (rrsets_for_domain(domain)).delete(type)
    end
    def add_rrset(r)
      # Are we updating an existing entry? If so, then replace it if the expiration
      # is later
      rrs = rrsets(r.name, r.type)
      r_expiration = Time.now.to_i + r.ttl
      if (rrs && (rrset_expiration(r.name, r.type) < r_expiration))
        # Overwrite it
        rrsets_for_domain(r.name)[r.type.code] = [r_expiration, r]
      elsif (!rrs)
        # Create it
        # See if we can get a hash for the name
        rrsets_for_dom = rrsets_for_domain(r.name)
        if (!rrsets_for_dom || !(rrsets_for_dom.instance_of?Hash))
          @rrsets[r.name.to_s.downcase] = Hash.new
          rrsets_for_dom = rrsets_for_domain(r.name)
        end      
        rrsets_for_dom[r.type.code] = [r_expiration, r]
      end
    end
  
    def neg_sets_for_domain
    end
    def add_negative()
    
    end
    def negatives(name, type)
      return []
    end
  
  
    # The main public lookup method.
    # Either returns the valid RRSet, or a Negative
    def lookup(n, t)
      name = Name.create(n)
      type = Types.new(t)
      # Look up in the valid RRSets
      if (rrsets = rrsets(name, type))
        return rrsets
      end
      # If no luck, then look up in the Negatives
      if (negative = negatives(name, type))
        return negative
      end
      return nil
    end
  
    def inspect
      return "RRSets : #{@rrsets},\nNegatives #{@negatives}\n"
    end
  end
end