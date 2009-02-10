# @TODO@ Cache should only add answer if it is "in-bailiwick" for the query
# i.e. if it is a subdomain of the server it was served by

# Cache should also cache negative answers
# Remember to remove expired items

class Cache 
  # How do we store the records?
  # How about an array of hashes?
  # Each hash is a domain name -> hash2
  # Each hash2 is type -> [expiration, data] where data is either RRSet or nil
  class Negative
    attr_accessor :type, :name, :soa
  end
  def initialize()
    @rrsets = []    
    @negatives = [] # Store.new # Do these have a ttl? Yes - the SOA minimum field (RFC 2308)
  end
  
  def rrsets_for_domain(domain)
    return @rrsets[domain.to_s.lowercase]
  end
  def get_rrs_and_exps(domain, type)
    rrsets = rrsets_for_domain(domain)
    type_rrs = rrsets[Types.new(type)]
    # Check expiry
    if (type_rrs[0]) < Time.now.to_i
      delete_rrset(domain, type)
      return nil
    end
    return type_rrs
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
      # Add it
      rrsets_for_domain()[r.type] = [r_expiration, r]
    end
  end
  
  def neg_sets_for_domain
  end
  def add_negative()
    
  end
  
  
  # The main public lookup method.
  # Either returns the valid RRSet, or a Negative
  def lookup(name, type)
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
end