# @TODO@ Cache should only add answer if it is "in-bailiwick" for the query
# i.e. if it is a subdomain of the server it was served by

# Cache should also cache negative answers
# Remember to remove expired items

class Cache 
  # How do we store the records?
  def initialize()
    @rrsets = [] # @TODO@ Need an expiry
    @negatives = [] # Do these have a ttl?
  end
  
  def add_negative()
    
  end
  
  def add_rrset(r)
    # @TODO@ Are we updating an existing entry? If so, then replace it!
    foundrr = find_rrset(r.name, r.type, r.class)
    if (foundrr && (foundrr.))
      
    end
    @rrsets.push(r)
  end
end