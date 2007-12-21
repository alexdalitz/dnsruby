# @TODO@
# RFC4033, section 7
#   There is one more step that a security-aware stub resolver can take
#   if, for whatever reason, it is not able to establish a useful trust
#   relationship with the recursive name servers that it uses: it can
#   perform its own signature validation by setting the Checking Disabled
#   (CD) bit in its query messages.  A validating stub resolver is thus
#   able to treat the DNSSEC signatures as trust relationships between
#   the zone administrators and the stub resolver itself. 

module Dnsruby
  class DnssecVerifier
    # A class to cache trusted keys
    class KeyCache
      def initialize(keys=[])
        @keys = []
        add(keys)
      end
      def add(k)
        if (k == nil)
          return false
        elsif (k.instance_of?RRSet)
          k.rrs.each {|rr| @keys.push(rr)}
        elsif (k.kind_of?RR)
          @keys.push(k)
        elsif (k.kind_of?Array)
          k.each {|rr| @keys.push(rr)}
        else 
          return false
        end
        remove_duplicate_keys
        return true
      end
      def remove_duplicate_keys
        # @TODO@ There must be a better way than this!!
        @keys.each_index do |index|
          key = @keys[index]
          (index+1..@keys.length-1).each do |pos|
            if (key == @keys[pos])
              @keys.delete_at(pos)
            end
          end
        end
      end
      def each
        @keys.each {|key| yield key}
      end
      def keys
        return @keys 
      end
    end    

    @@trusted_keys = KeyCache.new
    @@to_be_trusted_keys = []

    #    def initialize
    #    # @TODO@ Maybe write a recursive validating resolver?
    #    
    #    end
  
    def self.check_rr_data(rrset, sigrec)
      #Each RR MUST have the same owner name as the RRSIG RR;
      if (rrset.name.to_s != sigrec.name.to_s)
        raise VerifyError.new("RRSET should have same owner name as RRSIG for verification (rrsert=#{rrset.name}, sigrec=#{sigrec.name}")
      end

      #Each RR MUST have the same class as the RRSIG RR;
      if (rrset.klass != sigrec.klass)
        raise VerifyError.new("RRSET should have same DNS class as RRSIG for verification")
      end

      #Each RR in the RRset MUST have the RR type listed in the
      #RRSIG RR's Type Covered field;
      if (rrset.type != sigrec.type_covered)
        raise VerifyError.new("RRSET should have same type as RRSIG for verification")
      end

      #Each RR in the RRset MUST have the TTL listed in the
      #RRSIG Original TTL Field;
      if (rrset.ttl  != sigrec.ttl)
        raise VerifyError.new("RRSET should have same ttl as RRSIG for verification")
      end
    
      # Now check that we are in the validity period for the RRSIG
      now = Time.now.to_i
      if ((sigrec.expiration < now) || (sigrec.inception > now))
        raise VerifyError.new("Signature record not in validity period")
      end
    end
    
    # Add the specified key(s) to the trusted key cache.
    # k can be a DNSKEY, or an Array or RRSet of DNSKEYs.
    def self.add_trusted_key(k)
      @@trusted_keys.add(k)
    end
    
    # Wipes the cache of trusted keys
    def self.clear_trusted_keys
      @@trusted_keys = KeyCache.new
      @@to_be_trusted_keys = []
    end
    
    def self.check_ds(key, ds)
      if (ds.check_key(key))
        @@trusted_keys.add(key)
      end
    end
    
    def self.verify_message(msg, keys = nil)
      # Use the set of trusted keys to check any RRSets we can, ideally
      # those of other DNSKEY RRSets first. Then, see if we can use any of the
      # new total set of keys to check the rest of the rrsets.
      # Return true if we can verify the whole message.
            
      @@trusted_keys.add(keys)
      
      msg.each_section do |section|
        ds_rrset = section.rrset(Types.DS)
        if (ds_rrset && ds_rrset.num_sigs > 0)
          if (verify_signature(ds_rrset))
            ds_rrset.rrs.each do |ds|
              # Work out which key this refers to, and add it to the trusted key store
              found = false
              msg.each_section do |section|
                section.rrset('DNSKEY').rrs.each do |rr|
                  if (check_ds(rr, ds))
                    found = true
                  end
                end
              end
              @@trusted_keys.each {|key|
                if (check_ds(key, ds))
                  found = true
                end
              }
              # If we couldn't find the trusted key, then we should store the 
              # key tag and digest in a @@to_be_trusted_keys.
              # Each time we see a new key (which has been signed) then we should 
              # check if it is sitting on the to_be_trusted_keys store. 
              # If it is, then we should add it to the trusted_keys and remove the
              # DS from the to_be_trusted store
              if (!found)
                @@to_be_trusted_keys.push(ds)
              end
            end
          else 
          end
        end
        
        key_rrset = section.rrset(Types.DNSKEY)
        if (key_rrset && key_rrset.num_sigs > 0)
          if (verify_signature(key_rrset))
            key_rrset.rrs.each do |rr|
              @@trusted_keys.add(rr)
            end
          else
            # See if the keys match any of the to_be_trusted_keys
            key_rrset.rrs.each do |key|
              @@to_be_trusted_keys.each do |tbtk|
                if (check_ds(key, tbtk))
                  @@to_be_trusted_keys.delete(tbtk)
                end
              end
            end
          end
        end
      end
      
      msg.section_rrsets.each do |section, rrsets|
        rrsets.each do |rrset|
          if (section == "additional" && rrset.num_sigs == 0)
            next
          end
          if (!verify_signature(rrset))
            return false
          end
        end
      end
      return true
    end
    
    def self.get_matching_key(keys, sigrecs)
      if ((keys == nil) || (sigrecs == nil))
        return nil, nil
      end
      keys.each {|key|
        sigrecs.each {|sig|
          if ((key.key_tag == sig.key_tag) && (key.algorithm == sig.algorithm))
            return key, sig
          end
        }
      }
      return nil, nil
    end
  
    # Verify the signature of an rrset encoded with the specified dnskey record
    def self.verify_signature(rrset, keys = nil)
      sigrecs = rrset.sigs
      #      print "\n\n    NO RRSIGS!!!\n\n" if (rrset.num_sigs == 0)
      return true if (rrset.num_sigs == 0)
      sigrecs.each do |sigrec|
        check_rr_data(rrset, sigrec)
      end

      keyrec = nil
      sigrec = nil
      keyrec, sigrec = get_matching_key(@@trusted_keys, sigrecs)
      if (keyrec == nil)
        keyrec, sigrec = get_matching_key(keys, sigrecs)        
      end
      
      return false if !keyrec
     
      # RFC 4034
      #3.1.8.1.  Signature Calculation
      
      if (keyrec.sep_key? && !keyrec.zone_key?)
        TheLog.error("DNSKEY with with SEP flag set and Zone Key flag not set was used to verify RRSIG over RRSET - this is not allowed by RFC4034 section 2.1.1")
        # @TODO@ Raise an exception?
        return false
      end          

      #Any DNS names in the RDATA field of each RR MUST be in
      #canonical form; and
      #The RRset MUST be sorted in canonical order.
      rrset = rrset.sort_canonical

      sig_data =sigrec.sig_data

      #RR(i) = owner | type | class | TTL | RDATA length | RDATA
      rrset.each do |rec|
        data = MessageEncoder.new { |msg|
          msg.put_rr(rec, true)
        }.to_s # @TODO@ worry about wildcards here?
        sig_data += data
      end
      
      # Now calculate the signature
      verified = false
      if (sigrec.algorithm == Algorithms.RSASHA1)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA1.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == HMAC_SHA256)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA256.new, sigrec.signature, sig_data)
      else
        raise RuntimeError.new("Algorithm #{sigrec.algorithm.string} unsupported by Dnsruby")
      end
    
      if (verified)
        # Sort out the TTLs - set it to the minimum valid ttl
        expiration_diff = (sigrec.expiration - Time.now.to_i).abs
        rrset.ttl = ([rrset.ttl, sigrec.ttl, sigrec.original_ttl, 
            expiration_diff].sort)[0]

        return true
      end
      return false
    end

  end  
end