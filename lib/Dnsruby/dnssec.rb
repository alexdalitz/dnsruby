#---
# @TODO@
# RFC4033, section 7
#   There is one more step that a security-aware stub resolver can take
#   if, for whatever reason, it is not able to establish a useful trust
#   relationship with the recursive name servers that it uses: it can
#   perform its own signature validation by setting the Checking Disabled
#   (CD) bit in its query messages.  A validating stub resolver is thus
#   able to treat the DNSSEC signatures as trust relationships between
#   the zone administrators and the stub resolver itself. 
#+++
module Dnsruby
  # Dnsruby will, by default, request DNSSEC records on each query. It
  # will also, by default, request that any checking be done by an upstream 
  # resolver - this assumes a secure link to a trusted resolver. In this case,
  # the client application need do nothing to enjoy the benefits of DNSSEC.
  # 
  # If an insecure link or untrusted resolver is used, then it is possible to
  # verify messages using the Dnsruby::Dnssec#verify method, once a chain
  # of trust has been established. In the absence of a signed root, the client 
  # application must supply Dnsruby
  # with a (set of) trusted key(s). Dnsruby can then use those keys to verify 
  # responses, and build up a new set of trusted keys under the apex of the
  # supplied trusted key. For example : 
  #
  #  res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
  #
  #  # Create the trusted key that we know for a parent zone of the zone
  #  # we are interested in. This is assumed to be a Secure Entry Point
  #  # (the SEP flag of the key will be set by default)
  #  trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
  #      :type => Dnsruby::Types.DNSKEY,
  #      :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
  #    })
  #  ret = Dnsruby::DnssecVerifier.add_trusted_key(trusted_key)
  #
  #  # Now use the trusted key to obtain the other keys for the zone
  #  r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.ANY)
  #  if (!Dnsruby::DnssecVerifier.verify(r))
  #     # handle verification failure
  #  end
  #
  #  r = res.query("www.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
  #  if (!Dnsruby::DnssecVerifier.verify(r))
  #     # handle verification failure
  #  end
  #
  #  # Follow the chain of trust
  #  r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DS)
  #  if (!Dnsruby::DnssecVerifier.verify(r))
  #     # handle verification failure
  #  end
  #    
  #  r = res.query("bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
  #  if (!Dnsruby::DnssecVerifier.verify(r))
  #     # handle verification failure
  #  end
  #    
  #  # Now query records in the zone we are interested in. 
  #  # Dnsruby stores all the keys so we can now verify any record signed by
  #  # any key in the trusted key store.
  #  r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.ANY)
  #  if (!Dnsruby::DnssecVerifier.verify(r))
  #     # handle verification failure
  #  end
  #  
  #  # Verify an rrset
  #  rrset = r.answer.rrset('NSEC')
  #  if (!Dnsruby::DnssecVerifier.verify(rrset))
  #     # handle verification failure
  #  end

  class Dnssec
    # A class to cache trusted keys
    class KeyCache #:nodoc: all
      # Cache includes expiration time for keys
      # Cache removes expired records
      def initialize(keys = nil)
        # Store key tag against [expiry, key]
        @keys = {}
        add(keys)
      end
      def add_key_with_expiration(k, expiration)
        priv_add_key(k, expiration)
      end
      def add(k)
        if (k == nil)
          return false
        elsif (k.instance_of?RRSet)
          add_rrset(k)
        elsif (k.kind_of?KeyCache)
          kaes = k.keys_and_expirations
          kaes.keys.each { |keykey|
            #            priv_add_key(keykey, kaes[keykey])
            priv_add_key(keykey[1], keykey[0])
          }
        else 
          raise ArgumentError.new("Expected an RRSet or KeyCache! Got #{k.class}")
        end
        return true
      end
      
      def add_rrset(k)
        # Get expiration from the RRSIG
        # There can be several RRSIGs here, one for each key which has signed the RRSet
        # We want to choose the one with the most secure signing algorithm, key length, 
        # and the longest expiration time - not easy!
        # for now, we simply accept all signed keys
        k.sigs.each { |sig|
          if (sig.type_covered = Types.DNSKEY)
            if (sig.inception <= Time.now.to_i)
              # Check sig.expiration, sig.algorithm
              if (sig.expiration > Time.now.to_i) 
                # add the keys to the store
                k.rrs.each {|rr| priv_add_key(rr, sig.expiration)}
              end
            end
          end
        }
      end
      
      def priv_add_key(k, exp) 
        # Check that the key does not already exist with a longer expiration!
        if (@keys[k] == nil) 
          @keys[k.key_tag] = [exp,k]
        elsif ((@keys[k])[0] < exp)
          @keys[k.key_tag] = [exp,k]
        end
      end
      
      def each
        # Only offer currently-valid keys here
        remove_expired_keys
        @keys.values.each {|v| yield v[1]}
      end
      def keys
        # Only offer currently-valid keys here
        remove_expired_keys
        ks = []
        @keys.values.each {|a| ks.push(a[1])}
        return ks
        #        return @keys.keys
      end
      def keys_and_expirations
        remove_expired_keys
        return keys()
      end
      def remove_expired_keys
        @keys.delete_if {|k,v|
          v[0] < Time.now.to_i
        }
      end
    end  


    class ValidationPolicy
      # Note that any DLV registries which have been configured will only be tried
      # after both the root and any local trust anchors (RFC 5074 section 5)
      
      #* Always use the root and ignore local trust anchors.
      ALWAYS_ROOT_ONLY = 1
      #* Use the root if successful, otherwise try local anchors.
      ROOT_THEN_LOCAL_ANCHORS = 2
      #* Use local trust anchors if available, otherwise use root.
      LOCAL_ANCHORS_THEN_ROOT = 3
      #* Always use local trust anchors and ignore the root.
      ALWAYS_LOCAL_ANCHORS_ONLY = 4
    end
    @@validation_policy = ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT
    
    def Dnssec.validation_policy=(p)
      if ((p >= ALWAYS_ROOT_ONY) && (p <= ALWAYS_LOCAL_ANCHORS))
        @@validation_policy = p
        # @TODO@ Should we be clearing the trusted keys now?
      end
    end
    def Dnssec.validation_policy
      @@validation_policy
    end
    
    # The DNSKEY RRs for the signed root (when it exists)
    @@root_anchors = KeyCache.new
    # @TODO@ Add methods for interacting with root anchors
    
    # The set of trust anchors. 
    # If the root is unsigned, then these must be initialised with at least
    # one trusted key by the client application, if verification is to be performed.
    @@trust_anchors = KeyCache.new
    
    @@dlv_registries = []

    def Dnssec.add_trust_anchor(t)
      self.add_trust_anchor_with_expiration(t, Time.utc(2035,"jan",1,20,15,1).to_i)
    end
    # Add the 
    def self.add_trust_anchor_with_expiration(k, expiration)
      k.flags = k.flags | RR::IN::DNSKEY::SEP_KEY
      @@trust_anchors.add_key_with_expiration(k, expiration)
    end
    
    def Dnssec.remove_trust_anchor(t)
      @@trust_anchors.delete(t)
    end
    # Wipes the cache of trusted keys
    def self.clear_trust_anchors
      @@trust_anchors = KeyCache.new
    end
    
    def self.trust_anchors
      return @@trust_anchors.keys
    end
    
    
    # The set of keys which are trusted. 
    @@trusted_keys = KeyCache.new
    
    # The set of keys which have been indicated by a DS RRSet which has been
    # signed by a trusted key. Although we have not yet located these keys, we
    # have the details (tag and digest) which can identify the keys when we 
    # see them. At that point, they will be added to our trusted keys.
    # @TODO@ Should add TTL to this!
    # @TODO@ Should we just use the (TBD) general cache for these?
    @@to_be_trusted_keys = []

    # Check that the RRSet and RRSIG record are compatible
    def self.check_rr_data(rrset, sigrec)#:nodoc: all
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
    
    # Add the specified keys to the trusted key cache.
    # k can be a KeyCache, or an RRSet of DNSKEYs.
    def self.add_trusted_key(k)
      @@trusted_keys.add(k)
    end
    
    # Wipes the cache of trusted keys
    def self.clear_trusted_keys
      @@trusted_keys = KeyCache.new
      @@to_be_trusted_keys = []
    end
    
    def self.trusted_keys
      return @@trusted_keys.keys
    end

    def self.validate(msg)
      query = Message.new()
      query.header.cd=true
      return self.validate_with_query(query, msg)
    end
    
    def self.validate_with_query(query, msg)
      # SHOULD ALWAYS VERIFY DNSSEC-SIGNED RESPONSES?
      # Yes - if a trust anchor is configured. Otherwise, act on CD bit (in query)
      if (((@@validation_policy > ValidationPolicy::ALWAYS_ROOT_ONLY) && (self.trust_anchors().length > 0)) ||
            # Check query here, and validate if CD is true
          (query.header.cd == true))
        # Validate!
        # Remember we may have to update any expired trusted keys
        validated = false
        if (@@validation_policy == ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY)
          validated = validate_with_achors(msg)
        elsif (@@validation_policy == ValidationPolicy::ALWAYS_ROOT_ONLY)
          validated = validate_with_root(msg)
        elsif (@@validation_policy == ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT)
          validated = validate_with_anchors(msg)
          if (!validated)
            validated = validate_with_root(msg)
          end
        elsif (@@validation_policy == ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS)
          validated = validate_with_root(msg)
          if (!validated)
            validated = validate_with_anchors(msg)
          end
        end
        if (!validated)
          validated = validate_with_dlv(msg)
        end
        return validated
      end
      return true
    end
    
    # @TODO@ Need to be able to verify RRSet with a provided set of keys ONLY
    # None of these keys should be added to the cache
    
    
    # @TODO@ It sounds like we need to maintain several sets of trusted keys :
    #   : one for signed root, one for local anchors, and one from dlv
    # Might it be simpler to write a GenericValidator, and then create three
    # instances - one with root anchors, one with trust anchors, and one for dlv?
    # @TODO@ Each validator should have its own cache!
    def self.validate_with_anchors(msg)
      # @TODO@ What do we do here?
      # See if it is a child of any of our trust anchors.
      # If it is, then see if we have a trusted key for it
      # If we don't, then see if we can get to it from the closest
      # trust anchor
      return true
    end

    def self.validate_with_root(msg)
      # @TODO@ What do we do here?
      # See if we have a trusted key for it
      # If we don't, then see if we can get to it from the closest trusted key
      # If not, then see if we can get there from the root
      return true
    end

    def self.validate_with_dlv(msg)
      # @TODO@ Check 
      return true
    end

    # Check that the key fits a signed DS record key details
    # If so, then add the key to the trusted keys
    def self.check_ds(key, ds_rrset)#:nodoc: all
      expiration = 0
      found = false
      ds_rrset.sigs.each { |sig|
        if (sig.type_covered = Types.DS)
          if (sig.inception <= Time.now.to_i)
            # Check sig.expiration, sig.algorithm
            if (sig.expiration > expiration) 
              expiration = sig.expiration
            end
          end
        end
      }
      if (expiration > 0)
        ds_rrset.each { |ds|
          if (ds.class == RR::IN::DS)
            if (ds.check_key(key))
              @@trusted_keys.add_key_with_expiration(key, expiration)
              found = true
            end
          end
        }
      end
      return found
    end
    
    # Verify the specified message (or RRSet) using the set of trusted keys.
    # If keys is a DNSKEY, or an Array or RRSet of DNSKEYs, then keys
    # is added to the set of trusted keys before the message (or RRSet) is 
    # verified. 
    # 
    # If msg is a Dnsruby::Message, then any signed DNSKEY or DS RRSets are 
    # processed first, and any new keys are added to the trusted key set 
    # before the other RRSets are checked.
    # 
    # msg can be a Dnsruby::Message or Dnsruby::RRSet.
    # keys may be nil, or a KeyCache or an RRSet of Dnsruby::RR::DNSKEY
    # 
    # Returns true if the message verifies OK, and false otherwise.
    def self.verify(msg) # , keys = nil)
      if (msg.kind_of?RRSet)
        return verify_rrset(msg) # , keys)
      end
      # Use the set of trusted keys to check any RRSets we can, ideally
      # those of other DNSKEY RRSets first. Then, see if we can use any of the
      # new total set of keys to check the rest of the rrsets.
      # Return true if we can verify the whole message.
            
      msg.each_section do |section|
        ds_rrset = section.rrset(Types.DS)
        if (ds_rrset && ds_rrset.num_sigs > 0)
          if (verify_rrset(ds_rrset))
            # Need to handle DS RRSets (with RRSIGs) not just DS records.
            #            ds_rrset.rrs.each do |ds|
            # Work out which key this refers to, and add it to the trusted key store
            found = false
            msg.each_section do |section|
              section.rrset('DNSKEY').rrs.each do |rr|
                if (check_ds(rr, ds_rrset))
                  found = true
                end
              end
            end
            (get_keys_to_check()).each {|key|
              if (check_ds(key, ds_rrset))
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
              @@to_be_trusted_keys.push(ds_rrset)
            end
            #            end
          else 
          end
        end
        
        key_rrset = section.rrset(Types.DNSKEY)
        if (key_rrset && key_rrset.num_sigs > 0)
          if (verify_rrset(key_rrset))
            #            key_rrset.rrs.each do |rr|
            @@trusted_keys.add(key_rrset) # rr)
          end
          check_to_be_trusted(key_rrset)
        end
      end
      
      msg.section_rrsets.each do |section, rrsets|
        rrsets.each do |rrset|
          # If delegation NS or glue AAAA/A, then don't expect RRSIG. 
          # Otherwise, expect RRSIG and fail verification if RRSIG is not present
          
          # Check for delegation
          dsrrset = msg.rrset('DS')
          nsrrset = msg.authority.rrset('NS')
          if ((msg.answer.size == 0) && (!dsrrset) && nsrrset) # && (nsrrset.length > 0))# (isDelegation)
            # Now check NSEC(3) records for absence of DS and SOA
            nsec = msg.authority.rrset('NSEC')
            if (nsec.length == 0) 
              nsec = msg.authority.rrset('NSEC3')
            end
            if (nsec.rrs.length > 0) 
              if (!(nsec.rrs[0].types.include?'DS') || !(nsec.rrset.rrs[0].types.include?'SOA'))
                next
              end
            end
          end
          
          # check for glue
          # if the ownername (in the addtional section) of the glue address is the same or longer as the ownername of the NS record, it is glue 
          if (msg.additional.size > 0)
            arec = msg.additional.rrset('A')
            if (arec.rrs.length == 0)
              arec = msg.additional.rrset('AAAA')
            end
            nsname = msg.rrset('NS').rrs()[0].name
            if (arec.rrs().length > 0)
              aname = arec.rrs()[0].name
              if (nsname.subdomain_of?aname)
                next
              end
            end
          end
          # If records are in additional, and no RRSIG, that's Ok - just don't use them!
          if ((section == "additional") && (rrset.sigs.length == 0))
            next
          end
          # else verify RRSet
          if (!verify_rrset(rrset))
            return false
          end
        end
      end
      return true
    end
    
    def self.check_to_be_trusted(key_rrset)
      # See if the keys match any of the to_be_trusted_keys
      key_rrset.rrs.each do |key|
        @@to_be_trusted_keys.each do |tbtk|
          # @TODO@ Check that the RRSet is still valid!!
          # Should we get it out of the main cache?
          #                if (check_ds(key, tbtk))
          tbtk.rrs.each {|ds|
            if (ds.check_key(key))
              @@trusted_keys.add_key_with_expiration(key, tbtk.sigs()[0].expiration)
              @@to_be_trusted_keys.delete(tbtk)
            end
          }
        end
        #            end
      end
      
    end
    
    def self.get_keys_to_check
      keys_to_check = []
      if (@@validation_policy == ValidationPolicy::ALWAYS_ROOT_ONLY)
        keys_to_check = @@trusted_keys.keys
      elsif (@@validation_policy == ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY)
        keys_to_check = @@trust_anchors.keys
      elsif (@@validation_policy == ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT)
        keys_to_check = @@trust_anchors.keys + @@trusted_keys.keys
      elsif (@@validation_policy == ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS)
        keys_to_check = @@trusted_keys.keys + @@trust_anchors.keys
      end
      return keys_to_check
    end
    
    # Find the first matching DNSKEY and RRSIG record in the two sets.
    def self.get_matching_key(keys, sigrecs)#:nodoc: all
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
  
    # Verify the signature of an rrset encoded with the specified KeyCache
    # or RRSet. If no signature is included, false is returned.
    #
    # Returns true if the RRSet verified, false otherwise.
    def self.verify_rrset(rrset, keys = nil)
      # @TODO@ Finer-grained reporting than "false". 
      sigrecs = rrset.sigs
      #      return false if (rrset.num_sigs == 0)
      if (rrset.num_sigs == 0)
        raise VerifyError.new("No signatures in the RRSet") 
      end
      sigrecs.each do |sigrec|
        check_rr_data(rrset, sigrec)
      end

      keyrec = nil
      sigrec = nil
      if keys.nil?
        if (rrset.rrs()[0].type == Types.DNSKEY)
          check_to_be_trusted(rrset)
        end
        keyrec, sigrec = get_matching_key(get_keys_to_check, sigrecs)
      else
        keyrec, sigrec = get_matching_key(keys, sigrecs)
      end
      
      #      return false if !keyrec
      if (!keyrec)
        raise VerifyError.new("Signing key not found")
      end
     
      # RFC 4034
      #3.1.8.1.  Signature Calculation
      
      if (keyrec.sep_key? && !keyrec.zone_key?)
        Dnsruby.log.error("DNSKEY with with SEP flag set and Zone Key flag not set was used to verify RRSIG over RRSET - this is not allowed by RFC4034 section 2.1.1")
        #        return false
        raise VerifyError.new("DNSKEY with SEP flag set and Zone Key flag not set")
      end          
      
      #Any DNS names in the RDATA field of each RR MUST be in
      #canonical form; and
      #The RRset MUST be sorted in canonical order.
      rrset = rrset.sort_canonical

      sig_data = sigrec.sig_data

      #RR(i) = owner | type | class | TTL | RDATA length | RDATA
      rrset.each do |rec|
        old_ttl = rec.ttl
        rec.ttl = sigrec.original_ttl
        data = MessageEncoder.new { |msg|
          msg.put_rr(rec, true)
        }.to_s # @TODO@ worry about wildcards here?
        rec.ttl = old_ttl
        if (RUBY_VERSION >= "1.9")
          data.force_encoding("ASCII-8BIT")
        end
        sig_data += data
      end
      
      # Now calculate the signature
      verified = false
      if (sigrec.algorithm == Algorithms.RSASHA1)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA1.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == Algorithms.RSASHA256)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA256.new, sigrec.signature, sig_data)
      else
        raise RuntimeError.new("Algorithm #{sigrec.algorithm.code} unsupported by Dnsruby")
      end
    
      if (!verified)
        raise VerifyError.new("Signature failed to cryptographically verify")
      end
      # Sort out the TTLs - set it to the minimum valid ttl
      expiration_diff = (sigrec.expiration.to_i - Time.now.to_i).abs
      rrset.ttl = ([rrset.ttl, sigrec.ttl, sigrec.original_ttl, 
          expiration_diff].sort)[0]

      return true
    end

  end  
end