# This class does verification/validation from a single point - signed root,
# DLV, trust anchors. Dnssec controls a set of these to perform validation for
# the client.
# This class should only be used by Dnsruby
module Dnsruby
  class SingleVerifier # :nodoc: all
    class VerifierType
      ROOT = 0
      ANCHOR = 1
      DLV = 2
    end
    def initialize(vtype)
      @verifier_type = vtype
      # The DNSKEY RRs for the signed root (when it exists)
      @root_anchors = KeyCache.new
      # Could add methods for interacting with root anchors - see test/tc_itar.rb
      # for example of how to load ITAR trust anchors into dnsruby

      # The set of trust anchors.
      # If the root is unsigned, then these must be initialised with at least
      # one trusted key by the client application, if verification is to be performed.
      @trust_anchors = KeyCache.new

      @dlv_registries = []

      # The set of keys which are trusted.
      @trusted_keys = KeyCache.new

      # The set of keys which have been indicated by a DS RRSet which has been
      # signed by a trusted key. Although we have not yet located these keys, we
      # have the details (tag and digest) which can identify the keys when we
      # see them. At that point, they will be added to our trusted keys.
      @discovered_ds_store = []
      # The configured_ds_store is the set of DS records which have been configured
      # by the client as trust anchors. Use Dnssec#add_trust_anchor to add these
      @configured_ds_store = []
    end

    def add_trust_anchor(t)
      add_trust_anchor_with_expiration(t, Time.utc(2035,"jan",1,20,15,1).to_i)
    end
    # Add the
    def add_trust_anchor_with_expiration(k, expiration)
      if (k.type == Types.DNSKEY)
        k.flags = k.flags | RR::IN::DNSKEY::SEP_KEY
        @trust_anchors.add_key_with_expiration(k, expiration)
      elsif (k.type == Types.DS)
        @configured_ds_store.push(k)
      end
    end

    def remove_trust_anchor(t)
      @trust_anchors.delete(t)
    end
    # Wipes the cache of trusted keys
    def clear_trust_anchors
      @trust_anchors = KeyCache.new
    end

    def trust_anchors
      return @trust_anchors.keys + @configured_ds_store
    end

    # Check that the RRSet and RRSIG record are compatible
    def check_rr_data(rrset, sigrec)#:nodoc: all
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
    def add_trusted_key(k)
      @trusted_keys.add(k)
    end

    # Wipes the cache of trusted keys
    def clear_trusted_keys
      @trusted_keys = KeyCache.new
      @discovered_ds_store = []
      @configured_ds_store = []
    end

    def trusted_keys
      discovered_ds = []
      @discovered_ds_store.each {|rrset|
        rrset.rrs.each {|rr|
          discovered_ds.push(rr)
        }
      }
      return @trusted_keys.keys + @configured_ds_store + discovered_ds
    end

    # Check that the key fits a signed DS record key details
    # If so, then add the key to the trusted keys
    def check_ds(key, ds_rrset)#:nodoc: all
      expiration = 0
      found = false
      ds_rrset.sigs.each { |sig|
        if (sig.type_covered == Types.DS)
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
              @trusted_keys.add_key_with_expiration(key, expiration)
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
    def verify(msg) # , keys = nil)
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
            # key tag and digest in a @@discovered_ds_store.
            # Each time we see a new key (which has been signed) then we should
            # check if it is sitting on the discovered_ds_store.
            # If it is, then we should add it to the trusted_keys and remove the
            # DS from the discovered_ds_store
            if (!found)
              @discovered_ds_store.push(ds_rrset)
            end
            #            end
          else
          end
        end

        key_rrset = section.rrset(Types.DNSKEY)
        if (key_rrset && key_rrset.num_sigs > 0)
          if (verify_rrset(key_rrset))
            #            key_rrset.rrs.each do |rr|
            @trusted_keys.add(key_rrset) # rr)
          end
          check_ds_stores(key_rrset)
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

    def check_ds_stores(key_rrset)
      # See if the keys match any of the to_be_trusted_keys
      key_rrset.rrs.each do |key|
        @configured_ds_store.each do |ds|
          if (ds.check_key(key))
            @trusted_keys.add_key_with_expiration(key, key_rrset.sigs()[0].expiration)
          end
        end
        @discovered_ds_store.each do |tbtk|
          # Check that the RRSet is still valid!!
          # Should we get it out of the main cache?
          if ((tbtk.sigs()[0].expiration < Time.now.to_i))
            @discovered_ds_store.delete(tbtk)
          else
            tbtk.rrs.each {|ds|
              if (ds.check_key(key))
                @trusted_keys.add_key_with_expiration(key, tbtk.sigs()[0].expiration)
                @discovered_ds_store.delete(tbtk)
              end
            }
          end
        end
        #            end
      end

    end

    def get_keys_to_check
      keys_to_check = @trust_anchors.keys + @trusted_keys.keys
      return keys_to_check
    end

    # Find the first matching DNSKEY and RRSIG record in the two sets.
    def get_matching_key(keys, sigrecs)#:nodoc: all
      if ((keys == nil) || (sigrecs == nil))
        return nil, nil
      end
      keys.each {|key|
        if ((key.revoked?)) # || (key.bad_flags?))
          next
        end

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
    def verify_rrset(rrset, keys = nil)
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
          check_ds_stores(rrset)
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
      if [Algorithms.RSASHA1,
          Algorithms.RSASHA1_NSEC3_SHA1].include?(sigrec.algorithm)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA1.new, sigrec.signature, sig_data)
        #      elsif (sigrec.algorithm == Algorithms.RSASHA256)
        #        verified = keyrec.public_key.verify(Digest::SHA256.new, sigrec.signature, sig_data)
      elsif [Algorithms.DSA,
          Algorithms.DSA_NSEC3_SHA1].include?(sigrec.algorithm)
        # we are ignoring T for now
        # t = sigrec.signature[0]
        # t = t.getbyte(0) if t.class == String
        r = RR::get_num(sigrec.signature[1, 20])
        s = RR::get_num(sigrec.signature[21, 20])
        r_asn1 = OpenSSL::ASN1::Integer.new(r)
        s_asn1 = OpenSSL::ASN1::Integer.new(s)

        asn1 = OpenSSL::ASN1::Sequence.new([r_asn1, s_asn1]).to_der
        verified = keyrec.public_key.verify(OpenSSL::Digest::DSS1.new, asn1, sig_data)
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

    def validate(msg)
      # @TODO@ What do we do here?
      # See if it is a child of any of our trust anchors.
      # If it is, then see if we have a trusted key for it
      # If we don't, then see if we can get to it from the closest
      # trust anchor
      #
        # @TODO@ Set the message security level!
      msg.security_level = Message::SecurityLevel::INSECURE
      return true # @TODO@ !!!!!
    end

  end
end