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
      @added_dlv_key = false
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

    def get_dlv_resolver
      res = Resolver.new
      query = Message.new("dlv.isc.org", Types.NS)
      query.do_validation = false
      ret = nil
      begin
        ret = res.send_message(query)
      rescue ResolvTimeout => e
#        print "ERROR - Can't get DLV nameserver : #{e}\n"
        TheLog.error("Can't get DLV nameserver : #{e}")
        return Resolver.new # @TODO@ !!!
      end
      ns_rrset = ret.answer.rrset(Types.NS)
      nameservers = []
      ns_rrset.rrs.sort_by {rand}.each {|rr|
        nameservers.push(rr.nsdname)
      }
      if (nameservers.length == 0)
#        print "Can't find DLV nameservers!\n"
        TheLog.error("Can't find DLV nameservers!\n")
      end
      res = Resolver.new
      #      nameservers.each {|addr|
      #        sr = SingleResolver.new(addr)
      #        sr.dnssec = true
      #        res.add_resolver(sr)
      #      }
      res.nameserver = nameservers
      res.update
      return res
    end
    def add_dlv_key(key)
      # Is this a ZSK or a KSK?
      # If it is a KSK, then get the ZSK from the zone
      if (key.sep_key?)
        get_dlv_key(key)
      end
    end
    def get_dlv_key(ksk) # :nodoc:
      # Using the KSK, get the ZSK for the DLV registry
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      query = Message.new("dlv.isc.org", Types.DNSKEY)
      query.do_validation = false
      #      print "Sending query : res.dnssec = #{@res.dnssec}"
      ret = nil
      begin
        ret = @res.send_message(query)
      rescue ResolvTimeout => e
#        print "ERROR - Couldn't find the DLV key\n"
        TheLog.error("Couldn't find the DLV key\n")
        return
      end
      key_rrset = ret.answer.rrset(Types.DNSKEY)
      begin
        verify(key_rrset, ksk)
        add_trusted_key(key_rrset)
#        print "Successfully added DLV key\n"
        TheLog.info("Successfully added DLV key")
        @added_dlv_key = true
      rescue VerifyError => e
#        print "Error verifying DLV key : #{e}\n"
        TheLog.error("Error verifying DLV key : #{e}")
      end
    end
    def add_trust_anchor(t)
      add_trust_anchor_with_expiration(t, Time.utc(2035,"jan",1,20,15,1).to_i)
    end
    # Add the
    def add_trust_anchor_with_expiration(k, expiration)
      if (k.type == Types.DNSKEY)
        k.flags = k.flags | RR::IN::DNSKEY::SEP_KEY
        @trust_anchors.add_key_with_expiration(k, expiration)
#        print "Adding trust anchor for #{k.name}\n"
        TheLog.info("Adding trust anchor for #{k.name}")
      elsif ((k.type == Types.DS) || ((k.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))
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
      if (rrset.name.to_s.downcase != sigrec.name.to_s.downcase)
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
        if ((sig.type_covered == Types.DS) || ((sig.type_covered == Types.DLV)&& (@verifier_type==VerifierType::DLV)))
          if (sig.inception <= Time.now.to_i)
            # Check sig.expiration, sig.algorithm
            if (sig.expiration > expiration)
              expiration = sig.expiration
            end
          end
        end
      }
      if (expiration > 0)
        ds_rrset.rrs.each { |ds|
          if ((ds.type === Types.DS) || ((ds.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))
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
    def verify(msg, keys = nil)
      if (msg.kind_of?RRSet)
        if (msg.type == Types.DNSKEY)
          verify_key_rrset(msg, keys)
        end
        if ((msg.type == Types.DS) || (msg.type == Types.DLV))
          verify_ds_rrset(msg, keys)

        end
        return verify_rrset(msg, keys)
      end
      # Use the set of trusted keys to check any RRSets we can, ideally
      # those of other DNSKEY RRSets first. Then, see if we can use any of the
      # new total set of keys to check the rest of the rrsets.
      # Return true if we can verify the whole message.

      msg.each_section do |section|
        ds_rrset = section.rrset(Types.DS)
        if ((!ds_rrset) && (@verifier_type == VerifierType::DLV))
          ds_rrset = section.rrset(Types.DLV)
        end
        verify_ds_rrset(ds_rrset, keys, msg)

        key_rrset = section.rrset(Types.DNSKEY)
        verify_key_rrset(key_rrset, keys)
      end

      msg.section_rrsets.each do |section, rrsets|
        rrsets.each do |rrset|
          # If delegation NS or glue AAAA/A, then don't expect RRSIG.
          # Otherwise, expect RRSIG and fail verification if RRSIG is not present

          if (section == "authority")
            # Check for delegation
            dsrrset = msg.authority.rrset('DS')
            #            nsrrset = msg.authority.rrset('NS')
            if ((msg.answer.size == 0) && (!dsrrset) && (rrset.type == Types.NS)) # && (nsrrset.length > 0))# (isDelegation)
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
            # If NS records delegate the name to the child's nameservers, then they MUST NOT be signed
            if (rrset.type == Types.NS)
              #              all_delegate = true
              #              rrset.rrs.each {|rr|
              #                name = Name.create(rr.nsdname)
              #                name.absolute = true
              #                if (!(name.subdomain_of?(rr.name)))
              #                  all_delegate = false
              #                end
              #              }
              #              if (all_delegate && rrset.sigs.length == 0)
              #                next
              #              end
              if ((rrset.name == msg.question()[0].qname) && (rrset.sigs.length == 0))
                next
              end
            end
          end

          if (section == "additional")
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
          end
          # If records are in additional, and no RRSIG, that's Ok - just don't use them!
          if ((section == "additional") && (rrset.sigs.length == 0))
            next
          end
          # else verify RRSet
          if (!verify_rrset(rrset, keys))
#            print "Failed to verify rrset\n"
            TheLog.debug("Failed to verify rrset")
            return false
          end
        end
      end
      return true
    end
    
    def verify_ds_rrset(ds_rrset, keys = nil, msg = nil)
      if (ds_rrset && ds_rrset.num_sigs > 0)
        if (verify_rrset(ds_rrset, keys))
          # Need to handle DS RRSets (with RRSIGs) not just DS records.
          #            ds_rrset.rrs.each do |ds|
          # Work out which key this refers to, and add it to the trusted key store
          found = false
          if (msg)
            msg.each_section do |section|
              section.rrset('DNSKEY').rrs.each do |rr|
                if (check_ds(rr, ds_rrset))
                  found = true
                end
              end
            end
          end
          get_keys_to_check().each {|key|
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
    end

    def verify_key_rrset(key_rrset, keys = nil)
      if (key_rrset && key_rrset.num_sigs > 0)
        if (verify_rrset(key_rrset, keys))
          #            key_rrset.rrs.each do |rr|
          @trusted_keys.add(key_rrset) # rr)
        end
        check_ds_stores(key_rrset)
      end
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
      # There can be multiple signatures in the RRSet - which one should we choose?
      if ((keys == nil) || (sigrecs == nil))
        return nil, nil
      end
      if (RR::DNSKEY === keys)
        keys = [keys]
      end
      enumerator = keys
      if (enumerator.class == RRSet)
        enumerator = enumerator.rrs
      end
      enumerator.each {|key|
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
      if (rrset.rrs.length == 0)
        raise VerifyError.new("No RRSet to veryify")
      end
      if (rrset.num_sigs == 0)
        raise VerifyError.new("No signatures in the RRSet : #{rrset.name}, #{rrset.type}")
      end
      sigrecs.each do |sigrec|
        check_rr_data(rrset, sigrec)
      end

      keyrec = nil
      sigrec = nil
      if (rrset.type == Types.DNSKEY)
        if (keys && ((keys.type == Types.DS) || ((keys.type == Types.DLV) && (@verifier_type == VerifierType::DLV))))
          rrset.rrs.each do |key|
            keys.rrs.each do |ds|
              if (ds.check_key(key))
                @trusted_keys.add_key_with_expiration(key, rrset.sigs()[0].expiration)
              end
            end
          end
        else
          check_ds_stores(rrset)
        end
      end
      if ((keys.nil?) || ((keys.type == Types.DS) || ((keys.type == Types.DLV) && (@verifier_type == VerifierType::DLV))))
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

    def find_closest_dlv_anchor_for(name) # :nodoc:
      # To find the closest anchor, query DLV.isc.org for [a.b.c.d], then [a.b.c], [a.b], etc.
      # once closest anchor found, simply run follow_chain from that anchor
      n = Name.create(name)
      root = Name.create(".")
      while (n != root)
        # Try to find name in DLV, and return it if possible
        dlv_rrset = query_dlv_for(n)
        if (dlv_rrset)
          key_rrset = get_zone_key_from_dlv_rrset(dlv_rrset, n)
          return key_rrset
        end
        # strip the name
        n = n.strip_label
      end
      return false
    end

    def get_zone_key_from_dlv_rrset(dlv_rrset, name)
      # We want to return the key for the zone i.e. DS/DNSKEY for .se, NOT DLV for se.dlv.isc.org
      # So, we have the DLv record. Now use it to add the zone's DNSKEYs to the trusted key set.
      res = get_nameservers_for(name)
      if (!res)
        res = Resolver.new
      end
      query = Message.new(name, Types.DNSKEY)
      query.do_validation = false
      ret = nil
      begin
        ret = res.send_message(query)
      rescue ResolvTimeout => e
#        print "Error getting zone key from DLV RR for #{name} : #{e}\n"
        TheLog.error("Error getting zone key from DLV RR for #{name} : #{e}")
        return false
      end
      key_rrset = ret.answer.rrset(Types.DNSKEY)
      begin
        verify(key_rrset, dlv_rrset)
        #        Cache.add(ret)
        return key_rrset
      rescue VerifyError => e
#        print "Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}\n"
        TheLog.debug("Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}")
      end
      return false
    end

    def query_dlv_for(name) # :nodoc:
      # See if there is a record for name in dlv.isc.org
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      begin
        query = Message.new(name.to_s+".dlv.isc.org", Types.DLV)
        @res.single_resolvers()[0].prepare_for_dnssec(query)
        query.do_validation = false
        ret = nil
        begin
          ret = @res.send_message(query)
        rescue ResolvTimeout => e
#          print "Error getting DLV record for #{name} : #{e}\n"
          TheLog.info("Error getting DLV record for #{name} : #{e}")
          return nil
        end
        dlv_rrset = ret.answer.rrset(Types.DLV)
        if (dlv_rrset.rrs.length > 0)
          begin
            verify(dlv_rrset)
            #            Cache.add(ret)
            return dlv_rrset
          rescue VerifyError => e
#            print "Error verifying DLV records for #{name}, #{e}\n"
            TheLog.info("Error verifying DLV records for #{name}, #{e}")
          end
        end
      rescue NXDomain
#        print "NXDomain for DLV lookup for #{name}\n"
        return nil
      end
      return nil
    end

    def find_closest_anchor_for(name) # :nodoc:
      # Check if we have an anchor for name.
      # If not, strip off first label and try again
      # If we get to root, then return false
      n = Name.create(name)
      root = Name.create(".")
      while (n != root)
        # Try the trusted keys first, then the DS set
        (@trust_anchors.keys + @trusted_keys.keys + @configured_ds_store + @discovered_ds_store).each {|key|
          return key if key.name == n
        }
        # strip the name
        n = n.strip_label
      end
      return false
    end

    def follow_chain(anchor, name) # :nodoc:
      # Follow the chain from the anchor to name, returning the appropriate
      # key at the end, or false.
      #
      # i.e. anchor = se, name = foo.example.se
      #   get anchor for example.se with se anchor
      #   get anchor for foo.example.se with example.se anchor
      next_key = anchor
      next_step = anchor.name
      parent = next_step
#      print "Follow chain from #{anchor.name} to #{name}\n"
      TheLog.debug("Follow chain from #{anchor.name} to #{name}")

      res = nil
      while ((next_step != name) || (next_key.type != Types.DNSKEY))
        dont_move_on = false
        if (next_key.type != Types.DNSKEY)
          dont_move_on = true
        end
        next_key, res = get_anchor_for(next_step, parent, next_key, res)
        return false if (!next_key)
        # Add the next label on
        if (!dont_move_on)
          parent = next_step
          next_step = Name.new(name.labels[name.labels.length-1-next_step.labels.length,1] +
              next_step.labels , name.absolute?)
        end
      end

#      print "Returning #{next_key.type} for #{next_step}, #{(next_key.type != Types.DNSKEY)}\n"

      return next_key
    end

    def get_anchor_for(child, parent, current_anchor, parent_res = nil) # :nodoc:
#      print "Trying to discover anchor for #{child} from #{parent}\n"
      TheLog.debug("Trying to discover anchor for #{child} from #{parent}")
      # We wish to return a DNSKEY which the caller can use to verify name
      # We are either given a key or a ds record from the parent zone
      # If given a DNSKEY, then find a DS record signed by that key for the child zone
      # Use the DS record to find a valid key in the child zone
      # Return it

      # Find NS RRSet for parent
      child_res = nil
      begin
        #        parent_res = Resolver.new
        #        parent_res.dnssec = true
        if (child!=parent)
          if (!parent_res)
#            print "No res passed - try to get nameservers for #{parent}\n"
            parent_res = get_nameservers_for(parent)
            if (!parent_res)
              parent_res = Resolver.new # @TODO@
            end
          end
          # Use that Resolver to query for DS record and NS for children
          ds_rrset = current_anchor
          if (current_anchor.type == Types.DNSKEY)
#            print "Trying to find DS records for #{child} from servers for #{parent}\n"
            TheLog.debug("Trying to find DS records for #{child} from servers for #{parent}")
            query = Message.new(child, Types.DS)
            query.do_validation = false
            ds_ret = nil
            begin
              ds_ret = parent_res.send_message(query)
            rescue ResolvTimeout => e
#              print "Error getting DS record for #{child} : #{e}\n"
              TheLog.error("Error getting DS record for #{child} : #{e}")
              return false, nil
            end
            ds_rrset = ds_ret.answer.rrset(Types.DS)
            if (ds_rrset.rrs.length == 0)
              # @TODO@ Check NSEC(3) records
              print "NO DS RECORDS RETURNED FOR #{parent}\n"
              child_res = parent_res
            else
              if (!verify(ds_rrset, current_anchor))
#                print "FAILED TO VERIFY DS RRSET FOR #{child}\n"
                TheLog.info("FAILED TO VERIFY DS RRSET FOR #{child}")
                return false, nil
              end
              # Try to make the resolver from the authority/additional NS RRSets in DS response
              child_res = get_nameservers_from_message(child, ds_ret)
            end
          end
        end
        # Make Resolver using all child NSs
        if (!child_res)
          child_res = get_nameservers_for(child, parent_res)
        end
        if (!child_res)
          child_res = Resolver.new # @TODO@
        end
        # Query for DNSKEY record, and verify against DS in parent.
        # Need to get resolver NOT to verify this message - we verify it afterwards
#        print "Trying to find DNSKEY records for #{child} from servers for #{child}\n"
        TheLog.info("Trying to find DNSKEY records for #{child} from servers for #{child}")
        query = Message.new(child, Types.DNSKEY)
        query.do_validation = false
        key_ret = nil
        begin
          key_ret = child_res.send_message(query)
        rescue ResolvTimeout => e
#          print "Error getting DNSKEY for #{child} : #{e}\n"
          TheLog.error("Error getting DNSKEY for #{child} : #{e}")
          return false, nil
        end
        verified = true
        key_rrset = key_ret.answer.rrset(Types.DNSKEY)
        if (key_rrset.rrs.length == 0)
#          print "NO DNSKEY RECORDS RETURNED FOR #{child}\n"
          TheLog.debug("NO DNSKEY RECORDS RETURNED FOR #{child}")
          #        end
          verified = false
        else
          # Should check that the matching key's zone flag is set (RFC 4035 section 5.2)
          key_rrset.rrs.each {|k|
            if (!k.zone_key?)
#              print "Discovered DNSKEY is not a zone key - ignoring\n"
              TheLog.debug("Discovered DNSKEY is not a zone key - ignoring")
              return false, new_res
            end
          }
          if (!verify(key_rrset, ds_rrset))
            if (!verify(key_rrset))
              #        if (!verify(key_ret))
              verified = false
            end
          end

        end
        
        # Try to make the resolver from the authority/additional NS RRSets in DNSKEY response
        new_res = get_nameservers_from_message(child,  key_ret) # @TODO@ ?
        if (!new_res)
          new_res = child_res
        end
        if (!verified)
          TheLog.info("Failed to verify DNSKEY for #{child}")
          return false, new_res
        end
        #        Cache.add(key_ret)
        return key_rrset, new_res
      rescue VerifyError => e
#        print "Verification error : #{e}\n"
        TheLog.info("Verification error : #{e}\n")
        return false, new_res
      end
    end

    def get_nameservers_for(name, res = nil)
      # @TODO@ Want to make it optional whether to follow chain of authoritative
      # servers, or ask local resolver for DNSKEY/DS records.
      # Should ask parent res!
      if (!res)
        res = Resolver.new
      end
      res.dnssec = true

      query = Message.new(name, Types.NS)
      query.do_validation = false
      ns_ret = nil
      begin
        ns_ret = res.send_message(query)
      rescue ResolvTimeout => e
#        print "Error getting NS records for #{name} : #{e}\n"
        TheLog.error("Error getting NS records for #{name} : #{e}")
        return Resolver.new # @TODO@ !!!
      end

      ret = get_nameservers_from_message(name, ns_ret)
      return ret
    end

    def get_nameservers_from_message(name, ns_ret)

      ns_rrset = ns_ret.answer.rrset(Types.NS)
      if (!ns_rrset || ns_rrset.length == 0)
        ns_rrset = ns_ret.authority.rrset(Types.NS) # @TOO@ Is ths OK?
      end
      if (!ns_rrset || ns_rrset.length == 0 || ns_rrset.name.to_s != name.to_s)
        return nil
      end
      if (ns_rrset.sigs.length > 0)
        #                verify_rrset(ns_rrset) # @TODO@ ??
      end
      #      Cache.add(ns_ret)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.A) }
      nameservers = []
      add_nameservers(ns_rrset, ns_additional, nameservers) # if (ns_additional.length > 0)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.AAAA) }
      add_nameservers(ns_rrset, ns_additional, nameservers) if (ns_additional.length > 0)
      # Make Resolver using all NSs
      if (nameservers.length == 0)
#        print "Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}\n"
        TheLog.info("Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}")
        return  nil # @TODO@
      end
      res = Resolver.new()
      #      nameservers.each {|addr|
      #        sr = SingleResolver.new(addr)
      #        sr.dnssec = true
      #        res.add_resolver(sr)
      #      }
      res.nameserver=(nameservers)
      # Set the retry_delay to be (at least) the number of nameservers
      # Otherwise, the queries will be sent at a rate of more than one a second!
      res.retry_delay = nameservers.length * 2
      res.dnssec = true
      return res
    end

    def add_nameservers(ns_rrset, ns_additional, nameservers) # :nodoc:
      # Want to go through all of the ns_rrset NS records,
      #      print "Checking #{ns_rrset.rrs.length} NS records against #{ns_additional.length} address records\n"
      ns_rrset.rrs.sort_by {rand}.each {|ns_rr|
        #   and see if we can find any of the names in the A/AAAA records in ns_additional
        found_addr = false
        ns_additional.each {|addr_rr|
          if (ns_rr.nsdname.to_s == addr_rr.name.to_s)
            #            print "Found address #{addr_rr.address} for #{ns_rr.nsdname}\n"
            nameservers.push(addr_rr.address.to_s)
            found_addr = true
            break
            # If we can, then we add the server A/AAAA address to nameservers
          end
          # If we can't, then we add the server NS name to nameservers

        }
        if (!found_addr)
          #          print "Couldn't find address - adding #{ns_rr.nsdname}\n"
          nameservers.push(ns_rr.nsdname)
        end

      }
    end

    def validate(msg, query)
      # See if it is a child of any of our trust anchors.
      # If it is, then see if we have a trusted key for it
      # If we don't, then see if we can get to it from the closest
      # trust anchor
      # Otherwise, try DLV (if configured)
      #
      #
      # So - find closest existing trust anchor
      error = nil
      msg.security_level = Message::SecurityLevel.INDETERMINATE
      qname = msg.question()[0].qname
      closest_anchor = find_closest_anchor_for(qname)
      error = try_to_follow_from_anchor(closest_anchor, msg, qname)

      if ((msg.security_level.code < Message::SecurityLevel::SECURE) &&
            (@verifier_type == VerifierType::DLV) &&
            @added_dlv_key)
        # If we can't find anything, and we're set to check DLV, then
        # check the DLV registry and work down from there.
        dlv_anchor = find_closest_dlv_anchor_for(qname)
        if (dlv_anchor)
#          print "Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}\n"
          TheLog.debug("Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}")
          error = try_to_follow_from_anchor(dlv_anchor, msg, qname)
        else
#          print "Couldn't find DLV anchor for #{qname}\n"
          TheLog.debug("Couldn't find DLV anchor for #{qname}")
        end
      end
      if (error)
        raise error
      end
      if (msg.security_level.code != Message::SecurityLevel::SECURE)
        begin
          if verify(msg) # Just make sure we haven't picked the keys up anywhere
            msg.security_level = Message::SecurityLevel.SECURE
          end
        rescue VerifyError
        end
      end
      if (msg.security_level.code > Message::SecurityLevel::UNCHECKED)
        return true
      else
        return false
      end
    end

    def try_to_follow_from_anchor(closest_anchor, msg, qname)
      error = nil
      if (closest_anchor)
        # Then try to descend to the level we're interested in
        actual_anchor = follow_chain(closest_anchor, qname)
        if (!actual_anchor)
          TheLog.debug("Unable to follow chain from anchor : #{closest_anchor.name}")
          msg.security_level = Message::SecurityLevel.INSECURE
        else
          TheLog.debug("Found anchor #{actual_anchor.name}, #{actual_anchor.type} for #{qname}")
          begin
            if (verify(msg, actual_anchor))
              TheLog.debug("Validated #{qname}")
              msg.security_level = Message::SecurityLevel.SECURE
            end
          rescue VerifyError => e
            TheLog.info("BOGUS #{qname}! Error : #{e}")
            msg.security_level = Message::SecurityLevel.BOGUS
            error = e
          end
        end
      else
        #        print "Unable to find an anchor for #{qname}\n"
        msg.security_level = Message::SecurityLevel.INSECURE
      end
      return error
    end

  end
end