# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require 'weakref'
require 'securerandom'


# This class does verification/validation from a single point - signed root,
# DLV, trust anchors. Dnssec controls a set of these to perform validation for
# the client.
# This class should only be used by Dnsruby
module Dnsruby
  class SingleVerifier # :nodoc: all
    # RRsets carry only serializable provenance, never a verifier, mutex or
    # validation budget. The weak registry lets another verifier check whether
    # the original trust source has since been removed.
    LearnedTrust = Struct.new(:expiration, :signature_expiration, :transaction, :sources)
    VALIDATION_ALGORITHMS = [Algorithms.RSASHA1, Algorithms.RSASHA1_NSEC3_SHA1,
      Algorithms.RSASHA256, Algorithms.RSASHA512,
      Algorithms.ECDSAP256SHA256, Algorithms.ECDSAP384SHA384].freeze
    private_constant :LearnedTrust, :VALIDATION_ALGORITHMS
    @provenance_mutex = Mutex.new
    @trust_sources = {}
    @next_source_id = 0
    @source_namespace = SecureRandom.hex(16).freeze

    def self.register_trust_source(verifier)
      @provenance_mutex.synchronize do
        @trust_sources.delete_if { |_id, source| !source.weakref_alive? }
        @next_source_id += 1
        identity = [@source_namespace, Process.pid, @next_source_id].freeze
        @trust_sources[identity] = WeakRef.new(verifier)
        identity
      end
    end

    def self.trust_source(id)
      @provenance_mutex.synchronize do
        source = @trust_sources[id]
        source.__getobj__ if source && source.weakref_alive?
      end
    rescue WeakRef::RefError
      nil
    end
    private_class_method :register_trust_source, :trust_source

    class VerifierType
      ROOT = 0
      ANCHOR = 1
      DLV = 2
    end
    def initialize(vtype)
      @trust_mutex = Mutex.new
      @trust_generation = 0
      @trust_source_id = SingleVerifier.send(:register_trust_source, self)
      @verifier_type = vtype
      @added_dlv_key = false
      #  The set of trust anchors.
      #  If the root is unsigned, then these must be initialised with at least
      #  one trusted key by the client application, if verification is to be performed.
      @trust_anchors = KeyCache.new
      # Track configured expiration independently of KeyCache pruning so an
      # expired anchor invalidates learned trust and in-flight publication.
      @configured_dnskey_identities = {}

      #  The set of keys which are trusted.
      @trusted_keys = KeyCache.new
      @trusted_key_provenance = {}

      #  The set of keys which have been indicated by a DS RRSet which has been
      #  signed by a trusted key. Although we have not yet located these keys, we
      #  have the details (tag and digest) which can identify the keys when we
      #  see them. At that point, they will be added to our trusted keys.
      @discovered_ds_store = []
      #  The configured_ds_store is the set of DS records which have been configured
      #  by the client as trust anchors. Use Dnssec#add_trust_anchor to add these
      @configured_ds_store = []
    end

    def set_hints(hints)
      @@hints = hints
    end

    def get_recursor
      if (!defined?@@recursor)
        if (defined?@@hints)
          Recursor.set_hints(@@hints, Resolver.new)
          @@recursor = Recursor.new()
        else
          @@recursor = Recursor.new
        end
      end
      @@recursor.dnssec = true
      return @@recursor
    end

    def get_dlv_resolver # :nodoc:
      #       if (Dnssec.do_validation_with_recursor?)
      #         return Recursor.new
      #       else
      resolver = nil
      if (Dnssec.default_resolver)
        resolver = Dnssec.default_resolver
      else
        resolver = Resolver.new
      end
      #       end
      resolver.dnssec = true
      return resolver
    end
    def add_dlv_key(key)
      #  Is this a ZSK or a KSK?
      #  If it is a KSK, then get the ZSK from the zone
      if (key.sep_key?)
        get_dlv_key(key)
      end
    end
    def get_dlv_key(ksk) # :nodoc:
      with_validation { get_dlv_key_internal(ksk) }
    end

    private def get_dlv_key_internal(ksk)
      #  Using the KSK, get the ZSK for the DLV registry
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      #       print "Sending query : res.dnssec = #{@res.dnssec}"
      ret = nil
      begin
        ret = @res.query_no_validation_or_recursion("dlv.isc.org.", Types.DNSKEY)
        if (!ret)
          raise ResolvError.new("Couldn't get response from Recursor")
        end
      rescue ResolvError => e
        #         print "ERROR - Couldn't find the DLV key\n"
        TheLog.error("Couldn't find the DLV key\n")
        return
      end
      key_rrset = ret.answer.rrset("dlv.isc.org", Types.DNSKEY)
      begin
        verify(key_rrset, ksk)
        add_trusted_key(key_rrset)
        #         print "Successfully added DLV key\n"
        TheLog.info("Successfully added DLV key")
        @added_dlv_key = true
      rescue VerifyError => e
        #         print "Error verifying DLV key : #{e}\n"
        TheLog.error("Error verifying DLV key : #{e}")
      end
    end
    def add_trust_anchor(t)
      add_trust_anchor_with_expiration(t, Time.utc(2035,"jan",1,20,15,1).to_i)
    end
    #  Add the
    def add_trust_anchor_with_expiration(k, expiration)
      @trust_mutex.synchronize do
        if (k.type == Types.DNSKEY)
          @trust_anchors.add_key_with_expiration(k, expiration)
          identity = KeyCache.key_identity(k)
          @configured_dnskey_identities[identity] = [@configured_dnskey_identities[identity] || expiration, expiration].max
          TheLog.info("Adding trust anchor for #{k.name}")
        elsif ((k.type == Types.DS) || ((k.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))
          @configured_ds_store.push(k)
        end
      end
    end

    def remove_trust_anchor(t)
      @trust_mutex.synchronize do
        configured = false
        removed = if (t.type == Types.DNSKEY)
          configured = @configured_dnskey_identities.delete(KeyCache.key_identity(t))
          @trust_anchors.delete(t)
        else
          @configured_ds_store.delete(t)
        end
        # Cached keys and in-flight discoveries may depend on this anchor.
        clear_learned_keys if removed || configured
        removed
      end
    end
    #  Remove configured anchors and any keys learned from them.
    def clear_trust_anchors
      @trust_mutex.synchronize do
        @trust_anchors = KeyCache.new
        @configured_dnskey_identities = {}
        @configured_ds_store = []
        clear_learned_keys
      end
    end

    def trust_anchors
      @trust_mutex.synchronize do
        expire_trust_anchors
        @trust_anchors.keys + @configured_ds_store
      end
    end

    # Caller holds @trust_mutex. As with explicit removal, cached descendants
    # cannot outlive a configured DNSKEY anchor. Other configured anchors remain
    # available and can establish fresh trust without retaining stale descendants.
    def expire_trust_anchors
      now = Time.now.to_i
      expired = @configured_dnskey_identities.any? { |_identity, expiration| expiration <= now }
      return unless expired
      @configured_dnskey_identities.delete_if { |_identity, expiration| expiration <= now }
      @trust_anchors.remove_expired_keys
      clear_learned_keys
    end
    private :expire_trust_anchors

    #  Check that the RRSet and RRSIG record are compatible
    def check_rr_data(rrset, sigrec)#:nodoc: all
      # Each RR MUST have the same owner name as the RRSIG RR;
      if (rrset.name.canonical != sigrec.name.canonical)
        raise VerifyError.new("RRSET should have same owner name as RRSIG for verification (rrsert=#{rrset.name}, sigrec=#{sigrec.name}")
      end

      # Each RR MUST have the same class as the RRSIG RR;
      if (rrset.klass != sigrec.klass)
        raise VerifyError.new("RRSET should have same DNS class as RRSIG for verification")
      end

      # Each RR in the RRset MUST have the RR type listed in the
      # RRSIG RR's Type Covered field;
      if (rrset.type != sigrec.type_covered)
        raise VerifyError.new("RRSET should have same type as RRSIG for verification")
      end

      # RFC 4035 5.3.1: a signature is authoritative only within its zone.
      # DNSKEY is apex data; DS is parent-side data at a strict descendant.
      zone = sigrec.signers_name
      unless within_zone?(rrset.name, zone)
        raise VerifyError, 'RRSet owner is outside the signing zone'
      end
      if rrset.type == Types.DNSKEY && rrset.name != zone
        raise VerifyError, 'DNSKEY RRSet must be signed by its own zone'
      end
      if rrset.type == Types.DS && !rrset.name.subdomain_of?(zone)
        raise VerifyError, 'DS RRSet must be signed by a parent zone'
      end
      if sigrec.labels < zone.labels.length
        raise VerifyError, 'Wildcard source is outside the signing zone'
      end

      #       #Each RR in the RRset MUST have the TTL listed in the
      #       #RRSIG Original TTL Field;
      #       if (rrset.ttl  != sigrec.original_ttl)
      #         raise VerifyError.new("RRSET should have same ttl as RRSIG original_ttl for verification (should be #{sigrec.original_ttl} but was #{rrset.ttl}")
      #       end

      #  Now check that we are in the validity period for the RRSIG
      now = Time.now.to_i
      if ((sigrec.expiration < now) || (sigrec.inception > now))
        raise VerifyError.new("Signature record not in validity period")
      end
    end

    # A bad or expired signature must not hide another usable signature.
    # Filter before considering DS stores so invalid signature metadata cannot
    # determine the expiration of a newly discovered key.
    def valid_signatures(rrset)
      error = nil
      signatures = rrset.sigs.select do |sigrec|
        ValidationBudget.current&.check!(1)
        begin
          check_rr_data(rrset, sigrec)
          true
        rescue VerifyError => e
          error = e
          false
        end
      end
      raise error if signatures.empty? && error
      signatures
    end
    private :valid_signatures

    #  Add the specified keys to the trusted key cache.
    #  k can be a KeyCache, or an RRSet of DNSKEYs.
    def add_trusted_key(k, expiration = nil)
      provenance = learned_provenance(k)
      return false if provenance && !usable_provenance?(provenance)
      expiration ||= provenance&.expiration
      previous = @trust_mutex.synchronize { @trusted_key_provenance.dup }
      invalid = previous.reject { |_identity, trust| usable_provenance?(trust) }
      publish_trust do
        invalid.each do |identity, trust|
          next unless @trusted_key_provenance[identity].equal?(trust)
          @trusted_keys.delete_identity(identity)
          @trusted_key_provenance.delete(identity)
        end
        if provenance && (operation = trust_operation)
          k.rrs.each { |key| operation[:keys][KeyCache.key_identity(key)] = [key, provenance] }
        end
        result = @trusted_keys.add(k, expiration)
        if provenance && expiration && expiration > Time.now.to_i
          k.rrs.each do |key|
            identity = KeyCache.key_identity(key)
            previous = @trusted_key_provenance[identity]
            @trusted_key_provenance[identity] = provenance if !previous || previous.expiration < expiration
          end
        end
        result
      end
    end

    def add_root_ds(ds)
      @trust_mutex.synchronize { @configured_ds_store.push(ds) }
    end

    #  Clear learned trust and configured DS/DLV anchors, retaining DNSKEY anchors.
    def clear_trusted_keys
      @trust_mutex.synchronize do
        clear_learned_keys
        @configured_ds_store = []
      end
    end

    # Caller holds @trust_mutex, also used by every learned-trust publication.
    def clear_learned_keys
      @trust_generation += 1
      @trusted_keys = KeyCache.new
      @trusted_key_provenance = {}
      @res = nil
      @discovered_ds_store = []
    end
    private :clear_learned_keys

    def trusted_keys
      keys, configured, discovered = @trust_mutex.synchronize do
        expire_trust_anchors
        @discovered_ds_store.reject! { |expiration, _rrset| expiration <= Time.now.to_i }
        [cached_trust_keys, @configured_ds_store.dup, @discovered_ds_store.map(&:last)]
      end
      keys.select { |key| usable_cached_key?(key) } + configured +
        discovered.select { |rrset| usable_provenance?(learned_provenance(rrset)) }.flat_map(&:rrs)
    end

    # Public verification and discovery methods enter here explicitly. Nested
    # calls retain both the operation's limits and this verifier's trust generation.
    def with_validation
      ValidationBudget.with { with_trust_generation { yield } }
    end
    private :with_validation

    # Nested verification and network discovery share the generation in which
    # the outer operation started. No trust lock is held during either work.
    def with_trust_generation
      operations = Thread.current[:dnsruby_trust_generations] ||= {}
      return yield if operations.key?(self)
      generation = @trust_mutex.synchronize do
        expire_trust_anchors
        @trust_generation
      end
      operations[self] = { generation: generation, keys: {}, ds: [], rrsets: {}.compare_by_identity }
      begin
        yield
      ensure
        operations.delete(self)
        Thread.current[:dnsruby_trust_generations] = nil if operations.empty?
      end
    end

    def publish_trust
      generation = trust_operation&.fetch(:generation)
      @trust_mutex.synchronize do
        expire_trust_anchors
        ValidationBudget.current&.check!
        return false if generation && generation != @trust_generation
        yield
      end
    end
    private :with_trust_generation, :publish_trust

    def trust_operation
      Thread.current[:dnsruby_trust_generations]&.fetch(self, nil)
    end

    def learned_provenance(rrset)
      return unless rrset.respond_to?(:type)
      trust_operation&.fetch(:rrsets)&.fetch(rrset, nil) || rrset.instance_variable_get(:@dnsruby_learned_trust)
    end

    def current_trust_generation?(generation)
      @trust_mutex.synchronize do
        expire_trust_anchors
        generation == @trust_generation
      end
    end

    def usable_provenance?(provenance)
      return false unless provenance
      now = Time.now.to_i
      return false if provenance.signature_expiration < now
      return false unless provenance.expiration > now ||
        provenance.transaction.equal?(ValidationBudget.current&.transaction)
      provenance.sources.all? do |identity, generation|
        source = SingleVerifier.send(:trust_source, identity)
        source && source.send(:current_trust_generation?, generation)
      end
    end

    def key_provenance(key)
      identity = KeyCache.key_identity(key)
      configured = @trust_mutex.synchronize do
        expire_trust_anchors
        @configured_dnskey_identities.key?(identity)
      end
      return if configured
      local = trust_operation&.fetch(:keys)&.fetch(identity, nil)
      return local.last if local
      @trust_mutex.synchronize { @trusted_key_provenance[identity] }
    end

    def usable_cached_key?(key)
      provenance = key_provenance(key)
      !provenance || usable_provenance?(provenance)
    end

    # Caller holds @trust_mutex. Keep provenance bounded by the live key cache.
    def cached_trust_keys
      keys = @trusted_keys.keys
      identities = keys.to_h { |key| [KeyCache.key_identity(key), true] }
      @trusted_key_provenance.delete_if { |identity, _provenance| !identities.key?(identity) }
      keys
    end

    def admit_provenance(provenance)
      return unless provenance
      raise VerifyError, 'Learned trust is no longer valid' unless usable_provenance?(provenance)
      LearnedTrust.new(provenance.expiration, provenance.signature_expiration,
        ValidationBudget.current.transaction, provenance.sources).freeze
    end

    def admit_learned_rrset(rrset)
      provenance = learned_provenance(rrset)
      return unless provenance
      admitted = admit_provenance(provenance)
      trust_operation[:rrsets][rrset] = admitted
      admitted
    end

    def authenticated_provenance(rrset, signature, expiration, parent = nil)
      # Retain the original receipt deadline when the same response is checked
      # again. Cache lifetime and permission to finish this request are distinct.
      previous = learned_provenance(rrset)
      expiration = [expiration, previous.expiration].min if previous
      signature_expiration = signature.expiration
      if parent
        expiration = [expiration, parent.expiration].min
        signature_expiration = [signature_expiration, parent.signature_expiration].min
      end
      sources = (parent ? parent.sources : []) + [[@trust_source_id, trust_operation.fetch(:generation)].freeze]
      LearnedTrust.new(expiration, signature_expiration, ValidationBudget.current.transaction,
        sources.uniq.freeze).freeze
    end

    def retain_learned_rrset(rrset, provenance)
      # The frozen value is safe to retain across verifier fallback, cloning,
      # cache eviction, and Marshal round trips.
      rrset.instance_variable_set(:@dnsruby_learned_trust, provenance)
      rrset.rrs.each { |rr| rr.instance_variable_set(:@dnsruby_learned_trust, provenance) }
      trust_operation[:rrsets][rrset] = provenance if trust_operation
    end
    private :trust_operation, :learned_provenance, :current_trust_generation?,
      :usable_provenance?, :key_provenance, :usable_cached_key?,
      :authenticated_provenance, :retain_learned_rrset, :cached_trust_keys,
      :admit_provenance, :admit_learned_rrset

    #  Check that the key fits a signed DS record key details
    # A DS digest match identifies a candidate; only a verified DNSKEY RRset
    # can publish that key and establish its authenticated cache lifetime.
    def check_ds(key, ds_rrset, expiration = nil)#:nodoc: all
      with_validation { check_ds_internal(key, ds_rrset, expiration) }
    end

    private def check_ds_internal(key, ds_rrset, expiration)
      unless expiration
        verification = {}
        verify_rrset(ds_rrset, nil, verification)
        expiration = verification.fetch(:expiration)
      end
      provenance = learned_provenance(ds_rrset)
      return false if provenance && !usable_provenance?(provenance)
      return false if !provenance && expiration < Time.now.to_i
      ds_rrset.rrs.any? do |ds|
        ValidationBudget.current&.check!(1)
        next false unless ds.check_key(key)
        true
      end
    end

    #  Verify the specified message (or RRSet) using the set of trusted keys.
    #  If keys is a DNSKEY, or an Array or RRSet of DNSKEYs, then keys
    #  is added to the set of trusted keys before the message (or RRSet) is
    #  verified.
    # 
    #  If msg is a Dnsruby::Message, then any signed DNSKEY or DS RRSets are
    #  processed first, and any new keys are added to the trusted key set
    #  before the other RRSets are checked.
    # 
    #  msg can be a Dnsruby::Message or Dnsruby::RRSet.
    #  keys may be nil, or a KeyCache or an RRSet of Dnsruby::RR::DNSKEY
    # 
    #  Returns true if the message verifies OK, and false otherwise.
    def verify(msg, keys = nil)
      verify_result(msg, keys) == :secure
    end

    def verify_result(msg, keys = nil) # :nodoc:
      with_validation do
        result = verify_internal(msg, keys)
        result == true ? :secure : result
      end
    end

    private def verify_internal(msg, keys)
      if (msg.kind_of?RRSet)
        if (msg.type == Types.DNSKEY)
          return verify_key_rrset(msg, keys)
        end
        if ((msg.type == Types.DS) || (msg.type == Types.DLV))
          return verify_ds_rrset(msg, keys)

        end
        return verify_rrset(msg, keys)
      end
      #  Use the set of trusted keys to check any RRSets we can, ideally
      #  those of other DNSKEY RRSets first. Then, see if we can use any of the
      #  new total set of keys to check the rest of the rrsets.
      #  Return true if we can verify the whole message.

      sections = msg.section_rrsets
      context = { message: msg, proofs: {}, sections: sections,
        verified: {}.compare_by_identity }
      sections.each_value do |rrsets|
        #         print "Checking section : #{section}\n"
        ds_rrsets = rrsets.select { |rrset| rrset.type == Types.DS }
        if ((!ds_rrsets || ds_rrsets.length == 0) && (@verifier_type == VerifierType::DLV))
          ds_rrsets = rrsets.select { |rrset| rrset.type == Types.DLV }
        end
        ds_rrsets.each {|ds_rrset|
          if ((ds_rrset && ds_rrset.rrs.length > 0) && !verify_ds_rrset(ds_rrset, keys, msg, context))
            raise VerifyError.new("Failed to verify DS RRSet")
            #             return false
          end
        }

        key_rrsets = rrsets.select { |rrset| rrset.type == Types.DNSKEY }
        key_rrsets.each {|key_rrset|
          if ((key_rrset && key_rrset.rrs.length > 0) && !verify_key_rrset(key_rrset, keys, context))
            raise VerifyError.new("Failed to verify DNSKEY RRSet")
            #             return false
          end
        }
      end

      #  Then, look through all the remaining RRSets, and verify them all (unless not necessary).
      sections.each do |section, rrsets|
        rrsets.each do |rrset|
          # Key learning already authenticated these exact per-message sets.
          next if context[:verified].key?(rrset)
          #  If delegation NS or glue AAAA/A, then don't expect RRSIG.
          #  Otherwise, expect RRSIG and fail verification if RRSIG is not present

          if ((section == "authority") && (rrset.type == Types.NS))
            # Parent-side delegation NS records are unsigned, including when
            # the query is below the cut and its DS RRset authenticated above.
            question = msg.question.first
            terminal, answered = terminal_answer(msg, question) if question
            if question && !answered && rrset.klass == question.qclass &&
                within_zone?(terminal, rrset.name) && rrset.sigs.empty? &&
                rrsets.any? { |set| set.type == Types.DS && set.name == rrset.name &&
                  set.klass == rrset.klass && context[:verified].key?(set) &&
                  rrset.name.subdomain_of?(context[:verified][set][:signature].signers_name) }
              next
            end
            #  Check for delegation
            dsrrset = rrsets.find { |set| set.type == Types.DS && set.name == rrset.name && set.klass == rrset.klass }
            if question && !answered && rrset.klass == question.qclass &&
                within_zone?(terminal, rrset.name) && !dsrrset
              #  Now check NSEC(3) records for absence of DS and SOA
              nsec = msg.authority.rrsets('NSEC')[0]
              if (!nsec || (nsec.length == 0))
                nsec = msg.authority.rrsets('NSEC3')[0]
              end
              if (nsec && (nsec.rrs.length > 0))
                if (!(nsec.rrs()[0].types.include?'DS') || !(nsec.rrs()[0].types.include?'SOA'))
                  next # delegation which we expect to be unsigned - so don't verify it!
                end
              end
            end
            #  If NS records delegate the name to the child's nameservers, then they MUST NOT be signed
            if (rrset.type == Types.NS)
              #               all_delegate = true
              #               rrset.rrs.each {|rr|
              #                 name = Name.create(rr.nsdname)
              #                 name.absolute = true
              #                 if (!(name.subdomain_of?(rr.name)))
              #                   all_delegate = false
              #                 end
              #               }
              #               if (all_delegate && rrset.sigs.length == 0)
              #                 next
              #               end
              if ((rrset.name.canonical == msg.question()[0].qname.canonical) && (rrset.sigs.length == 0))
                next
              end
            end
          end

          if (section == "additional")
            #  check for glue
            #  if the ownername (in the addtional section) of the glue address is the same or longer as the ownername of the NS record, it is glue
            if (msg.additional.size > 0)
              arec = msg.additional.rrsets('A')[0]
              if (!arec || arec.rrs.length == 0)
                arec = msg.additional.rrsets('AAAA')[0]
              end
              ns_rrsets = msg.additional.rrsets('NS')
              ns_rrsets.each {|ns_rrset|
                if (ns_rrset.length > 0)
                  nsname = ns_rrset.rrs()[0].name
                  if (arec && arec.rrs().length > 0)
                    aname = arec.rrs()[0].name
                    if (nsname.subdomain_of?aname)
                      next
                    end
                  end
                end
              }
            end
          end
          #  If records are in additional, and no RRSIG, that's Ok - just don't use them!
          if ((section == "additional") && (rrset.sigs.length == 0))
            #  @TODO@ Make sure that we don't cache these records!
            next
          end
          #  else verify RRSet
          #           print "About to verify #{rrset.name}, #{rrset.type}\n"
          if (!verify_rrset(rrset, keys, context))
            #             print "FAILED TO VERIFY RRSET #{rrset.name}, #{rrset.type}\n"
            TheLog.debug("Failed to verify rrset")
            return false
          end
        end
      end
      verify_nsecs(msg, context)
      apply_verified_lifetimes(msg, context)
      return context[:insecure] ? :insecure : true
    end

    # Check denial at the end of an alias chain, not at the original QNAME.
    # A CNAME-only answer without a negative SOA can legitimately be partial.
    # Positive wildcard proofs are checked when their signatures verify.
    def verify_nsecs(msg, context = nil) # :nodoc:
      question = msg.question.first
      return unless question && [RCode.NOERROR, RCode.NXDOMAIN].include?(msg.rcode)
      name, answered = terminal_answer(msg, question)
      return if msg.rcode == RCode.NOERROR && answered
      raise VerifyError, 'NXDOMAIN response contains the requested answer' if answered

      authority = context ? context[:sections].fetch('authority') : msg.authority.rrsets
      klass, qtype = question.qclass, question.qtype
      soa = authority.select do |set|
        set.type == Types.SOA && set.klass == klass && within_zone?(name, set.name)
      end.max_by { |set| set.name.labels.length }
      referral = if msg.rcode == RCode.NOERROR && !soa
        authority.select do |set|
          set.type == Types.NS && set.klass == klass && within_zone?(name, set.name)
        end.max_by { |set| set.name.labels.length }
      end
      if referral
        # A signed delegation with DS needs no denial. An unsigned referral
        # proves the absence of DS at the delegation, not absence of QTYPE.
        return if authority.any? { |set| set.type == Types.DS && set.name == referral.name && set.klass == klass }
        name, qtype = referral.name, Types.DS
      elsif msg.rcode == RCode.NOERROR && name != question.qname && !soa
        return
      end

      proofs = authority.select { |set| [Types.NSEC, Types.NSEC3].include?(set.type) && set.klass == klass }
      if proofs.empty?
        raise VerifyError, "Missing denial proof for #{name}"
      end
      zone = soa&.name
      if context && soa
        signature = context[:verified][soa]&.fetch(:signature)
        raise VerifyError, 'Negative SOA is not signed by its zone' unless signature && signature.signers_name == zone
      end
      groups = {}
      proofs.each do |set|
        ValidationBudget.current&.check!(1)
        signature = context && context[:verified][set]&.fetch(:signature)
        next if context && !signature
        signing_zone = signature&.signers_name || (set.type == Types.NSEC3 ? set.name.strip_label : zone)
        next unless signing_zone && within_zone?(name, signing_zone)
        next if zone && signing_zone != zone
        # DS denial at a non-root delegation must come from the parent.
        next if qtype == Types.DS && name == signing_zone && !name.labels.empty?
        next if signature && signature.labels != set.name.labels.length &&
          !(set.name.wild? && signature.labels == set.name.labels.length - 1)
        (groups[[signing_zone, set.type]] ||= []).concat(set.rrs)
      end
      insecure = false
      groups.each do |(signing_zone, type), records|
        result = if type == Types.NSEC3
          nsec3_denial(records, name, qtype, signing_zone, msg.rcode, !!referral)
        else
          nsec_denial(records, name, qtype, signing_zone, msg.rcode, !!referral)
        end
        if result == :secure
          return true
        elsif result == :insecure
          insecure = true
        end
      end
      if insecure
        context[:insecure] = true if context
        return true
      end
      raise VerifyError, "No authenticated denial proof for #{name}, #{qtype}"
    end

    def terminal_answer(msg, question)
      name = question.qname
      seen = {}
      loop do
        ValidationBudget.current&.check!(1)
        raise VerifyError, 'CNAME loop in answer' if seen[name.canonical]
        seen[name.canonical] = true
        records = msg.answer.select { |rr| rr.name == name && rr.klass == question.qclass && rr.type != Types.RRSIG }
        return [name, true] if records.any? { |rr| question.qtype == Types.ANY || rr.type == question.qtype }
        aliases = records.select { |rr| rr.type == Types.CNAME }
        return [name, false] if aliases.empty?
        targets = aliases.map(&:domainname).uniq
        raise VerifyError, 'Conflicting CNAME targets in answer' unless targets.length == 1
        name = targets.first
      end
    end

    def within_zone?(name, zone)
      name == zone || name.subdomain_of?(zone)
    end

    def denial_bitmap?(record, qtype, referral = false)
      types = record.types
      # ANY has no data-type bit. NSEC3 can represent an empty nonterminal;
      # an exact NSEC owner necessarily has at least its own NSEC RRset.
      return record.type == Types.NSEC3 && types.empty? if qtype == Types.ANY
      return false if types.include?(qtype) || types.include?(Types.CNAME)
      return types.include?(Types.NS) && !types.include?(Types.SOA) if referral
      # A parent delegation cannot deny ordinary data in the child zone.
      qtype == Types.DS || !types.include?(Types.NS) || types.include?(Types.SOA)
    end

    def nsec3_denial(records, name, qtype, zone, rcode, referral)
      records = records.select do |rr|
        ValidationBudget.current&.check!(1)
        rr.name.strip_label == zone && rr.usable_hash?
      end
      return unless records.any?
      # Do not combine independently salted/iterated chains into one proof.
      parameters = records.map { |rr| [rr.hash_alg, rr.iterations, rr.salt] }.uniq
      return unless parameters.length == 1
      hashes = {}
      hash_for = lambda do |candidate|
        hashes[candidate.canonical] ||= records.first.hash_name(candidate)
      end
      matching = lambda do |candidate|
        hashed = hash_for.call(candidate)
        find_denial_record(records) { |rr| rr.owner_hash == hashed }
      end
      covering = lambda do |candidate|
        hashed = hash_for.call(candidate)
        find_denial_record(records) { |rr| rr.covers_hash?(hashed) }
      end
      exact = matching.call(name)
      if rcode == RCode.NOERROR && exact
        return referral ? :insecure : :secure if denial_bitmap?(exact, qtype, referral)
        return
      end
      return if exact

      child, closest, next_cover = name, name.strip_label, nil
      while within_zone?(closest, zone)
        ValidationBudget.current&.check!(1)
        if (record = matching.call(closest))
          # RFC 5155 8.3: a DNAME or parent-side delegation is not an
          # authoritative closest encloser for names below it.
          return if record.types.include?(Types.DNAME) ||
            (record.types.include?(Types.NS) && !record.types.include?(Types.SOA))
          next_cover = covering.call(child)
          break
        end
        break if closest == zone
        child, closest = closest, closest.strip_label
      end
      return unless next_cover
      if rcode == RCode.NOERROR && qtype == Types.DS
        return :insecure if next_cover.opt_out?
        return
      end
      wildcard = Name.new([Name::Label.new('*')] + closest.labels, true)
      if rcode == RCode.NXDOMAIN
        return unless covering.call(wildcard)
      else
        wildcard_record = matching.call(wildcard)
        return unless wildcard_record && denial_bitmap?(wildcard_record, qtype)
      end
      next_cover.opt_out? ? :insecure : :secure
    end

    def nsec_denial(records, name, qtype, zone, rcode, referral)
      records = records.select do |rr|
        ValidationBudget.current&.check!(1)
        within_zone?(rr.name, zone) && within_zone?(rr.next_domain, zone)
      end
      return unless records.any?
      return unless consistent_nsec_intervals?(records)
      exact = find_denial_record(records) { |rr| rr.name == name }
      if rcode == RCode.NOERROR && exact
        return referral ? :insecure : :secure if denial_bitmap?(exact, qtype, referral)
        return
      end
      return if exact || referral
      if rcode == RCode.NOERROR && find_denial_record(records) { |rr| rr.next_domain.subdomain_of?(name) && interval_covers?(rr.name, rr.next_domain, name) }
        # An NSEC ending at a descendant proves an empty nonterminal exists.
        return :secure
      end
      return unless find_denial_record(records) { |rr| nsec_covers_next_closer?(rr, name, zone) }
      closest = name.strip_label
      while within_zone?(closest, zone)
        break if find_denial_record(records) { |rr| within_zone?(rr.name, closest) || within_zone?(rr.next_domain, closest) }
        return if closest == zone
        closest = closest.strip_label
      end
      next_closer = Name.new(name.labels.last(closest.labels.length + 1), true)
      return unless find_denial_record(records) { |rr| nsec_covers_next_closer?(rr, next_closer, zone) }
      wildcard = Name.new([Name::Label.new('*')] + closest.labels, true)
      if rcode == RCode.NXDOMAIN
        return :secure if find_denial_record(records) { |rr| nsec_covers_next_closer?(rr, wildcard, zone) }
      else
        record = find_denial_record(records) { |rr| rr.name == wildcard }
        return :secure if record && denial_bitmap?(record, qtype)
      end
      nil
    end

    def find_denial_record(records)
      records.find do |record|
        ValidationBudget.current&.check!(1)
        yield record
      end
    end

    def consistent_nsec_intervals?(records)
      # If an interval contains any observed owner, it contains the next
      # distinct owner in canonical order. Sorting avoids an all-pairs scan.
      owners = records.group_by do |rr|
        ValidationBudget.current&.check!(1)
        rr.name.canonical
      end.values.sort do |first, second|
        ValidationBudget.current&.check!(1)
        first.first.name.canonically_before(second.first.name) ? -1 : 1
      end
      owners.each_with_index do |group, index|
        following = owners[(index + 1) % owners.length].first.name
        group.each do |rr|
          ValidationBudget.current&.check!(1)
          return false if interval_covers?(rr.name, rr.next_domain, following)
        end
      end
      true
    end

    # Section#rrsets intentionally returns copies. Publish their authenticated
    # bounds only after the entire message has passed validation, including its
    # denial proof, so the response cache receives the same lifetimes.
    def apply_verified_lifetimes(msg, context)
      limits = {}
      now = Time.now.to_i
      context[:verified].each do |rrset, result|
        identity = [rrset.name.canonical, rrset.klass.code, rrset.type.code]
        previous = limits[identity]
        limits[identity] = [([rrset.ttl] + Array(previous&.first)).min,
          ([result[:expiration]] + Array(previous&.last)).min]
      end
      msg.each_resource do |rr|
        type = rr.type == Types.RRSIG ? rr.type_covered : rr.type
        limit = limits[[rr.name.canonical, rr.klass.code, type.code]]
        next unless limit
        previous = rr.instance_variable_get(:@dnsruby_authenticated_expiration)
        deadline = [previous, limit.last].compact.min
        rr.ttl = [rr.ttl, limit.first, [deadline - now, 0].max].min
        rr.instance_variable_set(:@dnsruby_authenticated_expiration, deadline)
        rr.instance_variable_set(:@dnsruby_received_at, now)
      end
    end
    private :terminal_answer, :within_zone?, :denial_bitmap?, :nsec3_denial,
      :nsec_denial, :apply_verified_lifetimes, :find_denial_record, :consistent_nsec_intervals?

    def verify_ds_rrset(ds_rrset, keys = nil, msg = nil, context = {}) # :nodoc:
      with_validation { verify_ds_rrset_internal(ds_rrset, keys, msg, context) }
    end

    private def verify_ds_rrset_internal(ds_rrset, keys, msg, context)
      #       print "verify_ds_rrset #{ds_rrset}\n"
      if (ds_rrset && ds_rrset.num_sigs > 0)
        if (verify_rrset(ds_rrset, keys, context))
          return true if context[:insecure]
          provenance = context.fetch(:provenance)
          retain_learned_rrset(ds_rrset, provenance)
          if usable_provenance?(provenance)
            publish_trust do
              same_set = lambda { |set| set.name == ds_rrset.name && set.klass == ds_rrset.klass && set.type == ds_rrset.type }
              trust_operation[:ds].reject! { |set, _trust| same_set.call(set) }
              trust_operation[:ds] << [ds_rrset, provenance]
              @discovered_ds_store.reject! { |_expiration, set| same_set.call(set) }
              if provenance.expiration > Time.now.to_i
                @discovered_ds_store.push([provenance.expiration, ds_rrset])
              end
            end
          end
          return true
        else
          return false
        end
      end
      return false # no DS rrset to verify
    end

    def verify_key_rrset(key_rrset, keys = nil, context = {}) # :nodoc:
      with_validation { verify_key_rrset_internal(key_rrset, keys, context) }
    end

    private def verify_key_rrset_internal(key_rrset, keys, context)
      #       print "verify_key_rrset\n"
      verified = false
      if (key_rrset && key_rrset.num_sigs > 0)
        if (verify_rrset(key_rrset, keys, context))
          #             key_rrset.rrs.each do |rr|
          #           print "Adding keys : "
          #           key_rrset.rrs.each {|rr| print "#{rr.key_tag}, "}
          #           print "\n"
          unless context[:insecure]
            retain_learned_rrset(key_rrset, context.fetch(:provenance))
            add_trusted_key(key_rrset, context.fetch(:expiration))
          end
          verified = true
        end
      end
      return verified
    end

    def check_ds_stores(key_rrset, signatures = nil) # :nodoc:
      with_validation { check_ds_stores_internal(key_rrset, signatures) }
    end

    private def check_ds_stores_internal(key_rrset, signatures)
      signatures ||= valid_signatures(key_rrset)
      return if signatures.empty?
      # A digest match supplies a candidate key, not a cache lifetime. Publish
      # only after authenticating the DNSKEY RRset and its TTL.
      verify_key_rrset(key_rrset)
    end

    def ds_candidate_keys(key_rrset, explicit_ds = nil)
      configured, discovered = @trust_mutex.synchronize do
        expire_trust_anchors
        @discovered_ds_store.reject! { |expiration, _rrset| expiration <= Time.now.to_i }
        [@configured_ds_store.dup, @discovered_ds_store.map(&:last)]
      end
      stores = configured.map { |ds| [nil, [ds]] }
      stores.concat(discovered.filter_map do |rrset|
        provenance = learned_provenance(rrset)
        [admit_provenance(provenance), rrset.rrs] if usable_provenance?(provenance)
      end)
      stores.concat((trust_operation&.fetch(:ds) || []).filter_map do |rrset, provenance|
        [provenance, rrset.rrs] if usable_provenance?(provenance)
      end)
      if explicit_ds
        # Caller-supplied DS records are explicit trust input. If this is a
        # learned DS RRset or a new set wrapping learned records, retain their
        # original absolute deadlines and trust sources.
        provenance = admit_learned_rrset(explicit_ds)
        stores = explicit_ds.rrs.filter_map do |record|
          trust = provenance || learned_provenance(record)
          next if trust && !usable_provenance?(trust)
          [admit_provenance(trust), [record]]
        end
        raise VerifyError, 'Learned DS trust is no longer valid' if stores.empty?
      end
      candidates = {}
      key_rrset.rrs.each do |key|
        stores.each do |provenance, records|
          next unless records.any? { |ds| ValidationBudget.current&.check!(1); ds.check_key(key) }
          identity = KeyCache.key_identity(key)
          previous = candidates[identity]
          if !previous || (previous.last && (!provenance || provenance.expiration > previous.last.expiration))
            candidates[identity] = [key, provenance]
          end
        end
      end
      candidates
    end
    private :ds_candidate_keys

    def get_keys_to_check # :nodoc:
      anchors, keys = @trust_mutex.synchronize do
        expire_trust_anchors
        [@trust_anchors.keys, cached_trust_keys]
      end
      local = (trust_operation&.fetch(:keys)&.values || []).filter_map do |key, provenance|
        key if usable_provenance?(provenance)
      end
      (anchors + keys.select { |key| usable_cached_key?(key) } + local).uniq { |key| KeyCache.key_identity(key) }
    end

    #  Find the first matching DNSKEY and RRSIG record in the two sets.
    def get_matching_key(keys, sigrecs)#:nodoc: all
      each_matching_key(keys, sigrecs) { |key, sig| return key, sig }
      return nil, nil
    end

    # A key tag is only a hint: every candidate must be cryptographically tried.
    def each_matching_key(keys, sigrecs)
      if ((keys == nil) || (sigrecs == nil))
        return
      end
      if ((RR::DNSKEY === keys) || (RR::DS === keys) ||
            ((RR::DLV === keys) && (@verifier_type == VerifierType::DLV)))
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
          ValidationBudget.current&.check!(1)
          if key.key_tag == sig.key_tag && key.algorithm == sig.algorithm &&
              key.name.canonical == sig.signers_name.canonical && key.klass == sig.klass
            yield key, sig
          end
        }
      }
    end
    private :each_matching_key

    #  Verify the signature of an rrset encoded with the specified KeyCache
    #  or RRSet. If no signature is included, false is returned.
    # 
    #  Returns true if the RRSet verified, false otherwise.
    def verify_rrset(rrset, keys = nil, context = {})
      with_validation { verify_rrset_internal(rrset, keys, context) }
    end

    private def verify_rrset_internal(rrset, keys, context)
      received_at = rrset.rrs.map { |rr| rr.instance_variable_get(:@dnsruby_received_at) }.compact.min || Time.now.to_i
      #       print "Verify_rrset #{rrset.name}, #{rrset.type}\n"
#      print "ABOUT TO VERIFY WITH #{keys == nil ? '0' : keys.length} keys\n"
#      if (keys != nil)
#        if (keys.length > 0)
#          print "KEY TAG : #{keys[0].key_tag}\n"
#        end
#      end
      sigrecs = rrset.sigs
      if (rrset.rrs.length == 0)
        raise VerifyError.new("No RRSet to verify")
      end
      if (rrset.num_sigs == 0)
        raise VerifyError.new("No signatures in the RRSet : #{rrset.name}, #{rrset.type}")
      end
      sigrecs = valid_signatures(rrset)
      raise ArgumentError.new("Expecting DNSKEY, DLV, DS, RRSet, Array or nil for keys : got #{keys.class} instead") if
      (keys && (![Array, RR::IN::DNSKEY, RR::IN::DLV, RR::IN::DS].include?keys.class) && (keys.class != RRSet))

      explicit_keys = !keys.nil?
      explicit_provenance = admit_learned_rrset(keys)
      # Wrap a single DS or DLV record without losing its learned provenance.
      if [RR::IN::DS, RR::IN::DLV].include?(keys.class)
        keys = RRSet.new([keys])
        retain_learned_rrset(keys, explicit_provenance) if explicit_provenance
      end

      ds_keys = {}
      explicit_ds = keys if keys.is_a?(RRSet) &&
        (keys.type == Types.DS || (keys.type == Types.DLV && @verifier_type == VerifierType::DLV))
      if rrset.type == Types.DNSKEY && (keys.nil? || explicit_ds)
        ds_keys = ds_candidate_keys(rrset, explicit_ds)
      end
      if keys.nil? || explicit_ds
        keys = get_keys_to_check + ds_keys.values.map(&:first)
      end

      error = VerifyError.new("Signing key not found")
      canonical_data = {}
      each_matching_key(keys, sigrecs) do |keyrec, sigrec|
        begin
          identity = KeyCache.key_identity(keyrec)
          parent_provenance = if explicit_ds
            ds_keys.key?(identity) ? ds_keys[identity].last : key_provenance(keyrec)
          elsif explicit_keys
            explicit_provenance || admit_learned_rrset(keyrec)
          elsif ds_keys.key?(identity)
            ds_keys[identity].last
          else
            key_provenance(keyrec)
          end
          next if parent_provenance && !usable_provenance?(parent_provenance)
          parent_provenance = admit_provenance(parent_provenance)
          ValidationBudget.current&.signature!
          ttl_expiration = received_at + [rrset.ttl, sigrec.ttl, sigrec.original_ttl].min
          previous_expirations = (rrset.rrs + [sigrec]).map do |rr|
            rr.instance_variable_get(:@dnsruby_authenticated_expiration)
          end.compact
          verify_rrset_with_key(rrset, keyrec, sigrec, canonical_data)
          check_wildcard_proof(rrset, sigrec, keys, context) if context[:message]
          if parent_provenance && !usable_provenance?(parent_provenance)
            raise VerifyError, 'Learned trust expired during verification'
          end
          expiration = ([ttl_expiration, sigrec.expiration] + previous_expirations).min
          provenance = authenticated_provenance(rrset, sigrec, expiration, parent_provenance)
          verified_at = Time.now.to_i
          rrset.ttl = [rrset.ttl, [provenance.expiration - verified_at, 0].max].min
          rrset.each do |rr|
            rr.instance_variable_set(:@dnsruby_authenticated_expiration, provenance.expiration)
            rr.instance_variable_set(:@dnsruby_received_at, verified_at)
          end
          context[:expiration] = provenance.expiration
          context[:provenance] = provenance
          context[:signature] = sigrec
          context[:verified][rrset] = { signature: sigrec, expiration: provenance.expiration } if context[:verified]
          return true
        rescue VerifyError => e
          error = e
        rescue OpenSSL::OpenSSLError => e
          # Wire-decoded DNSKEYs may only be parsed by OpenSSL at this point.
          # A malformed colliding candidate must not mask a valid signing key.
          error = VerifyError.new("Signature failed to cryptographically verify: #{e.message}")
        end
      end
      raise error
    end

    def verify_rrset_with_key(rrset, keyrec, sigrec, canonical_data = {})
      #  RFC 4034
      # 3.1.8.1.  Signature Calculation

      unless keyrec.zone_key?
        raise VerifyError, 'DNSKEY Zone Key flag is not set'
      end
      unless VALIDATION_ALGORITHMS.include?(sigrec.algorithm)
        if [Algorithms.DSA, Algorithms.DSA_NSEC3_SHA1].include?(sigrec.algorithm)
          raise VerifyError, "Algorithm #{sigrec.algorithm.code} is prohibited for DNSSEC validation"
        end
        raise VerifyError, "Algorithm #{sigrec.algorithm.code} unsupported by Dnsruby"
      end

      # Canonical RDATA is independent of the signature. The RR wire body only
      # varies with Original TTL and wildcard label count (RFC 4034 section 3.1.8).
      # Keep it local to this verification so mutable caller records are never
      # cached across calls, and do not temporarily mutate their TTLs.
      sig_data = sigrec.sig_data + canonical_rrset_data(rrset, sigrec, canonical_data)
      ValidationBudget.current&.check!(sig_data.bytesize / 64 + 1)

      #  Now calculate the signature
      verified = false
      if [Algorithms.RSASHA1,
          Algorithms.RSASHA1_NSEC3_SHA1].include?(sigrec.algorithm)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA1.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == Algorithms.RSASHA256)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA256.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == Algorithms.RSASHA512)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA512.new, sigrec.signature, sig_data)
      elsif [Algorithms.ECDSAP256SHA256, Algorithms.ECDSAP384SHA384].include?(sigrec.algorithm)
        byte_size = (keyrec.public_key.group.degree + 7) / 8
        if sigrec.signature.bytesize != 2 * byte_size
          raise VerifyError, "Invalid ECDSA signature length"
        end
        sig_bytes = sigrec.signature[0..(byte_size - 1)]
        sig_char = sigrec.signature[byte_size..-1] || ''
        asn1 = OpenSSL::ASN1::Sequence.new([sig_bytes, sig_char].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der

        digest_obj = if sigrec.algorithm == Algorithms.ECDSAP384SHA384
                       OpenSSL::Digest::SHA384.new
                     else
                       OpenSSL::Digest::SHA256.new
                     end

        verified = keyrec.public_key.dsa_verify_asn1(digest_obj.digest(sig_data), asn1)
      else
        raise VerifyError.new("Algorithm #{sigrec.algorithm.code} unsupported by Dnsruby")
      end

      if (!verified)
        raise VerifyError.new("Signature failed to cryptographically verify")
      end
      ValidationBudget.current&.check!
      # Commit lifetime bounds only after the wildcard proof also succeeds.
      raise VerifyError, 'Signature expired during verification' if sigrec.expiration.to_i < Time.now.to_i
      #             print "VERIFIED OK\n"
      return true
    end
    private :verify_rrset_with_key

    def canonical_rrset_data(rrset, signature, cache)
      identity = [signature.original_ttl, signature.labels]
      return cache[identity] if cache.key?(identity)
      name = rrset.name
      if signature.labels < 0 || signature.labels > name.labels.length
        raise VerifyError, 'Invalid RRSIG label count'
      elsif signature.labels < name.labels.length
        name = Name.new([Name::Label.new('*')] + name.labels.last(signature.labels), true)
      end
      rdatas = cache[:rdatas] ||= rrset.rrs.map do |record|
        ValidationBudget.current&.check!(1)
        data = MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s
        ValidationBudget.current&.check!(data.bytesize / 64 + 1)
        data
      end.uniq.sort
      prefix = MessageEncoder.new do |encoder|
        encoder.put_name(name, true)
        encoder.put_pack('nnN', rrset.type.code, rrset.klass.code, signature.original_ttl)
      end.to_s
      cache[identity] = rdatas.map do |data|
        ValidationBudget.current&.check!(1)
        prefix + [data.bytesize].pack('n') + data
      end.join
    end
    private :canonical_rrset_data

    # A valid wildcard signature authenticates the source wildcard, not the
    # expanded owner. RFC 4035 5.3.4 / RFC 5155 8.8 also require denial of the
    # next-closer name. Keep this at message level: verify_rrset alone has no
    # response from which to obtain that proof.
    def check_wildcard_proof(rrset, signature, keys, context)
      labels = signature.labels
      return if labels == rrset.name.labels.length
      return if rrset.name.wild? && labels == rrset.name.labels.length - 1
      zone = signature.signers_name
      closest = Name.new(rrset.name.labels.last(labels), true)
      next_closer = Name.new(rrset.name.labels.last(labels + 1), true)
      unless closest == zone || closest.subdomain_of?(zone)
        raise VerifyError, 'Wildcard source is outside the signing zone'
      end
      proof_id = [zone.canonical, rrset.klass.code, next_closer.canonical]
      if (cached = context[:proofs][proof_id])
        context[:insecure] = true if cached == :insecure
        return
      end

      authority = context[:message].authority
      insecure_proof = false
      (authority.rrsets(Types.NSEC) + authority.rrsets(Types.NSEC3)).each do |proof|
        ValidationBudget.current&.check!(1)
        next unless proof.klass == rrset.klass
        covers = proof.rrs.any? do |record|
          if record.type == Types.NSEC
            nsec_covers_next_closer?(record, next_closer, zone)
          else
            nsec3_covers_next_closer?(record, next_closer, zone)
          end
        end
        next unless covers
        # Only signatures from the wildcard's zone can authenticate its proof.
        # An expanded NSEC itself cannot prove the absence of its new owner.
        signatures = proof.sigs.select do |sig|
          sig.signers_name == zone && (sig.labels == proof.name.labels.length ||
            (proof.name.wild? && sig.labels == proof.name.labels.length - 1))
        end
        next if signatures.empty?
        begin
          verify_rrset(RRSet.new(proof.rrs + signatures), keys)
          if proof.type == Types.NSEC3 && proof.rrs.any? { |rr| rr.flags == 1 }
            insecure_proof = true
            next
          end
          context[:proofs][proof_id] = :secure
          return
        rescue VerifyError
          # Another authenticated denial record may supply the proof.
        end
      end
      if insecure_proof
        context[:proofs][proof_id] = :insecure
        context[:insecure] = true
        return
      end
      raise VerifyError, "No authenticated wildcard denial proof for #{rrset.name}"
    end

    def nsec_covers_next_closer?(record, name, zone)
      owner, following = record.name, record.next_domain
      return false unless [owner, following].all? { |n| n == zone || n.subdomain_of?(zone) }
      # A descendant proves an empty nonterminal exists. Parent-side denial
      # below a delegation or DNAME cannot establish absence in that subtree.
      return false if following.subdomain_of?(name) || owner.subdomain_of?(name)
      if name.subdomain_of?(owner)
        return false if record.types.include?(Types.DNAME) ||
          (record.types.include?(Types.NS) && !record.types.include?(Types.SOA))
      end
      interval_covers?(owner, following, name)
    end

    def nsec3_covers_next_closer?(record, name, zone)
      return false unless record.name.strip_label == zone && record.hash_alg == Nsec3HashAlgorithms.SHA_1
      # An Opt-Out interval can hide an insecure delegation, so cannot prove
      # this wildcard expansion secure (RFC 5155 section 9.2).
      return false unless [0, 1].include?(record.flags) && record.next_hashed.bytesize == 20
      owner = record.name.labels.first.to_s.downcase
      return false unless /\A[0-9a-v]{32}\z/.match?(owner)
      following = RR::NSEC3.encode_next_hashed(record.next_hashed).downcase
      hashed = RR::NSEC3.calculate_hash(name, record.iterations, RR::NSEC3.decode_salt(record.salt), record.hash_alg)
      interval_covers?(owner, following, hashed)
    end

    def interval_covers?(first, following, name)
      return false if name == first || name == following
      if first.is_a?(Name)
        first.canonically_before(following) ?
          first.canonically_before(name) && name.canonically_before(following) :
          first.canonically_before(name) || name.canonically_before(following)
      else
        first < following ? first < name && name < following : first < name || name < following
      end
    end
    private :check_wildcard_proof, :nsec_covers_next_closer?, :nsec3_covers_next_closer?, :interval_covers?

    def find_closest_dlv_anchor_for(name) # :nodoc:
      with_validation { find_closest_dlv_anchor_for_internal(name) }
    end

    private def find_closest_dlv_anchor_for_internal(name)
      #  To find the closest anchor, query DLV.isc.org for [a.b.c.d], then [a.b.c], [a.b], etc.
      #  once closest anchor found, simply run follow_chain from that anchor

      #  @TODO@ REALLY NEED AGGRESSIVE NEGATIVE CACHING HERE!!
      #  i.e. don't look up zones which we *know* we don't have a DLV anchor for

      n = Name.create(name)
      root = Name.create(".")
      while (n != root)
        #  Try to find name in DLV, and return it if possible
        dlv_rrset = query_dlv_for(n)
        if (dlv_rrset)
          key_rrset = get_zone_key_from_dlv_rrset(dlv_rrset, n)
          return key_rrset
        end
        #  strip the name
        n = n.strip_label
      end
      return false
    end

    def get_zone_key_from_dlv_rrset(dlv_rrset, name) # :nodoc:
      with_validation { get_zone_key_from_dlv_rrset_internal(dlv_rrset, name) }
    end

    private def get_zone_key_from_dlv_rrset_internal(dlv_rrset, name)
      #  We want to return the key for the zone i.e. DS/DNSKEY for .se, NOT DLV for se.dlv.isc.org
      #  So, we have the DLv record. Now use it to add the zone's DNSKEYs to the trusted key set.
      res = get_nameservers_for(name)
      if (!res)
        if (Dnssec.do_validation_with_recursor?)
          res = get_recursor
        else
          if(Dnssec.default_resolver)
            res = Dnssec.default_resolver
          else
            res = Resolver.new
          end
        end
      end
      res.dnssec = true
      #       query = Message.new(name, Types.DNSKEY)
      #       query.do_validation = false
      ret = nil
      begin
        #         ret = res.send_message(query)
        ret = res.query_no_validation_or_recursion(name, Types.DNSKEY)
        if (!ret)
          raise ResolvError.new("Couldn't get DNSKEY from Recursor")
        end
      rescue ResolvError => e
        #         print "Error getting zone key from DLV RR for #{name} : #{e}\n"
        TheLog.error("Error getting zone key from DLV RR for #{name} : #{e}")
        return false
      end
      key_rrset = ret.answer.rrset(name, Types.DNSKEY)
      begin
        verify(key_rrset, dlv_rrset)
        #         Cache.add(ret)
        return key_rrset
      rescue VerifyError => e
        #         print "Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}\n"
        TheLog.debug("Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}")
      end
      return false
    end

    def query_dlv_for(name) # :nodoc:
      with_validation { query_dlv_for_internal(name) }
    end

    private def query_dlv_for_internal(name)
      #  See if there is a record for name in dlv.isc.org
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      begin
        name_to_query = name.to_s+".dlv.isc.org"
        #         query = Message.new(name_to_query, Types.DLV)
        #         @res.single_resolvers()[0].prepare_for_dnssec(query)
        #         query.do_validation = false
        ret = nil
        begin
          #           ret = @res.send_message(query)
          ret = @res.query_no_validation_or_recursion(name_to_query, Types.DLV)
          if (!ret)
            raise ResolvError.new("Couldn't get DLV record from Recursor")
          end
        rescue ResolvError => e
          #           print "Error getting DLV record for #{name} : #{e}\n"
          TheLog.info("Error getting DLV record for #{name} : #{e}")
          return nil
        end
        dlv_rrset = ret.answer.rrset(name_to_query,Types.DLV)
        if (dlv_rrset.rrs.length > 0)
          begin
            verify(dlv_rrset)
            #             Cache.add(ret)
            return dlv_rrset
          rescue VerifyError => e
            #             print "Error verifying DLV records for #{name}, #{e}\n"
            TheLog.info("Error verifying DLV records for #{name}, #{e}")
          end
        end
      rescue NXDomain
        #         print "NXDomain for DLV lookup for #{name}\n"
        return nil
      end
      return nil
    end

    def find_closest_anchor_for(name) # :nodoc:
      #  Check if we have an anchor for name.
      #  If not, strip off first label and try again
      #  If we get to root, then return false
      name = "." if name == ""
      n = Name.create(name)
      root = Name.create(".")
      configured, keys, discovered = @trust_mutex.synchronize do
        expire_trust_anchors
        @discovered_ds_store.reject! { |expiration, _rrset| expiration <= Time.now.to_i }
        [@trust_anchors.keys + @configured_ds_store, cached_trust_keys, @discovered_ds_store.map(&:last)]
      end
      anchors = configured + keys.select { |key| usable_cached_key?(key) } +
        discovered.select { |rrset| usable_provenance?(learned_provenance(rrset)) }
      if trust_operation
        anchors.concat(trust_operation[:keys].values.filter_map { |key, trust| key if usable_provenance?(trust) })
        anchors.concat(trust_operation[:ds].filter_map { |rrset, trust| rrset if usable_provenance?(trust) })
      end
      while (true) # n != root)
        #  Try the trusted keys first, then the DS set
        anchors.each {|key|
          return key if key.name.canonical == n.canonical
        }
        break if (n.to_s == root.to_s)
        #  strip the name
        n = n.strip_label
      end
      return false
    end

    #  @TODO@ Handle REVOKED keys! (RFC 5011)
    #  Remember that revoked keys will have a different key_tag than pre-revoked.
    #  So, if we see a revoked key, we should go through our key store for
    #  that authority and remove any keys with the pre-revoked key_tag.

    def follow_chain(anchor, name) # :nodoc:
      with_validation { follow_chain_internal(anchor, name) }
    end

    private def follow_chain_internal(anchor, name)
      admit_learned_rrset(anchor)
      #  Follow the chain from the anchor to name, returning the appropriate
      #  key at the end, or false.
      # 
      #  i.e. anchor = se, name = foo.example.se
      #    get anchor for example.se with se anchor
      #    get anchor for foo.example.se with example.se anchor
      next_key = anchor
      next_step = anchor.name
      parent = next_step
      #       print "Follow chain from #{anchor.name} to #{name}\n"
      TheLog.debug("Follow chain from #{anchor.name} to #{name}")

      #       res = nil
      res = Dnssec.default_resolver
      #       while ((next_step != name) || (next_key.type != Types.DNSKEY))
      while (true)
        ValidationBudget.current&.check!(1)
        #         print "In loop for parent=#{parent}, next step = #{next_step}\n"
        dont_move_on = false
        if (next_key.type != Types.DNSKEY)
          dont_move_on = true
        end
        next_key, res = get_anchor_for(next_step, parent, next_key, res)
        if (next_step.canonical.to_s == name.canonical.to_s)
          #       print "Returning #{next_key.type} for #{next_step}, #{(next_key.type != Types.DNSKEY)}\n"
          return next_key
        end
        return false if (!next_key)
        #  Add the next label on
        if (!dont_move_on)
          parent = next_key.name
          next_step = Name.new(name.labels[name.labels.length-1-next_step.labels.length,1] +
              next_step.labels , name.absolute?)
          #           print "Next parent = #{parent}, next_step = #{next_step}, next_key.type = #{next_key.type.string}\n"
        end
      end

      #       print "Returning #{next_key.type} for #{next_step}, #{(next_key.type != Types.DNSKEY)}\n"

      return next_key
    end

    def get_anchor_for(child, parent, current_anchor, parent_res = nil) # :nodoc:
      with_validation { get_anchor_for_internal(child, parent, current_anchor, parent_res) }
    end

    private def get_anchor_for_internal(child, parent, current_anchor, parent_res)
      admit_learned_rrset(current_anchor)
      if current_anchor.type == Types.DS
        records = current_anchor.is_a?(RRSet) ? current_anchor.rrs : [current_anchor]
        # A cached or configured DS is already trusted input, but its learned
        # provenance must still be live before its algorithm policy is used.
        return false, parent_res unless records.any? { |record| supported_ds?(record) }
      end
      ds_rrset = current_anchor
      #       print "Trying to discover anchor for #{child} from #{parent}\n"
      TheLog.debug("Trying to discover anchor for #{child} from #{parent} using #{current_anchor}, #{parent_res}")
      #  We wish to return a DNSKEY which the caller can use to verify name
      #  We are either given a key or a ds record from the parent zone
      #  If given a DNSKEY, then find a DS record signed by that key for the child zone
      #  Use the DS record to find a valid key in the child zone
      #  Return it

      #  Find NS RRSet for parent
      child_res = nil
      if (Dnssec.do_validation_with_recursor?)
        parent_res = get_recursor
        child_res = get_recursor
      end
      begin
        if (child!=parent)
          if (!parent_res)
            #                       print "No res passed - try to get nameservers for #{parent}\n"
            parent_res = get_nameservers_for(parent)
            if (!parent_res)
              if (Dnssec.do_validation_with_recursor?)
                parent_res = get_recursor
              else
                if (Dnssec.default_resolver)
                  parent_res = Dnssec.default_resolver
                else
                  parent_res = Resolver.new
                end
              end
            end
            parent_res.dnssec = true
          end
          #  Use that Resolver to query for DS record and NS for children
          if (current_anchor.type == Types.DNSKEY)
            #             print "Trying to find DS records for #{child} from servers for #{parent}\n"
            TheLog.debug("Trying to find DS records for #{child} from servers for #{parent}")
            ds_ret = nil
            begin
              ds_ret = parent_res.query_no_validation_or_recursion(child, Types.DS)
              if (!ds_ret)
                raise ResolvError.new("Couldn't get DS records from Recursor")
              end
            rescue NXDomain => e
              # NXDOMAIN is usable only with its authenticated denial response.
              ds_ret = e.response
              raise VerifyError, "Missing DS denial response for #{child}" unless ds_ret
            rescue ResolvError => e
              raise VerifyError, "Error getting DS record for #{child}: #{e}"
            end
            ds_rrset = ds_ret.answer.rrset(child, Types.DS)
            if (ds_rrset.rrs.length == 0)
              denial = authenticated_ds_absence(ds_ret, child, current_anchor)
              # A label need not be a zone cut. Continue using the current
              # zone's key unless the proof establishes an unsigned delegation.
              return denial == :insecure ? [false, parent_res] : [current_anchor, parent_res]
            else
              begin
                unless verify(ds_rrset, current_anchor) || verify(ds_rrset)
                  raise VerifyError, "Unsigned DS RRSet for #{child}"
                end
                # RFC 4035 5.2: a securely authenticated delegation whose DS
                # records all use unavailable algorithms/digests is insecure.
                # Mixed sets must still establish trust using a supported DS.
                unless ds_rrset.rrs.any? { |ds| supported_ds?(ds) }
                  return false, parent_res
                end
                # Try the child nameservers only after authenticating its DS.
                unless Dnssec.do_validation_with_recursor?
                  child_res = get_nameservers_from_message(child, ds_ret)
                end
              rescue VerifyError => e
                #                 print "FAILED TO VERIFY DS RRSET FOR #{child}\n"
                TheLog.info("FAILED TO VERIFY DS RRSET FOR #{child}")
                # return false, nil
                # raise ResolvError.new("FAILED TO VERIFY DS RRSET FOR #{child}")
                raise VerifyError.new("FAILED TO VERIFY DS RRSET FOR #{child}")
              end
            end
          end
        end
        #  Make Resolver using all child NSs
        if (!child_res)
          child_res = get_nameservers_for(child, parent_res)
        end
        if (!child_res)
          if (Dnssec.do_validation_with_recursor?)
            child_res = get_recursor
          else
            if (Dnssec.default_resolver)
              child_res = Dnssec.default_resolver
            else
              if (Dnssec.default_resolver)
                child_res = Dnssec.default_resolver
              else
                child_res = Resolver.new
              end
            end
            child_res.dnssec = true
          end
        end
        #  Query for DNSKEY record, and verify against DS in parent.
        #  Need to get resolver NOT to verify this message - we verify it afterwards
        #         print "Trying to find DNSKEY records for #{child} from servers for #{child}\n"
        TheLog.info("Trying to find DNSKEY records for #{child} from servers for #{child}")
        #         query = Message.new(child, Types.DNSKEY)
        #         query.do_validation = false
        key_ret = nil
        begin
          #           key_ret = child_res.send_message(query)
          key_ret = child_res.query_no_validation_or_recursion(child, Types.DNSKEY)
          if (!key_ret)
            raise ResolvError.new("Couldn't get info from Recursor")
          end
        rescue ResolvError => e
          #           print "Error getting DNSKEY for #{child} : #{e}\n"
          TheLog.error("Error getting DNSKEY for #{child} : #{e}")
          # return false, nil
          raise VerifyError.new("Error getting DNSKEY for #{child} : #{e}")
        end
        key_rrset = key_ret.answer.rrset(child, Types.DNSKEY)
        if key_rrset.rrs.empty?
          raise VerifyError, "Missing DNSKEY RRSet for #{child}"
        end
        begin
          raise VerifyError, "Unsigned DNSKEY RRSet for #{child}" unless verify(key_rrset, ds_rrset)
        rescue VerifyError
          # Another explicitly configured or already learned anchor can still
          # authenticate this same zone. Non-zone keys are ignored as signers.
          raise VerifyError, "Couldn't verify DNSKEY and DS records for #{child}" unless verify(key_rrset)
        end

        #  Try to make the resolver from the authority/additional NS RRSets in DNSKEY response
        new_res = get_nameservers_from_message(child,  key_ret) # @TODO@ ?
        if (!new_res)
          new_res = child_res
        end
        #         Cache.add(key_ret)
        return key_rrset, new_res
      rescue VerifyError => e
        #         print "Verification error : #{e}\n"
        TheLog.info("Verification error : #{e}\n")
        # return false, nil # new_res
        raise VerifyError.new("Verification error : #{e}\n")
      end
    end

    def supported_ds?(record)
      VALIDATION_ALGORITHMS.include?(record.algorithm) && [1, 2, 4].include?(record.digest_type.code)
    end
    private :supported_ds?

    # Authenticate denial against the current parent key before classifying
    # an unsigned delegation. A successful denial at an ordinary name simply
    # means there is no zone cut at this label (RFC 4035 5.2 / RFC 5155 8.9).
    def authenticated_ds_absence(message, child, anchor)
      question = message.question.first
      unless question && question.qname == child && question.qtype == Types.DS &&
          question.qclass == anchor.klass && [RCode.NOERROR, RCode.NXDOMAIN].include?(message.rcode)
        raise VerifyError, "Unexpected DS denial response for #{child}"
      end
      zone = anchor.name
      groups = {}
      (message.authority.rrsets(Types.NSEC) + message.authority.rrsets(Types.NSEC3)).each do |proof|
        ValidationBudget.current&.check!(1)
        next unless proof.klass == anchor.klass
        signatures = proof.sigs.select do |signature|
          signature.signers_name == zone && (signature.labels == proof.name.labels.length ||
            (proof.name.wild? && signature.labels == proof.name.labels.length - 1))
        end
        next if signatures.empty?
        begin
          verify_rrset(RRSet.new(proof.rrs + signatures), anchor)
          (groups[proof.type] ||= []).concat(proof.rrs)
        rescue VerifyError
          # A second proof/signature may still provide valid denial.
        end
      end
      groups.each do |type, records|
        check = type == Types.NSEC3 ? :nsec3_denial : :nsec_denial
        if message.rcode == RCode.NOERROR &&
            send(check, records, child, Types.DS, zone, message.rcode, true) == :insecure
          return :insecure
        end
        result = send(check, records, child, Types.DS, zone, message.rcode, false)
        return result if result
      end
      raise VerifyError, "No authenticated DS denial proof for #{child}"
    end
    private :authenticated_ds_absence

    def get_nameservers_for(name, res = nil) # :nodoc:
      #  @TODO@ !!!
      if (Dnssec.do_validation_with_recursor?)
        return get_recursor
      else
        resolver = nil
        if (Dnssec.default_resolver)
          resolver = Dnssec.default_resolver
        else
          resolver = Resolver.new
        end
        resolver.dnssec = true
        return resolver
      end
    end

    def get_nameservers_from_message(name, ns_ret) # :nodoc:
      if (Dnssec.default_resolver)
        return Dnssec.default_resolver
      end

      ns_rrset = ns_ret.answer.rrset(name, Types.NS)
      if (!ns_rrset || ns_rrset.length == 0)
        ns_rrset = ns_ret.authority.rrset(name, Types.NS) # @TODO@ Is ths OK?
      end
      if (!ns_rrset || ns_rrset.length == 0 || ns_rrset.name.canonical != name.canonical)
        return nil
      end
      if (ns_rrset.sigs.length > 0)
        #                 verify_rrset(ns_rrset) # @TODO@ ??
      end
      #       Cache.add(ns_ret)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.A) }
      nameservers = []
      add_nameservers(ns_rrset, ns_additional, nameservers) # if (ns_additional.length > 0)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.AAAA) }
      add_nameservers(ns_rrset, ns_additional, nameservers) if (ns_additional.length > 0)
      #  Make Resolver using all NSs
      if (nameservers.length == 0)
        #         print "Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}\n"
        TheLog.info("Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}")
        return  nil # @TODO@ Could return a recursor here?
        # return Recursor.new
      end
      res = Resolver.new()
      res.nameserver=(nameservers)
      #  Set the retry_delay to be (at least) the number of nameservers
      #  Otherwise, the queries will be sent at a rate of more than one a second!
      res.retry_delay = nameservers.length * 2
      res.dnssec = true
      return res
    end

    def add_nameservers(ns_rrset, ns_additional, nameservers) # :nodoc:
      #  Want to go through all of the ns_rrset NS records,
      #       print "Checking #{ns_rrset.rrs.length} NS records against #{ns_additional.length} address records\n"
      ns_rrset.rrs.sort_by {rand}.each {|ns_rr|
        #    and see if we can find any of the names in the A/AAAA records in ns_additional
        found_addr = false
        ns_additional.each {|addr_rr|
          if (ns_rr.nsdname.canonical == addr_rr.name.canonical)
            #             print "Found address #{addr_rr.address} for #{ns_rr.nsdname}\n"
            nameservers.push(addr_rr.address.to_s)
            found_addr = true
            break
            #  If we can, then we add the server A/AAAA address to nameservers
          end
          #  If we can't, then we add the server NS name to nameservers

        }
        if (!found_addr)
          #           print "Couldn't find address - adding #{ns_rr.nsdname}\n"
          nameservers.push(ns_rr.nsdname)
        end

      }
    end

    def validate_no_rrsigs(msg) # :nodoc:
      with_validation { validate_no_rrsigs_internal(msg) }
    end

    private def validate_no_rrsigs_internal(msg)
      #       print "Validating unsigned response\n"
      #  WHAT IF THERE ARE NO RRSIGS IN MSG?
      #  Then we need to check that we do not expect any RRSIGs
      if (!msg.question()[0] && msg.answer.length == 0)
        #         print "Returning Message insecure OK\n"
        msg.security_level = Message::SecurityLevel.INSECURE
        return true
      end
      qname = msg.question()[0].qname
      closest_anchor = find_closest_anchor_for(qname)
      #       print "Found closest anchor :#{closest_anchor}\n"
      if (closest_anchor)
        actual_anchor = follow_chain(closest_anchor, qname)
        #         print "Actual anchor : #{actual_anchor}\n"
        if (actual_anchor)
          #           print("Anchor exists for #{qname}, but no signatures in #{msg}\n")
          TheLog.error("Anchor exists for #{qname}, but no signatures in #{msg}")
          msg.security_level = Message::SecurityLevel.BOGUS
          return false
        end
      end
      if ((@verifier_type == VerifierType::DLV) &&
            @added_dlv_key)
        #  Remember to check DLV registry as well (if appropriate!)
        #         print "Checking DLV for closest anchor\n"
        dlv_anchor = find_closest_dlv_anchor_for(qname)
        #         print "Found DLV closest anchor :#{dlv_anchor}\n"
        if (dlv_anchor)
          actual_anchor = follow_chain(dlv_anchor, qname)
          #           print "Actual anchor : #{actual_anchor}\n"
          if (actual_anchor)
            #             print("DLV Anchor exists for #{qname}, but no signatures in #{msg}\n")
            TheLog.error("DLV Anchor exists for #{qname}, but no signatures in #{msg}")
            msg.security_level = Message::SecurityLevel.BOGUS
            return false
          end

        end
      end
      #       print "Returning Message insecure OK\n"
      msg.security_level = Message::SecurityLevel.INSECURE
      return true
    end

    def validate(msg, query)
      with_validation { validate_internal(msg, query) }
    end

    private def validate_internal(msg, query)
      if (msg.rrsets('RRSIG').length == 0)
        return validate_no_rrsigs(msg)
      end

      #  See if it is a child of any of our trust anchors.
      #  If it is, then see if we have a trusted key for it
      #  If we don't, then see if we can get to it from the closest
      #  trust anchor
      #  Otherwise, try DLV (if configured)
      # 
      # 
      #  So - find closest existing trust anchor
      error = nil
      msg.security_level = Message::SecurityLevel.INDETERMINATE
      qname = msg.question()[0].qname
      closest_anchor = find_closest_anchor_for(qname)
      if (!closest_anchor)

      end
      TheLog.debug("Closest anchor for #{qname} is #{closest_anchor} - trying to follow down")
      error = try_to_follow_from_anchor(closest_anchor, msg, qname)

      if ((msg.security_level.code < Message::SecurityLevel::SECURE) &&
            (@verifier_type == VerifierType::DLV) &&
            @added_dlv_key)
        #  If we can't find anything, and we're set to check DLV, then
        #  check the DLV registry and work down from there.
        dlv_anchor = find_closest_dlv_anchor_for(qname)
        if (dlv_anchor)
          #           print "Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}\n"
          TheLog.debug("Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}")
          error = try_to_follow_from_anchor(dlv_anchor, msg, qname)
        else
          #           print "Couldn't find DLV anchor for #{qname}\n"
          TheLog.debug("Couldn't find DLV anchor for #{qname}")
        end
      end
      if (msg.security_level.code != Message::SecurityLevel::SECURE)
        begin
          #           print "Trying to verify one last time\n"

          if (result = verify_result(msg)) # Keys may have been learned during discovery.
            set_verified_security_level(msg, result)
            return true
          end
        rescue VerifyError
        end
      end
      if (error)
        raise error
      end
      if (msg.security_level == Message::SecurityLevel.BOGUS)
        raise VerifyError.new("Bogus record")
      end
      if (msg.security_level.code > Message::SecurityLevel::UNCHECKED)
        return true
      else
        return false
      end
    end

    def try_to_follow_from_anchor(closest_anchor, msg, qname) # :nodoc:
      with_validation { try_to_follow_from_anchor_internal(closest_anchor, msg, qname) }
    end

    private def try_to_follow_from_anchor_internal(closest_anchor, msg, qname)
      error = nil
      if (closest_anchor)
        #  Then try to descend to the level we're interested in
        actual_anchor = false
        begin
          actual_anchor = follow_chain(closest_anchor, qname)
        rescue VerifyError => e
          TheLog.debug("Broken chain from anchor : #{closest_anchor.name}")
          msg.security_level = Message::SecurityLevel.BOGUS
          return e
        end
        # follow_chain returns false only for an authenticated unsigned delegation.
        if (!actual_anchor)
          TheLog.debug("Unable to follow chain from anchor : #{closest_anchor.name}")
          msg.security_level = Message::SecurityLevel.INSECURE
        else
          actual_anchor_keys = ""
          actual_anchor.rrs.each {|rr| actual_anchor_keys += ", #{rr.key_tag}"}
          TheLog.debug("Found anchor #{actual_anchor.name}, #{actual_anchor.type} for #{qname} : #{actual_anchor_keys}")
          #           print "Found anchor #{actual_anchor.name}, #{actual_anchor.type} for #{qname} : #{actual_anchor_keys}\n"
          begin
            if (result = verify_result(msg, actual_anchor))
              TheLog.debug("Validated #{qname}")
              set_verified_security_level(msg, result)
            end
          rescue VerifyError => e
            TheLog.info("BOGUS #{qname}! Error : #{e}")
            #             print "BOGUS #{qname}! Error : #{e}\n"
            msg.security_level = Message::SecurityLevel.BOGUS
            error = e
          end
        end
      else
        #         print "Unable to find an anchor for #{qname}\n"
        msg.security_level = Message::SecurityLevel.INSECURE
      end
      return error
    end

    def set_verified_security_level(msg, result)
      msg.security_level = result == :secure ? Message::SecurityLevel.SECURE : Message::SecurityLevel.INSECURE
      msg.header.ad = false if result == :insecure
      msg.security_error = nil
    end
    private :set_verified_security_level

  end
end
