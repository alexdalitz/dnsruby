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
#See the License f181or the specific language governing permissions and 
#limitations under the License.
#++
require 'digest/sha2'
require 'Dnsruby/key_cache'
require 'Dnsruby/single_verifier'
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
  #  # (the SEP flag of the key will be set by default if a DNSKEY is used)
  #  # A DS RR could also be used here
  #  trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
  #      :type => Dnsruby::Types.DNSKEY,
  #      :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
  #    })
  #  ret = Dnsruby::DnssecVerifier.add_trust_anchor(trusted_key)
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


    class ValidationPolicy
      # @TODO@ Could do this by getting client to add verifiers in the order they
      # want them to be used. Could then dispense with all this logic
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

    @@root_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)

    @@dlv_verifier = SingleVerifier.new(SingleVerifier::VerifierType::DLV)

    # @TODO@ Could add a new one of these fpr each anchor.
    @@anchor_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
    # Should we be loading IANA Trust Anchor Repository? - no need - imported by ISC DLV


    # @TODO@ Should we provide methods like :
#    def Dnssec.enable_isc_dlv
#
#    end
#    def Dnssec.load_itar
#
#    end
#    def Dnssec.load_tar(tar)
#
#    end
    def Dnssec.add_dlv_key(dlv_key)
      @@dlv_verifier.add_dlv_key(dlv_key)
    end
    def Dnssec.add_trust_anchor(t)
        # @TODO@ Create a new verifier?
        @@anchor_verifier.add_trust_anchor(t)
    end
    # Add the 
    def self.add_trust_anchor_with_expiration(k, expiration)
      # Create a new verifier?
      @@anchor_verifier.add_trust_anchor_with_expiration(k, expiration)
    end
    
    def Dnssec.remove_trust_anchor(t)
      @@anchor_verifier.remove_trust_anchor(t)
    end
    # Wipes the cache of trusted keys
    def self.clear_trust_anchors
      @@anchor_verifier.clear_trust_anchors
    end
    
    def self.trust_anchors
      return @@anchor_verifier.trust_anchors
    end

    def self.clear_trusted_keys
      [@@anchor_verifier, @@root_verifier, @@dlv_verifier].each {|v|
        v.clear_trusted_keys
      }
    end

    # Returns true for secure/insecure, false otherwise
    # This method will set the security_level on msg to the appropriate value.
    # Could be : secure, insecure, bogus or indeterminate
    # If an error is encountered during verification, then the thrown exception
    # will define the error.
    def self.validate(msg)
      query = Message.new()
      query.header.cd=true
      return self.validate_with_query(query, msg)
    end
    
    def self.validate_with_query(query, msg)
      # First, just check there is something to validate!
      found_sigs = false
      msg.each_resource {|rr|
        if (rr.type == Types.RRSIG)
          found_sigs = true
        end
      }
      if (!found_sigs)
        msg.security_level = Message::SecurityLevel.INSECURE
        return true
      end


      # SHOULD ALWAYS VERIFY DNSSEC-SIGNED RESPONSES?
      # Yes - if a trust anchor is configured. Otherwise, act on CD bit (in query)
      TheLog.debug("Checking whether to validate, query.cd = #{query.header.cd}")
      if (((@@validation_policy > ValidationPolicy::ALWAYS_ROOT_ONLY) && (self.trust_anchors().length > 0)) ||
            # Check query here, and validate if CD is true
          (query.header.cd == true))
        TheLog.debug("Starting validation")

        # Validate!
        # Need to think about trapping/storing exceptions and security_levels here
        last_error = ""
        last_level = Message::SecurityLevel.BOGUS
        last_error_level = Message::SecurityLevel.BOGUS
        if (@@validation_policy == ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
        elsif (@@validation_policy == ValidationPolicy::ALWAYS_ROOT_ONLY)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
        elsif (@@validation_policy == ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level, 
            Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
          if (last_level != Message::SecurityLevel.SECURE)
            last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
              Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
          end
        elsif (@@validation_policy == ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
          if (last_level != Message::SecurityLevel.SECURE)
            last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
              Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
          end
        end
        if (last_level != Message::SecurityLevel.SECURE)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level, 
            Proc.new{|m, q| validate_with_dlv(m, q)}, msg, query)
        end
        # Set the message security level!
        msg.security_level = last_level
        raise VerifyError.new(last_error) if (last_level < 0)
        return (msg.security_level.code > Message::SecurityLevel::UNCHECKED)
      end
      msg.security_level = Message::SecurityLevel.UNCHECKED
      return true
    end

    def self.try_validation(last_level, last_error, last_error_level, proc, msg, query)   # :nodoc:
      begin
        proc.call(msg, query)
        last_level = Message::SecurityLevel.new([msg.security_level.code, last_level].max)
      rescue VerifyError => e
        if (last_error_level < last_level)
          last_error = e.to_s
          last_error_level = last_level
        end
      end
      return last_level, last_error, last_error_level
    end
        
    # We need to maintain several sets of trusted keys :
    #   : one for signed root, one for local anchors, and one from dlv
    #
    # So, keep DNSSEC validation level stuff in this class, and split verification
    # and validation out to SingleVerifiers (which can each do every type of validation,
    # but which will only be asked to do one type). i.e. DlvVerifier, RootVerifier,
    # AnchorVerifier, etc. Would you have one AnchorVerifier for each trust anchor?
    def self.validate_with_anchors(msg, query)
      return @@anchor_verifier.validate(msg, query)
    end

    def self.validate_with_root(msg, query)
      return @@root_verifier.validate(msg, query)
    end

    def self.validate_with_dlv(msg, query)
      return @@dlv_verifier.validate(msg, query)
    end

    def self.verify(msg)
      return ((@@anchor_verifier.verify(msg) ||
            @@root_verifier.verify(msg) ||
            @@dlv_verifier.verify(msg)))
    end

    def self.anchor_verifier
      return @@anchor_verifier
    end
    def self.dlv_verifier
      return @@dlv_verifier
    end
    def self.root_verifier
      return @@root_verifier
    end




    def self.verify_rrset(rrset, keys = nil)
      return ((@@anchor_verifier.verify_rrset(rrset, keys) ||
            @@root_verifier.verify_rrset(rrset, keys) ||
            @@dlv_verifier.verify_rrset(rrset, keys)))
    end
  end
end