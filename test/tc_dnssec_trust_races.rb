require_relative 'spec_helper'
require 'openssl'
require 'base64'
require 'timeout'

class DnssecTrustRacesTest < Minitest::Test
  def setup
    Dnsruby::Dnssec.reset
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    exponent = @rsa.e.to_s(2)
    key_data = Base64.strict_encode64([exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2))
    @key = Dnsruby::RR.create("private.invalid. 300 IN DNSKEY 257 3 8 #{key_data}")
    @child = Dnsruby::RR.create("child.private.invalid. 300 IN DNSKEY 257 3 8 #{key_data}")
    @keys = signed(@key, @key)
    @child_keys = signed(@child, @child)
    @ds = Dnsruby::RR::DS.from_key(@child, 2)
    @ds.ttl = 300
    @ds_set = signed(@ds, @key)
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_public_verification_cannot_republish_dnskeys_after_remove_or_clear
    [:remove, :clear].each do |operation|
      Dnsruby::Dnssec.reset
      Dnsruby::Dnssec.add_trust_anchor(@key)
      assert(Dnsruby::Dnssec.verify(@keys))
      revoke(operation)
      assert_raises(Dnsruby::VerifyError) { Dnsruby::Dnssec.verify(@keys) }
      Dnsruby::Dnssec.add_trust_anchor(@key)
      verifier = Dnsruby::Dnssec.anchor_verifier
      pause_after(verifier, :verify_rrset, -> { revoke(operation) }) do
        assert(Dnsruby::Dnssec.verify(@keys))
      end
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { Dnsruby::Dnssec.verify(@keys) }
      assert_raises(Dnsruby::VerifyError) { Dnsruby::Dnssec.root_verifier.verify(@keys) }
    end
  end

  def test_signed_ds_cannot_republish_discovered_ds_or_matched_dnskeys
    [:remove, :clear].product([false, true]).each do |operation, include_key|
      Dnsruby::Dnssec.reset
      Dnsruby::Dnssec.add_trust_anchor(@key)
      verifier = Dnsruby::Dnssec.anchor_verifier
      message = if include_key
        Dnsruby::Message.new('child.private.invalid.', 'DNSKEY').tap { |m| m.add_answer(@child) }
      end
      pause_after(verifier, :verify_rrset, -> { revoke(operation) }) do
        assert(verifier.verify_ds_rrset(@ds_set, nil, message))
      end
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify(@child_keys) }
    end
  end

  def test_configured_and_discovered_ds_cannot_publish_after_snapshot_is_revoked
    [:remove, :clear].product([false, true]).each do |operation, discovered|
      Dnsruby::Dnssec.reset
      verifier = Dnsruby::Dnssec.anchor_verifier
      anchor = discovered ? @key : @ds
      Dnsruby::Dnssec.add_trust_anchor(anchor)
      assert(verifier.verify(@ds_set)) if discovered
      # Stop after a real digest match, while check_ds_stores still owns its old
      # snapshot; removal must not block on cryptographic or network work.
      pause_after(discovered ? @ds_set.rrs.first : @ds, :check_key, -> { revoke(operation, anchor) }) do
        verifier.check_ds_stores(@child_keys)
      end
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify(@child_keys) }
    end
  end

  def test_validation_carries_generation_across_anchor_lookup_and_network_discovery
    [:remove, :clear].each do |operation|
      Dnsruby::Dnssec.reset
      Dnsruby::Dnssec.add_trust_anchor(@key)
      verifier = Dnsruby::Dnssec.anchor_verifier
      message = Dnsruby::Message.new('private.invalid.', 'DNSKEY')
      @keys.each { |rr| message.add_answer(rr) }
      # Stand in for the network lookup: the supplied anchor is exactly the one
      # captured by validate before removal, and the cryptographic check is real.
      keys = @keys
      verifier.define_singleton_method(:follow_chain) do |anchor, _name|
        verify(keys, anchor)
        keys
      end
      pause_after(verifier, :find_closest_anchor_for, -> { revoke(operation) }) do
        verifier.validate(message, message)
      end
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { Dnsruby::Dnssec.verify(@keys) }
    end
  end

  private

  def revoke(operation, key = @key)
    operation == :remove ? Dnsruby::Dnssec.remove_trust_anchor(key) : Dnsruby::Dnssec.clear_trust_anchors
  end

  def pause_after(object, method_name, mutation)
    arrived, resume, start = Queue.new, Queue.new, Queue.new
    original = object.method(method_name)
    own_method = object.singleton_class.instance_methods(false).include?(method_name)
    object.singleton_class.remove_method(method_name) if own_method
    thread = nil
    object.define_singleton_method(method_name) do |*args|
      result = original.call(*args)
      if Thread.current.equal?(thread)
        arrived << true
        resume.pop
      end
      result
    end
    thread = Thread.new { start.pop; yield }
    start << true
    Timeout.timeout(3) { arrived.pop }
    Timeout.timeout(3) { mutation.call }
    resume << true
    Timeout.timeout(3) { thread.value }
  ensure
    object.singleton_class.remove_method(method_name) if original
    object.define_singleton_method(method_name, original) if own_method
    thread.kill if thread && thread.alive?
    thread.join if thread
  end

  def signed(record, key)
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: 300,
      type_covered: record.type, algorithm: 8, labels: record.name.labels.length,
      original_ttl: 300, expiration: Time.now.to_i + 3600, inception: Time.now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    signature.signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + data)
    Dnsruby::RRSet.new([record, signature])
  end
end
