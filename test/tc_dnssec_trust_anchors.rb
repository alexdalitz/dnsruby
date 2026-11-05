require_relative 'spec_helper'
require 'minitest/mock'
require 'open3'
require 'rbconfig'

class DnssecTrustAnchorsTest < Minitest::Test
  FIXTURE_DIRECTORY = File.expand_path('fixtures', __dir__)
  FIXTURE_TIME = Time.utc(2026, 11, 5, 12)
  ROOT_DS = [
    '. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
    '. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16'
  ].freeze

  def setup
    Dnsruby::Dnssec.reset
    @root_keys = read_fixture('root-dnskey')
    @org_ds = read_fixture('org-ds')
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_cold_start_authenticates_ksk_2024_without_reset
    # A new process exercises the initialization path without a reset or any
    # previously authenticated keys, regardless of the suite's random order.
    script = <<~'RUBY'
      require 'dnsruby'
      require 'minitest/mock'
      records = File.readlines(ARGV.fetch(0)).reject { |line| line.start_with?(';') || line.strip.empty? }
      keys = Dnsruby::RRSet.new(records.map { |line| Dnsruby::RR.create(line) })
      Time.stub(:now, Time.utc(2026, 11, 5, 12)) do
        verifier = Dnsruby::Dnssec.root_verifier
        abort 'unexpected startup anchors' unless verifier.trust_anchors.map(&:key_tag).sort == [20326, 38696]
        abort 'startup cache is warm' unless verifier.get_keys_to_check.empty?
        abort 'fixture must have only the KSK-2024 signature' unless keys.sigs.map(&:key_tag) == [38696]
        abort 'KSK-2024 validation failed' unless verifier.verify_key_rrset(keys)
      end
    RUBY
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', script,
      File.join(FIXTURE_DIRECTORY, 'root-dnskey-2026-11-05.zone')
    )
    assert(status.success?, "Cold-start validation failed:\n#{stdout}\n#{stderr}")
  end

  def test_reset_restores_only_current_anchors_and_authenticates_ksk_2024
    Time.stub(:now, FIXTURE_TIME) do
      2.times do
        Dnsruby::Dnssec.reset
        verifier = Dnsruby::Dnssec.root_verifier
        assert_equal(ROOT_DS.map { |text| Dnsruby::RR.create(text) }, verifier.trust_anchors)
        assert_empty(verifier.get_keys_to_check)
        assert_equal([38696], @root_keys.sigs.map(&:key_tag))
        assert(verifier.verify_key_rrset(@root_keys))
      end
    end
  end

  def test_ksk_2017_alone_cannot_validate_the_fixture
    Time.stub(:now, FIXTURE_TIME) do
      verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ROOT)
      verifier.add_root_ds(Dnsruby::RR.create(ROOT_DS.first))
      error = assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }
      assert_match(/Signing key not found/, error.message)
    end
  end

  def test_corrupted_signature_is_rejected_with_cold_and_warm_caches
    Time.stub(:now, FIXTURE_TIME) do
      verifier = Dnsruby::Dnssec.root_verifier
      corrupted = read_fixture('root-dnskey')
      signature = corrupted.sigs.first.signature.dup
      signature.setbyte(0, signature.getbyte(0) ^ 1)
      corrupted.sigs.first.signature = signature
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(corrupted) }
      zone_key = @root_keys.rrs.find { |key| !key.sep_key? }
      refute_includes(verifier.get_keys_to_check.map(&:key_tag), zone_key.key_tag)
      assert(verifier.verify_key_rrset(@root_keys))
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(corrupted) }
      Dnsruby::Dnssec.clear_trusted_keys
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(corrupted) }
      assert(verifier.verify_key_rrset(@root_keys))
    end
  end

  def test_cache_clear_preserves_root_anchors_and_discards_learned_dnskeys_and_ds
    Time.stub(:now, FIXTURE_TIME) do
      verifier = Dnsruby::Dnssec.root_verifier
      assert(verifier.verify_key_rrset(@root_keys))
      assert(verifier.verify_ds_rrset(@org_ds))
      assert_includes(verifier.trusted_keys, @org_ds.rrs.first)
      refute_empty(verifier.get_keys_to_check)

      Dnsruby::Dnssec.clear_trusted_keys

      assert_equal(ROOT_DS.map { |text| Dnsruby::RR.create(text) }, verifier.trust_anchors)
      assert_equal(verifier.trust_anchors, verifier.trusted_keys)
      assert_empty(verifier.get_keys_to_check)
      refute(Dnsruby::Dnssec.no_keys?)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_ds_rrset(@org_ds) }
      assert(verifier.verify_key_rrset(@root_keys))
      assert(verifier.verify_ds_rrset(@org_ds))
    end
  end

  def test_cache_clear_preserves_custom_dnskey_ds_and_dlv_anchors
    Time.stub(:now, FIXTURE_TIME) do
      key = signing_key
      ds = Dnsruby::RR.create(ROOT_DS.last)
      dlv = Dnsruby::RR.create(ROOT_DS.last.sub(' DS ', ' DLV '))
      Dnsruby::Dnssec.add_trust_anchor(key)
      Dnsruby::Dnssec.add_trust_anchor(ds)
      Dnsruby::Dnssec.dlv_verifier.add_trust_anchor(dlv)
      assert(Dnsruby::Dnssec.anchor_verifier.verify_key_rrset(@root_keys))
      assert(Dnsruby::Dnssec.dlv_verifier.verify_key_rrset(@root_keys))

      Dnsruby::Dnssec.clear_trusted_keys

      assert_equal([key, ds], Dnsruby::Dnssec.trust_anchors)
      assert_equal([key], Dnsruby::Dnssec.anchor_verifier.get_keys_to_check)
      assert_equal([dlv], Dnsruby::Dnssec.dlv_verifier.trust_anchors)
      assert_empty(Dnsruby::Dnssec.dlv_verifier.get_keys_to_check)
      assert(Dnsruby::Dnssec.anchor_verifier.verify_key_rrset(@root_keys))
      assert(Dnsruby::Dnssec.dlv_verifier.verify_key_rrset(@root_keys))
    end
  end

  def test_explicit_clear_removes_custom_anchors_and_derived_trust
    Time.stub(:now, FIXTURE_TIME) do
      Dnsruby::Dnssec.add_trust_anchor(signing_key)
      Dnsruby::Dnssec.add_trust_anchor(Dnsruby::RR.create(ROOT_DS.last))
      verifier = Dnsruby::Dnssec.anchor_verifier
      assert(verifier.verify_key_rrset(@root_keys))
      assert(verifier.verify_ds_rrset(@org_ds))

      Dnsruby::Dnssec.clear_trust_anchors

      assert_empty(Dnsruby::Dnssec.trust_anchors)
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }
      assert_equal([20326, 38696], Dnsruby::Dnssec.root_verifier.trust_anchors.map(&:key_tag))
    end
  end

  def test_remove_ds_anchor_invalidates_derived_trust_and_retains_other_anchors
    Time.stub(:now, FIXTURE_TIME) do
      old_ds, new_ds = ROOT_DS.map { |text| Dnsruby::RR.create(text) }
      Dnsruby::Dnssec.add_trust_anchor(old_ds)
      Dnsruby::Dnssec.add_trust_anchor(new_ds)
      verifier = Dnsruby::Dnssec.anchor_verifier
      assert(verifier.verify_key_rrset(@root_keys))
      assert(verifier.verify_ds_rrset(@org_ds))

      Dnsruby::Dnssec.remove_trust_anchor(new_ds)

      assert_equal([old_ds], Dnsruby::Dnssec.trust_anchors)
      assert_equal([old_ds], verifier.trusted_keys)
      assert_empty(verifier.get_keys_to_check)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }
    end
  end

  def test_remove_equivalent_dnskey_anchor_invalidates_derived_trust
    Time.stub(:now, FIXTURE_TIME) do
      key = signing_key
      Dnsruby::Dnssec.add_trust_anchor(key)
      verifier = Dnsruby::Dnssec.anchor_verifier
      assert(verifier.verify_key_rrset(@root_keys))

      equivalent_key = Dnsruby::RR.create(key.to_s)
      equivalent_key.ttl += 1 # TTL is not part of a DNSKEY's identity.
      refute_same(key, equivalent_key)
      Dnsruby::Dnssec.remove_trust_anchor(equivalent_key)

      assert_empty(Dnsruby::Dnssec.trust_anchors)
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }
    end
  end

  def test_removing_unconfigured_key_with_same_tag_preserves_trust
    Time.stub(:now, FIXTURE_TIME) do
      key = signing_key
      Dnsruby::Dnssec.add_trust_anchor(key)
      verifier = Dnsruby::Dnssec.anchor_verifier
      assert(verifier.verify_key_rrset(@root_keys))
      cached_keys = verifier.trusted_keys
      foreign_key = key.clone
      foreign_key.name = 'example.' # Owner name is not included in the key tag.
      assert_equal(key.key_tag, foreign_key.key_tag)

      Dnsruby::Dnssec.remove_trust_anchor(foreign_key)

      assert_equal([key], Dnsruby::Dnssec.trust_anchors)
      assert_equal(cached_keys, verifier.trusted_keys)
      assert(verifier.verify_key_rrset(@root_keys))
    end
  end

  def test_explicit_remove_and_clear_work_for_dlv_anchors
    Time.stub(:now, FIXTURE_TIME) do
      verifier = Dnsruby::Dnssec.dlv_verifier
      dlv = Dnsruby::RR.create(ROOT_DS.last.sub(' DS ', ' DLV '))
      verifier.add_trust_anchor(dlv)
      assert(verifier.verify_key_rrset(@root_keys))
      verifier.remove_trust_anchor(dlv)
      assert_empty(verifier.trust_anchors)
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }

      verifier.add_trust_anchor(dlv)
      assert(verifier.verify_key_rrset(@root_keys))
      verifier.clear_trust_anchors
      assert_empty(verifier.trust_anchors)
      assert_empty(verifier.trusted_keys)
      assert_raises(Dnsruby::VerifyError) { verifier.verify_key_rrset(@root_keys) }
    end
  end

  private

  def read_fixture(name)
    lines = File.readlines(File.join(FIXTURE_DIRECTORY, "#{name}-2026-11-05.zone"))
    records = lines.reject { |line| line.start_with?(';') || line.strip.empty? }
    Dnsruby::RRSet.new(records.map { |line| Dnsruby::RR.create(line) })
  end

  def signing_key
    @root_keys.rrs.find { |key| key.key_tag == 38696 }
  end
end
