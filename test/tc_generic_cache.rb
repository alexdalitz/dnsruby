require_relative 'spec_helper'
require 'weakref'
require 'timeout'
require 'open3'
require 'rbconfig'

class TestGenericCache < Minitest::Test
  Generic = Dnsruby::RR::Generic
  Cache = Dnsruby::RR::GenericCache

  def evict
    (50_000...(50_000 + Cache::LIMIT + 2)).each { |type| Dnsruby::RR.get_class(type, 9) }
  end

  def test_live_frozen_class_and_record_survive_eviction
    klass = Dnsruby::RR.get_class(61_001, 1)
    klass.class_eval { def client_method; :preserved; end }
    record = klass.new("\x00\xffx".b)
    klass.freeze
    evict
    assert_same(klass, Dnsruby::RR.get_class(61_001, 1))
    assert_same(klass, Generic.const_get('Type61001_Class1'))
    assert_equal(:preserved, record.client_method)
    assert_equal([0, 255, 120], record.data.bytes)
  end

  def test_names_have_native_mutability_and_class_copies_are_anonymous
    klass = Dnsruby::RR.get_class(61_002, 1)
    assert(klass.name.frozen?)
    [:to_s, :inspect].each do |method|
      original = klass.public_send(method)
      refute(original.frozen?)
      original << ' changed'
      refute_equal(original, klass.public_send(method))
    end
    [klass.dup, klass.clone].each do |copy|
      assert_nil(copy.name)
      assert_match(/\A#<Class:0x[0-9a-f]+>\z/, copy.to_s)
      assert_equal(61_002, copy::TypeValue)
    end
  end

  def test_explicit_factory_preserves_names_arguments_errors_and_registration
    klass = Generic.create('61003', '1')
    assert_equal('61003', klass::TypeValue)
    assert_equal('1', klass::ClassValue)
    assert_same(klass, Dnsruby::ClassHash[['61003', '1']])
    assert_equal('Dnsruby::RR::Generic::Type61003_Class1', Module.instance_method(:name).bind(klass).call)
    nonnumeric = Generic.create('Alpha', 'Beta')
    assert_same(nonnumeric, Generic.const_get('TypeAlpha_ClassBeta'))
    assert_raises(NameError) { Generic.create(-1, 1) }
    assert_raises(NameError) { Generic.create('bad-name', 1) }
    evict
    assert_same(klass, Dnsruby::ClassHash[['61003', '1']])
    assert_same(nonnumeric, Dnsruby::ClassHash[['Alpha', 'Beta']])
  end

  def test_explicit_registration_overrides_live_automatic_class
    automatic = Dnsruby::RR.get_class(61_004, 1)
    explicit = Generic.create(61_004, 1)
    refute_same(automatic, explicit)
    evict
    assert_same(explicit, Dnsruby::RR.get_class(61_004, 1))
    assert_same(explicit, Generic.const_get('Type61004_Class1'))
    custom = Object.new
    Dnsruby::ClassHash[[61_004, 1]] = custom
    assert_same(custom, Dnsruby::RR.find_class(61_004, 1))
  ensure
    Dnsruby::ClassHash.delete([61_004, 1])
  end

  def test_subclass_noninherited_lookup_preserves_native_constant_boundaries
    name = 'Type62170_Class1'
    explicit = Generic.create(62_170, 1)
    parent = Class.new(Generic)
    child = Class.new(parent)
    [parent, child].each do |receiver|
      assert_same(explicit, receiver.const_get(name))
      [false, nil].each do |inherit|
        assert_raises(NameError) { receiver.const_get(name, inherit) }
        refute(receiver.const_defined?(name, inherit))
      end
    end
    own = Class.new
    parent.const_set(name, own)
    assert_same(own, parent.const_get(name, false))
    assert_same(own, child.const_get(name))
    assert_raises(NameError) { child.const_get(name, false) }
    # The documented virtual-name fallback remains available to subclasses.
    virtual = Dnsruby::RR.get_class(62_171, 1)
    assert_same(virtual, child.const_get('Type62171_Class1', false))
    refute(child.const_defined?('Type62171_Class1', false))
  ensure
    Generic.send(:remove_const, name) if name && Generic.const_defined?(name, false)
    Dnsruby::ClassHash.delete([62_170, 1])
  end

  def test_external_deletion_is_different_from_fifo_eviction
    klass = Dnsruby::RR.get_class(61_005, 1)
    Dnsruby::ClassHash.delete([61_005, 1])
    refute_same(klass, Dnsruby::RR.get_class(61_005, 1))
    held = Dnsruby::RR.get_class(61_006, 1)
    evict
    assert_same(held, Dnsruby::RR.get_class(61_006, 1))
    evict
    Dnsruby::ClassHash.delete([61_006, 1])
    refute_same(held, Dnsruby::RR.get_class(61_006, 1))
  end

  def test_deleted_live_class_stays_named_without_becoming_reusable
    [false, true].each_with_index do |explicit, index|
      pair = [62_210 + index, 1]
      name = "Type#{pair[0]}_Class1"
      held = Dnsruby::RR.get_class(*pair)
      Dnsruby::ClassHash[pair] = held if explicit
      Dnsruby::ClassHash.delete(pair)
      evict
      Dnsruby::ClassHash.rehash
      Dnsruby::ClassHash.transform_values! { |value| value }
      assert_same(held, Generic.const_get(name))
      refute(Dnsruby::ClassHash.key?(pair))
      replacement = Dnsruby::RR.get_class(*pair)
      refute_same(held, replacement)
      assert_same(replacement, Generic.const_get(name))
      evict
      assert_same(replacement, Dnsruby::RR.get_class(*pair))
    end
  end

  def test_bulk_registry_removal_and_replacement_invalidate_lookup
    [:delete_if, :reject!, :keep_if, :select!, :filter!, :transform_keys!, :transform_values!].each_with_index do |operation, index|
      type = 61_100 + index
      pair = [type, 1]
      held = Dnsruby::RR.get_class(*pair)
      if operation == :transform_keys!
        Dnsruby::ClassHash.transform_keys! { |key| key == pair ? [type, 2] : key }
      elsif operation == :transform_values!
        Dnsruby::ClassHash.transform_values! { |value| value.equal?(held) ? nil : value }
        Dnsruby::ClassHash.compact!
      else
        keep = [:keep_if, :select!, :filter!].include?(operation)
        Dnsruby::ClassHash.public_send(operation) { |key, _| keep ? key != pair : key == pair }
      end
      refute_same(held, Dnsruby::RR.get_class(*pair), operation.to_s)
    end
  end

  def test_inherited_callback_can_wait_for_another_thread
    parent = Generic.singleton_class
    original = parent.instance_method(:inherited)
    calls = []
    parent.send(:define_method, :inherited) do |subclass|
      worker = Thread.new { Dnsruby::RR.get_class(1, 1) }
      raise 'lookup blocked by factory lock' unless worker.join(2)
      calls << worker.value
      original.bind(self).call(subclass)
    end
    Dnsruby::RR.get_class(61_007, 1)
    assert_equal([Dnsruby::RR::IN::A], calls)
  ensure
    parent.send(:remove_method, :inherited) if parent
  end

  def test_simultaneous_lookups_publish_one_class
    start = Queue.new
    threads = Array.new(8) do
      Thread.new { start.pop; 100.times.map { Dnsruby::RR.get_class(61_008, 1) } }
    end
    8.times { start << true }
    classes = threads.flat_map(&:value)
    assert_equal(1, classes.map(&:object_id).uniq.length)
    held = classes.first
    threads = Array.new(4) do |worker|
      Thread.new do
        300.times do |index|
          Dnsruby::RR.get_class(30_000 + worker * 300 + index, 9)
          raise 'live Class identity lost' unless held.equal?(Dnsruby::RR.get_class(61_008, 1))
        end
      end
    end
    threads.each(&:value)
    assert_same(held, Dnsruby::RR.get_class(61_008, 1))
  end

  def test_constant_inspection_does_not_allocate_or_reactivate
    held = Dnsruby::RR.get_class(61_009, 1)
    held.const_set(:ClientConstant, 42)
    evict
    refute(Dnsruby::ClassHash.key?([61_009, 1]))
    assert(Generic.const_defined?('Type61009_Class1::ClientConstant'))
    assert(Generic.const_defined?('Type61010_Class1::TypeValue'))
    refute(Dnsruby::ClassHash.key?([61_009, 1]))
    refute(Dnsruby::ClassHash.key?([61_010, 1]))
    refute(Generic.const_defined?('Type61009_Class1::Object'))
    child = Class.new(Generic)
    refute(child.const_defined?('Type61009_Class1', false))
    assert(child.const_defined?('Type61009_Class1'))
  end
  def test_registry_copies_cannot_change_the_cache
    [:dup, :clone].each_with_index do |copy_method, index|
      pair = [61_020 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      copy = Dnsruby::ClassHash.public_send(copy_method)
      copy.delete(pair)
      copy[pair] = Object.new
      copy.reject! { |key, _| key == pair }
      copy.clear
      assert_same(held, Dnsruby::ClassHash[pair])
      evict
      refute(Dnsruby::ClassHash.key?(pair), copy_method.to_s)
      assert_same(held, Dnsruby::RR.get_class(*pair))
    end
  end

  def test_two_argument_super_factory_is_invoked_and_stays_anonymous
    calls = []
    wrapper = Module.new do
      define_method(:create) do |type, klass|
        calls << [type, klass]
        super(type, klass)
      end
    end
    Generic.singleton_class.prepend(wrapper)
    generated = Dnsruby::RR.get_class(61_030, 1)
    assert_equal([[61_030, 1]], calls)
    assert_nil(Module.instance_method(:name).bind(generated).call)
    explicit = Generic.create(61_031, 1)
    assert_equal('Dnsruby::RR::Generic::Type61031_Class1', Module.instance_method(:name).bind(explicit).call)
  ensure
    wrapper.send(:remove_method, :create) if wrapper
  end

  def test_alias_factory_and_unrelated_direct_create
    singleton = Generic.singleton_class
    singleton.send(:alias_method, :client_saved_create, :create)
    direct = nil
    singleton.send(:define_method, :create) do |type, klass|
      direct = client_saved_create(61_033, 1)
      client_saved_create(type, klass)
    end
    generated = Dnsruby::RR.get_class(61_032, 1)
    assert_nil(Module.instance_method(:name).bind(generated).call)
    assert_equal('Dnsruby::RR::Generic::Type61033_Class1', Module.instance_method(:name).bind(direct).call)
  ensure
    if singleton
      singleton.send(:alias_method, :create, :client_saved_create)
      singleton.send(:remove_method, :client_saved_create)
    end
  end

  def test_custom_factory_result_and_exception_context_cleanup
    wrapper = Module.new do
      define_method(:create) do |type, klass|
        raise 'client factory error' if type == 61_034
        return Dnsruby::RR::IN::TXT if type == 61_035
        super(type, klass)
      end
    end
    Generic.singleton_class.prepend(wrapper)
    assert_raises(RuntimeError) { Dnsruby::RR.get_class(61_034, 1) }
    assert_nil(Thread.current[:dnsruby_generic_factory])
    assert_same(Dnsruby::RR::IN::TXT, Dnsruby::RR.get_class(61_035, 1))
    assert_nil(Thread.current[:dnsruby_generic_factory])
  ensure
    wrapper.send(:remove_method, :create) if wrapper
  end

  def test_nested_same_pair_inherited_lookup_and_display_customization
    singleton = Generic.singleton_class
    original = singleton.instance_method(:inherited)
    inside = false
    nested = nil
    singleton.send(:define_method, :inherited) do |subclass|
      unless inside
        inside = true
        nested = Dnsruby::RR.get_class(61_036, 1)
      end
      subclass.define_singleton_method(:to_s) { 'client display' }
      original.bind(self).call(subclass)
    end
    generated = Dnsruby::RR.get_class(61_036, 1)
    assert_same(nested, generated)
    assert_equal('client display', generated.to_s)
    assert_nil(Module.instance_method(:name).bind(generated).call)
    assert_nil(Thread.current[:dnsruby_generic_factory])
  ensure
    singleton.send(:remove_method, :inherited) if singleton
  end

  def test_registry_default_callback_does_not_run_under_the_cache_lock
    previous = Dnsruby::ClassHash.default_proc
    calls = 0
    Dnsruby::ClassHash.default_proc = proc do |hash, pair|
      worker = Thread.new { Dnsruby::RR.get_class(1, 1) }
      raise 'default proc blocked by cache lock' unless worker.join(2)
      calls += 1
      nil
    end
    Dnsruby::RR.get_class(61_037, 1)
    assert_equal(1, calls)
  ensure
    Dnsruby::ClassHash.default_proc = previous
  end

  def test_explicit_merge_registration_of_the_same_class_is_retained
    [:merge!, :update].each_with_index do |operation, index|
      pair = [61_040 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      Dnsruby::ClassHash.public_send(operation, {pair => held})
      evict
      assert_same(held, Dnsruby::ClassHash[pair])
    end
  end

  def test_partial_registry_mutation_is_observed_when_client_block_raises
    held = Dnsruby::RR.get_class(61_042, 1)
    Dnsruby::RR.get_class(61_043, 1)
    assert_raises(RuntimeError) do
      Dnsruby::ClassHash.delete_if do |pair, _|
        raise 'client callback' if pair == [61_043, 1]
        pair == [61_042, 1]
      end
    end
    refute_same(held, Dnsruby::RR.get_class(61_042, 1))
  end

  def test_one_byte_wire_records_do_not_permanently_retain_classes_or_names
    weak = Thread.new do
      first = nil
      (3 * Cache::LIMIT).times do |index|
        type, klass = 40_000 + index, 12
        wire = [0, 0x8000, 0, 1, 0, 0].pack('n6') + "\0" + [type, klass, 0, 1].pack('nnNn') + 'x'
        record = Dnsruby::Message.decode(wire).answer.first
        raise 'opaque byte changed' unless record.data == 'x'
        first ||= WeakRef.new(record.class)
      end
      first
    end.value
    5.times { GC.start(full_mark: true, immediate_sweep: true) }
    refute(weak.weakref_alive?)
    assert_equal(Cache::LIMIT, Dnsruby::ClassHash.keys.count { |pair| pair[1] == 12 })
    assert_equal(0, Generic.constants(false).count { |name| name.to_s.match?(/\AType4\d+_Class12\z/) })
    assert_equal(0, Symbol.all_symbols.count { |name| name.to_s.match?(/\AType4\d+_Class12\z/) })
    assert_operator(ObjectSpace.each_object(String).count { |name| name.ascii_only? && name.match?(/\A(?:Dnsruby::RR::Generic::)?Type4\d+_Class12\z/) }, :<=, 2 * Cache::LIMIT)
  end

  def test_replacement_remains_indexed_after_old_class_is_collected
    old, replacement = Thread.new do
      previous = Dnsruby::RR.get_class(61_044, 1)
      Dnsruby::ClassHash.delete([61_044, 1])
      [WeakRef.new(previous), Dnsruby::RR.get_class(61_044, 1)]
    end.value
    evict
    5.times { GC.start(full_mark: true, immediate_sweep: true) }
    refute(old.weakref_alive?)
    assert_same(replacement, Generic.const_get('Type61044_Class1'))
    assert_same(replacement, Dnsruby::RR.get_class(61_044, 1))
  end

  def after_native_hash_return(operation, concurrent)
    owner = Thread.current
    fired = false
    trace = TracePoint.new(:c_return) do |event|
      next if fired || Thread.current != owner || event.defined_class != Hash
      next unless event.self.equal?(Dnsruby::ClassHash) && event.method_id == operation
      fired = true
      Thread.new(&concurrent).value
    end
    result = trace.enable { yield }
    assert(fired, "native #{operation} was observed")
    result
  ensure
    trace.disable if trace
  end

  def test_concurrent_deletion_does_not_orphan_republished_classes
    32.times do |index|
      pair = [62_000 + index, 1]
      Dnsruby::RR.get_class(*pair)
      after_native_hash_return(:delete, -> { Dnsruby::RR.get_class(*pair) }) do
        Dnsruby::ClassHash.delete(pair)
      end
    end
    evict
    assert_equal(0, Dnsruby::ClassHash.keys.count { |pair| (62_000...62_032).cover?(pair[0]) })
  end

  def test_concurrent_clear_and_replace_keep_new_publications_tracked
    automatic_keys = Cache.snapshot.keys.map(&:registry_key)
    saved = Dnsruby::ClassHash.reject { |key, _| automatic_keys.any? { |item| item.equal?(key) } }
    [:clear, :replace].each_with_index do |operation, index|
      pair = [62_050 + index, 1]
      Dnsruby::RR.get_class(*pair)
      after_native_hash_return(operation, -> { Dnsruby::RR.get_class(*pair) }) do
        operation == :clear ? Dnsruby::ClassHash.clear : Dnsruby::ClassHash.replace({})
      end
      evict
      refute(Dnsruby::ClassHash.key?(pair), operation.to_s)
    end
  ensure
    Dnsruby::ClassHash.replace(saved) if saved
  end

  def test_array_subclass_registration_and_deletion
    subclass = Class.new(Array) do
      def length; raise 'must use native Array contents'; end
      def to_a; raise 'must use native Array contents'; end
    end
    key = subclass.new([62_100, 1])
    held = Dnsruby::RR.get_class(62_100, 1)
    Dnsruby::ClassHash[key] = held
    evict
    assert_same(held, Dnsruby::ClassHash[[62_100, 1]])
    Dnsruby::ClassHash.delete(key)
    refute_same(held, Dnsruby::RR.get_class(62_100, 1))
  end

  def test_array_singleton_methods_do_not_change_registration_or_deletion
    [:zero, :raise, :reenter].each_with_index do |mode, index|
      pair = [62_103 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      callbacks = 0
      pair.define_singleton_method(:length) do
        callbacks += 1
        case mode
        when :zero then 0
        when :raise then raise 'must use native Array contents'
        when :reenter
          Dnsruby::RR.get_class(45_000 + callbacks, 41)
          2
        end
      end
      pair.define_singleton_method(:[]) { |*_| raise 'must use native Array contents' }
      pair.define_singleton_method(:to_a) { raise 'must use native Array contents' }
      Dnsruby::ClassHash[pair] = held
      evict
      assert_same(held, Dnsruby::ClassHash[[62_103 + index, 1]], mode.to_s)
      assert_same(held, Dnsruby::ClassHash.delete(pair), mode.to_s)
      refute_same(held, Dnsruby::RR.get_class(62_103 + index, 1), mode.to_s)
      assert_equal(0, callbacks, mode.to_s)
    end
  end

  def test_rehash_moves_mutable_keys_even_after_fifo_eviction
    [false, true].each_with_index do |churn, index|
      pair = [62_110 + 2 * index, 1]
      held = Dnsruby::RR.get_class(*pair)
      key = Dnsruby::ClassHash.keys.find { |item| item == pair }
      key[0] += 1
      evict if churn
      assert_same(Dnsruby::ClassHash, Dnsruby::ClassHash.rehash)
      refute_same(held, Dnsruby::RR.get_class(*pair))
      assert_same(held, Dnsruby::RR.get_class(pair[0] + 1, 1))
    end
  end

  def test_explicit_registration_survives_concurrent_fifo_eviction
    [:[]=, :merge!, :update].each_with_index do |operation, index|
      pair = [62_120 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      after_native_hash_return(operation, -> { evict }) do
        operation == :[]= ? Dnsruby::ClassHash[pair] = held : Dnsruby::ClassHash.public_send(operation, {pair => held})
      end
      evict
      assert_same(held, Dnsruby::ClassHash[pair], operation.to_s)
    end
  end

  def test_merge_callback_deletion_is_not_resurrected
    [:merge!, :update].each_with_index do |operation, index|
      pair = [62_130 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      Dnsruby::ClassHash.public_send(operation, {pair => held}) do |key, _, value|
        Dnsruby::ClassHash.delete(key)
        value
      end
      refute(Dnsruby::ClassHash.key?(pair))
      evict
      refute(Dnsruby::ClassHash.key?(pair))
    end
  end

  def test_merge_callback_cached_lookups_are_visible_and_remain_bounded
    [:merge!, :update].each_with_index do |operation, index|
      pair = [62_140 + 2 * index, 1]
      lookup_pair = [pair[0] + 1, 1]
      held = Dnsruby::RR.get_class(*pair)
      cached = Dnsruby::RR.get_class(*lookup_pair)
      Dnsruby::ClassHash.public_send(operation, {pair => held}) do |_, _, value|
        worker = Thread.new do
          assert_same(cached, Dnsruby::RR.get_class(*lookup_pair))
          assert_same(cached, Dnsruby::ClassHash[lookup_pair])
          assert_same(cached, Generic.const_get("Type#{lookup_pair[0]}_Class1"))
        end
        raise 'lookup blocked by registry mutation' unless worker.join(2)
        worker.value
        value
      end
      evict
      assert_same(held, Dnsruby::ClassHash[pair])
      refute(Dnsruby::ClassHash.key?(lookup_pair))
      assert_same(cached, Dnsruby::RR.get_class(*lookup_pair))
    end
  end

  def test_merge_callback_new_lookups_follow_native_hash_mutation_rules
    [:merge!, :update].each_with_index do |operation, index|
      # Recent Ruby releases forbid new keys while a merge conflict block is
      # running. Probe native Hash behavior so older supported Rubies retain
      # coverage too, without bypassing the registry's native mutation rules.
      native = {existing: true}
      native_error = begin
        native.public_send(operation, {existing: true}) { native[:added] = true }
        nil
      rescue RuntimeError => error
        error
      end
      pair = [62_144 + 2 * index, 1]
      lookup_pair = [pair[0] + 1, 1]
      held = Dnsruby::RR.get_class(*pair)
      generated = nil
      merge = lambda do
        Dnsruby::ClassHash.public_send(operation, {pair => held}) do |_, _, value|
          worker = Thread.new do
            Thread.current.report_on_exception = false
            Dnsruby::RR.get_class(*lookup_pair)
          end
          raise 'lookup blocked by registry mutation' unless worker.join(2)
          generated = worker.value
          assert_same(generated, Dnsruby::ClassHash[lookup_pair])
          value
        end
      end
      if native_error
        error = assert_raises(native_error.class, &merge)
        assert_equal(native_error.message, error.message)
        refute(Dnsruby::ClassHash.key?(lookup_pair))
      else
        assert_same(Dnsruby::ClassHash, merge.call)
      end
      generated ||= Dnsruby::RR.get_class(*lookup_pair)
      assert_same(generated, Dnsruby::ClassHash[lookup_pair])
      evict
      refute(Dnsruby::ClassHash.key?(lookup_pair))
      assert_same(generated, Dnsruby::RR.get_class(*lookup_pair))
    end
  end

  def test_rejected_registry_publication_can_be_retried
    pair = [62_148, 1]
    error = assert_raises(RuntimeError) do
      Dnsruby::ClassHash.each_pair { Dnsruby::RR.get_class(*pair) }
    end
    assert_match(/can't add a new key into hash during iteration/, error.message)
    refute(Dnsruby::ClassHash.key?(pair))
    generated = Dnsruby::RR.get_class(*pair)
    assert_same(generated, Dnsruby::ClassHash[pair])
    evict
    refute(Dnsruby::ClassHash.key?(pair))
    assert_same(generated, Dnsruby::RR.get_class(*pair))
  end

  def test_hash_and_equality_callbacks_run_outside_the_cache_lock
    subclass = Class.new(Array) do
      def check_callback
        worker = Thread.new { Dnsruby::RR.get_class(62_151, 1) }
        raise 'Hash key callback blocked by registry lock' unless worker.join(2)
        worker.value
      end
      def hash; check_callback; super; end
      def eql?(other); check_callback; super; end
    end
    pair = subclass.new([62_150, 1])
    held = Dnsruby::RR.get_class(62_150, 1)
    Dnsruby::ClassHash[pair] = held
    evict
    assert_same(held, Dnsruby::ClassHash[pair])
  end

  def test_replace_conversion_callbacks_remain_visible_but_removed_entries_are_invalidated
    held = nil
    replacement = Object.new
    replacement.define_singleton_method(:to_hash) do
      held = Dnsruby::RR.get_class(62_160, 1)
      raise 'factory publication hidden from callback' unless Dnsruby::ClassHash[[62_160, 1]].equal?(held)
      {}
    end
    automatic_keys = Cache.snapshot.keys.map(&:registry_key)
    saved = Dnsruby::ClassHash.reject { |key, _| automatic_keys.any? { |item| item.equal?(key) } }
    Dnsruby::ClassHash.replace(replacement)
    refute_same(held, Dnsruby::RR.get_class(62_160, 1))
  ensure
    Dnsruby::ClassHash.replace(saved) if saved
  end

  def test_replace_registers_classes_created_during_argument_conversion
    automatic_keys = Cache.snapshot.keys.map(&:registry_key)
    saved = Dnsruby::ClassHash.reject { |key, _| automatic_keys.any? { |item| item.equal?(key) } }
    [false, true].each_with_index do |concurrent_churn, index|
      pair = [62_162 + index, 1]
      held = nil
      conversions = 0
      replacement = Object.new
      replacement.define_singleton_method(:to_hash) do
        conversions += 1
        held = Dnsruby::RR.get_class(*pair)
        {pair => held}
      end
      if concurrent_churn
        after_native_hash_return(:replace, -> { evict }) do
          assert_same(Dnsruby::ClassHash, Dnsruby::ClassHash.replace(replacement))
        end
      else
        assert_same(Dnsruby::ClassHash, Dnsruby::ClassHash.replace(replacement))
      end
      assert_equal(1, conversions)
      evict
      assert_same(held, Dnsruby::ClassHash[pair])
      assert_same(held, Dnsruby::RR.get_class(*pair))
    end
  ensure
    Dnsruby::ClassHash.replace(saved) if saved
  end

  def test_replace_preserves_native_hash_conversion_defaults_and_identity
    automatic_keys = Cache.snapshot.keys.map(&:registry_key)
    saved = Dnsruby::ClassHash.reject { |key, _| automatic_keys.any? { |item| item.equal?(key) } }
    registry = Dnsruby::ClassHash
    source = Hash.new(:missing)
    source[:client] = :registered
    assert_same(registry, registry.replace(source))
    assert_equal(:missing, registry[:absent])
    assert_equal(:registered, registry[:client])
    assert_same(registry, registry.replace(registry))
    assert_equal(source, registry)
    default = ->(hash, key) { [hash, key] }
    registry.replace(Hash.new(&default))
    assert_same(default, registry.default_proc)
    assert_equal([registry, :absent], registry[:absent])
    key = [62_164, 1]
    identity = {}.compare_by_identity
    identity[key] = :identity_value
    registry.replace(identity)
    assert(registry.compare_by_identity?)
    assert_equal(:identity_value, registry[key])
    assert_nil(registry[key.dup])
    invalid = Object.new
    conversions = 0
    invalid.define_singleton_method(:to_hash) { conversions += 1; [] }
    assert_raises(TypeError) { registry.replace(invalid) }
    assert_equal(1, conversions)
    assert(registry.compare_by_identity?)
    assert_equal(:identity_value, registry[key])
    frozen = registry.dup.freeze
    assert_raises(FrozenError) { frozen.replace(invalid) }
    assert_equal(1, conversions)
  ensure
    Dnsruby::ClassHash.replace(saved) if saved
  end

  def test_frozen_registry_replace_does_not_coerce_its_argument
    script = <<~RUBY
      require 'dnsruby'
      source = Object.new
      source.define_singleton_method(:to_hash) { raise 'argument converted before frozen check' }
      Dnsruby::ClassHash.freeze
      begin
        Dnsruby::ClassHash.replace(source)
        raise 'frozen replacement succeeded'
      rescue FrozenError
      end
    RUBY
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', script)
    assert(status.success?, "#{stdout}\n#{stderr}")
    assert_empty(stderr)
  end

  def test_regeneration_removes_stale_native_binding_without_client_callbacks
    old = Generic.create(62_165, 1)
    Dnsruby::ClassHash.delete([62_165, 1])
    Generic.define_singleton_method(:remove_const) { |_| raise 'client callback under cache lock' }
    current = Dnsruby::RR.get_class(62_165, 1)
    refute_same(old, current)
    assert_same(current, Generic.const_get('Type62165_Class1'))
    refute(Module.instance_method(:const_defined?).bind(Generic).call('Type62165_Class1', false))
  ensure
    Generic.singleton_class.send(:remove_method, :remove_const)
  end

  def test_identity_hash_uses_distinct_classes_and_keeps_fifo_bound
    automatic_keys = Cache.snapshot.keys.map(&:registry_key)
    saved = Dnsruby::ClassHash.reject { |key, _| automatic_keys.any? { |item| item.equal?(key) } }
    Dnsruby::ClassHash.clear.compare_by_identity
    classes = 300.times.map { Dnsruby::RR.get_class(62_170, 1) }
    assert_equal(300, classes.map(&:object_id).uniq.length)
    assert_equal(Cache::LIMIT, Dnsruby::ClassHash.size)
    key = Dnsruby::ClassHash.keys.last
    held = Dnsruby::ClassHash[key]
    Dnsruby::ClassHash[key] = held
    300.times { Dnsruby::RR.get_class(62_171, 1) }
    assert_same(held, Dnsruby::ClassHash[key])
    assert_equal(Cache::LIMIT + 1, Dnsruby::ClassHash.size)
    Dnsruby::ClassHash.delete(key)
    refute(Dnsruby::ClassHash.key?(key))
    custom = Object.new
    custom.define_singleton_method(:hash) { raise "identity hash must not call hash" }
    custom.define_singleton_method(:eql?) { |_| raise "identity hash must not call eql?" }
    Dnsruby::ClassHash[custom] = held
    assert_same(held, Dnsruby::ClassHash.delete(custom))
  ensure
    Dnsruby::ClassHash.replace(saved) if saved
  end

  def test_array_subclass_hash_miss_does_not_detach_canonical_entry
    subclass = Class.new(Array) { def hash; super ^ 1; end }
    pair = [62_180, 1]
    held = Dnsruby::RR.get_class(*pair)
    assert_nil(Dnsruby::ClassHash.delete(subclass.new(pair)))
    assert_same(held, Dnsruby::ClassHash[pair])
    evict
    refute(Dnsruby::ClassHash.key?(pair))
    assert_same(held, Dnsruby::RR.get_class(*pair))
  end

  def test_distinct_array_subclass_updates_do_not_pin_canonical_entry
    subclass = Class.new(Array) { def hash; super ^ 1; end }
    [:[]=, :merge!, :update].each_with_index do |operation, index|
      pair = [62_190 + index, 1]
      held = Dnsruby::RR.get_class(*pair)
      custom = Class.new(Generic)
      2.times do
        key = subclass.new(pair)
        operation == :[]= ? Dnsruby::ClassHash[key] = custom : Dnsruby::ClassHash.public_send(operation, {key => custom})
      end
      evict
      refute(Dnsruby::ClassHash.key?(pair), operation.to_s)
      assert_same(custom, Dnsruby::ClassHash[subclass.new(pair)])
      assert_same(held, Dnsruby::RR.get_class(*pair))
    end
  end

  def test_custom_hash_aliases_address_the_native_pair
    [Array, Object].each_with_index do |base, index|
      [:same_class, :replacement].each_with_index do |mode, offset|
        pair = [62_200 + 2 * index + offset, 1]
        key_class = Class.new(base) do
          define_method(:method) { |_| raise "client method override" }
          define_method(:hash) { pair.hash }
          define_method(:eql?) { |other| other == pair }
        end
        key = base == Array ? key_class.new([pair[0] + 100, 1]) : key_class.new
        held = Dnsruby::RR.get_class(*pair)
        if mode == :same_class
          Dnsruby::ClassHash[key] = held
          evict
          assert_same(held, Dnsruby::ClassHash[pair])
        else
          custom = Class.new(Generic)
          Dnsruby::ClassHash[key] = custom
          assert_same(custom, Dnsruby::ClassHash[pair])
        end
        Dnsruby::ClassHash.delete(key)
        refute_same(held, Dnsruby::RR.get_class(*pair))
      end
    end
  end

end
