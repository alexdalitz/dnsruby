require_relative 'spec_helper'
require 'timeout'

class TestReviewCodeMapper < Minitest::Test
  def setup
    @mapper = Class.new(Dnsruby::CodeMapper)
    @mapper.const_set(:ONE, 1)
    @mapper.const_set(:TWO, 2)
    @mapper.update
  end

  def teardown
    Dnsruby::CodeMapper.class_variable_get(:@@arrays).delete(@mapper)
  end

  def maps
    Dnsruby::CodeMapper.class_variable_get(:@@arrays).fetch(@mapper)
  end

  def test_new_numeric_mappings_do_not_rebuild_existing_reverse_index
    # Count table traversals instead of depending on machine speed.
    inversions = 0
    maps.strings.define_singleton_method(:invert) do
      inversions += 1
      super()
    end
    100.times { |i| @mapper.add_pair("TYPE#{i + 1000}", i + 1000) }
    assert_equal(0, inversions)
    assert_equal('TYPE1099', @mapper.new(1099).to_s)
  end

  def test_aliases_reassignment_case_and_setters_preserve_hash_invert_semantics
    strings = maps.strings.dup
    stringsdown = maps.stringsdown.dup
    size = maps.maxcode
    [['new', 3], ['alias', 3], ['new', 4], ['alias', 5], ['ONE', 5],
     ['ONE', 5], ['ALIAS', 6], ['Mixed-Name', 7]].each do |name, code|
      strings[name] = code
      stringsdown[name.downcase] = code
      assert_equal(size += 1, @mapper.add_pair(name, code))
      assert_equal(strings, maps.strings)
      assert_equal(strings.invert, maps.values)
      assert_equal(stringsdown, maps.stringsdown)
    end
    value = @mapper.new('mixed_name')
    assert_equal(7, value.code)
    value.set_string('oNe')
    assert_equal([5, 'alias'], [value.code, value.string])
    value.set_code(6)
    assert_equal([6, 'ALIAS'], [value.code, value.string])
    assert_equal(6, @mapper.to_code('alias'))
    assert_equal('literal', @mapper.to_string('literal'))
  end

  def test_mutable_name_is_copied_and_frozen_name_keeps_identity
    name = +'mutable'
    @mapper.add_pair(name, 10)
    name.replace('changed')
    assert_equal('mutable', @mapper.to_string(10))
    assert_predicate(@mapper.to_string(10), :frozen?)
    assert_equal(10, @mapper.to_code('mutable'))
    assert_nil(@mapper.to_code('changed'))
    frozen = 'frozen'.freeze
    @mapper.add_pair(frozen, 11)
    assert_same(frozen, @mapper.to_string(11))
  end

  def test_custom_string_subclass_keeps_native_hash_behavior
    name_class = Class.new(String) do
      def dup
        raise 'Hash does not call user-defined dup'
      end
    end
    name = name_class.new('custom')
    expected = {name => 12}.invert
    @mapper.add_pair(name, 12)
    name.replace('changed')
    assert_equal(expected[12], @mapper.to_string(12))
    assert_equal(expected[12].frozen?, @mapper.to_string(12).frozen?)
  end

  def test_mutable_custom_code_is_rehashed_on_subsequent_insert
    # Historically add_pair accepts values other than integers. Hash#invert
    # rehashes them after mutation; the numeric optimization must not lose that.
    code = ['before']
    @mapper.add_pair('custom', code)
    code.replace(['after'])
    @mapper.add_pair('numeric', 13)
    assert_equal('custom', maps.values[['after']])
    assert_equal(maps.strings.invert, maps.values)
  end

  def test_update_discards_dynamic_pairs_and_rebuilds_constants
    @mapper.add_pair('extra', 3)
    @mapper.const_set(:THREE, 3)
    returned = @mapper.update
    assert_equal(maps.strings.keys, returned)
    assert_nil(@mapper.to_code('extra'))
    assert_equal(3, @mapper.to_code('three'))
    assert_equal('THREE', @mapper.to_string(3))
    assert_equal(3, maps.maxcode)
  end

  def test_update_retains_registrations_from_constant_lookup_callbacks
    @mapper.define_singleton_method(:const_get) do |name|
      add_pair('FROM_CALLBACK', 20)
      super(name)
    end
    @mapper.update
    assert_equal(20, @mapper.to_code('FROM_CALLBACK'))
    assert_equal('FROM_CALLBACK', @mapper.to_string(20))
    assert_equal(1, @mapper.to_code('ONE'))
    assert_equal(maps.strings.invert, maps.values)
  end

  def test_reentrant_custom_downcase_can_register_another_pair
    mapper = @mapper
    name = +'outer'
    name.define_singleton_method(:downcase) do
      mapper.add_pair('inner', 15)
      super()
    end
    Timeout.timeout(2) { @mapper.add_pair(name, 14) }
    assert_equal(14, @mapper.to_code('outer'))
    assert_equal(15, @mapper.to_code('inner'))
    assert_equal(maps.strings.invert, maps.values)
    assert_equal(4, maps.maxcode)
  end

  def test_custom_downcase_can_wait_for_another_writer_thread
    mapper = @mapper
    name = +'outer'
    name.define_singleton_method(:downcase) do
      Thread.new { mapper.add_pair('inner', 15) }.value
      super()
    end
    Timeout.timeout(2) { @mapper.add_pair(name, 14) }
    assert_equal(14, @mapper.to_code('outer'))
    assert_equal(15, @mapper.to_code('inner'))
    assert_equal(maps.strings.invert, maps.values)
  end

  def test_overridden_frozen_query_does_not_change_string_key_copying
    name = +'mutable'
    name.define_singleton_method(:frozen?) { true }
    @mapper.add_pair(name, 16)
    name.replace('changed')
    assert_equal('mutable', @mapper.to_string(16))
    assert_predicate(@mapper.to_string(16), :frozen?)
  end

  def test_concurrent_aliases_keep_reverse_mapping_consistent
    threads = 6.times.map do |worker|
      Thread.new do
        80.times { |i| @mapper.add_pair("NAME#{worker}-#{i}", 1000 + i) }
      end
    end
    Timeout.timeout(5) { threads.each(&:value) }
    assert_equal(maps.strings.invert, maps.values)
    assert_equal(482, maps.maxcode)
    6.times { |worker| assert_equal(1079, @mapper.to_code("NAME#{worker}-79")) }
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end
end
