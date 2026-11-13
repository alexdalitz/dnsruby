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
    # add_pair accepts values other than integers. Mutable keys must be
    # rehashed on insertion, matching Hash#invert.
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

  def test_dns_type_and_class_construction_rejects_out_of_range_without_interning
    [[Dnsruby::Types, 'TYPE'], [Dnsruby::Classes, 'CLASS']].each do |mapper, prefix|
      table = Dnsruby::CodeMapper.class_variable_get(:@@arrays).fetch(mapper)
      before = [table.strings.dup, table.stringsdown.dup, table.values.dup, table.maxcode]
      [-1, 65_536, 65_538, 2**128].each do |code|
        assert_raises(ArgumentError) { mapper.new(code) }
        assert_raises(ArgumentError) { mapper.new("#{prefix}#{code}") }
      end
      100.times { |i| assert_raises(ArgumentError) { mapper.new("#{prefix}#{65_536 + i}") } }
      ['', 'suffix', '.0', "\nignored"].each do |suffix|
        # An empty suffix tests the bare TYPE or CLASS prefix.
        text = suffix.empty? ? prefix : "#{prefix}123#{suffix}"
        assert_raises(ArgumentError) { mapper.new(text) }
      end
      assert_equal(before, [table.strings, table.stringsdown, table.values, table.maxcode])
    end
  end

  def test_dns_numeric_spelling_variants_do_not_grow_mapping_tables
    [[Dnsruby::Types, 'TYPE'], [Dnsruby::Classes, 'CLASS']].each do |mapper, prefix|
      code = 65_050
      assert_equal(code, mapper.new(code).code)
      table = Dnsruby::CodeMapper.class_variable_get(:@@arrays).fetch(mapper)
      before = [table.strings.dup, table.stringsdown.dup, table.values.dup, table.maxcode]
      100.times do |zeroes|
        text = "#{prefix.downcase}#{'0' * zeroes}#{code}"
        mapped = mapper.new(text)
        expected = zeroes.zero? ? "#{prefix}#{code}" : text
        assert_equal(code, mapped.code)
        assert_equal(expected, mapped.to_s)
        assert_equal(expected, mapper.new(mapped).to_s)
      end
      assert_equal(before, [table.strings, table.stringsdown, table.values, table.maxcode])
      [0, 65_535].each { |boundary| assert_equal(boundary, mapper.new(boundary).code) }
    end
    assert_equal('TYPE0001', Dnsruby::Types.new('TYPE0001').to_s)
    assert_equal('CLASS0001', Dnsruby::Classes.new('CLASS0001').to_s)
    assert_equal('A', Dnsruby::Types.new(1).to_s)
    assert_equal('IN', Dnsruby::Classes.new(1).to_s)
  end

  def test_dns_code_helpers_validate_range_and_numeric_strings
    [[Dnsruby::Types, 'TYPE', :typesbyname, :typesbyval],
     [Dnsruby::Classes, 'CLASS', :classesbyname, :classesbyval]].each do |mapper, prefix, byname, byval|
      assert_equal(1, mapper.public_send(byname, "#{prefix}0001"))
      assert_equal(mapper.to_string(1), mapper.public_send(byval, ' 0001 '))
      [-1, 65_536, 2**128].each do |code|
        assert_raises(ArgumentError) { mapper.public_send(byval, code) }
        assert_raises(ArgumentError) { mapper.public_send(byval, code.to_s) }
        assert_raises(ArgumentError) { mapper.public_send(byname, "#{prefix}#{code}") }
      end
    end
    error = assert_raises(ArgumentError) { Dnsruby::RR.create('x. IN TYPE65536 \\# 0') }
    assert_match(/0\.\.65535/, error.message)
    error = assert_raises(ArgumentError) { Dnsruby::RR.create('x. CLASS65536 TYPE65000 \\# 0') }
    assert_match(/0\.\.65535/, error.message)
  end

  def test_copying_a_mutated_dns_mapper_still_validates_the_wire_range
    [Dnsruby::Types, Dnsruby::Classes].each do |mapper|
      value = mapper.new(1)
      value.code = 65_536
      assert_raises(ArgumentError) { mapper.new(value) }
    end
    # Custom CodeMapper subclasses can accept values outside the DNS
    # type/class range.
    @mapper.add_pair('LARGE', 2**32)
    @mapper.add_pair('NEGATIVE', -1)
    assert_equal(2**32, @mapper.new('LARGE').code)
    assert_equal(-1, @mapper.new('NEGATIVE').code)
  end

  def test_dns_mappers_preserve_explicit_application_aliases
    arrays = Dnsruby::CodeMapper.class_variable_get(:@@arrays)
    [[Dnsruby::Types, 'TYPE'], [Dnsruby::Classes, 'CLASS']].each do |mapper, prefix|
      original = arrays.fetch(mapper)
      replacement = Dnsruby::CodeMapper::Arrays.new
      %i[strings stringsdown values].each do |field|
        replacement.public_send("#{field}=", original.public_send(field).dup)
      end
      replacement.maxcode = original.maxcode
      replacement.incremental = original.incremental
      arrays[mapper] = replacement
      begin
        existing = mapper.new(1)
        mapper.add_pair('PREFERRED-ONE-ALIAS', 1)
        assert_equal('PREFERRED-ONE-ALIAS', mapper.new(existing).to_s)
        numeric_spelling = mapper.new("#{prefix}0001")
        assert_equal("#{prefix}0001", mapper.new(numeric_spelling).to_s)
        mapper.add_pair("#{prefix}0001", 1)
        mapper.add_pair('LATEST-ONE-ALIAS', 1)
        assert_equal('LATEST-ONE-ALIAS', mapper.new(numeric_spelling).to_s)
        mapper.add_pair('APPLICATION-ALIAS', 65_052)
        assert_equal(65_052, mapper.new('application_alias').code)
        assert_equal("#{prefix}065052", mapper.new("#{prefix}065052").to_s)
        assert_equal(65_052, mapper.to_code('APPLICATION-ALIAS'))
        assert_equal('APPLICATION-ALIAS', mapper.new(65_052).to_s)
        assert_nil(mapper.to_code("#{prefix}065052"), 'automatic spelling must not replace the explicit alias')
      ensure
        arrays[mapper] = original
      end
    end
  end
end
