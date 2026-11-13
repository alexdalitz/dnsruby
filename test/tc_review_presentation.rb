require_relative 'spec_helper'
require 'stringio'

class TestReviewPresentation < Minitest::Test
  def presentation
    Dnsruby.const_get(:Presentation)
  end

  def test_record_parsing_never_enumerates_learned_class_names
    original = Dnsruby::Classes.method(:regexp)
    own_method = Dnsruby::Classes.singleton_methods(false).include?(:regexp)
    Dnsruby::Classes.define_singleton_method(:regexp) do
      raise 'record parsing must use an indexed class lookup'
    end
    record = Dnsruby::RR.create('example. 300 IN A 192.0.2.1')
    assert_equal('192.0.2.1', record.address.to_s)
    record = Dnsruby::RR.create("example. 300 IN TXT 'one(two);three'")
    assert_equal(['one(two);three'], record.strings)
  ensure
    if original
      Dnsruby::Classes.singleton_class.remove_method(:regexp)
      Dnsruby::Classes.define_singleton_method(:regexp, original) if own_method
    end
  end

  def test_numeric_and_registered_class_tokens_preserve_quote_boundaries
    arrays = Dnsruby::CodeMapper.class_variable_get(:@@arrays)
    original = arrays.fetch(Dnsruby::Classes)
    replacement = Dnsruby::CodeMapper::Arrays.new
    %i[strings stringsdown values].each do |name|
      replacement.public_send("#{name}=", original.public_send(name).dup)
    end
    replacement.maxcode = original.maxcode
    arrays[Dnsruby::Classes] = replacement
    Dnsruby::Classes.add_pair('PRIVATE', 60_000)
    %w[IN in CLASS65000 class65000 PRIVATE private].each do |klass|
      text = "owner 300 #{klass} TXT('one(two);three')"
      assert_equal(text.index('TXT') + 3, presentation.single_quoted_start(text), klass)
    end
    assert_nil(presentation.single_quoted_start("owner 300 UNREGISTERED TXT 'value'"))
    assert_nil(presentation.single_quoted_start("owner 300 IN A 'value'"))
  ensure
    arrays[Dnsruby::Classes] = original if original
  end

  def test_txt_continuation_recognizes_apostrophes_on_later_lines
    %w[TXT SPF TYPE16 TYPE99].each do |type|
      text = "owner 300 IN #{type} (\n 'one(two);three'\n 'four'\n)\n"
      record = Dnsruby::ZoneReader.new('example.').process_io(StringIO.new(text)).first
      assert_equal(['one(two);three', 'four'], record.strings, type)
    end
  end

  def test_omitted_owner_and_apostrophe_in_owner_keep_legacy_behavior
    text = "'owner 300 IN TXT ('first')\n IN TXT ('two(three);four')\n"
    records = Dnsruby::ZoneReader.new('example.').process_io(StringIO.new(text))
    assert_equal(['first'], records.first.strings)
    assert_equal(['two(three);four'], records.last.strings)
    assert_equal(records.first.name, records.last.name)
  end
end
