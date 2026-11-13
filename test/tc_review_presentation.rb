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
    %w[TXT SPF TYPE16 TYPE99 TYPE016 TYPE099 TYPE00016 TYPE00099].each do |type|
      text = "owner 300 IN #{type} (\n 'one(two);three'\n 'four'\n)\n"
      record = Dnsruby::ZoneReader.new('example.').process_io(StringIO.new(text)).first
      assert_equal(['one(two);three', 'four'], record.strings, type)
    end
  end

  def test_numeric_txt_and_spf_preserve_single_quoted_punctuation
    %w[TYPE016 TYPE099 TYPE00016 TYPE00099].each do |type|
      text = "owner 300 IN #{type} 'one(two);three'"
      direct = Dnsruby::RR.create(text)
      reader = Dnsruby::ZoneReader.new('example.')
      normalized = reader.normalise_line(text)
      record = reader.process_io(StringIO.new(text + "\n")).first
      assert_equal(['one(two);three'], direct.strings, type)
      assert_equal(direct.strings, Dnsruby::RR.create(normalized).strings, type)
      assert_equal(direct.strings, record.strings, type)
    end
  end

  def test_normalised_lines_remain_strings_accepted_by_public_rr_constructor
    [
      'www 300 IN A 192.0.2.1',
      "txt 300 IN TYPE016 'one(two);three'",
      'txt 300 IN TXT "one(two);three" \\"escaped ; ignored',
      'https 300 IN HTTPS 1 svc alpn="h2,h3"',
      'opaque 300 CLASS65000 TYPE65001 \\# 0'
    ].each do |text|
      reader = Dnsruby::ZoneReader.new('example.')
      line = reader.process_line(text.freeze)
      assert_instance_of(String, line)
      expected = Dnsruby::RR.create(line)
      record = Dnsruby::ZoneReader.new('example.').process_io(StringIO.new(text + "\n")).first
      assert_equal(expected, record, text)
    end
  end

  def test_process_line_preserves_subclass_normalization_hook_and_prefix_arguments
    seen = []
    reader_class = Class.new(Dnsruby::ZoneReader) do
      define_method(:normalise_line) do |line, prefix = false|
        seen << [line, prefix]
        # Replacement strings must be scanned even though process_line has
        # already scanned the original input passed to this hook.
        super(line.sub('192.0.2.1', '(192.0.2.2) ; added comment ('), prefix)
      end
    end
    line, type, name = reader_class.new('example.').process_line('www 300 IN A 192.0.2.1', true)
    assert_equal(1, seen.length)
    assert_instance_of(String, seen.first.first)
    assert_equal(true, seen.first.last)
    assert_equal('A', type)
    assert_equal('www.example.', name)
    assert_equal('192.0.2.2', Dnsruby::RR.create(line).address.to_s)
  end

  def test_prepend_hook_failure_does_not_leave_input_marked_as_scanned
    first_line = nil
    hook = Module.new do
      define_method(:normalise_line) do |line, prefix = false|
        unless first_line
          first_line = line
          raise ArgumentError, 'normalization hook rejected input'
        end
        super(line, prefix)
      end
    end
    reader_class = Class.new(Dnsruby::ZoneReader) { prepend hook }
    reader = reader_class.new('example.')
    assert_raises(ArgumentError) { reader.process_line('www 300 IN A 192.0.2.1') }
    # Reusing the same String after the failed call is a direct public call,
    # so its new grouping and comments must receive the normal scanner.
    first_line.replace('www 300 IN A (192.0.2.3) ; added comment (')
    line = reader.normalise_line(first_line)
    assert_equal('192.0.2.3', Dnsruby::RR.create(line).address.to_s)
    assert_equal('192.0.2.4', Dnsruby::RR.create(reader.process_line('next 300 IN A 192.0.2.4')).address.to_s)
  end

  def test_normalization_hook_can_mutate_the_input_before_super
    reader_class = Class.new(Dnsruby::ZoneReader) do
      def normalise_line(line, prefix = false)
        line.sub!('192.0.2.1', '(192.0.2.2) ; added comment (')
        super
      end
    end
    text = "www 300 IN A 192.0.2.1\n"
    record = reader_class.new('example.').process_io(StringIO.new(text)).first
    assert_equal('www.example.', record.name.to_s(true))
    assert_equal('192.0.2.2', record.address.to_s)
  end

  def test_process_io_parses_presentation_returned_by_a_replacement_hook
    reader_class = Class.new(Dnsruby::ZoneReader) do
      def normalise_line(line, prefix = false)
        # Applications can provide the normalization themselves and return
        # any valid RR presentation, including grouping and comments.
        'custom.example. 300 IN A (192.0.2.3) ; hook supplied this record'
      end
    end
    record = reader_class.new('example.').process_io(StringIO.new("www 300 IN A 192.0.2.1\n")).first
    assert_equal('custom.example.', record.name.to_s(true))
    assert_equal('192.0.2.3', record.address.to_s)
  end

  def test_process_line_scans_unchanged_input_once
    scanner = presentation.singleton_class
    ['www 300 IN A 192.0.2.1', 'txt 300 IN TXT "one(two);three"'].each do |line|
      scans = 0
      tracer = TracePoint.new(:call) do |event|
        scans += 1 if event.defined_class == scanner && event.method_id == :scan
      end
      normalized = tracer.enable do
        Dnsruby::ZoneReader.new('example.').process_line(line + "\n")
      end
      assert_equal(1, scans, line)
      assert_instance_of(String, normalized)
      assert_instance_of(Dnsruby::Name, Dnsruby::RR.create(normalized).name)
    end
  end

  def test_omitted_owner_and_apostrophe_in_owner_keep_legacy_behavior
    text = "'owner 300 IN TXT ('first')\n IN TXT ('two(three);four')\n"
    records = Dnsruby::ZoneReader.new('example.').process_io(StringIO.new(text))
    assert_equal(['first'], records.first.strings)
    assert_equal(['two(three);four'], records.last.strings)
    assert_equal(records.first.name, records.last.name)
  end

  def test_plain_records_and_grouped_records_produce_identical_wire_data
    [
      'www.example. 60 IN A 192.0.2.1',
      "www.example.\t60\tIN\tAAAA\t2001:db8::1",
      'example. IN MX 10 mail.example.',
      'example. 60 IN TXT plain',
      'example. 60 IN HTTPS 1 . alpn=h2 port=443',
      'é.example. 60 IN A 192.0.2.1'
    ].each do |text|
      plain = Dnsruby::RR.create(text.freeze)
      grouped = Dnsruby::RR.create("(#{text})")
      assert_equal(grouped, plain, text)
      assert_equal(grouped.clone, plain.clone, text)
    end
  end
end
