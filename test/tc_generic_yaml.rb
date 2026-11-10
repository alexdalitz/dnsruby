require_relative 'spec_helper'
require 'dnsruby/optional/yaml'
require 'tmpdir'
require 'open3'
require 'rbconfig'

class TestGenericYaml < Minitest::Test
  def record(type = 60_501)
    Dnsruby::RR.create("test.example. 60 IN TYPE#{type} \\# 3 00ff61")
  end

  def permitted(klass)
    [klass, Dnsruby::Name, Dnsruby::Name::Label, Dnsruby::Types, Dnsruby::Classes]
  end

  def test_records_classes_and_message_cycles_keep_identity_and_custom_fields
    rr = record
    rr.class.class_eval { def yaml_client_method; :preserved; end }
    rr.instance_variable_set(:@client, { 'self' => rr, 'class' => rr.class })
    message = Dnsruby::Message.new
    message.add_answer(rr)
    copy = YAML.unsafe_load(YAML.dump([rr, rr.class, message, rr]))
    assert_same(rr.class, copy[0].class)
    assert_same(rr.class, copy[1])
    assert_same(copy[0], copy[2].answer.first)
    assert_same(copy[0], copy[3])
    assert_same(copy[0], copy[0].instance_variable_get(:@client)['self'])
    assert_same(rr.class, copy[0].instance_variable_get(:@client)['class'])
    assert_same(copy[2], copy[2].answer.instance_variable_get(:@msg))
    assert_equal([0, 255, 97], copy[0].data.bytes)
    assert_equal(:preserved, copy[0].yaml_client_method)
    assert_equal(message.encode, copy[2].encode)
  end

  def assert_subprocess(script)
    # These are standalone load-order tests. Bundler and RUBYOPT preloads can
    # activate Psych before the script starts. Keep the selected Ruby executable,
    # library paths and gem paths, but remove inherited activation/preload hooks.
    environment = { 'RUBYOPT' => nil, 'RUBYGEMS_GEMDEPS' => nil }
    ENV.each_key { |key| environment[key] = nil if key.start_with?('BUNDLE') }
    if defined?(Bundler) && Bundler.respond_to?(:unbundled_env)
      # Retain vendor-installed dependencies and versions outside the bundle.
      original = Bundler.unbundled_env
      paths = Gem.path + original.fetch('GEM_PATH', '').split(File::PATH_SEPARATOR)
      environment['GEM_PATH'] = (paths + [original['GEM_HOME']] + Gem.default_path).compact.uniq.join(File::PATH_SEPARATOR)
    end
    ruby_options = ''.frozen? ? ['--enable-frozen-string-literal'] : []
    script = <<~RUBY + script
      raise 'Psych was activated before the test script' if Gem.loaded_specs['psych']
      raise 'Psych or YAML was defined before the test script' if defined?(Psych) || defined?(YAML)
    RUBY
    stdout, stderr, status = Open3.capture3(
      environment, RbConfig.ruby, *ruby_options, '-I', File.expand_path('../lib', __dir__), '-e', script)
    assert(status.success?, "#{script}\n#{stdout}\n#{stderr}")
    assert_empty(stderr)
    stdout
  end

  def test_core_does_not_load_yaml_resolve_autoloads_or_create_observers
    setups = [
      '',
      "autoload(:Psych, 'dnsruby-test-psych-autoload')",
      "module Psych; autoload(:ClassLoader, 'dnsruby-test-class-loader-autoload'); end"
    ]
    setups.each do |setup|
      assert_subprocess(<<~RUBY)
        #{setup}
        original_psych_autoload = Object.autoload?(:Psych)
        original_loader_autoload = Psych.autoload?(:ClassLoader) if defined?(Psych) && !original_psych_autoload
        class << TracePoint
          def new(*)
            raise 'core created a TracePoint'
          end
        end
        module Kernel
          alias require_without_yaml_guard require
          def require(path)
            raise LoadError, 'YAML unavailable' if ['psych', 'yaml'].include?(path)
            require_without_yaml_guard(path)
          end
        end
        require 'dnsruby'
        raise 'Psych activated early' if Gem.loaded_specs['psych']
        raise 'YAML activated early' if defined?(YAML)
        raise 'Psych autoload changed' unless Object.autoload?(:Psych) == original_psych_autoload
        if original_loader_autoload
          raise 'ClassLoader autoload changed' unless Psych.autoload?(:ClassLoader) == original_loader_autoload
        elsif !original_psych_autoload
          raise 'Psych was defined' if defined?(Psych)
        end
        raise 'adapter was defined' if Dnsruby::RR.const_defined?(:GenericYamlClassLoader, false)
        rr = Dnsruby::RR.create('example. 60 IN A 192.0.2.1')
        raise 'ordinary DNS record failed' unless rr.address.to_s == '192.0.2.1'
        raise 'generated DNS record failed' unless Dnsruby::RR.get_class(60_510, 1).new('data').data == 'data'
      RUBY
    end
  end

  def test_core_leaves_preloaded_and_later_loaded_psych_unmodified
    [true, false].each do |yaml_first|
      assert_subprocess(<<~RUBY)
        existing_traces = ObjectSpace.each_object(TracePoint).select(&:enabled?)
        require 'yaml' if #{yaml_first}
        original_ancestors = Psych::ClassLoader.ancestors if #{yaml_first}
        original_lookup = Psych::ClassLoader.instance_method(:path2class) if #{yaml_first}
        require 'dnsruby'
        require 'yaml'
        class UnrelatedAfterDnsrubyLoad; end
        raise 'adapter was defined' if Dnsruby::RR.const_defined?(:GenericYamlClassLoader, false)
        raise 'loader was patched' if Psych::ClassLoader.ancestors.any? { |entry| entry.name.to_s.start_with?('Dnsruby::') }
        if #{yaml_first}
          raise 'loader ancestors changed' unless Psych::ClassLoader.ancestors == original_ancestors
          raise 'loader method changed' unless Psych::ClassLoader.instance_method(:path2class) == original_lookup
        end
        new_traces = ObjectSpace.each_object(TracePoint).select(&:enabled?) - existing_traces
        raise 'core left an observer' unless new_traces.empty?
        rr = Dnsruby::RR.create('example. 60 IN A 192.0.2.1')
        raise 'named record changed' unless YAML.unsafe_load(YAML.dump(rr)) == rr
        raise 'named class changed' unless YAML.unsafe_load(YAML.dump(rr.class)).equal?(rr.class)
        plain = {'ordinary' => [1, 2, 3]}
        raise 'ordinary YAML changed' unless YAML.safe_load(YAML.dump(plain)) == plain
        generated = Dnsruby::RR.get_class(60_510, 1)
        [generated, generated.new('data')].each do |value|
          begin
            YAML.unsafe_load(YAML.dump(value))
            raise 'generated class loaded without optional adapter'
          rescue ArgumentError
          end
        end
        require 'dnsruby/optional/yaml'
        raise 'generated class changed' unless YAML.unsafe_load(YAML.dump(generated)).equal?(generated)
        raise 'generated record changed' unless YAML.unsafe_load(YAML.dump(generated.new('data'))).class.equal?(generated)
      RUBY
    end
  end

  def test_optional_entry_point_load_orders_and_repeat_require
    orders = [
      "require 'dnsruby/optional/yaml'",
      "require 'dnsruby'; require 'dnsruby/optional/yaml'",
      "require 'yaml'; require 'dnsruby/optional/yaml'",
      "require 'psych'; require 'dnsruby/optional/yaml'",
      "autoload(:Psych, 'psych'); require 'dnsruby'; require 'dnsruby/optional/yaml'",
      "module Psych; autoload(:ClassLoader, 'psych/class_loader'); end; require 'dnsruby'; require 'dnsruby/optional/yaml'"
    ]
    orders.each do |order|
      assert_subprocess(<<~RUBY)
        class << TracePoint
          def new(*)
            raise 'optional support created a TracePoint'
          end
        end
        #{order}
        adapter = Dnsruby::RR::GenericYamlClassLoader
        raise 'adapter not installed exactly once' unless Psych::ClassLoader.ancestors.count(adapter) == 1
        raise 'repeat require not idempotent' unless require('dnsruby/optional/yaml') == false
        raise 'adapter installed twice' unless Psych::ClassLoader.ancestors.count(adapter) == 1
        klass = Dnsruby::RR.get_class(60_510, 1)
        rr = klass.new('client data')
        raise 'record class changed' unless YAML.unsafe_load(YAML.dump(rr)).class.equal?(klass)
        begin
          YAML.safe_load(YAML.dump(rr))
          raise 'unpermitted record loaded'
        rescue Psych::DisallowedClass
        end
        plain = {'ordinary' => [1, 2, 3]}
        raise 'ordinary YAML changed' unless YAML.safe_load(YAML.dump(plain)) == plain
      RUBY
    end
  end

  def test_optional_entry_point_respects_selected_psych_version
    # Separate processes are needed: RubyGems activation cannot be undone.
    # Discover versions outside the parent's bundle as well as loading them there.
    versions = assert_subprocess(<<~RUBY).lines.map(&:strip)
      puts Gem::Specification.find_all_by_name('psych').map(&:version).uniq
    RUBY
    skip('No installed Psych gem metadata') if versions.empty?
    versions.each do |version|
      ['', "require 'yaml';"].each do |preload|
        assert_subprocess(<<~RUBY)
          require 'dnsruby'
          raise 'Psych activated early' if Gem.loaded_specs['psych']
          gem 'psych', '= #{version}'
          #{preload}
          require 'dnsruby/optional/yaml'
          raise 'wrong Psych version' unless Psych::VERSION == '#{version}'
          klass = Dnsruby::RR.get_class(60_510, 1)
          raise 'class changed' unless YAML.unsafe_load(YAML.dump(klass)).equal?(klass)
        RUBY
      end
    end
  end

  def test_frozen_psych_loader_allows_core_and_rejects_new_optional_installation
    assert_subprocess(<<~RUBY)
      require 'yaml'
      class << TracePoint
        def new(*)
          raise 'optional failure created a TracePoint'
        end
      end
      Psych::ClassLoader.freeze
      original_ancestors = Psych::ClassLoader.ancestors
      require 'dnsruby'
      raise 'loader was changed' unless Psych::ClassLoader.ancestors == original_ancestors
      rr = Dnsruby::RR.create('ordinary.example. 60 IN A 192.0.2.21')
      raise 'ordinary record failed' unless rr.address.to_s == '192.0.2.21'
      raise 'ordinary YAML failed' unless YAML.unsafe_load(YAML.dump(rr)) == rr
      begin
        require 'dnsruby/optional/yaml'
        raise 'frozen loader silently accepted an unavailable adapter'
      rescue FrozenError => error
        raise 'unclear frozen loader error' unless error.message.include?('dnsruby/optional/yaml') && error.message.include?('before freezing')
      end
      raise 'failed adapter was installed' if Psych::ClassLoader.ancestors.include?(Dnsruby::RR::GenericYamlClassLoader)
      raise 'failed adapter marked loaded' if $LOADED_FEATURES.any? { |path| path.end_with?('/dnsruby/optional/yaml.rb') }
      class UnrelatedAfterOptionalFailure; end
      raise 'core failed after optional failure' unless Dnsruby::RR.get_class(60_510, 1).new('data').data == 'data'
    RUBY
  end

  def test_freezing_loader_during_optional_installation_fails_clearly
    assert_subprocess(<<~RUBY)
      require 'yaml'
      class << TracePoint
        def new(*)
          raise 'optional failure created a TracePoint'
        end
      end
      Psych::ClassLoader.define_singleton_method(:prepend) do |*modules|
        freeze
        super(*modules)
      end
      begin
        require 'dnsruby/optional/yaml'
        raise 'concurrent freeze silently accepted an unavailable adapter'
      rescue FrozenError => error
        raise 'unclear frozen loader error' unless error.message.include?('dnsruby/optional/yaml') && error.message.include?('before freezing')
      end
      raise 'failed adapter was installed' if Psych::ClassLoader.ancestors.include?(Dnsruby::RR::GenericYamlClassLoader)
    RUBY
  end

  def test_installed_optional_adapter_works_with_subsequently_frozen_loader
    assert_subprocess(<<~RUBY)
      require 'dnsruby/optional/yaml'
      Psych::ClassLoader.freeze
      raise 'repeat require not idempotent' unless require('dnsruby/optional/yaml') == false
      raise 'adapter installed twice' unless Psych::ClassLoader.ancestors.count(Dnsruby::RR::GenericYamlClassLoader) == 1
      klass = Dnsruby::RR.get_class(60_510, 1)
      raise 'class changed' unless YAML.unsafe_load(YAML.dump(klass)).equal?(klass)
      raise 'record class changed' unless YAML.unsafe_load(YAML.dump(klass.new('data'))).class.equal?(klass)
    RUBY
  end

  def test_explicit_factory_deletion_and_regeneration_keep_live_yaml_class
    old = Dnsruby::RR::Generic.create(60_511, 1)
    Dnsruby::ClassHash.delete([60_511, 1])
    rr = record(60_511)
    rr.class.class_eval { def regenerated_client_method; :preserved; end }
    refute_same(old, rr.class)
    assert_same(rr.class, Dnsruby::RR::Generic.const_get('Type60511_Class1'))
    copy = YAML.unsafe_load(YAML.dump(rr))
    assert_same(rr.class, copy.class)
    assert_equal(rr, copy)
    assert_equal(:preserved, copy.regenerated_client_method)
    safe = YAML.safe_load(YAML.dump(rr), permitted_classes: permitted(rr.class))
    assert_same(rr.class, safe.class)
    assert_equal(rr, safe)
    assert_equal(:preserved, safe.regenerated_client_method)
  end

  def test_existing_yaml_representation_loads_without_a_native_constant
    path = 'Dnsruby::RR::Generic::Type60502_Class1'
    refute(Module.instance_method(:const_defined?).bind(Dnsruby::RR::Generic).call('Type60502_Class1', false))
    klass = YAML.unsafe_load("--- !ruby/class '#{path}'\n")
    rr = YAML.unsafe_load("--- !ruby/object:#{path}\ndata: old data\n")
    assert_same(Dnsruby::RR.get_class(60_502, 1), klass)
    assert_same(klass, rr.class)
    assert_equal('old data', rr.data)
    assert_equal("--- !ruby/class '#{path}'\n", YAML.dump(klass))
    assert_match(/\A--- !ruby\/object:#{Regexp.escape(path)}\n/, YAML.dump(rr))
    refute(Module.instance_method(:const_defined?).bind(Dnsruby::RR::Generic).call('Type60502_Class1', false))
  end

  def test_nested_custom_classes_require_an_explicitly_named_parent
    generated = Dnsruby::RR.get_class(60_515, 1)
    nested = Class.new
    generated.const_set(:ClientNested, nested)
    old_path = 'Dnsruby::RR::Generic::Type60515_Class1::ClientNested'
    assert_raises(ArgumentError) { YAML.unsafe_load("--- !ruby/class '#{old_path}'\n") }
    assert_raises(ArgumentError) { YAML.unsafe_load(YAML.dump(nested)) }

    explicit = Dnsruby::RR::Generic.create(60_516, 1)
    explicit_nested = Class.new
    explicit.const_set(:ClientNested, explicit_nested)
    assert_same(explicit_nested, YAML.unsafe_load(YAML.dump(explicit_nested)))
    assert_same(explicit_nested, YAML.unsafe_load(YAML.dump(explicit_nested.new)).class)
  end

  def test_safe_load_keeps_class_and_alias_restrictions
    rr = record(60_503)
    data = YAML.dump([rr, rr])
    assert_raises(Psych::DisallowedClass) { YAML.safe_load(data, aliases: true) }
    assert_raises(Psych::AliasesNotEnabled) { YAML.safe_load(data, permitted_classes: permitted(rr.class)) }
    copy = YAML.safe_load(data, permitted_classes: permitted(rr.class), aliases: true)
    assert_same(rr.class, copy[0].class)
    assert_same(copy[0], copy[1])
    assert_equal(rr, copy[0])
    path = 'Dnsruby::RR::Generic::Type60504_Class1'
    assert_nil(Dnsruby::RR::GenericCache.peek(60_504, 1))
    assert_raises(Psych::DisallowedClass) { YAML.safe_load("--- !ruby/class '#{path}'\n") }
    assert_nil(Dnsruby::RR::GenericCache.peek(60_504, 1))
    assert_raises(Psych::DisallowedClass) do
      YAML.safe_load("--- !ruby/class '#{path}'\n", permitted_classes: [Class])
    end
    assert_nil(Dnsruby::RR::GenericCache.peek(60_504, 1))
    assert_same(rr.class, YAML.safe_load(YAML.dump(rr.class), permitted_classes: [rr.class]))
  end

  def test_unknown_paths_and_nonclass_bindings_keep_native_errors
    ['UnrelatedMissingClass', 'Dnsruby::RR::Generic::Type60505_Class1::Missing',
     'Dnsruby::RR::Generic::TypeMissing_Class1', 'Other::Type60505_Class1'].each do |path|
      assert_raises(ArgumentError) { YAML.unsafe_load("--- !ruby/class '#{path}'\n") }
    end
    Dnsruby::RR::Generic.const_set(:Type60506_Class1, 123)
    assert_raises(TypeError) do
      YAML.unsafe_load("--- !ruby/class 'Dnsruby::RR::Generic::Type60506_Class1'\n")
    end
  ensure
    Dnsruby::RR::Generic.send(:remove_const, :Type60506_Class1)
  end

  def test_native_classes_and_explicit_factory_are_unchanged
    ordinary = Dnsruby::RR.create('test.example. 60 IN A 192.0.2.1')
    assert_equal(ordinary, YAML.unsafe_load(YAML.dump(ordinary)))
    assert_same(ordinary.class, YAML.unsafe_load(YAML.dump(ordinary.class)))
    explicit = Dnsruby::RR::Generic.create(60_507, 1)
    assert_same(explicit, YAML.unsafe_load(YAML.dump(explicit)))
    assert_same(explicit, YAML.unsafe_load(YAML.dump(record(60_507))).class)
  end

  def test_native_autoload_error_is_not_retried_by_the_fallback
    $dnsruby_yaml_autoload_calls = 0
    Dir.mktmpdir('dnsruby-yaml-test') do |directory|
      path = File.join(directory, 'native_class.rb')
      File.write(path, "$dnsruby_yaml_autoload_calls += 1\nraise NameError, 'client autoload failure'\n")
      Dnsruby::RR::Generic.autoload(:Type60509_Class1, path)
      error = assert_raises(NameError) do
        YAML.unsafe_load("--- !ruby/class 'Dnsruby::RR::Generic::Type60509_Class1'\n")
      end
      assert_match(/client autoload failure/, error.message)
      assert_equal(1, $dnsruby_yaml_autoload_calls)
    end
  ensure
    Dnsruby::RR::Generic.send(:remove_const, :Type60509_Class1)
    $dnsruby_yaml_autoload_calls = nil
  end

  def test_live_frozen_class_survives_eviction_and_yaml_loading
    rr = record(60_508).freeze
    klass = rr.class.freeze
    data = YAML.dump(rr)
    (40_000..40_300).each { |type| Dnsruby::RR.get_class(type, 1) }
    refute(Dnsruby::ClassHash.key?([60_508, 1]))
    assert_same(klass, YAML.unsafe_load(data).class)
    assert_equal(rr, YAML.unsafe_load(data))
    assert(rr.frozen?)
    assert(klass.frozen?)
  end
end
