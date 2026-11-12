require_relative 'spec_helper'
require 'minitest/mock'
require 'tempfile'

class TestNameserverBootstrap < Minitest::Test
  def with_resolv_conf(contents)
    Tempfile.create('dnsruby-nameserver-bootstrap') do |file|
      file.write(contents)
      file.flush
      yield file.path
    end
  end

  def answer_for(hostname, address = nil)
    message = Dnsruby::Message.new(hostname)
    if address
      type = address.include?(':') ? 'AAAA' : 'A'
      message.add_answer(Dnsruby::RR.create("#{hostname} 60 IN #{type} #{address}"))
    end
    message
  end

  # Exercise real Resolver and PacketSender initialization, replacing only DNS
  # queries. Bound configuration reads and construction so a regression cannot
  # recreate issue #179's unbounded chain of resolver threads. Worker threads
  # record their observations through queues instead of performing assertions.
  def with_lookup(defaults, response, recursive_response: nil, lookup_error: nil)
    original_new = Dnsruby::Resolver.method(:new)
    state = { queries: Queue.new, recursors: Queue.new, closed: Queue.new,
              resolvers: Queue.new, counts: Hash.new(0) }
    mutex = Mutex.new
    count = lambda do |kind|
      mutex.synchronize do
        state[:counts][kind] += 1
        raise 'Nameserver bootstrap reentered too many times' if state[:counts][kind] > 12
      end
    end
    default_config = lambda do
      count.call(:config_reads)
      config = defaults.respond_to?(:call) ? defaults.call : defaults
      config.merge(nameserver: Array(config[:nameserver]).dup)
    end
    factory = lambda do |*args|
      count.call(:resolver_constructions)
      resolver = original_new.call(*args)
      state[:resolvers] << resolver
      original_close = resolver.method(:close)
      resolver.define_singleton_method(:close) do
        state[:closed] << self
        original_close.call
      end
      resolver.define_singleton_method(:query) do |hostname, *|
        servers = single_resolvers.map(&:server)
        state[:queries] << [self, hostname.to_s, servers]
        raise lookup_error if lookup_error
        response
      end
      resolver
    end
    recursive_factory = lambda do |*args|
      state[:recursors] << args
      recursor = Object.new
      recursor.define_singleton_method(:query) do |hostname, *|
        recursive_response || Dnsruby::Message.new(hostname)
      end
      recursor
    end
    Dnsruby::Config.stub(:default_config_hash, default_config) do
      Dnsruby::Resolver.stub(:new, factory) do
        Dnsruby::Recursor.stub(:new, recursive_factory) do
          yield state, original_new
        end
      end
    end
  ensure
    unless state.nil?
      state[:resolvers].pop(true).close until state[:resolvers].empty?
    end
  end

  def test_resolv_conf_preserves_hostnames_literals_and_token_order
    servers = %w[ns.example.test 192.0.2.1 localhost 2001:db8::1 fe80::1%en0 ns.example.test]
    contents = "nameserver #{servers.first(3).join(' ')} # comment\n" \
               "nameserver #{servers.drop(3).join(' ')} ; comment\n"
    with_resolv_conf(contents) do |path|
      assert_equal(servers, Dnsruby::Config.parse_resolv_conf(path)[:nameserver])
    end
  end

  def test_overlong_nameserver_from_file_does_not_hide_a_valid_server_or_override
    previous_limit = Dnsruby::Name::Label.class_variable_get(:@@max_length)
    Dnsruby::Name::Label.set_max_length(Dnsruby::Name::Label::MaxLabelLength)
    invalid = ('a' * 64) + '.example.'
    with_resolv_conf("nameserver #{invalid}\nnameserver 127.0.0.1\n") do |path|
      defaults = Dnsruby::Config.parse_resolv_conf(path)
      Dnsruby::Config.stub(:default_config_hash, defaults) do
        config = Dnsruby::Config.new
        config.get_ready
        assert_equal(['127.0.0.1'], config.nameserver)
        resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.2')
        assert_equal(['127.0.0.2'], resolver.config.nameserver)
        assert_equal(['127.0.0.2'], resolver.single_resolvers.map(&:server))
        assert_raises(Dnsruby::ResolvError) do
          Dnsruby::Config.new.set_config_info(nameserver: [invalid])
        end
      end
    end
  ensure
    Dnsruby::Name::Label.set_max_length(previous_limit)
  end

  def test_failed_nameserver_replacement_preserves_config_and_active_senders
    resolver = Dnsruby::Resolver.new(nameserver: '127.0.0.1')
    original = resolver.single_resolvers.first
    assert_raises(ArgumentError) { resolver.nameserver = [] }
    assert_equal(['127.0.0.1'], resolver.config.nameserver)
    assert_equal([original], resolver.single_resolvers)
    resolver.nameserver = '127.0.0.2'
    assert_equal(['127.0.0.2'], resolver.config.nameserver)
    assert_equal(['127.0.0.2'], resolver.single_resolvers.map(&:server))
  end

  def test_invalid_default_nameserver_fails_without_recursive_initialization
    with_resolv_conf("nameserver 8.8.8.8,\n") do |path|
      defaults = -> { Dnsruby::Config.parse_resolv_conf(path) }
      with_lookup(defaults, answer_for('unused.example.test')) do |state, original_new|
        resolver = original_new.call
        error = assert_raises(ArgumentError) { resolver.add_config_nameservers }
        assert_equal('No valid nameservers found', error.message)
        assert_equal(['8.8.8.8,'], resolver.config.nameserver)
        assert_operator(state[:counts][:config_reads], :<=, 3)
        assert_equal(0, state[:counts][:resolver_constructions])
        assert(state[:queries].empty?)
        assert(state[:recursors].empty?)
      ensure
        resolver.close if resolver
      end
    end
  end

  def test_scoped_looking_dns_names_do_not_hide_valid_fallbacks
    contents = "nameserver fe80::1%\nnameserver fe80::gggg%en0\n" \
               "nameserver 192.0.2.1\nnameserver fe80::1%3\n"
    with_resolv_conf(contents) do |path|
      defaults = -> { Dnsruby::Config.parse_resolv_conf(path) }
      [nil, {config_info: path}, {config_info: {search: ['example.test']}}].each do |options|
        with_lookup(defaults, nil) do |state, original_new|
          resolver = options ? original_new.call(options) : original_new.call
          resolver.add_config_nameservers unless options
          assert_equal(['fe80::1%', 'fe80::gggg%en0', '192.0.2.1', 'fe80::1%3'], resolver.config.nameserver)
          assert_equal(['192.0.2.1', 'fe80::1%3'], resolver.single_resolvers.map(&:server))
          queried = []
          queried << state[:queries].pop(true)[1] until state[:queries].empty?
          # PacketSender also retries with nil after a failed server setter.
          assert_equal(['', '', 'fe80::1%', 'fe80::gggg%en0'].sort, queried.sort)
          assert_equal(4, state[:counts][:resolver_constructions])
        ensure
          resolver.close if resolver
        end
      end
    end
  end

  def test_invalid_scoped_defaults_do_not_block_explicit_nameserver
    with_resolv_conf("nameserver fe80::1%\n") do |path|
      defaults = -> { Dnsruby::Config.parse_resolv_conf(path) }
      with_lookup(defaults, nil) do |state, original_new|
        ['192.0.2.53', {nameserver: '2001:db8::53'}].each do |options|
          resolver = original_new.call(options)
          expected = options.is_a?(Hash) ? options[:nameserver] : options
          assert_equal([expected], resolver.single_resolvers.map(&:server))
        ensure
          resolver.close if resolver
        end
        resolver = original_new.call
        assert_raises(ArgumentError) { resolver.add_config_nameservers }
        assert_equal(['fe80::1%'], resolver.config.nameserver)
        assert(state[:queries].empty?)
        assert_equal(0, state[:counts][:resolver_constructions])
      ensure
        resolver.close if resolver
      end
    end
  end

  def test_explicit_config_hash_preserves_scoped_looking_dns_names
    config = Dnsruby::Config.new
    servers = ['fe80::1%', '192.0.2.1']
    config.set_config_info(nameserver: servers)
    assert_equal(servers, config.nameserver)
    assert_raises(ArgumentError) { Dnsruby::Config.ipv6_server_address(servers.first) }
  end

  def test_default_file_hostname_uses_literal_nameserver_without_changing_config
    hostname = 'ns.example.test'
    with_resolv_conf("nameserver #{hostname}\nnameserver 192.0.2.1\n") do |path|
      defaults = -> { Dnsruby::Config.parse_resolv_conf(path) }
      with_lookup(defaults, answer_for(hostname, '192.0.2.53')) do |state, original_new|
        resolver = original_new.call
        resolver.add_config_nameservers
        assert_equal([hostname, '192.0.2.1'], resolver.config.nameserver)
        assert_equal(['192.0.2.53', '192.0.2.1'], resolver.single_resolvers.map(&:server))
        lookup = state[:queries].pop(true)
        assert_equal(hostname, lookup[1])
        assert_equal(['192.0.2.1'], lookup[2])
        assert_same(lookup[0], state[:closed].pop(true))
        assert(state[:queries].empty?)
        assert_equal(1, state[:counts][:resolver_constructions])
      ensure
        resolver.close if resolver
      end
    end
  end

  def test_custom_file_hostname_uses_system_nameserver
    hostname = 'custom-ns.example.test'
    with_resolv_conf("nameserver #{hostname}\n") do |path|
      with_lookup({nameserver: ['192.0.2.1']}, answer_for(hostname, '192.0.2.53')) do |state, original_new|
        resolver = original_new.call(config_info: path)
        assert_equal([hostname], resolver.config.nameserver)
        assert_equal(['192.0.2.53'], resolver.single_resolvers.map(&:server))
        assert_equal([hostname, ['192.0.2.1']], state[:queries].pop(true).drop(1))
        assert(state[:queries].empty?)
      ensure
        resolver.close if resolver
      end
    end
  end

  def test_localhost_file_nameserver_does_not_require_dns
    with_resolv_conf("nameserver localhost\n") do |path|
      with_lookup(-> { Dnsruby::Config.parse_resolv_conf(path) }, nil) do |state, original_new|
        resolver = original_new.call(config_info: path)
        assert_equal(['localhost'], resolver.config.nameserver)
        assert_equal(['127.0.0.1'], resolver.single_resolvers.map(&:server))
        assert(state[:queries].empty?)
        assert_equal(0, state[:counts][:resolver_constructions])
      ensure
        resolver.close if resolver
      end
    end
  end

  def test_explicit_hostname_and_name_object_remain_supported
    hostname = 'explicit-ns.example.test'
    with_lookup({nameserver: ['192.0.2.1']}, answer_for(hostname, '192.0.2.53')) do |state, original_new|
      resolver = original_new.call(nameserver: hostname)
      assert_equal(['192.0.2.53'], resolver.single_resolvers.map(&:server))
      assert_equal('192.0.2.53', Dnsruby::Config.resolve_server(Dnsruby::Name.create(hostname)))
      2.times do
        assert_equal([hostname, ['192.0.2.1']], state[:queries].pop(true).drop(1))
      end
      assert(state[:queries].empty?)
    ensure
      resolver.close if resolver
    end
  end

  def test_bootstrap_keeps_ipv6_scopes_and_localhost_but_excludes_hostnames
    hostname = 'ns.example.test'
    servers = [hostname, '192.0.2.1', '2001:db8::1', 'fe80::1%en0',
               'fe80::1%3', 'localhost', '8.8.8.8,', 'fe80::1%']
    with_lookup({nameserver: servers}, answer_for(hostname, '192.0.2.53')) do |state, _|
      assert_equal('192.0.2.53', Dnsruby::Config.resolve_server(hostname))
      assert_equal(['192.0.2.1', '2001:db8::1', 'fe80::1%en0', 'fe80::1%3', '127.0.0.1'],
                   state[:queries].pop(true)[2])
      assert_equal([hostname, '192.0.2.1', '2001:db8::1', 'fe80::1%en0',
                    'fe80::1%3', 'localhost', '8.8.8.8,', 'fe80::1%'], servers)
      assert(state[:queries].empty?)
    end
  end

  def test_all_hostname_defaults_fail_before_creating_helper_resolver
    hostname = 'ns.example.test'
    with_lookup({nameserver: [hostname, 'other-ns.example.test']}, nil) do |state, _|
      error = assert_raises(ArgumentError) { Dnsruby::Config.resolve_server(hostname) }
      assert_match(/No nameserver addresses available/, error.message)
      assert_equal(1, state[:counts][:config_reads])
      assert_equal(0, state[:counts][:resolver_constructions])
      assert(state[:queries].empty?)
      assert(state[:recursors].empty?)
    end
  end

  def test_recursive_fallback_accepts_addresses_and_reuses_safe_resolver
    hostname = 'ns.example.test'
    { '192.0.2.53' => '192.0.2.53', '2001:db8::53' => '2001:DB8::53' }.each do |address, expected|
      with_lookup({nameserver: [hostname, '192.0.2.1']}, answer_for(hostname),
                  recursive_response: answer_for(hostname, address)) do |state, _|
        assert_equal(expected, Dnsruby::Config.resolve_server(hostname))
        lookup = state[:queries].pop(true)
        assert_equal(['192.0.2.1'], lookup[2])
        assert_equal([lookup[0]], state[:recursors].pop(true))
        assert_same(lookup[0], state[:closed].pop(true))
        assert_equal(1, state[:counts][:resolver_constructions])
        assert(state[:queries].empty?)
        assert(state[:recursors].empty?)
      end
    end
  end

  def test_recursive_fallback_after_query_error_and_without_address
    hostname = 'ns.example.test'
    [answer_for(hostname, '192.0.2.53'), answer_for(hostname)].each do |response|
      with_lookup({nameserver: [hostname, '192.0.2.1']}, nil,
                  lookup_error: Dnsruby::ResolvTimeout.new('simulated timeout'),
                  recursive_response: response) do |state, _|
        if response.answer.empty?
          error = assert_raises(ArgumentError) { Dnsruby::Config.resolve_server(hostname) }
          assert_match(/Recursor can't locate/, error.message)
        else
          assert_equal('192.0.2.53', Dnsruby::Config.resolve_server(hostname))
        end
        lookup = state[:queries].pop(true)
        assert_equal(['192.0.2.1'], lookup[2])
        assert_equal([lookup[0]], state[:recursors].pop(true))
        assert_same(lookup[0], state[:closed].pop(true))
        assert_equal(1, state[:counts][:resolver_constructions])
      end
    end
  end
end
