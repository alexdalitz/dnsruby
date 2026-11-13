require_relative 'spec_helper'
require 'stringio'
require 'minitest/mock'

class TestTsigApi < Minitest::Test
  KEY_NAME = 'api-key.example.'
  SECRET = ['a test-only shared secret'].pack('m0')

  def test_default_sha256_and_explicit_algorithms_across_public_apis
    configurations = [Dnsruby::Resolver.new(nameserver: '127.0.0.1'),
      Dnsruby::SingleResolver.new(server: '127.0.0.1'),
      Dnsruby::PacketSender.new(server: '127.0.0.1'), Dnsruby::ZoneTransfer.new]
    configurations.each do |configuration|
      [nil, 'hmac-sha256', 'hmac-md5'].each do |algorithm|
        configuration.tsig = algorithm ? [KEY_NAME, SECRET, algorithm] : [KEY_NAME, SECRET]
        key = Dnsruby::Resolver.get_tsig([configuration.tsig])
        if configuration.is_a?(Dnsruby::ZoneTransfer)
          wire = transfer_query(configuration, Time.now.to_i).encode
        else
          sender = configuration.is_a?(Dnsruby::Resolver) ? configuration.single_resolvers.first : configuration
          wire = sender.make_query_packet(Dnsruby::Message.new('example.'))
        end
        assert_signed_exchange(wire, key, algorithm)
      end
    end
    [nil, 'hmac-sha256', 'hmac-md5'].each do |algorithm|
      message = Dnsruby::Message.new('example.')
      if algorithm
        message.set_tsig(name: KEY_NAME, key: SECRET, algorithm: algorithm)
      else
        message.set_tsig(KEY_NAME, SECRET)
      end
      wire = message.encode
      assert_signed_exchange(wire, message.tsig, algorithm)
    end
  ensure
    configurations&.each { |configuration| configuration.close if configuration.respond_to?(:close) }
  end

  def test_explicit_algorithms_keep_the_existing_configuration_forms
    %w[hmac-md5 hmac-sha1 hmac-sha256 hmac-sha512].each do |algorithm|
      args = [KEY_NAME, SECRET, algorithm]
      direct = Dnsruby::Resolver.get_tsig(args)
      nested = Dnsruby::Resolver.get_tsig([args])
      assert_equal(direct.algorithm, nested.algorithm)
      assert_same(direct, Dnsruby::Resolver.get_tsig([direct]))
      message = Dnsruby::Message.new('example.')
      message.set_tsig(name: KEY_NAME, key: SECRET, algorithm: algorithm)
      assert_equal(direct.algorithm, Dnsruby::Message.decode(message.encode).tsig.algorithm)
    end
    assert_nil(Dnsruby::Resolver.get_tsig([nil]))
  end

  def test_explicit_md5_constructor_options_sign_and_verify
    configurations = []
    ['hmac-md5', 'HMAC-MD5.SIG-ALG.REG.INT.', Dnsruby::RR::TSIG::HMAC_MD5].each do |algorithm|
      args = [KEY_NAME, SECRET, algorithm]
      configurations = [Dnsruby::Resolver.new(nameserver: '127.0.0.1', tsig: args),
        Dnsruby::SingleResolver.new(server: '127.0.0.1', tsig: args),
        Dnsruby::PacketSender.new(server: '127.0.0.1', tsig: args)]
      configurations.each do |configuration|
        key = Dnsruby::Resolver.get_tsig([configuration.tsig])
        sender = configuration.is_a?(Dnsruby::Resolver) ? configuration.single_resolvers.first : configuration
        wire = sender.make_query_packet(Dnsruby::Message.new('example.'))
        assert_signed_exchange(wire, key, 'hmac-md5')
      end
      configurations.each(&:close)
    end
  ensure
    configurations&.each(&:close)
  end

  def test_invalid_tsig_configuration_fails_before_sending
    algorithms = ['unsupported-tsig-algorithm', Dnsruby::Name.create('unsupported-tsig-algorithm.')]
    configurations = [Dnsruby::Resolver.new(nameserver: '127.0.0.1'),
      Dnsruby::SingleResolver.new(server: '127.0.0.1'),
      Dnsruby::PacketSender.new(server: '127.0.0.1'), Dnsruby::ZoneTransfer.new]
    algorithms.each do |algorithm|
      args = [KEY_NAME, SECRET, algorithm]
      [args, [args]].each do |form|
        assert_configuration_error { Dnsruby::Resolver.get_tsig(form) }
      end
      configurations.each do |configuration|
        assert_configuration_error { configuration.tsig = args }
        assert_nil(configuration.tsig)
      end
      assert_configuration_error do
        Dnsruby::Message.new('example.').set_tsig(name: KEY_NAME, key: SECRET, algorithm: algorithm)
      end
      assert_configuration_error do
        Dnsruby::Resolver.new(nameserver: '127.0.0.1', tsig: args)
      end
      [Dnsruby::SingleResolver, Dnsruby::PacketSender].each do |klass|
        assert_configuration_error { klass.new(server: '127.0.0.1', tsig: args) }
      end
    end
  ensure
    configurations&.each { |configuration| configuration.close if configuration.respond_to?(:close) }
  end

  def test_key_configuration_does_not_log_the_secret
    output = StringIO.new
    Dnsruby.stub(:log, Logger.new(output)) do
      Dnsruby::Resolver.get_tsig([[KEY_NAME, SECRET]])
    end
    assert_includes(output.string, KEY_NAME.delete_suffix('.'))
    refute_includes(output.string, SECRET)
  end

  def test_md5_warning_is_once_per_process_and_never_logs_the_key
    klass = Dnsruby::RR::TSIG
    mutex = klass.const_get(:LEGACY_WARNING_MUTEX)
    previous = mutex.synchronize do
      old = klass.instance_variable_get(:@legacy_warning_issued)
      klass.instance_variable_set(:@legacy_warning_issued, false)
      old
    end
    output = StringIO.new
    logger = Logger.new(output)
    logger.level = Logger::WARN
    Dnsruby.stub(:log, logger) do
      Dnsruby::Resolver.get_tsig([[KEY_NAME, SECRET]])
      assert_empty(output.string)
      threads = Array.new(8) do
        Thread.new { Dnsruby::Resolver.get_tsig([[KEY_NAME, SECRET, 'hmac-md5']]) }
      end
      keys = threads.map(&:value)
      3.times do
        query = Dnsruby::Message.new('example.')
        keys.first.apply(query)
      end
    end
    assert_equal(1, output.string.lines.size)
    assert_match(/WARN.*HMAC-MD5/, output.string)
    assert_match(/RFC 8945.*MUST NOT/, output.string)
    assert_match(/hmac-sha256.*DNS server and client/, output.string)
    refute_includes(output.string, SECRET)
    refute_includes(output.string, KEY_NAME)
  ensure
    mutex&.synchronize { klass.instance_variable_set(:@legacy_warning_issued, previous) }
  end

  def test_tsig_is_rejected_outside_the_final_additional_position
    [:answer, :authority, :additional].each do |section|
      message = Dnsruby::Message.new('example.')
      signature = unsigned_tsig
      message.public_send("add_#{section}", signature)
      message.add_additional(Dnsruby::RR.create('example. 0 IN A 192.0.2.1'))
      error = assert_raises(Dnsruby::DecodeError) { Dnsruby::Message.decode(message.encode) }
      assert_instance_of(Dnsruby::Message, error.partial_message)
    end
    message = Dnsruby::Message.new('example.')
    message.add_additional(unsigned_tsig)
    other = unsigned_tsig
    other.name = 'another-key.example.'
    message.add_additional(other)
    assert_raises(Dnsruby::DecodeError) { Dnsruby::Message.decode(message.encode) }
  end

  def test_tsig_class_and_ttl_are_checked_before_record_dispatch
    [[Dnsruby::Classes::IN, 0], [Dnsruby::Classes::ANY, 60]].each do |klass, ttl|
      signature = unsigned_tsig
      message = Dnsruby::Message.new('example.')
      message.add_additional(signature)
      wire = message.encode
      decoded = Dnsruby::Message.decode(wire)
      fields = wire.index([Dnsruby::Types::TSIG, Dnsruby::Classes::ANY, 0].pack('nnN'), decoded.tsigstart)
      refute_nil(fields)
      wire[fields + 2, 6] = [klass, ttl].pack('nN')
      assert_raises(Dnsruby::DecodeError) { Dnsruby::Message.decode(wire) }
    end
  end

  def test_reused_zone_transfer_gets_a_fresh_timestamp_and_keeps_key_changes
    transfer = Dnsruby::ZoneTransfer.new
    transfer.tsig = KEY_NAME, SECRET
    first = transfer_query(transfer, 10_000)
    transfer.tsig.fudge = 600
    transfer.tsig.mac_length = 16
    second = transfer_query(transfer, 20_000)
    assert_equal(10_000, first.tsig.time_signed)
    assert_equal(20_000, second.tsig.time_signed)
    assert_equal(600, second.tsig.fudge)
    assert_equal(16, second.tsig.mac_size)
    assert_equal(second.tsig.mac, transfer.tsig.mac)
  end

  def test_zone_transfer_respects_explicit_times_and_can_return_to_current_time
    transfer = Dnsruby::ZoneTransfer.new
    transfer.tsig = KEY_NAME, SECRET
    transfer.tsig.time_signed = 1234
    assert_equal(1234, transfer_query(transfer, 10_000).tsig.time_signed)
    assert_equal(1234, transfer_query(transfer, 20_000).tsig.time_signed)
    transfer.tsig.time_signed = 2345
    assert_equal(2345, transfer_query(transfer, 30_000).tsig.time_signed)
    transfer.tsig.time_signed = nil
    assert_equal(40_000, transfer_query(transfer, 40_000).tsig.time_signed)
    assert_equal(50_000, transfer_query(transfer, 50_000).tsig.time_signed)
  end

  private

  def assert_configuration_error
    error = assert_raises(ArgumentError) { yield }
    assert_match(/Invalid TSIG algorithm/, error.message)
    refute_includes(error.message, SECRET)
  end

  def assert_signed_exchange(wire, client_key, algorithm)
    md5 = algorithm == 'hmac-md5'
    expected = md5 ? Dnsruby::RR::TSIG::HMAC_MD5 : Dnsruby::RR::TSIG::HMAC_SHA256
    query = Dnsruby::Message.decode(wire)
    signature = query.tsig
    assert_equal(expected, client_key.algorithm)
    assert_equal(expected, signature.algorithm)
    assert_equal(md5 ? 16 : 32, signature.mac_size)
    unsigned = wire.byteslice(0, query.tsigstart).dup
    unsigned[10, 2] = [query.header.arcount - 1].pack('n')
    name_wire = ->(name) { name.to_s.downcase.sub(/\.$/, '').split('.').map { |label| [label.bytesize].pack('C') + label }.join.b + "\0".b }
    variables = name_wire.call(signature.name) + [255, 0].pack('nN') + name_wire.call(signature.algorithm) +
      [signature.time_signed >> 32, signature.time_signed & 0xffff_ffff, signature.fudge,
        signature.error, signature.other_size].pack('nNn3') + signature.other_data
    assert_equal(OpenSSL::HMAC.digest(md5 ? 'MD5' : 'SHA256', SECRET.unpack1('m0'), unsigned + variables), signature.mac)
    server_key = Dnsruby::RR.create(name: KEY_NAME, type: 'TSIG', klass: 'ANY', key: SECRET,
      algorithm: algorithm || 'hmac-sha256')
    reply = Dnsruby::Message.new('example.')
    reply.header.qr = true
    server_key.apply(reply, query)
    response_wire = reply.encode
    decoded = Dnsruby::Message.decode(response_wire)
    assert_equal(true, client_key.verify(query, decoded, response_wire))
    assert(decoded.verified?)
  end

  def transfer_query(transfer, clock)
    writes = []
    socket = Object.new
    socket.define_singleton_method(:send) { |bytes, _flags| writes << bytes; bytes.bytesize }
    Time.stub(:now, Time.at(clock)) do
      transfer.send_message(socket, Dnsruby::Message.new('example.', Dnsruby::Types::AXFR))
    end
    assert_equal(writes.last.bytesize, writes.first.unpack1('n'))
    Dnsruby::Message.decode(writes.last)
  end

  def unsigned_tsig
    Dnsruby::RR.create(name: KEY_NAME, type: 'TSIG', klass: 'ANY',
      time_signed: Time.now.to_i, error: Dnsruby::RCode::BADKEY)
  end
end
