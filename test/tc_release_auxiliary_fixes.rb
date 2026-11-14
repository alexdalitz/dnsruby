require_relative 'spec_helper'
require 'minitest/mock'
require 'timeout'

class ReleaseAuxiliaryFixesTest < Minitest::Test
  def test_controlled_queue_wakes_for_each_producer_alias_and_preserves_nil
    [:push, :<<, :enq].each do |method|
      queue = Dnsruby::QueryControl::Queue.new
      control = Dnsruby::QueryControl.new
      started = Queue.new
      waiter = Thread.new { started << true; control.pop(queue) }
      started.pop
      queue.public_send(method, nil)
      assert_nil(Timeout.timeout(2) { waiter.value })
    ensure
      waiter&.kill
      waiter&.join
    end
  end

  def test_parent_cancellation_wakes_an_event_queue_without_consuming_a_result
    queue = Dnsruby::QueryControl::Queue.new
    parent = Dnsruby::QueryControl.new
    child = Dnsruby::QueryControl.new(parent: parent)
    ready = Queue.new
    original_pop = queue.method(:pop)
    queue.define_singleton_method(:pop) do |*args|
      ready << true
      original_pop.call(*args)
    end
    waiter = Thread.new do
      child.pop(queue)
    rescue Dnsruby::QueryControl::Cancelled => error
      error
    end
    ready.pop
    parent.cancel
    assert_instance_of(Dnsruby::QueryControl::Cancelled, Timeout.timeout(2) { waiter.value })
    queue << :later
    assert_equal(:later, queue.pop)
  ensure
    waiter&.kill
    waiter&.join
  end

  def test_event_queue_obeys_deadlines_and_closed_queues
    queue = Dnsruby::QueryControl::Queue.new
    control = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + 0.01)
    assert_raises(Dnsruby::QueryControl::DeadlineExceeded) do
      Timeout.timeout(2) { control.pop(queue) }
    end
    queue.close
    assert_nil(Dnsruby::QueryControl.new.pop(queue))
  end

  def test_compression_table_stops_recording_unrepresentable_offsets
    name = Dnsruby::Name.create('late.example.')
    encoder = Dnsruby::MessageEncoder.new
    # Exercise the offset decision directly, without constructing an oversized
    # or malformed DNS packet.
    encoder.to_s.stub(:bytesize, 0x4000) { encoder.put_name(name) }
    literal = encoder.to_s.dup
    encoder.to_s.stub(:bytesize, 0x4000) { encoder.put_name(name) }
    assert_equal(literal + literal, encoder.to_s)
  end

  def test_late_names_can_still_compress_to_an_early_suffix
    encoder = Dnsruby::MessageEncoder.new
    encoder.put_name(Dnsruby::Name.create('example.'))
    offset = encoder.to_s.bytesize
    encoder.to_s.stub(:bytesize, 0x4000) do
      encoder.put_name(Dnsruby::Name.create('late.example.'))
    end
    assert_equal("\x04late\xc0\x00".b, encoder.to_s.byteslice(offset..-1))
  end

  def test_zone_transfer_reuse_returns_current_ixfr_deltas_after_axfr
    soa1 = Dnsruby::RR.create('example. 300 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60')
    soa2 = Dnsruby::RR.create('example. 300 IN SOA ns.example. hostmaster.example. 2 60 60 3600 60')
    old_address = Dnsruby::RR.create('www.example. 300 IN A 192.0.2.1')
    new_address = Dnsruby::RR.create('www.example. 300 IN A 192.0.2.2')
    responses = [Dnsruby::Message.new('example.', 'AXFR'), Dnsruby::Message.new('example.', 'IXFR')]
    [soa1, old_address, soa1].each { |rr| responses[0].add_answer!(rr) }
    [soa2, soa1, old_address, soa2, new_address, soa2].each { |rr| responses[1].add_answer!(rr) }
    transfer = Dnsruby::ZoneTransfer.new
    transfer.define_singleton_method(:send_message) { |*| }
    transfer.define_singleton_method(:receive_message) { |*| responses.shift }
    socket = Object.new
    socket.define_singleton_method(:close) { }
    Socket.stub(:tcp, socket) do
      assert_equal([soa1, old_address], transfer.do_transfer('example.', '192.0.2.53'))
      transfer.transfer_type = Dnsruby::Types::IXFR
      transfer.serial = 1
      deltas = transfer.do_transfer('example.', '192.0.2.53')
      assert_equal(1, deltas.length)
      assert_instance_of(Dnsruby::ZoneTransfer::Delta, deltas.first)
      assert_equal([1, 2], [deltas.first.start, deltas.first.end])
      assert_includes(deltas.first.adds, new_address)
      assert_includes(deltas.first.deletes, old_address)
    end
  end

  def test_tsig_stream_copies_own_their_accumulation_buffer
    signer = Dnsruby::RR.create(name: 'key.example.', type: 'TSIG', klass: 'ANY',
      key: ['secret'].pack('m0'))
    query = Dnsruby::Message.new('example.', 'A')
    signer.apply(query)
    reply = Dnsruby::Message.new('example.', 'A')
    reply.header.qr = true
    signer.dup.apply(reply, query)
    wire = reply.encode.freeze
    assert(signer.verify_envelope(Dnsruby::Message.decode(wire), wire))
    copied_signer = signer.dup
    prior = signer.instance_variable_get(:@buf).dup
    intermediate = Dnsruby::Message.new('example.', 'A').encode.freeze
    assert(copied_signer.verify_envelope(Dnsruby::Message.decode(intermediate), intermediate))
    assert_equal(prior, signer.instance_variable_get(:@buf))
    assert_equal(prior + intermediate, copied_signer.instance_variable_get(:@buf))
  end

  def test_missing_nameserver_addresses_preserve_policy_and_release_cache_mutex
    recursor_class = Dnsruby::Recursor
    mutex = recursor_class.class_variable_get(:@@mutex)
    original_hints = recursor_class.class_variable_get(:@@hints)
    original_cache = recursor_class.class_variable_get(:@@authority_cache)
    recursor_class.class_variable_set(:@@hints, {})
    recursor_class.class_variable_set(:@@authority_cache, {})
    recursor = recursor_class.allocate
    recursor.ipv6_ok = true
    original_recursion = recursor.method(:_dorecursion)
    calls = Queue.new
    recursor.define_singleton_method(:_dorecursion) do |name, type, klass, zone, authorities, depth, no_validation|
      if name == 'www.example.'
        calls << [:retry, no_validation, authorities.fetch('ns.example.').values.map(&:downcase).sort]
        :finished
      else
        mutex.synchronize do
          calls << [type, no_validation, Dnsruby::QueryControl.current.deadline]
        end
        answer = Dnsruby::Message.new(name, type, klass)
        address = type == 'AAAA' ? '2001:db8::53' : '192.0.2.53'
        answer.add_answer(Dnsruby::RR.create("#{name} 300 IN #{type} #{address}"))
        answer
      end
    end
    authorities = {'ns.example.' => recursor_class::AddressCache.new}
    parent = Dnsruby::QueryControl.new(deadline: Dnsruby::TransportClock.now + 2)
    result = Dnsruby::QueryControl.with(parent) do
      Timeout.timeout(3) do
        original_recursion.call('www.example.', 'A', Dnsruby::Classes::IN, 'example.', authorities, 0, true)
      end
    end
    assert_equal(:finished, result)
    events = 3.times.map { calls.pop }
    assert_equal(%w[A AAAA], events.take(2).map(&:first).sort)
    events.take(2).each do |event|
      assert_equal(true, event[1])
      assert_equal(parent.deadline, event[2])
    end
    assert_equal([:retry, true, ['192.0.2.53', '2001:db8::53']], events.last)
  ensure
    recursor_class.class_variable_set(:@@hints, original_hints) if recursor_class
    recursor_class.class_variable_set(:@@authority_cache, original_cache) if recursor_class
  end

  def test_ds_queries_use_cached_parent_authorities_and_preserve_the_question
    with_cached_recursor_authorities do |recursor, zones|
      ['child.example', 'child.example.', Dnsruby::Name.create('child.example'),
        Dnsruby::Name.create('child.example.')].each do |name|
        ['DS', 43, Dnsruby::Types.new('DS')].each do |type|
          args = recursor.query(name, type, Dnsruby::Classes::IN, true)
          assert_same(name, args[0])
          assert_same(type, args[1])
          assert_equal('example.', args[3])
          assert_same(zones.fetch('example.'), args[4])
        end
      end
    end
  end

  def test_ds_queries_for_top_level_names_and_root_use_root_authorities
    with_cached_recursor_authorities do |recursor, zones|
      ['example', 'example.', '.', Dnsruby::Name.create('.')].each do |name|
        args = recursor.query(name, 'DS', Dnsruby::Classes::IN, true)
        assert_same(name, args[0])
        assert_equal('.', args[3])
        assert_same(zones.fetch('.'), args[4])
      end
    end
  end

  def test_other_record_types_still_use_cached_child_authorities
    with_cached_recursor_authorities do |recursor, zones|
      ['DNSKEY', 'A', Dnsruby::Types.new('NS')].each do |type|
        args = recursor.query('child.example.', type, Dnsruby::Classes::IN, true)
        assert_equal('child.example.', args[3])
        assert_same(zones.fetch('child.example.'), args[4])
      end
    end
  end

  def test_recursion_requests_dnssec_data_whenever_it_will_validate
    recursor_class = Dnsruby::Recursor
    original_cache = recursor_class.class_variable_get(:@@authority_cache)
    recursor_class.class_variable_set(:@@authority_cache, {})
    addresses = recursor_class::AddressCache.new
    addresses.push(['192.0.2.53', 300])
    authorities = {'ns.example.' => addresses}
    transport = Dnsruby::Resolver.new(nameserver: ['192.0.2.53'])
    recursor = recursor_class.new(transport)
    wire = nil
    validates = nil
    transport.define_singleton_method(:send_message) do |query|
      validates = query.do_validation
      wire = single_resolvers.first.make_query_packet(query)
      response = Dnsruby::Message.new('child.example.', 'DNSKEY')
      response.header.aa = true
      response
    end
    Dnsruby::Resolver.stub(:new, transport) do
      [nil, false, true].product([false, true]).each do |dnssec, no_validation|
        recursor.dnssec = dnssec
        recursor._dorecursion('child.example.', 'DNSKEY', Dnsruby::Classes::IN,
          'child.example.', authorities, 0, no_validation)
        query = Dnsruby::Message.decode(wire)
        assert_equal(!!dnssec || !no_validation, query.get_opt.dnssec_ok,
          "dnssec=#{dnssec.inspect}, no_validation=#{no_validation}")
        assert_equal(!no_validation, validates)
      end
    end
  ensure
    transport&.close
    recursor_class.class_variable_set(:@@authority_cache, original_cache) if recursor_class
  end

  private

  def with_cached_recursor_authorities
    recursor_class = Dnsruby::Recursor
    original_hints = recursor_class.class_variable_get(:@@hints)
    original_zones = recursor_class.class_variable_get(:@@zones_cache)
    zones = ['.', 'example.', 'child.example.'].to_h do |zone|
      [zone, { "ns.#{zone}" => recursor_class::AddressCache.new }]
    end
    recursor_class.class_variable_set(:@@hints, zones.fetch('.'))
    recursor_class.class_variable_set(:@@zones_cache, zones)
    recursor = recursor_class.allocate
    recursor.instance_variable_set(:@resolver, Struct.new(:recurse).new)
    recursor.define_singleton_method(:_dorecursion) { |*args| args }
    yield recursor, zones
  ensure
    recursor_class.class_variable_set(:@@hints, original_hints) if recursor_class
    recursor_class.class_variable_set(:@@zones_cache, original_zones) if recursor_class
  end
end
