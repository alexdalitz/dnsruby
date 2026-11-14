require_relative 'spec_helper'
require 'minitest/mock'
require 'timeout'

class ReviewCacheTest < Minitest::Test
  def setup
    @now = Time.utc(2026, 11, 14, 12)
    @cache = Dnsruby::Cache.new
  end

  def test_wire_snapshot_is_independent_of_source_and_returned_messages
    response = answer
    response.header.aa = true
    response.security_level = Dnsruby::Message::SecurityLevel.SECURE
    Time.stub(:now, @now) do
      @cache.add(response)
      response.answer.first.address = '192.0.2.2'
      found = @cache.find('cache.example.', 'A')
      assert_equal('192.0.2.1', found.answer.first.address.to_s)
      assert(found.cached)
      refute(found.header.aa)
      assert_equal(Dnsruby::Message::SecurityLevel.UNCHECKED, found.security_level)
      found.answer.first.address = '192.0.2.3'
      found.answer.first.ttl = 0
      again = @cache.find('cache.example.', 'A')
      assert_equal('192.0.2.1', again.answer.first.address.to_s)
      assert_equal(300, again.answer.first.ttl)
    end
  end

  def test_cache_reads_do_not_reencode_messages
    response = answer
    Time.stub(:now, @now) do
      @cache.add(response)
      # The stored form is already wire data. Only the returned copy is decoded.
      encodings = 0
      caller_thread = Thread.current
      trace = TracePoint.new(:call) do |event|
        encodings += 1 if Thread.current == caller_thread &&
          event.defined_class == Dnsruby::Message && event.method_id == :encode
      end
      trace.enable do
        assert_equal('192.0.2.1', @cache.find('cache.example.', 'A').answer.first.address.to_s)
      end
      assert_equal(0, encodings)
    end
  end

  def test_decoding_does_not_hold_the_cache_mutex
    @cache.add(answer)
    data = @cache.cache.values.first
    original = data.method(:message)
    started, resume = Queue.new, Queue.new
    data.define_singleton_method(:message) do
      started << true
      resume.pop
      original.call
    end
    reader = Thread.new { @cache.find('cache.example.', 'A') }
    Timeout.timeout(5) do
      started.pop
      @cache.add(answer('other.example.'))
      refute_nil(@cache.find('other.example.', 'A'))
    end
  ensure
    resume << true if resume
    reader&.join(5)
    reader&.kill if reader&.alive?
  end

  def test_authenticated_deadlines_survive_storage_delay_and_reinsertion
    response = answer
    record = response.answer.first
    record.instance_variable_set(:@dnsruby_authenticated_expiration, @now.to_i + 7)
    clean = Dnsruby::RR.create(record.to_s)
    assert_equal(clean, record)
    assert_equal(clean.hash, record.hash)
    Time.stub(:now, @now + 3) { @cache.add(response) }
    Time.stub(:now, @now + 5) do
      found = @cache.find('cache.example.', 'A')
      assert_equal(2, found.answer.first.ttl)
      assert_equal(@now.to_i + 7,
        found.answer.first.instance_variable_get(:@dnsruby_authenticated_expiration))
      @cache.add(found)
    end
    Time.stub(:now, @now + 7) { assert_nil(@cache.find('cache.example.', 'A')) }
  end

  def test_expiry_during_decode_does_not_remove_a_newer_entry
    clock = @now
    Time.stub(:now, -> { clock }) do
      @cache.add(answer)
      data = @cache.cache.values.first
      original = data.method(:message)
      cache = @cache
      replacement = answer
      data.define_singleton_method(:message) do
        result = original.call
        clock += 300
        cache.add(replacement)
        result
      end
      assert_nil(@cache.find('cache.example.', 'A'))
      assert_equal(300, @cache.find('cache.example.', 'A').answer.first.ttl)
    end
  end

  def test_decoded_response_ttl_runs_from_receipt_even_when_storage_is_delayed
    response = answer
    response.answer.first.ttl = 10
    decoded = Time.stub(:now, @now) { Dnsruby::Message.decode(response.encode) }
    Time.stub(:now, @now + 4) { @cache.add(decoded) }
    Time.stub(:now, @now + 7) do
      assert_equal(3, @cache.find('cache.example.', 'A').answer.first.ttl)
    end
    Time.stub(:now, @now + 10) { assert_nil(@cache.find('cache.example.', 'A')) }
  end

  def test_message_and_record_clones_preserve_absolute_lifetime_bounds
    response = Time.stub(:now, @now) { Dnsruby::Message.decode(answer.encode) }
    response.answer.first.instance_variable_set(:@dnsruby_authenticated_expiration, @now.to_i + 7)
    Time.stub(:now, @now + 3) do
      [response.clone.answer.first, response.answer.first.clone].each do |record|
        assert_equal(@now.to_i, record.instance_variable_get(:@dnsruby_received_at))
        assert_equal(@now.to_i + 7, record.instance_variable_get(:@dnsruby_authenticated_expiration))
      end
      @cache.add(response.clone)
    end
    Time.stub(:now, @now + 7) { assert_nil(@cache.find('cache.example.', 'A')) }
  end

  def test_opt_flags_are_not_aged_as_a_ttl
    response = answer
    opt = Dnsruby::RR::OPT.new(1232, 32768)
    opt.name = '.'
    response.add_additional(opt)
    Time.stub(:now, @now) { @cache.add(response) }
    Time.stub(:now, @now + 5) do
      found = @cache.find('cache.example.', 'A')
      assert_equal(295, found.answer.first.ttl)
      assert_equal(response.get_opt.ttl, found.get_opt.ttl)
    end
  end

  def test_successful_message_decoding_does_not_generate_a_query_id
    response = answer
    response.header.id = 4321
    wire = response.encode
    SecureRandom.stub(:random_number, ->(*) { flunk('Decoding allocated a random query ID') }) do
      decoded = Dnsruby::Message.decode(wire)
      assert_equal(4321, decoded.header.id)
      assert_equal('192.0.2.1', decoded.answer.first.address.to_s)
    end
  end

  private

  def answer(name = 'cache.example.')
    Dnsruby::Message.new(name, 'A').tap do |message|
      message.add_answer(Dnsruby::RR.create("#{name} 300 IN A 192.0.2.1"))
    end
  end
end
