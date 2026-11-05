require_relative 'spec_helper'
require 'minitest/mock'

class TestScopedIPv6Select < Minitest::Test
  def test_scoped_response_with_interface_punctuation_is_delivered
    with_registered_query('fe80::1%7') do |selector, socket, _client_id, message|
      message.answerip = 'fe80::1%eth-test.100'
      message.answerfrom = message.answerip
      bytes = 'response bytes'
      delivered = []

      selector.stub(:send_response_to_client, ->(*args) { delivered << args }) do
        selector.process_message(message, bytes, socket)
      end

      assert_equal([[message, bytes, socket]], delivered)
    end
  end

  def test_decode_error_attribution_accepts_numeric_and_named_zones
    [
      ['FE80:0000:0000:0000:0000:0000:0000:0001%7', 'fe80::1%eth-test.100'],
      ['fe80::1%eth-test.100', 'FE80:0:0:0:0:0:0:1%7'],
    ].each do |destination, source|
      with_registered_query(destination) do |selector, socket, client_id, _message|
        assert_equal(client_id, selector.get_client_id_from_answerfrom(socket, source, 53))
      end
    end
  end

  def test_decode_error_attribution_requires_matching_address_and_port
    with_registered_query('fe80::1%7') do |selector, socket, _client_id, _message|
      assert_nil(selector.get_client_id_from_answerfrom(socket, 'fe80::2%eth-test.100', 53))
      assert_nil(selector.get_client_id_from_answerfrom(socket, 'fe80::1%eth-test.100', 54))
      assert_nil(selector.get_client_id_from_answerfrom(socket, '192.0.2.1', 53))
    end
  end

  def test_decode_error_attribution_stays_on_the_receiving_socket
    with_registered_query('fe80::1%7') do |selector, first_socket, first_id, _message|
      with_registered_query('fe80::1%8') do |_other_selector, second_socket, second_id, _other_message|
        assert_equal(first_id, selector.get_client_id_from_answerfrom(first_socket, 'fe80::1%eth0', 53))
        assert_equal(second_id, selector.get_client_id_from_answerfrom(second_socket, 'fe80::1%eth1', 53))
      end
    end
  end

  private

  def with_registered_query(destination)
    # Use existing tables when a resolver is active. Otherwise provide only the
    # tables these methods need, without starting a select loop or binding TCP.
    # Stubs live on a separate object and tokens never enter the IO.select set.
    selector_class = Dnsruby::SelectThread
    temporary_variables = []
    { :@@mutex => Mutex.new, :@@query_hash => {}, :@@socket_hash => {} }.each do |name, value|
      next if selector_class.class_variable_defined?(name)
      selector_class.class_variable_set(name, value)
      temporary_variables << name
    end
    selector = selector_class.send(:allocate)
    socket = Object.new
    message = Dnsruby::Message.new('scoped.example')
    # A negative ID cannot collide with a response arriving on a live socket.
    message.header.id = -message.object_id
    client_id = [Object.new, message]
    settings = Dnsruby::SelectThread::QuerySettings.new
    settings.query = message
    settings.socket = socket
    settings.client_query_id = client_id
    settings.dest_server = destination
    settings.dest_port = 53

    mutex = selector_class.class_variable_get(:@@mutex)
    queries = selector_class.class_variable_get(:@@query_hash)
    sockets = selector_class.class_variable_get(:@@socket_hash)
    mutex.synchronize do
      queries[client_id] = settings
      sockets[socket] = [client_id]
    end

    begin
      yield selector, socket, client_id, message
    ensure
      mutex.synchronize do
        queries.delete(client_id)
        sockets.delete(socket)
      end
      temporary_variables.each { |name| selector_class.remove_class_variable(name) }
    end
  end
end
