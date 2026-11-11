$VERBOSE = true

if Warning.respond_to?(:[]=)
  Warning[:deprecated] = true
end

if ENV['RUN_EXTRA_TASK'] == 'TRUE'
  require 'simplecov'

  # Generate reports locally; CI uploads coverage after the tests complete.
  SimpleCov.formatter = SimpleCov::Formatter::HTMLFormatter
  SimpleCov.start do
    add_filter '/test/'
  end
end

require 'minitest'
require 'minitest/autorun'
require 'minitest/display'

Minitest::Display.options = {
  suite_names: true,
  color: true,
  print: {
    success: ".",
    failure: "F",
    error: "R"
  }
}
# This is in a self invoking anonymous lambda so local variables do not
# leak to the outer scope.
-> do
  load_dir = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
  $LOAD_PATH.unshift(load_dir) unless $LOAD_PATH.include?(load_dir)
  require_relative '../lib/dnsruby'
  require_relative 'test_utils'
end.()

def with_retries(max_attempts: 5, exceptions: [Dnsruby::ServFail, Dnsruby::ResolvTimeout], success_check: ->(result) { result }, &block)
  attempts = 0
  while attempts < max_attempts
    begin
      result = block.call
      return result if success_check.call(result)  # e.g., for nil-check: ->(r) { r }
    rescue *exceptions => e
      puts "Retry #{attempts + 1}/#{max_attempts}: #{e.class} - #{e.message}" if ENV['DEBUG_TESTS']
    end
    sleep(1)
    attempts += 1
  end
  raise Minitest::Assertion, "Failed after #{max_attempts} retries"
end
