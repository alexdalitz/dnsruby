require 'coveralls'
Coveralls.wear!

require 'simplecov'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  Coveralls::SimpleCov::Formatter
]
SimpleCov.start do
  add_filter 'test/'
end

require 'minitest/autorun'
require 'dnsruby'
