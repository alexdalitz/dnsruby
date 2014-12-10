if ENV['RUN_EXTRA_TASK'] == 'TRUE'
  require 'coveralls'
  Coveralls.wear!

  require 'simplecov'

  SimpleCov.formatter =
    SimpleCov::Formatter::MultiFormatter[SimpleCov::Formatter::HTMLFormatter,
                                         Coveralls::SimpleCov::Formatter]
  SimpleCov.start do
    add_filter 'test/'
  end
end

require 'minitest'
require 'minitest/autorun'
require 'dnsruby'
