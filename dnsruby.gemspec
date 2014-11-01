# Note: require_relative will not work in 1.9; see (1) below.
require File.expand_path(File.join(File.dirname(__FILE__), 'lib', 'dnsruby', 'version.rb'))

SPEC = Gem::Specification.new do |s|
  s.name = "dnsruby"
  s.version = Dnsruby::VERSION
  s.authors = ["Alex Dalitz"]
  s.email = 'alex@caerkettontech.com'
  s.homepage = "https://github.com/alexdalitz/dnsruby"
  s.platform = Gem::Platform::RUBY
  s.summary = "Ruby DNS(SEC) implementation"
  s.description = \
'Dnsruby is a pure Ruby DNS client library which implements a
stub resolver. It aims to comply with all DNS RFCs, including
DNSSEC NSEC3 support.'
  s.license = "Apache License, Version 2.0"
  candidatestest = Dir.glob("test/**/*")
  candidateslib = Dir.glob("lib/**/*")
  candidatesdoc = Dir.glob("html**/*")
  candidatesdemo = Dir.glob("demo/**/*")
  rakefile = ['Rakefile']
  candidates = rakefile + candidatestest + candidateslib + candidatesdoc + candidatesdemo
  s.files = candidates.delete_if { |item| /rdoc$/.match(item) }
  s.test_file = "test/ts_offline.rb"
  s.has_rdoc = true
  s.extra_rdoc_files = ["DNSSEC", "EXAMPLES", "README", "EVENTMACHINE"]

  s.add_development_dependency 'rake', '~> 10', '>= 10.3.2'
  s.add_development_dependency 'minitest', '~> 5.4'
end



=begin
(1) require_relative 'lib/dnsruby/version' works in Ruby versions >= 2.0,
but in 1.9 results in the following error:

 There was a LoadError while loading dnsruby.gemspec:
cannot infer basepath from
  /Users/kbennett/work/dnsruby/dnsruby.gemspec:1:in `require_relative'

Does it try to require a relative path? That's been removed in Ruby 1.9.
=end
