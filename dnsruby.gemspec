lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dnsruby/version'

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
  s.extra_rdoc_files = ["DNSSEC", "EXAMPLES", "README.md", "EVENTMACHINE"]

  s.add_development_dependency 'rake', '~> 10', '>= 10.3.2'
  s.add_development_dependency 'minitest', '~> 5.4'
end

