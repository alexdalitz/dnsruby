require 'rubygems'
SPEC = Gem::Specification.new do |s|
  s.name = "Dnsruby"
  s.version = "0.5.0"
  s.authors = ["AlexD"]
  s.email = "alexd@nominet.org.uk"
  s.homepage = "http://rubyforge.org/projects/dnsruby/"
  s.platform = Gem::Platform::RUBY
  s.summary = "Ruby DNS implementation"
  candidatestest = Dir.glob("test/**/*")
  candidateslib = Dir.glob("lib/**/*")
  candidatesdoc = Dir.glob("doc/**/*")
   candidates = candidatestest + candidateslib + candidatesdoc
  s.files = candidates.delete_if do |item|
                      item.include?("CVS") || item.include?("rdoc") ||
                         item.include?("svn")
                end
  s.autorequire="Dnsruby"
  s.test_file = "test/ts_offline.rb"
  s.has_rdoc = true
  s.extra_rdoc_files = ["README"]
end

