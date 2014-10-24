require 'rake/testtask'
require 'rdoc/task'

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include("lib/**/*.rb")
  rd.rdoc_files.exclude("lib/Dnsruby/iana_ports.rb")
  rd.main = "Dnsruby"
#  rd.options << "--ri"
end
  
task :test do
  require_relative 'test/ts_dnsruby.rb'
end
