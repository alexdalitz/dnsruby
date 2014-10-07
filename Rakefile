require 'rake/testtask'
require 'rdoc/task'

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include("lib/**/*.rb")
  rd.rdoc_files.exclude("lib/Dnsruby/iana_ports.rb")
  rd.main = "Dnsruby"
#  rd.options << "--ri"
end
  
task :test => :install do 
#  require 'rake/runtest'
#  Rake.run_tests 'test/ts_dnsruby.rb'
  require 'rake/testtask'

  Rake::TestTask.new do |t|
    t.libs << "test"
    t.test_files = FileList['test/ts_dnsruby.rb']
    t.verbose = true
  end
end

task :default => :install do
end

task :install do
  sh "ruby setup.rb"
end

