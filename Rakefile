require 'rake/testtask'
require 'rake/rdoctask'

Rake::RDocTask.new do |rd|
  rd.main = "README.rdoc"
  rd.rdoc_files.include("README.rdoc", "lib/**/*.rb")
  rd.options << "--ri"
end
  
task :test => :install do 
  require 'rake/runtest'
  Rake.run_tests 'test/ts_dnsruby.rb'
end

task :default => :install do
end

task :install do
  sh "ruby setup.rb"
end

