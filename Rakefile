require 'rake/testtask'
require 'rdoc/task'

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include("lib/**/*.rb")
  rd.rdoc_files.exclude("lib/Dnsruby/iana_ports.rb")
  rd.main = "Dnsruby"
#  rd.options << "--ri"
end


def create_task(task_name, test_suite_filespec)
  Rake::TestTask.new do |t|
    t.name = task_name
    t.test_files = FileList[test_suite_filespec]
    t.verbose = true
  end
end


create_task(:test,         'test/ts_dnsruby.rb')
create_task(:test_offline, 'test/ts_offline.rb')
create_task(:test_online,  'test/ts_online.rb')
