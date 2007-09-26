require 'rubygems'
require 'test/unit'
require 'eventmachine'
require 'Dnsruby'
begin
require 'test/tc_soak_base'
rescue Exception
  require 'tc_soak_base'
end
 
class TestEventMachineSoak < Test::Unit::TestCase
  def setup
    #Dnsruby::TheLog.level=Logger::DEBUG
    Dnsruby::Resolver.use_eventmachine(true)
  end
  def teardown
    Dnsruby::Resolver.use_eventmachine(false)    
  end
  
end
