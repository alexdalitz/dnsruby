require 'test/unit'
require 'dnsruby'

class TestValidator < Test::Unit::TestCase
  def test_validator
    # @TODO@
  end

  def test_resolver_cd_validation_fails
    res = Dnsruby::Resolver.new("a.ns.se")
    r = res.query("se", Dnsruby::Types.ANY)
    # @TODO@ Check the response here
    #    fail("Implement Resolver validation checking!")
    print("Implement Resolver validation checking!")
    # We wanna check with CD on and off, and make sure it fails/works
    # need to remember to get resolver to validate iff cd on query is true
    # @TODO@ Remember to check the message security_level!
  end

end
