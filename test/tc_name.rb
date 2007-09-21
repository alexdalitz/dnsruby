#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require 'rubygems'
require 'test/unit'
require 'dnsruby'
include Dnsruby
class TestName < Test::Unit::TestCase
  def test_label_length
    Name::Label.set_max_length(Name::Label::MaxLabelLength) # Other tests may have changed this  
    # Test max label length = 63
    begin
      name = Name.create("a.b.12345678901234567890123456789012345678901234567890123456789012345.com")
      assert(false, "Label of more than max=63 allowed")
    rescue ResolvError
    end
  end
  
  def test_name_length
    # Test max name length=255
    begin
      name = Name.create("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123.com")
      assert(false, "Name of length > 255 allowed")
    rescue ResolvError
    end
  end
  
  def test_absolute
    n = Name.create("example.com")
    assert(!n.absolute?)
    n = Name.create("example.com.")
    assert(n.absolute?)
  end

  def test_wild
    n = Name.create("example.com")
    assert(!n.wild?)
    n = Name.create("*.example.com.")
    assert(n.wild?)
  end
end
