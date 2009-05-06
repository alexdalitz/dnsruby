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
module Dnsruby
  # CodeMapper superclass looks after String to code mappings (e.g. OpCode, RCode, etc.)
  # 
  # Subclasses simply define a mapping of codes to variable names, and CodeMapper provides utility methods.
  # 
  # All strings will come out as upper case
  # 
  # Example :
  #   Types::AAAA or Types.AAAA
  #   rcode.string or rcode.code
  class CodeMapper # :nodoc: all
    include Comparable
    
    @@strings = {}
    @@stringsdown = {}
    @@values = {}
    @@maxcode = {}
    
    attr_accessor :string, :code
    alias to_code code
    alias to_i code
    alias to_string string
    alias to_s string
    
    def CodeMapper.maxcode
      return @maxcode
    end
    
    # Creates the CodeMapper from the defined constants
    def CodeMapper.update
      
      @@strings[self] = {}
      @@stringsdown[self] = {}
      @@values[self] = {}
      @@maxcode[self] = 0
      
      constants = self.constants - CodeMapper.constants
      constants.each do |i|
        @@strings[self].store(i.to_s, const_get(i))
      end 
      @@maxcode[self] = constants.length
      @@values[self] = @@strings[self].invert
      @@stringsdown[self] = Hash.new
      @@strings[self].keys.each do |s|
        @@stringsdown[self].store(s.downcase, @@strings[self][s])    
      end
    end
    
    # Add new a code to the CodeMapper
    def CodeMapper.add_pair(string, code)
      @@strings[self].store(string, code)
      @@values[self]=@@strings[self].invert
      @@stringsdown[self].store(string.downcase, code)
      @@maxcode[self]+=1
    end
    
    def unknown_string(arg) #:nodoc: all
      raise ArgumentError.new("String #{arg} not a member of #{self.class}")
    end
    
    def unknown_code(arg) #:nodoc: all
      # Be liberal in what you accept...
#      raise ArgumentError.new("Code #{arg} not a member of #{self.class}")
      Classes.add_pair(arg.to_s, arg)
      set_code(arg)
    end
    
    def self.method_missing(methId) #:nodoc: all
      str = methId.id2name
      return self.new(str)
    end
    
    def initialize(arg) #:nodoc: all
      if (arg.kind_of?String)
        arg.gsub!("_", "-")
        if (@@stringsdown[self.class][arg.downcase] != nil)
          set_string(arg)
        else 
          unknown_string(arg)
        end
      elsif (arg.kind_of?Fixnum)
        if (@@values[self.class][arg] != nil)
          set_code(arg)
        else 
          unknown_code(arg)
        end
      elsif (arg.kind_of?self.class)
        set_code(arg.code)
      else
        raise ArgumentError.new("Unknown argument #{arg} for #{self.class}")
      end
    end
    
    def set_code(arg)
      @code = arg
      @string = @@values[self.class][@code]
    end
    
    def set_string(arg)
      @code = @@stringsdown[self.class][arg.downcase]
      @string = @@strings[self.class].invert[@code]
    end
    
    def inspect
      return @string
    end    
    
    def CodeMapper.to_string(arg)
      if (arg.kind_of?String) 
        return arg
      else
        return @@values[self][arg]
      end
    end
    
    def CodeMapper.to_code(arg)
      if (arg.kind_of?Fixnum)
        return arg
      else
        return @@stringsdown[self][arg.downcase]
      end
    end
    
    def <=>(other)
      if (other.class == Fixnum)
        self.code <=> other
      else
        self.code <=> other.code
      end
    end
    
    def ==(other)
      if other.kind_of?CodeMapper
        if other.string == @string && other.code == @code
          return true 
        end
      elsif other.kind_of?String
        if other == @string
          return true
        end
      elsif other.kind_of?Fixnum
        if other == @code
          return true
        end
      end
      return false
    end
    alias eql? == # :nodoc:

    # Return a regular expression which matches any codes or strings from the CodeMapper.
    def self.regexp
      # Longest ones go first, so the regex engine will match AAAA before A, etc.
      return @@strings[self].keys.sort { |a, b| b.length <=> a.length }.join('|')
    end
    
  end
end