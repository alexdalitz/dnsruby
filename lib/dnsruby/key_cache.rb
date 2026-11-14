# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

module Dnsruby
  class KeyCache #:nodoc: all
    #  Cache includes expiration time for keys
    #  Cache removes expired records
    def initialize(keys = nil)
      # Store DNSKEY identity against [expiry, key]. A 16-bit key tag can collide.
      @keys = {}
      add(keys)
    end

    # TTL and cached OpenSSL objects are not part of a DNSKEY's identity.
    # Copy mutable fields so later changes cannot corrupt the hash index.
    def self.key_identity(key)
      [key.name.canonical.freeze, key.klass.code, key.type.code,
       key.flags, key.protocol, key.algorithm.code, key.key.dup.freeze].freeze
    end
    def add_key_with_expiration(k, expiration)
      priv_add_key(k, expiration)
    end
    def add(k, expiration = nil)
      if (k == nil)
        return false
      elsif (k.instance_of?RRSet)
        add_rrset(k, expiration)
      elsif (k.kind_of?KeyCache)
        k.keys_and_expirations.each { |expiration, key|
          priv_add_key(key, expiration)
        }
      else
        raise ArgumentError.new("Expected an RRSet or KeyCache! Got #{k.class}")
      end
      return true
    end

    def add_rrset(k, expiration = nil)
      return unless k.type == Types.DNSKEY
      now = Time.now.to_i
      # Verification supplies an absolute deadline derived from the signature
      # that actually verified. Never extend it using other supplied RRSIGs.
      # Explicit callers without that deadline get a conservative TTL bound.
      unless expiration
        signatures = k.sigs.select { |sig| sig.inception <= now && sig.expiration >= now }
        return if signatures.empty?
        expiration = ([now + k.ttl] + signatures.map(&:expiration)).min
      end
      return if expiration <= now
      k.rrs.each { |rr| priv_add_key(rr, expiration) }
    end

    def priv_add_key(k, exp)
      #  Check that the key does not already exist with a longer expiration!
      identity = self.class.key_identity(k)
      if !@keys[identity] || @keys[identity][0] < exp
        @keys[identity] = [exp, k]
      end
    end

    def each
      #  Only offer currently-valid keys here
      remove_expired_keys
      @keys.values.each {|v| yield v[1]}
    end
    def delete(key)
      delete_identity(self.class.key_identity(key))
    end
    def delete_identity(identity)
      cached = @keys.delete(identity)
      cached && cached[1]
    end
    def keys
      #  Only offer currently-valid keys here
      remove_expired_keys
      ks = []
      @keys.values.each {|a| ks.push(a[1])}
      return ks
      #         return @keys.keys
    end
    def keys_and_expirations
      remove_expired_keys
      @keys.values.map(&:dup)
    end
    def remove_expired_keys
      @keys.delete_if {|k,v|
        v[0] <= Time.now.to_i
      }
    end
    def find_key_for(name)
      each {|key| return key if key.name == name}
      return false
    end
  end
end
