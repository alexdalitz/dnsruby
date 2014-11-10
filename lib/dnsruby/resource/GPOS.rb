#--
#Copyright 2014 Verisign Inc.
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
#++
module Dnsruby
  class RR
    # Class for Geographic Position (GPOS) resource records.
    #
    # RFC 1712 (https://www.ietf.org/rfc/rfc1712.txt)
    class GPOS < RR

      TypeValue = Types::GPOS
      ClassValue = Classes::IN
      ClassHash[[TypeValue, ClassValue]] = self  #:nodoc: all

      attr_accessor :latitude, :longitude, :altitude,  # NOTE: these are strings, not numbers
                    :owner,    :ttl


      DEFAULT_TTL = 60 * 60  # ?

      REQUIRED_KEYS = [:latitude, :longitude, :altitude]


      def initialize(latitude, longitude, altitude, ttl = DEFAULT_TTL, owner = nil, inet_class = Classes::IN)
        from_hash(
            latitude:   latitude,
            longitude:  longitude,
            altitude:   altitude,
            ttl:        ttl,
            owner:      owner,
            inet_class: inet_class
        )
      end


      def from_hash(init_data)

        self.class.validate_floats(init_data)

        @latitude   = init_data[:latitude].to_s
        @longitude  = init_data[:longitude].to_s
        @altitude   = init_data[:altitude].to_s
        @owner      = init_data[:owner]
        @ttl        = init_data[:ttl]
        @inet_class = init_data[:inet_class] || Classes::IN

        self
      end

      # From the RFC:
      #    GPOS has the following format:
      # <owner> <ttl> <class> GPOS <longitude> <latitude> <altitude>
      def to_s
        [owner, ttl, inet_class, 'GPOS', longitude, latitude, altitude].join(' ')
      end


      def to_binary
        "%-16.16s%-16.16s%-16.16s" % [latitude, longitude, altitude]
      end


      def inspect
        "#{self.class}: latitude: #{latitude}, longitude: #{longitude}, altitude: #{altitude}," +
            " owner: #{owner}, ttl: #{ttl}, class: #{@inet_class}"
      end


      def self.valid_float?(object)
        begin
          Float(object)
          true
        rescue
          false
        end
      end


      def self.validate_float_in_range(label, object, bound)
        number = Float(object)
        valid_range = (-Float(bound)..Float(bound))
        unless valid_range.include?(number)
          raise "Value of #{label} (#{number}) was not in the range #{valid_range}."
        end
      end


      def self.validate_floats(init_data)
        bad_float_keys = REQUIRED_KEYS.reject { |key| valid_float?(init_data[key]) }
        unless bad_float_keys.empty?
          message = "The following key value pair(s) do not have valid floats or float strings:\n"
          bad_float_keys.each do |key|
            message << "%:-12.12s => %s\n" % [init_data[key]]
          end
          raise message
        end

        validate_float_in_range('latitude',  init_data[:latitude], 90)
        validate_float_in_range('longitude', init_data[:longitude], 180)
      end
    end
  end
end



