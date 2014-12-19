# encoding: ASCII-8BIT

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
        @ttl        = init_data[:ttl] || DEFAULT_TTL
        @inet_class = init_data[:inet_class] || Classes::IN

        self
      end

      # From the RFC:
      #    GPOS has the following format:
      # <owner> <ttl> <class> GPOS <longitude> <latitude> <altitude>
      def to_s
        [owner, ttl, inet_class, 'GPOS', longitude, latitude, altitude].join(' ')
      end


      def encode_rdata(msg, _canonical=false) #:nodoc: all
        msg.put_bytes(to_binary)
      end


      def to_binary
        binary_string = ''
        binary_string << latitude.length.chr
        binary_string << latitude
        binary_string << longitude.length.chr
        binary_string << longitude
        binary_string << altitude.length.chr
        binary_string << altitude
        # s.force_encoding('ASCII-8BIT')
        # puts s.encoding
        # puts s
        binary_string
      end

      def self.from_binary(binary_string)

        s = binary_string.clone

        lat_len = s[0].ord;           s = s[1..-1]
        latitude = s[0...lat_len];    s = s[lat_len..-1]

        long_len = s[0].ord;          s = s[1..-1]
        longitude = s[0...long_len];  s = s[long_len..-1]

        alt_len = s[0].ord;           s = s[1..-1]
        altitude = s[0...alt_len];    s = s[alt_len..-1]

        # puts [latitude, longitude, altitude].join(', ')

        # puts "Remaining binary string contains #{s.length} chars:\n"
        # s.each_byte { |ch| puts ch.ord }

        # require 'ripl'
        # Ripl.start :binding => binding

        validate_latitude(latitude)
        validate_longitude(longitude)

        new(latitude, longitude, altitude)
      end

      def self.decode_rdata(message)
        return from_binary(message.get_bytes(48))
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


      def self.validate_latitude(value)
        validate_float_in_range('latitude',  value, 90)
      end

      def self.validate_longitude(value)
        validate_float_in_range('longitude', value, 180)
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

        validate_latitude(init_data[:latitude])
        validate_longitude(init_data[:longitude])
      end
    end
  end
end



