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
# require 'base64'
begin
require 'openssl'
rescue LoadError
  print "OpenSSL not found - ignoring\n"
end
module Dnsruby
  class RR
    # A TSIG record contains authentication data for a DNS message. This class
    # also holds the shared key and provides signing and verification helpers.
    # RFC 8945 section 4 describes the record format and MAC calculation.
    #
    # Example code :
    #     res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    # 
    #     # Now configure the resolver with the TSIG key for signing/verifying
    #     KEY_NAME="rubytsig"
    #     KEY = "8n6gugn4aJ7MazyNlMccGKH1WxD2B3UvN/O/RA6iBupO2/03u9CTa3Ewz3gBWTSBCH3crY4Kk+tigNdeJBAvrw=="
    #     res.tsig=KEY_NAME, KEY
    # 
    #     update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    #     # Generate update record name, and test it has been made. Then delete it and check it has been deleted
    #     update_name = generate_update_name
    #     update.absent(update_name)
    #     update.add(update_name, 'TXT', 100, "test signed update")
    # 
    #     # Resolver will automatically sign message and verify response
    #     response = res.send_message(update)
    #     assert(response.verified?) # Check that the response has been verified
    class TSIG < RR
      HMAC_MD5 = Name.create("HMAC-MD5.SIG-ALG.REG.INT.")
      HMAC_SHA1 = Name.create("hmac-sha1.")
      HMAC_SHA256 = Name.create("hmac-sha256.")
      HMAC_SHA512 = Name.create("hmac-sha512.")

      DEFAULT_FUDGE     = 300

      DEFAULT_ALGORITHM = HMAC_SHA256

      DIGESTS = {
        'hmac-md5.sig-alg.reg.int' => 'MD5', 'hmac-sha1' => 'SHA1',
        'hmac-sha256' => 'SHA256', 'hmac-sha512' => 'SHA512'
      }.freeze
      private_constant :DIGESTS
      LEGACY_WARNING_MUTEX = Mutex.new
      private_constant :LEGACY_WARNING_MUTEX

      # BADTIME and BADTRUNC replies carry a MAC; BADKEY and BADSIG do not
      # (RFC 8945 sections 5.3.2 and 5.4). Only authenticated errors can end
      # a pending query.
      SIGNED_ERRORS = {18 => 'BADTIME', 22 => 'BADTRUNC'}.freeze
      private_constant :SIGNED_ERRORS

      # Generates a TSIG record and adds it to the message.
      # Takes an optional original_request argument for the case where this is
      # a response to a query (RFC 8945 section 4.3.1).
      # 
      # Message#tsigstate will be set to :Signed.
      def apply(message, original_request=nil)
        if (!message.signed?)
          tsig_rr = generate(message, original_request)
          message.add_additional(tsig_rr)
          message.tsigstate = :Signed
          @query = message
          tsig_rr.query = message
        end
      end

      def query=q#:nodoc: all
        @query = q
      end


      # Generates a TSIG record. The caller must authenticate original_request
      # before using it to sign a response.
      def generate(msg, original_request = nil, data="", msg_bytes=nil, tsig_rr=self)#:nodoc: all
        verifying = !msg_bytes.nil?
        unless msg_bytes
          tsig_rr.warn_if_legacy_algorithm
          if [msg.answer, msg.authority, msg.additional].any? { |section| section.any? { |rr| rr.type == Types::TSIG } }
            raise EncodeError, 'Message already contains a TSIG'
          end
          if !msg.header.qr && tsig_rr.error != RCode.NOERROR
            raise EncodeError, 'A TSIG request must have error NOERROR'
          end
          if msg.header.qr && [RCode.BADSIG, RCode.BADKEY].include?(tsig_rr.error)
            raise EncodeError, 'BADKEY and BADSIG responses must be unsigned'
          end
          if original_request && tsig_rr.error == RCode.BADTIME
            tsig_rr = tsig_rr.dup
            tsig_rr.time_signed = original_request.tsig.time_signed
            tsig_rr.fudge = original_request.tsig.fudge
          end
        end
        time_signed=@time_signed
        if (!time_signed)
          time_signed=Time.now.to_i
        end
        if (tsig_rr.time_signed)
          time_signed = tsig_rr.time_signed
        end
        validate_wire_fields(tsig_rr, time_signed) unless msg_bytes
        if !msg_bytes && msg.header.qr && tsig_rr.other_size != (tsig_rr.error == RCode.BADTIME ? 6 : 0)
          raise EncodeError, 'Invalid TSIG response Other Data length'
        end
        original_id = verifying ? tsig_rr.original_id : (original_request ? original_request.tsig.original_id : msg.header.id)

        if (original_request)
          # Responses include the request MAC exactly as transmitted.
          mac_bytes = MessageEncoder.new {|m|
            m.put_pack('n', original_request.tsig.mac_size)
            m.put_bytes(original_request.tsig.mac)
          }.to_s
          data  += mac_bytes
          msg.header.id = original_request.header.id unless msg_bytes
        end

        if (!msg_bytes)
          msg_bytes = msg.encode
          data += [original_id].pack('n') + msg_bytes.byteslice(2..-1)
        else
          data += verification_message(msg, msg_bytes, tsig_rr)
        end

        data += sig_data(tsig_rr, time_signed)

        mac = calculate_mac(tsig_rr.algorithm, data)
        if !verifying && @mac_length
          minimum = [10, mac.bytesize / 2].max
          unless (minimum..mac.bytesize).cover?(@mac_length)
            raise EncodeError, "TSIG MAC length must be between #{minimum} and #{mac.bytesize} octets"
          end
          if original_request && @mac_length < original_request.tsig.mac_size
            raise EncodeError, 'TSIG response MAC must not be shorter than the request MAC'
          end
          mac = mac.byteslice(0, @mac_length)
        end

        mac_size = mac.length

        new_tsig_rr = Dnsruby::RR.create(name: tsig_rr.name, type: Types.TSIG,
          ttl: tsig_rr.ttl, klass: tsig_rr.klass, key: @key, mac_length: @mac_length)
        # Copy fields directly so verifying an incoming record doesn't trigger
        # the warning for configuring a legacy key.
        new_tsig_rr.from_data([tsig_rr.algorithm, time_signed, tsig_rr.fudge,
          mac_size, mac, original_id, tsig_rr.error, tsig_rr.other_size, tsig_rr.other_data])
        return new_tsig_rr

      end

      def warn_if_legacy_algorithm #:nodoc: all
        name = @algorithm.to_s.downcase.sub(/\.$/, '')
        return unless [HMAC_MD5.to_s.downcase.sub(/\.$/, ''), 'hmac-md5'].include?(name)
        warn = LEGACY_WARNING_MUTEX.synchronize do
          unless TSIG.instance_variable_get(:@legacy_warning_issued)
            TSIG.instance_variable_set(:@legacy_warning_issued, true)
            true
          end
        end
        if warn
          Dnsruby.log.warn('HMAC-MD5 TSIG is enabled as a legacy compatibility exception. RFC 8945 says it MUST NOT be used. Update the TSIG key and configure hmac-sha256 on both the DNS server and client.')
        end
      end

      def calculate_mac(algorithm, data)
        name = algorithm.to_s.downcase.sub(/\.$/, '')
        digest = DIGESTS[name]
        raise VerifyError, "Algorithm #{algorithm} unsupported by TSIG" unless digest
        OpenSSL::HMAC.digest(digest, @key.gsub(' ', '').unpack1('m*'), data)
      end

      def verification_message(message, bytes, signature)
        wire = Header.decrement_arcount_encoded(bytes.dup).byteslice(0, message.tsigstart)
        wire[0, 2] = [signature.original_id].pack('n')
        wire
      end
      private :verification_message

      def validate_wire_fields(signature, time_signed)
        valid = signature.klass == Classes.ANY && signature.ttl == 0 &&
          time_signed.is_a?(Integer) && (0...(1 << 48)).cover?(time_signed) &&
          [signature.fudge, signature.original_id, signature.error, signature.mac_size, signature.other_size].all? do |value|
            value.is_a?(Integer) && (0..65_535).cover?(value)
          end
        valid &&= signature.mac.is_a?(String) && signature.mac_size == signature.mac.bytesize &&
          signature.other_data.is_a?(String) && signature.other_size == signature.other_data.bytesize
        raise EncodeError, 'Invalid TSIG fields' unless valid
      end
      private :validate_wire_fields

      #  Private method to return the TSIG RR data to be signed
      def sig_data(tsig_rr, time_signed=@time_signed) #:nodoc: all
        return MessageEncoder.new { |msg|
          msg.put_name(tsig_rr.name.downcase, true)
          msg.put_pack('nN', tsig_rr.klass.code, tsig_rr.ttl)
          msg.put_name(tsig_rr.algorithm.downcase, true)

          time_high = (time_signed >> 32)
          time_low = (time_signed & 0xFFFFFFFF)
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', tsig_rr.fudge)
          msg.put_pack('n', tsig_rr.error)
          msg.put_pack('n', tsig_rr.other_size)
          msg.put_bytes(tsig_rr.other_data)
        }.to_s
      end

      # Verify a response using the original query's MAC (RFC 8945 section 5.4).
      # Removes the TSIG record and sets Message#tsigstate and Message#tsigerror.
      # Returns false for server errors, even with a valid MAC. Check the
      # Verified state and error code to identify authenticated errors.
      def verify(query, response, response_bytes, buf="")
        signature = response.tsig
        signed_error = signature && response.header.get_header_rcode == RCode.NOTAUTH &&
          SIGNED_ERRORS.key?(signature.error)
        return false unless verify_common_fields(response, signed_error)

        expected = generate(response, query, buf, response_bytes, signature).mac
        return false unless verify_mac(response, signature, expected)
        # A BADTIME reply echoes the request's timers; only Other Data carries
        # the server's clock (RFC 8945 section 5.2.3).
        if signed_error && signature.error == RCode.BADTIME && query && query.tsig &&
            (signature.time_signed != query.tsig.time_signed || signature.fudge != query.tsig.fudge)
          return verification_failed(response, RCode.BADTIME)
        end
        return false unless verify_time(response, signature)
        return false unless verify_truncation_policy(response, signature)
        response.tsigstate = :Verified
        response.tsigerror = signature.error
        signature.error == RCode.NOERROR
      end

      def verify_common(response) #:nodoc: all
        verify_common_fields(response, false)
      end

      def verification_failed(response, error)
        response.tsigstate = :Failed
        response.tsigerror = error
        false
      end

      def verify_common_fields(response, signed_error)
        signature = response.tsig
        return verification_failed(response, RCode.FORMERR) unless signature
        response.additional.delete(signature)
        response.header.arcount -= 1
        return verification_failed(response, RCode.FORMERR) unless signature.is_a?(TSIG)
        begin
          validate_wire_fields(signature, signature.time_signed)
        rescue EncodeError
          return verification_failed(response, RCode.FORMERR)
        end
        if response.header.qr && signature.other_size != (signature.error == RCode.BADTIME ? 6 : 0)
          return verification_failed(response, RCode.FORMERR)
        end
        unless signature.name.downcase == @name.downcase && signature.algorithm.downcase == @algorithm.downcase &&
            DIGESTS.key?(signature.algorithm.to_s.downcase.sub(/\.$/, ''))
          return verification_failed(response, RCode.BADKEY)
        end
        if signature.error != RCode.NOERROR && !signed_error
          return verification_failed(response, signature.error)
        end
        true
      end

      def verify_mac(response, signature, expected)
        minimum = [10, expected.bytesize / 2].max
        unless (minimum..expected.bytesize).cover?(signature.mac_size)
          return verification_failed(response, RCode.FORMERR)
        end
        unless OpenSSL.fixed_length_secure_compare(expected.byteslice(0, signature.mac_size), signature.mac)
          return verification_failed(response, RCode.BADSIG)
        end
        true
      end

      def verify_time(response, signature)
        unless (Time.now.to_i - signature.time_signed).abs <= signature.fudge
          return verification_failed(response, RCode.BADTIME)
        end
        true
      end

      def verify_truncation_policy(response, signature)
        # RFC 8945 section 7 permits a local minimum above the protocol limit.
        if @mac_length && signature.mac_size < @mac_length
          return verification_failed(response, 22) # BADTRUNC
        end
        true
      end
      private :verification_failed, :verify_common_fields, :verify_mac, :verify_time, :verify_truncation_policy

      def initialize_copy(original)
        super
        @buf = @buf.dup if @buf
      end
      private :initialize_copy

      # Verify a stream, such as a zone transfer. Each signature covers the
      # messages since the previous one. RFC 8945 section 5.3.1 requires senders
      # to sign every message. For compatibility, receivers must accept up to
      # 99 unsigned messages between signatures. The caller must also check
      # that the final message is signed.
      #
      # Sets response.tsigstate to :Verified, :Intermediate or :Failed.
      def verify_envelope(response, response_bytes)
        if (!@buf)
          @num_envelopes = 0
          @last_signed = 0
        end
        @num_envelopes += 1
        if (!response.tsig)
          if ((@num_envelopes > 1) && (@num_envelopes - @last_signed < 100))
            Dnsruby.log.debug("Receiving intermediate envelope in TSIG TCP session")
            response.tsigstate = :Intermediate
            response.tsigerror = RCode.NOERROR
            @buf << response_bytes
            return true
          else
            response.tsigerror = RCode.FORMERR
            response.tsigstate = :Failed
            Dnsruby.log.error("Expecting signed packet")
            return false
          end
        end
        #  We have a TSIG - process it!
        tsig = response.tsig
        if (@num_envelopes == 1)
          Dnsruby.log.debug("First response in TSIG TCP session - verifying normally")
          #  Process it as a standard answer
          ok = verify(@query, response, response_bytes)
          if (ok)
            mac_bytes = MessageEncoder.new {|m|
              m.put_pack('n', tsig.mac_size)
              m.put_bytes(tsig.mac)
            }.to_s
            @buf = mac_bytes
            @last_signed = @num_envelopes
            @last_time_signed = tsig.time_signed
          end
          return ok
        end
        Dnsruby.log.debug("Processing TSIG on TSIG TCP session")

        if (!verify_common(response))
          return false
        end

        data = @buf + verification_message(response, response_bytes, tsig)

        #  Let's add the timers
        timers_data = MessageEncoder.new { |msg|
          time_high = (tsig.time_signed >> 32)
          time_low = (tsig.time_signed & 0xFFFFFFFF)
          msg.put_pack('nN', time_high, time_low)
          msg.put_pack('n', tsig.fudge)
        }.to_s
        data += timers_data
        mac = calculate_mac(tsig.algorithm, data)
        return false unless verify_mac(response, tsig, mac)
        return false unless verify_time(response, tsig)
        if @last_time_signed && tsig.time_signed < @last_time_signed
          return verification_failed(response, RCode.BADTIME)
        end
        return false unless verify_truncation_policy(response, tsig)
        mac_bytes = MessageEncoder.new {|m|
          m.put_pack('n', tsig.mac_size)
          m.put_bytes(tsig.mac)
        }.to_s
        @buf=mac_bytes
        @last_signed = @num_envelopes
        @last_time_signed = tsig.time_signed

        response.tsigstate = :Verified
        response.tsigerror = RCode.NOERROR
        return true
      end


      TypeValue = Types::TSIG #:nodoc: all
      ClassValue = nil #:nodoc: all
      ClassHash[[TypeValue, Classes::ANY]] = self #:nodoc: all

      # Gets or sets the domain name that specifies the name of the algorithm.
      # Supported algorithms are hmac-md5, hmac-sha1, hmac-sha256 and hmac-sha512.
      # SHA-256 is the default. You can select MD5 for legacy servers, but its
      # use does not comply with RFC 8945 section 6.
      # 
      #     rr.algorithm=(algorithm_name)
      #     print "algorithm = ", rr.algorithm, "\n"
      # 
      attr_reader :algorithm

      # Gets or sets the signing time as the number of seconds since 1 Jan 1970
      # 00:00:00 UTC.
      # 
      # The default signing time is the current time.
      # 
      #     rr.time_signed=(time)
      #     print "time signed = ", rr.time_signed, "\n"
      # 
      attr_accessor :time_signed

      # Gets or sets the "fudge", i.e., the seconds of error permitted in the
      # signing time.
      # 
      # The default fudge is 300 seconds.
      # 
      #     rr.fudge=(60)
      #     print "fudge = ", rr.fudge, "\n"
      # 
      attr_reader :fudge

      # Returns the number of octets in the message authentication code (MAC).
      # Set when a record is decoded or a message is signed.
      # 
      #     print "MAC size = ", rr.mac_size, "\n"
      # 
      attr_accessor :mac_size

      # MAC length in bytes for signing, and minimum length to accept.
      # nil signs with the full digest and accepts the RFC 8945 minimum.
      # mac_size holds the actual length in a signed or decoded record.
      attr_reader :mac_length

      def mac_length=(length)
        unless length.nil? || (length.is_a?(Integer) && length.positive?)
          raise ArgumentError, 'TSIG mac_length must be a positive integer or nil'
        end
        @mac_length = length
      end

      # Returns the message authentication code (MAC) as a binary string.
      # Set when a record is decoded or a message is signed.
      # 
      #     print "MAC = ", rr.mac, "\n"
      # 
      attr_accessor :mac

      # Gets or sets the original message ID.
      # 
      #     rr.original_id(12345)
      #     print "original ID = ", rr.original_id, "\n"
      # 
      attr_accessor :original_id

      # Returns the RCODE covering TSIG processing.  Common values are
      # NOERROR, BADSIG, BADKEY, BADTIME and BADTRUNC (RFC 8945 section 5).
      # 
      #     print "error = ", rr.error, "\n"
      # 
      attr_accessor :error

      # Returns the length of the Other Data.  Should be zero unless the
      # error is BADTIME.
      # 
      #     print "other len = ", rr.other_size, "\n"
      # 
      attr_accessor :other_size

      # Returns the Other Data.  This field should be empty unless the
      # error is BADTIME, in which case it will contain the server's
      # time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
      # 
      #     print "other data = ", rr.other_data, "\n"
      # 
      attr_accessor :other_data

      # Stores the secret key used for signing/verifying messages.
      attr_accessor :key

      def init_defaults
        #  @TODO@ Have new() method which takes key_name and key?
        @algorithm   = DEFAULT_ALGORITHM
        @fudge       = DEFAULT_FUDGE
        @mac_size    = 0
        @mac_length  = nil
        @mac         = ""
        @original_id = rand(65536)
        @error       = 0
        @other_size   = 0
        @other_data  = ""
        @time_signed = nil
        @buf = nil

        # TSIG records use class ANY and TTL zero (RFC 8945 section 4.2).
        @klass = Classes.ANY
        @ttl = 0
      end

      def from_data(data) #:nodoc: all
        @algorithm, @time_signed, @fudge, @mac_size, @mac, @original_id, @error, @other_size, @other_data = data
      end

      def name=(n)
        if (n.instance_of?String)
          n = Name.create(n)
        end
        if (!n.absolute?)
          @name = Name.create(n.to_s + ".")
        else
          @name = n
        end
      end

      #  Create the RR from a standard string
      def from_string(str) #:nodoc: all
        parts = str.split("[:/]")
        if (parts.length < 2 || parts.length > 3)
          raise ArgumentException.new("Invalid TSIG key specification")
        end
        if (parts.length == 3)
          return TSIG.new(parts[0], parts[1], parts[2]);
        else
          return TSIG.new(DEFAULT_ALGORITHM, parts[0], parts[1]);
        end
      end

      # Set the algorithm to use to generate the HMAC
      # Supported values are :
      # * hmac-md5 (legacy; its use does not comply with RFC 8945)
      # * hmac-sha1
      # * hmac-sha256
      # * hmac-sha512
      def algorithm=(alg)
        unless alg.is_a?(String) || alg.is_a?(Name)
          raise ArgumentError, "#{alg.class} not valid for TSIG algorithm; use String or Name"
        end
        name = alg.to_s.downcase.sub(/\.$/, '')
        name = HMAC_MD5.to_s.downcase.sub(/\.$/, '') if name == 'hmac-md5'
        raise ArgumentError, 'Invalid TSIG algorithm' unless DIGESTS.key?(name)
        @algorithm = Name.create(name + '.')
        warn_if_legacy_algorithm
      end

      def fudge=(f)
        if (f < 0 || f > 0xFFFF)
          @fudge = DEFAULT_FUDGE
        else
          @fudge = f
        end
      end

      def rdata_to_string
        rdatastr=""
        if (@algorithm!=nil)
          error = @error
          error = "UNDEFINED" unless error!=nil
          rdatastr = "#{@original_id} #{@time_signed} #{@algorithm.to_s(true)} #{error}";
          if (@other_size > 0 && @other_data!=nil)
            rdatastr += " #{@other_data}"
          end
          rdatastr += " " + mac.unpack("H*").to_s
        end

        return rdatastr
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        validate_wire_fields(self, @time_signed)
        # Algorithm Name must be uncompressed (RFC 8945 section 4.2).
        msg.put_name(@algorithm.downcase, true)
        time_high = (@time_signed >> 32)
        time_low = (@time_signed & 0xFFFFFFFF)
        msg.put_pack('nN', time_high, time_low)
        msg.put_pack('n', @fudge)
        msg.put_pack('n', @mac_size)
        msg.put_bytes(@mac)
        msg.put_pack('n', @original_id)
        msg.put_pack('n', @error)
        msg.put_pack('n', @other_size)
        msg.put_bytes(@other_data)
      end

      def self.decode_rdata(msg) #:nodoc: all
        # RFC 8945 section 4.2 forbids compression in the algorithm name.
        labels, length = [], 1
        loop do
          raise DecodeError, 'Truncated TSIG algorithm name' unless msg.has_remaining?
          size, = msg.get_unpack('C')
          break if size == 0
          raise DecodeError, 'Compressed or invalid TSIG algorithm name' unless size && size <= 63
          length += size + 1
          raise DecodeError, 'TSIG algorithm name exceeds 255 octets' if length > 255
          msg.assert_buffer_position_valid(msg.index + size)
          labels << Name::Label.new(msg.get_bytes(size))
        end
        alg = Name.new(labels)
        time_high, time_low = msg.get_unpack("nN")
        time_signed = (time_high << 32) + time_low
        fudge, = msg.get_unpack("n")
        mac_size, = msg.get_unpack("n")
        mac = msg.get_bytes(mac_size)
        original_id, = msg.get_unpack("n")
        error, = msg.get_unpack("n")
        other_size, = msg.get_unpack("n")
        other_data = msg.get_bytes(other_size)
        return self.new([alg, time_signed, fudge, mac_size, mac, original_id, error, other_size, other_data])
      end
    end
  end
end
