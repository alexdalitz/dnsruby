require 'dnsruby'
require 'yaml'

module Dnsruby
  class RR
    # Before SVCB/HTTPS support, types 64 and 65 were stored as opaque generic
    # RDATA. Psych allocates the current class when resolving their old paths;
    # hydrate that same object so aliases, cycles and application fields survive.
    module LegacySvcbYaml # :nodoc: all
      def init_with(coder)
        coder.map.each { |name, value| instance_variable_set("@#{name}", value) }
        return unless /\A!ruby\/object:Dnsruby::RR::Generic::Type(?:64|65)_Class\d+\z/.match?(coder.tag)

        unless @data.is_a?(String)
          raise DecodeError, 'Legacy SVCB/HTTPS YAML must contain binary RDATA'
        end
        if @data.empty? && ![Classes::ANY, Classes::NONE].include?(@klass)
          raise DecodeError, 'Legacy SVCB/HTTPS YAML has empty RDATA outside an UPDATE delete'
        end
        decoded = self.class.decode_rdata(MessageDecoder.new(@data.b))
        @priority, @target, @params = decoded.priority, decoded.target, decoded.params
        @type = Types.new(self.class::TypeValue)
        # Psych's freeze:true has already frozen the stored scalar, but these
        # decoded fields were created after its visitor traversed the YAML map.
        if @data.frozen?
          if @target
            @target.labels.each do |label|
              label.string.freeze
              label.downcase.freeze
              label.freeze
            end
            @target.labels.freeze
            @target.freeze
          end
          @params.each_value(&:freeze)
          @params.freeze
          @type.string = @type.string.dup.freeze
          @type.freeze
        end
      end
    end

    # Psych's native class lookup bypasses const_missing. Keep its existing YAML
    # representation without giving generated classes permanent Ruby names.
    module GenericYamlClassLoader # :nodoc: all
      private

      def path2class(path)
        super
      rescue ArgumentError, NameError
        name = /\ADnsruby::RR::Generic::(Type\d+_Class\d+)\z/.match(path)
        raise unless name
        raise if GenericConstantInspection::NATIVE_DEFINED.bind_call(Generic, name[1], false)
        resolved = Dnsruby::RR::Generic.const_get(name[1], false)
        raise unless resolved.is_a?(Module)
        resolved
      end
    end
  end
end

# Install only on explicit opt-in, using the application's selected Psych.
# Restricted#find still checks permitted_classes before reaching path2class.
loader = Psych::ClassLoader
unless loader.ancestors.include?(Dnsruby::RR::GenericYamlClassLoader)
  begin
    loader.prepend(Dnsruby::RR::GenericYamlClassLoader)
  rescue FrozenError
    raise FrozenError, 'Cannot install dnsruby/optional/yaml: Psych::ClassLoader is frozen; require the adapter before freezing it'
  end
end

unless Dnsruby::RR::SVCB.ancestors.include?(Dnsruby::RR::LegacySvcbYaml)
  Dnsruby::RR::SVCB.prepend(Dnsruby::RR::LegacySvcbYaml)
end
