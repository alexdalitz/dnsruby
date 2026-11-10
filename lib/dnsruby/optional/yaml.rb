require 'dnsruby'
require 'yaml'

module Dnsruby
  class RR
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
