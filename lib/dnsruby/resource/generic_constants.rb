module Dnsruby
  class RR
    module GenericConstantInspection
      NATIVE_DEFINED = Module.instance_method(:const_defined?)
      NATIVE_GET = Module.instance_method(:const_get)
      NATIVE_ANCESTORS = Module.instance_method(:ancestors)
      EMPTY = Module.new

      def self.native_defined?(receiver, path, inherit, nested = false)
        if nested
          first = path.split('::', -1).first
          NATIVE_DEFINED.bind_call(EMPTY, first, false) # Validate; never reinterpret :: as an absolute suffix.
          ancestors = inherit ? NATIVE_ANCESTORS.bind_call(receiver) : [receiver]
          ancestors = ancestors.take_while { |ancestor| !ancestor.equal?(Object) } unless receiver.equal?(Object)
          return false unless ancestors.any? { |ancestor| NATIVE_DEFINED.bind_call(ancestor, first, false) }
        end
        NATIVE_DEFINED.bind_call(receiver, path, inherit)
      end

      def self.nested_defined?(receiver, path, inherit)
        native_defined?(receiver, path, inherit, true) || virtual_defined?(receiver, path, inherit, true)
      end

      def self.virtual_defined?(receiver, path, inherit, nested = false)
        parts = path.split('::', -1)
        parts.each_index do |index|
          prefix = parts[0..index].join('::')
          next if prefix.empty? && index.zero?
          next if native_defined?(receiver, prefix, inherit, nested)
          owner = if index.zero?
            receiver
          elsif index == 1 && parts.first.empty?
            Object
          else
            NATIVE_GET.bind_call(receiver, parts[0...index].join('::'), inherit)
          end
          generic = Dnsruby::RR::Generic
          return false unless owner.equal?(generic) || (inherit && owner.is_a?(Class) && owner < generic)
          local = parts[index]
          found = GenericCache.named(local)
          numeric = /\AType(\d+)_Class(\d+)\z/.match(local)
          return false unless found || numeric
          return true if index == parts.length - 1
          suffix = parts[(index + 1)..].join('::')
          if found
            return nested_defined?(found, suffix, inherit)
          end
          type, klass = numeric.captures.map(&:to_i)
          registered = Dnsruby::ClassHash[[type, klass]] || GenericCache.peek(type, klass)
          if registered
            raise TypeError, "#{path} does not refer to class/module" unless registered.is_a?(Module)
            return nested_defined?(registered, suffix, inherit)
          end
          NATIVE_DEFINED.bind_call(EMPTY, suffix, false) # Preserve delimiter validation before a projected value.
          # These are the only constants every newly reconstructed Class owns.
          if ['TypeValue', 'ClassValue'].include?(parts[index + 1])
            return true if index + 2 == parts.length
            raise TypeError, "#{path} does not refer to class/module"
          end
          ancestor = Dnsruby::RR::ClassInsensitiveTypes[type] || generic
          return nested_defined?(inherit ? ancestor : EMPTY, suffix, inherit)
        end
        false
      end

      def const_defined?(name, inherit = true)
        unless name.is_a?(String) || name.is_a?(Symbol)
          original = name
          name = String.try_convert(name)
          raise TypeError, "no implicit conversion of #{original.class} into String" unless name
        end
        return true if super(name, inherit)
        path = name.is_a?(Symbol) ? name.to_s : String.new(name)
        GenericConstantInspection.virtual_defined?(self, path, inherit)
      end
    end
  end
end
Dnsruby::RR::Generic.singleton_class.prepend(Dnsruby::RR::GenericConstantInspection)
