require 'thread'
require 'weakref'

module Dnsruby
  class RR
    # Only automatically generated integer pairs belong to this cache. Explicit
    # registrations and the public Generic.create factory retain their lifetime.
    module GenericCache # :nodoc: all
      LIMIT = 256
      READ = Hash.instance_method(:fetch)
      WRITE = Hash.instance_method(:[]=)
      DELETE = Hash.instance_method(:delete)
      KEYS = Hash.instance_method(:keys)
      HAS_KEY = Hash.instance_method(:key?)
      REMOVE_CONSTANT = Module.instance_method(:remove_const)
      Entry = Struct.new(:name, :pair, :klass, :registry_key, :version, :automatic, :index)
      NameIndex = Struct.new(:current)
      # The FIFO and its ClassHash entries retain automatic classes. The
      # name index is weak and also resolves caller-held classes after explicit
      # registry deletion. Entry#automatic distinguishes reusable entries from
      # those retained only for constant lookup.
      # Each automatic class owns its Entry and the name's stable index cell.
      # The cell refers weakly to the latest Entry, so an older caller-held class
      # does not retain its replacement. Updating the cell avoids replacing a
      # WeakMap value (unsafe on Ruby 3.2) or rebuilding maps (whose finalizers
      # can retain every previous map on older Ruby versions).
      # Entry versions prevent older mutation cleanup discarding a publication.
      @lock = Mutex.new
      @names = ObjectSpace::WeakMap.new
      @fifo = {}.compare_by_identity
      @version = 0

      class << self
        def eligible?(type, klass)
          type.instance_of?(Integer) && klass.instance_of?(Integer) && type >= 0 && klass >= 0
        end

        def key(type, klass)
          # WeakMap uses object identity. Deduplicated strings give equal pairs
          # the same collectible key, which the live Class owns.
          -("Type#{type}_Class#{klass}".encode(Encoding::UTF_8))
        end

        def named(name)
          return nil unless name.ascii_only?
          @lock.synchronize { indexed_entry(-name.encode(Encoding::UTF_8))&.klass }
        end

        def find(type, klass)
          return nil unless eligible?(type, klass)
          pair = [type, klass]
          @lock.synchronize do
            registered = READ.bind(ClassHash).call(pair, nil)
            return registered if registered
            found = automatic_entry(key(type, klass))
            retain(found) if reusable?(found)
          end
        end

        def peek(type, klass)
          return nil unless eligible?(type, klass)
          @lock.synchronize { automatic_entry(key(type, klass))&.klass }
        end

        def factory(type, klass)
          previous = Thread.current[:dnsruby_generic_factory]
          Thread.current[:dnsruby_generic_factory] = eligible?(type, klass) ? [type, klass] : nil
          yield
        ensure
          Thread.current[:dnsruby_generic_factory] = previous
        end

        def automatic?(type, klass)
          return false unless eligible?(type, klass) && Thread.current[:dnsruby_generic_factory] == [type, klass]
          Thread.current[:dnsruby_generic_factory] = nil
          true
        end

        def create(type, klass)
          # Class.new invokes the application's inherited hook. Never hold the
          # registry lock while running it, or while setting up the new Class.
          generated = Class.new(Generic)
          generated.const_set(:TypeValue, type)
          generated.const_set(:ClassValue, klass)
          name = key(type, klass)
          generated.instance_variable_set(:@generic_display_name, "Dnsruby::RR::Generic::#{name}".freeze)
          entry = Entry.new(name, [type, klass].freeze, generated, nil, nil, true)
          # WeakMap's values are weak too. The class keeps its mutable bookkeeping
          # alive even when a client freezes the class itself.
          generated.instance_variable_set(:@generic_cache_entry, entry)
          @lock.synchronize do
            registered = READ.bind(ClassHash).call(entry.pair, nil)
            return registered if registered
            found = automatic_entry(name)
            return retain(found) if reusable?(found)
            # A previous explicit factory call may have left a native constant
            # after its registry entry was deleted. Let lookup (including YAML)
            # reach the replacement class instead of that stale binding.
            if GenericConstantInspection::NATIVE_DEFINED.bind(Generic).call(name, false)
              REMOVE_CONSTANT.bind(Generic).call(name)
            end
            index = @names[name]
            entry.index = index || NameIndex.new
            entry.index.current = WeakRef.new(entry)
            @names[name] = entry.index unless index
            retain(entry)
          end
        end

        # Custom Hash keys can address a different pair from their Array
        # contents, or need not be Arrays at all. Resolve them with Ruby's own
        # stored-key comparison, outside the cache lock (hash/eql? may call back).
        def registry_pair(pair)
          return pair if ClassHash.compare_by_identity?
          native_method = Object.instance_method(:method)
          if Array === pair && native_method.bind(pair).call(:hash).owner == Array && native_method.bind(pair).call(:eql?).owner == Array
            return pair
          end
          copy = Hash.instance_method(:dup).bind(ClassHash).call
          keys = KEYS.bind(copy).call
          index = 0
          Hash.instance_method(:transform_values!).bind(copy).call do |_|
            stored = keys[index]
            index += 1
            stored
          end
          missing = Object.new
          stored = READ.bind(copy).call(pair, missing)
          return stored unless stored.equal?(missing)
          # A live entry may already have left the FIFO. An explicit deletion
          # still invalidates that entry when the custom key addresses its pair.
          entries = @lock.synchronize { automatic_entries }
          weak = entries.to_h { |entry| [entry.pair, entry.pair] }
          READ.bind(weak).call(pair, pair)
        end

        # Native Hash mutations run outside the lock. Their cleanup must not
        # remove a newer publication by a concurrent or reentrant lookup.
        def snapshot(pair = nil)
          name = pair_name(pair) if pair
          return {} if pair && !name
          @lock.synchronize do
            entries = if pair && ClassHash.compare_by_identity?
              @fifo.keys.select { |entry| entry.registry_key.equal?(pair) }
            elsif pair
              [automatic_entry(name)].compact
            else
              automatic_entries + @fifo.keys
            end
            entries.each_with_object({}.compare_by_identity) { |entry, saved| saved[entry] = entry.version }
          end
        end

        def forget(snapshot, pairs = nil, removed_only: false)
          names = pairs&.filter_map { |pair| pair_name(pair) }
          @lock.synchronize do
            entries = snapshot.keys
            entries.select! { |entry| names.include?(entry.name) } if names
            entries += names ? names.filter_map { |name| automatic_entry(name) } : @fifo.keys
            entries.each do |entry|
              next if pairs && !pairs.any? { |pair| targets?(entry, pair) }
              unchanged = snapshot.key?(entry) && snapshot[entry] == entry.version
              unchanged &&= !READ.bind(ClassHash).call(registry_key(entry), nil).equal?(entry.klass) if removed_only
              discard(entry) if unchanged || stale?(entry)
            end
          end
        end

        def register(snapshot, pair, value)
          name = pair_name(pair)
          return unless name
          @lock.synchronize do
            identity = ClassHash.compare_by_identity?
            previous = snapshot.keys.find do |entry|
              entry.klass.equal?(value) && targets?(entry, pair) && (identity ? entry.registry_key.equal?(pair) : entry.name == name)
            end
            # FIFO eviction may have run after the explicit write but before its
            # cleanup. Preserve a successfully assigned automatic class.
            if previous && previous.automatic && !@fifo.key?(previous) && !moved?(previous) && !READ.bind(ClassHash).call(registry_key(previous), nil)
              actual = identity ? pair : previous.pair.dup
              WRITE.bind(ClassHash).call(actual, value)
            end
            entries = identity ? @fifo.keys.select { |entry| entry.registry_key.equal?(pair) } : [automatic_entry(name)].compact
            entries.each do |entry|
              next unless targets?(entry, pair)
              discard(entry) if READ.bind(ClassHash).call(registry_key(entry), nil).equal?(value)
            end
          end
        end

        def rehash
          @lock.synchronize do
            (automatic_entries + @fifo.keys).each { |entry| discard(entry) if moved?(entry) || stale?(entry) }
          end
        end

        private

        def automatic_entry(name)
          entry = indexed_entry(name)
          entry if entry&.automatic
        end

        def automatic_entries
          @names.values.filter_map { |index| dereference(index) }.select(&:automatic)
        end

        def indexed_entry(name)
          dereference(@names[name])
        end

        def dereference(index)
          index&.current&.__getobj__
        rescue WeakRef::RefError
          nil
        end

        def pair_name(pair)
          return unless Array === pair
          # A native slice strips singleton methods, unlike Array#to_a.
          pair = Array.instance_method(:[]).bind(pair).call(0, 3)
          key(*pair) if pair.length == 2 && eligible?(*pair)
        end

        def targets?(entry, pair)
          return entry.registry_key.equal?(pair) if ClassHash.compare_by_identity?
          return false unless pair_name(pair) == entry.name
          keys = KEYS.bind(ClassHash).call
          pair.equal?(entry.registry_key) || !keys.any? { |item| item.equal?(pair) } || !keys.any? { |item| item.equal?(entry.registry_key) }
        end

        def moved?(entry)
          entry.registry_key && !ClassHash.compare_by_identity? && !entry.pair.eql?(entry.registry_key)
        end

        def reusable?(entry)
          return false unless entry
          discard(entry) if moved?(entry)
          !moved?(entry) && !ClassHash.compare_by_identity?
        end

        def registry_key(entry)
          ClassHash.compare_by_identity? ? entry.registry_key : entry.pair
        end

        def stale?(entry)
          @fifo.key?(entry) && !READ.bind(ClassHash).call(registry_key(entry), nil).equal?(entry.klass)
        end

        def discard(entry)
          entry.automatic = false
          @fifo.delete(entry)
        end

        def retain(entry)
          pair = entry.pair
          inserted = pair.dup
          actual = inserted
          unless ClassHash.compare_by_identity?
            registered = READ.bind(ClassHash).call(pair, nil)
            return registered if registered
            if HAS_KEY.bind(ClassHash).call(pair)
              actual = KEYS.bind(ClassHash).call.find { |item| pair.eql?(item) } || actual
            end
          end
          WRITE.bind(ClassHash).call(inserted, entry.klass)
          entry.registry_key = actual
          entry.version = (@version += 1)
          @fifo[entry] = true
          while @fifo.length > LIMIT
            old, = @fifo.shift
            if moved?(old)
              discard(old)
            elsif READ.bind(ClassHash).call(registry_key(old), nil).equal?(old.klass)
              DELETE.bind(ClassHash).call(registry_key(old))
            end
          end
          entry.klass
        end
      end
    end

    # User edits to the public registry invalidate automatic lookup entries.
    # Native Hash operations above distinguish internal eviction from deletion.
    module GenericRegistryChanges # :nodoc: all
      def []=(key, value)
        return super unless equal?(Dnsruby::ClassHash) && !frozen?
        pair = GenericCache.registry_pair(key)
        before = GenericCache.snapshot(pair)
        result = super
        GenericCache.register(before, pair, value)
        result
      end
      alias store []=

      def delete(key, &block)
        return super unless equal?(Dnsruby::ClassHash) && !frozen?
        pair = GenericCache.registry_pair(key)
        before = GenericCache.snapshot(pair)
        result = super
        GenericCache.forget(before, [pair], removed_only: true)
        result
      end

      def clear
        return super unless equal?(Dnsruby::ClassHash) && !frozen?
        before = GenericCache.snapshot
        result = super
        GenericCache.forget(before)
        GenericCache.rehash
        result
      end

      def replace(other)
        return super unless equal?(Dnsruby::ClassHash) && !frozen?
        # Native conversion can call back into the factory. Snapshot afterwards
        # so entries returned by to_hash become explicit registrations too.
        replacement = {}.replace(other)
        before = GenericCache.snapshot
        result = super(replacement)
        replacement.each_pair do |key, value|
          GenericCache.register(before, GenericCache.registry_pair(key), value)
        end
        GenericCache.forget(before)
        GenericCache.rehash
        result
      end

      def rehash
        result = super
        GenericCache.rehash if equal?(Dnsruby::ClassHash)
        result
      end

      [:merge!, :update].each do |operation|
        define_method(operation) do |*args, &block|
          return super(*args, &block) unless equal?(Dnsruby::ClassHash) && !frozen?
          before = keys
          snapshot = GenericCache.snapshot
          touched = []
          begin
            super(*args) do |key, old, value|
              value = block.call(key, old, value) if block
              touched << [key, value]
              value
            end
          ensure
            touched.each { |key, value| GenericCache.register(snapshot, key, value) }
            GenericCache.forget(snapshot, (keys - before) | touched.map(&:first))
            GenericCache.rehash
          end
        end
      end

      [:delete_if, :reject!, :keep_if, :select!, :filter!, :shift,
       :transform_keys!, :transform_values!, :compact!].each do |operation|
        define_method(operation) do |*args, &block|
          return super(*args, &block) unless equal?(Dnsruby::ClassHash) && !frozen?
          before = dup
          snapshot = GenericCache.snapshot
          begin
            super(*args, &block)
          ensure
            changed = (before.keys | keys).reject do |key|
              before.key?(key) && key?(key) && before[key].equal?(self[key])
            end
            GenericCache.forget(snapshot, changed)
            GenericCache.rehash
          end
        end
      end
    end
  end
  ClassHash.extend(RR::GenericRegistryChanges)
end
