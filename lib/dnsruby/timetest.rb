class TestDomain
  ROOT_NAMESERVERS = %w[
      a.root-servers.net
      b.root-servers.net
      c.root-servers.net
      d.root-servers.net
      e.root-servers.net
      f.root-servers.net
      g.root-servers.net
      h.root-servers.net
      i.root-servers.net
      j.root-servers.net
      k.root-servers.net
      l.root-servers.net
      m.root-servers.net
    ].freeze

  def name
    "example.com"
  end

  def recursive_query(type, ns: ROOT_NAMESERVERS)
    return [] unless ns

    msg = nil
    puts "Time: #{Benchmark.realtime { msg = resolve_query(type, ns: ns, recurse: false, cache: ROOT_NAMESERVERS.intersect?(ns)) }}"
    return [] unless msg

    # The answer is received.
    return msg.answer.map { |rr| rr.rdata_to_string } if msg.answer

    # Another layer of intermediaries.
    authority = msg.authority.
      find_all { |rr| rr.type == Dnsruby::Types.NS }.
      map(&:rdata).map(&:to_s).reject(&:blank?)
    return [] unless authority

    recursive_query(type, ns: authority)
  end

  private

  def resolve_query(type, ns: nil, recurse: true, cache: true)
    puts "Caching: #{cache} | NS: #{ns.first}"

    resolver = Dnsruby::Resolver.
      new(recurse: recurse, do_caching: cache, retry_times: 2)

    resolver.nameserver = [ns].flatten.shift

    resolver.query(name, type)
  end
end