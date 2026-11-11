[![Build Status](https://github.com/alexdalitz/dnsruby/actions/workflows/ci.yml/badge.svg)]
[![Coverage Status](https://img.shields.io/coveralls/alexdalitz/dnsruby.svg)](https://coveralls.io/r/alexdalitz/dnsruby?branch=master)

<img src="http://caerkettontech.com/dnsruby/DNSRuby-colour-mid.png" width="200" height="200" />

Dnsruby
=======

Dnsruby is a pure Ruby DNS client library which implements a
stub resolver. It aims to comply with all DNS RFCs.

Dnsruby presents an enhanced API for DNS. It is based on Ruby's core
resolv.rb Resolv API, but has been much extended to provide a
complete DNS implementation.

Dnsruby runs a single I/O thread to handle all concurrent
queries. It is therefore suitable for high volume DNS applications.

**Upgrading to v2?** Read the [upgrade notes](RELEASE_NOTES.md#upgrading-to-v2),
particularly if you persist generated record classes or customise them. Legacy
IPv6 string formatting is preserved, and stored generic SVCB/HTTPS records can
be migrated by requiring `dnsruby/optional/yaml` before loading their YAML.

The following is a (non-exhaustive) list of features :

- Implemented RRs :  A, AAAA, AFSDB, ANY, CAA, CERT, CNAME, DNAME,
     GPOS, HINFO, ISDN, LOC, MB, MG, MINFO, MR, MX, NAPTR, NS, NSAP,
     NXT, OPT, PTR, PX, RP, RT, SOA, SPF, SRV, SVCB, HTTPS, TKEY,
     TSIG, TXT, WKS, X25, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS, DLV

- Generic RR types supported (RFC3597)

- (Signed) Zone transfer (AXFR and IXFR) supported

- (Signed) Dynamic updates supported

- DNSSEC validation supported

Dependencies
------------

Dnsruby requires Ruby 3.0 or later. RubyGems installs its `base64`, `logger` and
`simpleidn` dependencies. TSIG and DNSSEC also require Ruby's OpenSSL library;
tests that require OpenSSL are skipped when it is unavailable.

Demo Code
---------

The demo folder contains some example programs using Dnsruby.
These examples include a basic dig tool (rubydig) and a tool to
concurrently resolve many names, amongst others.

Unit Tests
----------

Tests require a current version of minitest (see the .gemspec file
for which version is required).  In order for the tests to run
successfully you may need to have the bundler gem installed and
run `bundle` or `bundle install` from the project root to install
a suitable version of minitest.

There are "online" and "offline" tests.  You can use rake to
conveniently run the tests.  From the project root you can run:
```
rake test          # run all tests
rake test_offline  # run only offline tests
rake test_online   # run only online tests
```
If you get the following error when running rake test tasks,
then you may need to preface the command with bundle exec to
ensure that the gem versions specified in Gemfile.lock are used
at runtime:

```
bundle exec rake test
```

The separate `rake soak` target uses the legacy manual harness in
`test/localdns.rb` and `test/test_dnsserver.rb`, which still needs the RubyDNS
and NIO development dependencies. It is not included in the standard suites;
the normal TCP pipelining tests use their own local server.

Usage Help
----------

IPv6 link-local nameservers need an interface zone, supplied as an interface
name or numeric index. For example:

```ruby
resolver = Dnsruby::Resolver.new(nameserver: 'fe80::1%en0')
response = resolver.query('example.com')
```

Use the address and interface of your DNS server. Scoped addresses also work
in `resolv.conf` (for example, `nameserver fe80::1%en0`). The zone is local
socket routing information and must not be included in an AAAA record.

IPv6 text keeps the historical Dnsruby format by default. To opt into canonical
RFC 5952 output, call `Dnsruby::IPv6.create('2001:DB8::1').to_s_canonical`, which
returns `2001:db8::1`.

There are a couple of blog articles that might be helpful
in understanding how to use Dnsruby. These used to be hosted by
Nominet UK, however the original content has been copied to the
dnsruby github wiki at :

https://github.com/alexdalitz/dnsruby/wiki

Contact/Links
-------

| Link Type | Link/Text |
|-----|-----
| Author Email | alex@caerkettontech.com |
| Github | https://github.com/alexdalitz/dnsruby |
| Google Group | https://groups.google.com/forum/#!forum/dnsruby |
| Rubygems | http://rubygems.org/gems/dnsruby/ |
| Documentation | https://www.rubydoc.info/gems/dnsruby/ |
