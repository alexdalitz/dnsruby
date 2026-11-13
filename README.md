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

Dnsruby uses one selector thread for responses and timeouts. TCP sends started
by that thread use a bounded worker pool, so a slow connect or write does not
block unrelated responses. Public sends remain synchronous in the caller.

See the [compatibility notes](RELEASE_NOTES.md#compatibility-with-1740) when
upgrading from 1.74.0, including the change to the default
[TSIG algorithm](#updating-tsig-keys).

The following is a (non-exhaustive) list of features :

- Implemented RRs :  A, AAAA, AFSDB, ANY, CAA, CERT, CNAME, DNAME,
     GPOS, HINFO, ISDN, LOC, MB, MG, MINFO, MR, MX, NAPTR, NS, NSAP,
     NXT, OPT, PTR, PX, RP, RT, SOA, SPF, SRV, SVCB, HTTPS, TKEY,
     TSIG, TXT, WKS, X25, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS, DLV

- Generic RR types supported (RFC3597)

- (Signed) Zone transfer (AXFR and IXFR) supported

- (Signed) Dynamic updates supported

- DNSSEC validation supported

Updating TSIG keys
------------------

TSIG now uses HMAC-SHA256 by default. The key name, algorithm and secret need
to match the DNS server's configuration. If your server uses MD5, you can
update both sides to SHA-256 or select MD5 explicitly.

With BIND, you can generate a SHA-256 key using
[tsig-keygen](https://bind9.readthedocs.io/en/stable/manpages.html#tsig-keygen-tsig-key-generation-tool):

```sh
tsig-keygen -a hmac-sha256 dnsruby-key.example.
```

Install the key on the server, give it the required update or transfer
permissions, and reload the configuration. If a script generates your keys,
update that too. Then use the same name and base64 secret in the application:

```ruby
resolver.tsig = 'dnsruby-key.example.', secret, 'hmac-sha256'
```

For a key set on a message:

```ruby
message.set_tsig(name: 'dnsruby-key.example.', key: secret,
                 algorithm: 'hmac-sha256')
```

These explicit SHA-256 settings also work in 1.74.0, so you can make the change
before upgrading. Keep the generated secret private.

To continue using an existing MD5 key, select it explicitly:

```ruby
resolver.tsig = key_name, secret, 'hmac-md5'
```

For a message, use `algorithm: 'hmac-md5'` in the `set_tsig` hash. Dnsruby keeps
this option for compatibility, although
[RFC 8945 section 6](https://www.rfc-editor.org/rfc/rfc8945.html#section-6)
prohibits MD5 use. SHA-256 is recommended, and there is no automatic fallback
to MD5.
A lost reply or an unauthenticated error is not a safe reason to retry with MD5.

Selecting MD5 logs a warning once per process. To see it, set
`Dnsruby.log.level = Logger::WARN` before configuring TSIG; the default log
level is FATAL.

DNSSEC validation limits
------------------------

DNSSEC replies can contain enough keys and signatures to make validation very
expensive. Dnsruby limits the work it will do for one answer, including any
queries needed to follow the chain of trust. The defaults are 64 signature
verification attempts, 100,000 work units (including key/signature comparisons
and NSEC3 hashes), and five seconds. Validation stops sooner if the query times
out or you close the resolver.

Hitting a limit raises `Dnsruby::ValidationLimitError`, which is a `VerifyError`.
The answer fails validation; it isn't accepted as an insecure answer. If your
application needs to validate unusually large amounts of trusted data, you can
change the limits before starting queries:

```ruby
Dnsruby::Dnssec.validation_limits = {
  max_signature_verifications: 128, max_work: 200_000, timeout: 10.0
}
```

Any settings you leave out use their defaults, and all limits must be positive.
For asynchronous validation, up to four workers can run at once, with another
64 responses waiting. Further responses fail with `ValidationLimitError`.

Cancellation is checked between operations and while waiting on the network.
An OpenSSL operation already in progress is allowed to finish first.

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

The separate soak target starts its own UDP/TCP server on an ephemeral loopback
port, using Ruby's standard-library DNS codec. It needs no public DNS access,
privileged port, or separately running server, and is not part of the standard
suites. After `bundle install`, run a small smoke workload first:

```sh
SOAK_THREADS=4 SOAK_ROUNDS=3 SOAK_ASYNC_ROUNDS=3 SOAK_TIMEOUT=30 bundle exec rake soak
```

For the default workload (81,512 queries across eight cases), allow enough file
descriptors and give each case a longer deadline on a busy laptop:

```sh
ulimit -n 4096
SOAK_TIMEOUT=300 bundle exec rake soak
```

Increase `SOAK_ROUNDS` and `SOAK_ASYNC_ROUNDS` for longer runs. The tests reject
errors, wrong responses and duplicate completions; they do not measure heap or
descriptor growth during a multi-day run. The old RubyDNS/NIO helper files remain
available but are not used by this harness.

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
