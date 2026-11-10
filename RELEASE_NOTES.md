# Release Notes

## v2.0.0

This release fixes resolver hangs and unbounded memory growth, updates DNSSEC
trust anchors, and adds support for SVCB and HTTPS records.

**Before upgrading:** v2 changes Ruby persistence and reflection for automatically
generated record classes, makes their YAML compatibility opt-in, and changes
IPv6 text formatting. See the upgrade notes below if you cache Ruby objects,
customise record classes, or compare address strings.

### Main fixes and new features

* **Bound memory use for unknown record types.** Dnsruby now keeps at most 256
  automatically generated record classes in its strong-reference cache. Unused
  classes can be collected; classes and records still held by your application
  remain usable. Explicit registrations are retained.
* **Update the DNSSEC root trust anchors.** Add KSK-2024 (key tag 38696), remove the
  revoked KSK-2010 key (19036), and restore the current anchors on `Dnssec.reset`.
  Fixes [#225](https://github.com/alexdalitz/dnsruby/issues/225).
* **Fix nameserver-related hangs.** Hostname nameservers no longer cause recursive
  resolver configuration, and IPv6 link-local nameservers can include an interface
  zone such as `%eth0`. Fixes [#179](https://github.com/alexdalitz/dnsruby/issues/179)
  and [#184](https://github.com/alexdalitz/dnsruby/issues/184), with separate fixes
  for the problems discussed in [PR #221](https://github.com/alexdalitz/dnsruby/pull/221).
* **Make TCP queries recover cleanly from bad replies and disconnects.** Restore
  local pipelining tests ([#155](https://github.com/alexdalitz/dnsruby/issues/155))
  and handle peer closure correctly.
  Malformed replies no longer stop the shared selector or prevent unrelated
  queries from finishing. Malformed truncated TCP replies fail with a decode
  error instead of starting an endless retry loop. UDP-to-TCP fallback respects
  `no_tcp` and `ignore_truncation`.
* **Add SVCB and HTTPS record support.** Parse, encode and read these records from
  zone files, including relative TargetName values. Also fix escaped quotes in
  zone-file character strings, and use standard IPv6 text formatting (see below).
  Included in [PR #222](https://github.com/alexdalitz/dnsruby/pull/222).
* **Enforce the DNS name-length limit correctly.** Check the 255-octet limit
  against the encoded wire name. Names of 256 or 257 wire octets that previously
  slipped through now raise `ResolvError`.
  [PR #223](https://github.com/alexdalitz/dnsruby/pull/223).
* **Allow `simpleidn` 0.3.x as well as 0.2.x.** The supported range is now
  `>= 0.2.1`, `< 0.4.0`. Updating this dependency can change Unicode name
  conversion; see below. [PR #224](https://github.com/alexdalitz/dnsruby/pull/224).

### Upgrading to v2

#### Automatically generated record classes

These changes affect classes Dnsruby creates for unknown DNS type/class pairs.
Ordinary named record classes, such as `Dnsruby::RR::IN::A`, are unaffected by
these persistence and reflection changes.

* **Marshal is no longer supported for automatically generated classes.** This
  includes their records and any message, array or hash containing those records.
  Previously saved Marshal data using generated class names may also fail to
  load. DNS wire encoding remains available, but it is not a replacement for
  arbitrary Ruby object persistence.
* **Keep a reference to classes you customise.** Obtain the class with
  `RR.get_class(type, klass)` and use `class_eval` instead of reopening it with a
  `class Generic::TypeN_ClassN` declaration. While you hold the class or one of its
  records, its identity and customisations are preserved. If it is collected and
  later recreated, those customisations are lost.
* **Do not treat `ClassHash` as a history of every generated type.** Automatic
  entries can be evicted. Explicit `Generic.create` and `ClassHash` registrations
  remain persistent, including entries supplied through `ClassHash.replace`.
  Custom factories that allocate their own classes remain responsible for their
  memory use.
* **Generated names are resolved on demand, rather than stored as permanent Ruby
  constants.** Ordinary lookup and `Generic.const_defined?` still work. Code that
  depends on native constant enumeration, `defined?`, `const_source_location`,
  `remove_const`, or exact `inspect` output needs adjustment. Explicitly named
  registrations retain their normal Ruby constant behaviour.

For a finite set of application-owned record types, call
`Generic.create(type, klass)` before creating records if you need permanent class
names and normal Marshal behaviour. Do not do this for arbitrary types received
from the network: permanent registrations would restore unbounded retention.

#### Optional YAML support and existing caches

YAML compatibility for automatically generated record classes is now an explicit
opt-in. If you save or load those records, their class objects, or messages that
contain them, load the adapter shipped with Dnsruby:

```ruby
require 'dnsruby/optional/yaml'
```

This loads Dnsruby and YAML, respecting an already selected Psych version.
Ordinary named records, such as `Dnsruby::RR::IN::TXT`, do not need the adapter.
Loading the core library alone neither loads Psych nor installs YAML hooks or
load-order observers.

With the adapter enabled, existing YAML using generated record paths remains
supported. Safe loading still requires the appropriate permitted classes and
aliases. Without it, loading YAML for automatically generated classes fails;
use the explicit require above when migrating an application that relied on
this behaviour.

Two limits remain:

* **Custom classes nested beneath an automatically generated class are not
  supported.** Their old YAML paths may fail to load, and new dumps may not round
  trip. Put custom data classes in a stable application namespace, or explicitly
  register a finite set of record types with `Generic.create` before defining
  nested classes or creating records.
* **Load the adapter before freezing `Psych::ClassLoader`.** Installing it on an
  already frozen loader raises `FrozenError` with an explanation. Freezing the
  loader after installation is supported. The core library and ordinary named
  record YAML continue to work without installing the adapter.

The AXFR demo keeps its existing Marshal cache format. It prints transfers that
contain unsupported dynamic records with a warning, leaving any previous cache
unchanged. It refetches legacy caches whose generated class names cannot be
loaded. After an uncached transfer, use `-f` to force another transfer rather than
reuse an older cache.

#### Address and name formatting

* **IPv6 text now follows RFC 5952.** `IPv6#to_s` and `#inspect` use lowercase hex,
  omit leading zeros and compress the longest run of zero fields. This also
  affects text from AAAA, IPSECKEY and APL records. IPv4-mapped addresses use forms
  such as `::ffff:192.0.2.1`; deprecated IPv4-compatible addresses remain in hex.
  This formatting change does not alter wire encoding. Update tests or code that
  compares the old text literally.
* **Unicode conversion depends on your `simpleidn` version.** Version 0.3 uses
  Unicode 17 mappings, while 0.2.3 uses Unicode 15.1. For example,
  `"\u04C0.example"` converts to `xn--s5a.example` with 0.3 instead of
  `xn--d5a.example` with 0.2.3. Existing lockfiles may retain 0.2.x; review conversion
  results when updating the dependency if exact DNS names matter to your code.

### Other behaviour and compatibility details

* Simplify the generated-record cache by removing duplicate lookup bookkeeping.
  Registration, deletion, live-class lookup and eviction behaviour are preserved.
* `Dnssec.clear_trusted_keys` continues to clear learned keys and all DS/DLV
  anchors, including built-in root DS anchors, while retaining configured DNSKEY
  anchors. Removing a local anchor also discards keys learned from it.
  `Dnssec.reset` restores the built-in root anchors.
* Hostname nameserver bootstrap preserves the configured UDP payload size.
  Names containing `:` or `%` still undergo DNS lookup unless the complete string
  is a valid scoped IPv6 endpoint. Explicit IPv6 parsing rejects malformed
  compression and invalid zones.
* A malformed reply is assigned only to an identifiable query on its receiving
  socket. Unknown or ambiguous IDs leave queries active so valid replies and
  timeouts can still be processed. TCP framing handles even zero-, one- and
  two-byte malformed payloads. Malformed UDP replies must match the expected
  address and port, and the ID when present.
* SVCB/HTTPS recognise `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`,
  `ech`, `ipv6hint`, `dohpath`, `ohttp` and `docpath`; other keys use `keyNNNNN`.
* `Generic.const_defined?` reports whether a generated name can be resolved,
  including numeric names not used before. Native reflection and checks through
  other receivers, such as `Object.const_defined?`, do not gain this behaviour.
  On a `Generic` subclass, `const_get(name, false)` can still resolve a virtual
  generated name even when `const_defined?(name, false)` is false. This exception
  does not apply to permanently defined classes. When an explicit registration is
  deleted and regenerated, its stale native binding is removed so YAML can find
  the replacement live class.
* Add offline DNSSEC rollover, trust-anchor lifecycle and malformed-response
  regression tests, local TCP/scoped IPv6 transport tests, and DS digest coverage
  with modern OpenSSL.
* Make the TCP source-port test use an available local port, and isolate YAML
  load-order tests from Bundler and inherited Ruby preloads. This prevents test
  failures caused by occupied ports or the test runner activating Psych early.

## v1.74.0

* Resolve all configured nameservers in parallel
* Only raise ArgumentError from Resolver if _all_ configured nameservers are invalid - otherwise, just log the bad one(s) and continue
* print out extra OPT data
*  Fix wakeup socket deletion on stopping of select thread
* Make sure to add nameservers if using config_info in Resolver
* Fix for RRSET pruning and potential cache poisoning - thanks Alexander Tan
* Fix WKS record protocol field encoding and decoding size according to RFC 1035 Section 3.4.2 where PROTOCOL is an 8 bit (#220)
* Updating workflows to include Ruby 4, and get rdoc working for it

## v1.73.1

* fix(caa): add support for issuevmc (#214) - thanks Mark McDonnell!

## v1.73.0

* Ruby 3.4 updates - thanks @zarqman!
* Enable setting up a custom UDP size when DNSSEC validation is disabled
* EDNS OPT RR for udp_size > 512 - thanks @mrideout!
* Test code improvements - thanks @mrideout!
* base64 gem version fixes
* Fix for file descriptor leak on truncated UDP messages

## v1.72.4

* allow parsing case insensitive property tags for CAA records - thanks ruby-dev!
* Add logger as a dependency for Ruby 3.5.0+ support - thanks Alexandre ZANNI!

## v1.72.3

* Fix cached answer response time - thanks Andre Meij!
* Add base64 as a dependency for Ruby 3.4.0+ support - thanks Alexandre ZANNI!

## v1.72.2

* Invalid CAA handling fixes - thanks Noah Smethwick and Ryan Doherty!

## v.1.72.1

* Add issuemail CAA record support - thanks Ryan Doherty!

## v.1.72.0

* Fix compatibility with the `--enable-string-literal` Ruby option - thanks Jean byroot Boussier!

## v.1.71.0

* Fix assigning public_key in ECDSA - thanks Jiří Kubíček!

## v.1.70.0

* OpenSSL 3 support
* Resource record hashes no longer include the rdata
* Removed requite to title-cased Digest - thanks jhawthron

## v.1.61.9

* Remove unused net-ftp dependency

## v.1.61.8

* Fix compatability with Ruby 3.1 - thanks @byroot Jean Boussier
* Get the digdlv demo to enable dnssec

## v1.61.7

* Fix namespace issue from v1.61.6

## v1.61.6

* RD bit not set on Recursor queries (thanks Sean Dilda!)
* Handle quoted strings followed by unquoted strings in TXT records
* do not worry about rogue repeated Ids - just log an error and get on with life
* Clear Ruby warnings
* Use GitHub Actions rather than Travis

## v1.61.5

* CAA record fixes - add contactphone and contactemail
* Fix eprecation warnings

## v1.61.4

* Dnsruby::Name : document .punycode
* gemspec enhancement
* add yard build file
* fix create name include url special characters
* Fix uninitialized constant error when using via Rails
* Implement ECDSAP256SHA256 (13) / ECDSAP384SHA384 (14) algorithms for DNSKEY
* Reinitialize all IANA TAR keys with Dnssec.reset

## v1.61.3

* TCP timeout and port changes

## v1.61.2

* Add new root key

## v1.61.1

* Add Addressable as a gem runtime dependency

## v1.61.0

* Add URI, CDS and CDNSKEY records
* Supply port to DNS.new as optiona parameter
* Supply timeout to zone transfer connect
* Fix multi-line strings
* Try absolute name as candidate in DNS even if not dot supplied
* Do not try to generate candidates if no domain is given
* Handle new OpenSSL interface as well as old
* Handle new DSA interface
* fix encode error select thread issue
* handle encoding errors
* add punycode support
* Make sure dnssec is enabled in verifier and also in digroot demo
* Other minor fixes and changes to test code and infrastructure

## v1.60.2

* Fix deletion of TXT records with spaces in dynamic updates (thanks Sean Dilda)
* Fix use of non-default ports in Dnsruby::Resolver (thanks Thomas Morgan)
* Fix NAPTR encoding for null rdata dynamic update packets
* Fix CAA resource record encoding
* Avoid changing ruby global thread abort behavior (thanks Brent Cook)

## v1.60.1

* DNSSEC validation switched OFF by default (but can still be switched on)
* Add APL RR support (thanks Manabu Sonoda)
* Various test fixes (thanks Keith Bennett)
* 'include' issues fixed (thanks Keith Bennett!)
* Fixnum replacement (thanks Keith Bennett)
* Zone transfer fixes (thanks Manabu Sonoda)
* Name decoding fix
* MX record passing error now raised
* CAA RR support (thanks Richard Luther)
* TLSA RR support (thanks Manabu Sonoda)


## v1.60.0

* TCP multi-packet support fixed
* Response 'Message' now included with exception.
* Docs added
* CNAME dynamic update fix

## v1.59.3

* Output TXT record multiple strings correctly
* NONE class encoding fix
* only add name labels if there are any

## v1.59.2

* Timeout error fix

## v1.59.1

* Support for HMAC SHA512 TSIG keys
* Fix TCP pipelining tests
* IDN encoding error returned as Dnsruby::OtherResolvError

## v1.59.0

* Add LICENSE file
* Add Cache max_size (gihub issue 64)
* Disable caching for SOA lookups in demo check_soa.rb
* Fix for invalid nameserver in config
* Fix encoding for OPT data (thanks Craig Despeaux)
* Various test system fixes
* OPT fixes
* DNSSEC verification failure handling wrt lack of DS chain
* DNSSEC validation policy name constants
* Fix for BOGUS DLV chains
* demo upgrades
* Resolver hints improvements 


## v1.58.0

* Add TCP pipelining (reusing a single TCP connection for multiple requests).
* Enhance zone reading, including reading data from a string.
* Add add_answer! method for adding duplicate answers, as needed for an AXFR response.
* Add support for GPOS and NXT resource records.
* Test cleanup, including removal of use of Nominet servers, soak_test cleanup.
* Refactorings: MessageDecoder, Resolv, Resolver (part).
* Fix zone reader adding unwanted dot to relative hostnames being converted to absolute.
* Fix default access for tsig options in Resolver.
* Fix ZoneTransfer not to use deprecated SingleResolver.
* Fix Resolver bug in parameter to create_tsig_options.
* Fix tests to always use working copy and not gem.


## v1.57.0

* Add query_raw method as alias for send_plain_message, with option to raise or return error.
* Fixed a bug in RR hash calculation where TTL should have been ignored but wasn't.
* Add support for (obsolete) GPOS resource record type.
* Tweak Travis CI configuration.
* Fix zone reader for case where a line contains whitespace preceding a comment.
* Add post install message.
* Improve README.
* Moved content of NEWS to RELEASE_NOTES.md.
* Use git ls-files now to determine files for inclusion in gem.


## v1.56.0

* Drop support for Ruby 1.8, using lambda -> and hash 'key: value' notations.
* First release since the move from Rubyforge to Github (https://github.com/alexdalitz/dnsruby).
* Add EDNS client subnet support.
* Relocate CodeMapper subclasses, Resolv, RR, and RRSet classes.
* Add Travis CI and coveralls integration.
* Improve Google IPV6 support.
* Convert some file names to snake case.
* Remove trailing whitespace from lines, and ensure that comments have space between '#' and text.
* Restore test success when running under JRuby.
* Disabled attempt to connect to Nominet servers, which are no longer available.
* Convert from test/unit to minitest/autorun to support Ruby 2.1+.
* Remove setup.rb.
* Other minor refactoring and improvements to production code, test code, and documentation.


## v1.53

* Validation routine fixes
* Ruby 1.9 fixes
* Recursor fixes
* IPv4 Regex fixes
* Fixes for A/PTR lookups with IP-like domain name
* TXT and SSHFP processing fixes
* Default retry parameters in Resolver more sensible


## v1.48

* Fixed deadlock/performance issue seen on some platforms
* DNSSEC validation now disabled by default
* Signed root DS record can be added to validator
* ITAR support removed
* multi-line DS/RRSIG reading bug fixed (thanks Marco Davids!)
* DS algorithms of more than one digit can now be read from string
* LOC records now parsed correctly
* HINFO records now parsed correctly


## v1.42

* Complicated TXT and NAPTR records now handled correctly
* ZoneReader now handles odd escape characters correctly
* Warns when immediate timeout occurs because no nameservers are configured
* Easy hmac-sha1/256 options to Resolver#tsig=
* ZoneReader fixed for "IN CNAME @" notations
* ZoneReader supports wildcards
* Dnsruby.version method added - currently returns 1.42


## v1.41

* RFC3597 unknown classes (e.g. CLASS32) now handled correctly
    in RRSIGs
* Resolver#do_caching flag added for Resolver-level caching
* DNSKEY#key_tag now cached - only recalculated when key data
    changes
* Bugfix where Resolver would not time queries out if no 
    nameservers were configured
* Recursor now performs A and AAAA queries in parallel
* Fix for zero length salt
* Fixing priming for signed root
* Fixes for DLV verification
* Other minor fixes


## v1.40

* Zone file reading support added (Dnsruby::ZoneReader)
* Name and Label speed-ups
* CodeMapper speed-ups
* DHCID RR added
* LOC presentation format parsing fixed
* KX RR added
* Quotations now allowed in text representation for ISDN, X25 and HINFO
* AFSDB from_string fixes
* Fixing CERT types and from_string
* CERT now allows algorithm 0
* Fix for DS record comparison
* HIP RR added
* Minor bug fixes
* IPSECKEY RR added
* Clients can now manipulate Name::Labels
