# Release Notes

## v2.0.0

This release adds SVCB and HTTPS records, fixes resolver hangs and TCP reliability
problems, limits memory growth from unknown record types, and updates DNSSEC
trust anchors. Ruby 3.0 or later is required.

**Before upgrading:** applications that save automatically generated record
classes, or customise those classes, should read the compatibility notes below.
Existing IPv6 string formatting is preserved.

### Fixes and new features

* **SVCB and HTTPS records.** Read and write these records in DNS messages and zone
  files, including relative target names, numeric `keyNNNNN` values and escaped
  text. IPv6 hints use RFC 5952 formatting.
  [PR #222](https://github.com/alexdalitz/dnsruby/pull/222).
* **More reliable TCP queries.** Pipelined queries handle immediate replies,
  concurrent sends, partial writes and disconnected servers. Failed queries
  report an error promptly, and stalled writes respect the packet timeout.
  Malformed replies no longer interrupt unrelated queries or cause endless TCP
  retries. UDP-to-TCP fallback respects `no_tcp` and `ignore_truncation`.
  [#155](https://github.com/alexdalitz/dnsruby/issues/155).
* **Nameserver configuration fixes.** Hostname nameservers no longer cause
  recursive configuration hangs. IPv6 link-local nameservers accept interface
  zones, such as `fe80::1%eth0`, including in `resolv.conf`.
  [#179](https://github.com/alexdalitz/dnsruby/issues/179),
  [#184](https://github.com/alexdalitz/dnsruby/issues/184),
  [PR #221](https://github.com/alexdalitz/dnsruby/pull/221).
* **Updated DNSSEC root trust anchors.** Add KSK-2024 (key tag 38696), remove the
  revoked KSK-2010 key (19036), and restore the current anchors on `Dnssec.reset`.
  `Dnssec.clear_trusted_keys` clears learned keys and DS/DLV anchors while retaining
  configured DNSKEY anchors. Removing a local anchor discards keys learned from it.
  [#225](https://github.com/alexdalitz/dnsruby/issues/225).
* **Bounded memory use for unknown records.** Keep at most 256 automatically
  generated record classes in the cache. Classes and records held by your
  application remain usable, and explicit registrations are retained.
  Replacing registry entries also keeps weak-index bookkeeping bounded on
  Ruby 3.0–3.2, avoiding accumulating weak maps and slow finalizer processing.
* **Safe query-ID reuse.** Callbacks from a completed query cannot affect a new
  query reusing the same client ID, including when a callback overlaps `close`.
* **Zone-file parsing fixes.** Preserve quoted and escaped parentheses, comments
  and quotes in record values.
* **Correct DNS name-length checks.** Names longer than 255 octets on the wire now
  raise `ResolvError`, including some 256- and 257-octet names previously accepted.
  [PR #223](https://github.com/alexdalitz/dnsruby/pull/223).
* **Support `simpleidn` 0.3.x.** The supported range is now `>= 0.2.1`, `< 0.4.0`.
  Updating from 0.2.x can change Unicode-to-DNS name conversion; check the results
  if your application depends on exact converted names.
  [PR #224](https://github.com/alexdalitz/dnsruby/pull/224).

### Upgrading to v2

#### Automatically generated record classes

The memory limit changes how classes for unknown DNS type/class pairs are kept
alive. Ordinary named classes, such as `Dnsruby::RR::IN::A`, are unaffected.

* **Marshal:** automatically generated classes and their records can no longer
  be dumped with Marshal. This also affects messages and other containers holding
  those records; previously saved data using generated class names may not load.
* **Customisation:** keep a reference to a class obtained with
  `RR.get_class(type, klass)` and customise it with `class_eval`. Reopening a
  generated class with a `class Generic::TypeN_ClassN` declaration is unsupported.
  Customisations survive while the class or its records are held by your application.
* **Registries and reflection:** automatic `ClassHash` entries can be evicted,
  and generated names are no longer permanent Ruby constants. Ordinary lookup
  still works, but native constant enumeration and reflection can differ.

For a finite set of application-owned record types, call `Generic.create(type,
klass)` before creating records to retain permanent class names and normal
Marshal behaviour. Do not register arbitrary types received from the network:
doing so would restore unbounded memory use. Explicit `ClassHash` registrations
also remain persistent.

#### Existing caches

YAML persistence of automatically generated record classes and migration of
stored generic SVCB/HTTPS records are not supported. Ordinary named records are
unaffected.

The AXFR demo keeps its Marshal cache format. Transfers containing unsupported
generated records are displayed with a warning and leave any existing cache
unchanged. Unreadable legacy caches are refetched; use `-f` to force a fresh
transfer when needed.

#### SVCB and HTTPS record data

Types 64 and 65 now return parsed SVCB and HTTPS records. Existing `data` and
`rdata` readers still return the raw binary RDATA, and `rdlength` reports its
byte length. The bytes reflect changes to `priority`, `target`, or `params`.
Assign raw bytes with `rdata=` (or `data=`), or supply `rdata:` in `RR.create`'s
Hash, to update the parsed fields. Returned byte strings are snapshots; use
these writers to replace the record data. Presentation output uses the
registered `SVCB` and `HTTPS` mnemonics instead of `TYPE64` and `TYPE65`.

Decoded records also retain the original binary `@rdata` snapshot for existing
reflective consumers such as JSONDNS. As with other records' construction-time
metadata, that private snapshot does not track later field mutations; use the
public `rdata` reader for current bytes.

#### IPv6 formatting

`IPv6#to_s`, `#inspect` and existing record presentations keep their v1.74 output.
For canonical RFC 5952 text, explicitly call `IPv6#to_s_canonical`. This changes
only the presentation, not the DNS wire data.


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
