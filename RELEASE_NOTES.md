# Release Notes

## v2.0.0

This release adds SVCB and HTTPS records, fixes resolver hangs and TCP handling,
limits memory growth from unknown record types, and updates the DNSSEC trust
anchors. Ruby 3.0 or later is required.

The default UDP payload size is now 1232 bytes, down from 4096, and TSIG defaults
to HMAC-SHA256. Existing IPv6 string formatting is preserved. See the
compatibility notes below for the changes from 1.74.0.

### Fixes and new features

* **SVCB and HTTPS records.** Read and write these records in DNS messages and
  zone files, including relative target names, numeric `keyNNNNN` values and
  escaped text. IPv6 hints use RFC 5952 formatting.
  [PR #222](https://github.com/alexdalitz/dnsruby/pull/222).
* **TCP queries.** Pipelined queries handle concurrent sends, immediate replies,
  partial writes and disconnected servers. Connects and writes respect their
  deadlines, and cancellation releases the sender worker promptly. Matching
  replies is faster when many queries share a connection. Malformed replies no
  longer interrupt other queries or cause endless TCP retries.
  UDP-to-TCP fallback still respects `no_tcp` and `ignore_truncation`, and
  retrying without EDNS keeps the current transport.
  Ordinary queries reject replies with the wrong ID, opcode or query/response
  flag; `send_raw` retains its existing behavior.
  [#155](https://github.com/alexdalitz/dnsruby/issues/155).
* **Nameserver configuration.** Hostname nameservers no longer cause recursive
  configuration hangs. IPv6 link-local nameservers accept interface zones,
  such as `fe80::1%eth0`, including in `resolv.conf`.
  [#179](https://github.com/alexdalitz/dnsruby/issues/179),
  [#184](https://github.com/alexdalitz/dnsruby/issues/184),
  [PR #221](https://github.com/alexdalitz/dnsruby/pull/221).
* **DNSSEC root trust anchors.** Add KSK-2024 (key tag 38696), remove the revoked
  KSK-2010 key (19036), and restore the current anchors on `Dnssec.reset`.
  `Dnssec.clear_trusted_keys` clears learned keys and DS/DLV anchors while
  retaining configured DNSKEY anchors. Removing a configured anchor, or letting
  it expire, also removes keys learned from it. Keys with the same tag can
  coexist, and validation tries each matching key even if another is malformed
  or unusable.
  [#225](https://github.com/alexdalitz/dnsruby/issues/225).
* **Memory use for unknown records.** The cache holds at most 256 automatically
  generated record classes. Classes still held by an application remain usable,
  and explicit registrations are retained. Replacing registered classes no
  longer accumulates memory or slows garbage collection on Ruby 3.0–3.2.
* **Query cancellation and timeouts.** A callback from a completed query cannot
  affect a later query that reuses its ID. The total `query_timeout` also covers
  local DNSSEC validation; late results are ignored after timeout or close.
  Once validation starts, replies from other nameservers cannot replace the
  accepted answer. Waiting UDP and TCP writers check for cancellation at least
  every 50 ms while scheduled, without holding the cancellation lock.
* **Authenticated replies.** TSIG queries require a fresh authenticated exchange
  and do not use the shared response cache. Unsigned replies and invalid MACs
  are ignored while waiting for a valid reply; if none arrives, the timeout
  reports the authentication error. Authenticated BADTIME and BADTRUNC replies
  report the server's error. Queries are prepared before signing, including
  when the key is set on a Message. Already signed messages keep their headers
  and OPT record. Cache lookups also include the question class.
* **TSIG verification.** MACs are checked before timestamps and local truncation
  policy, and verification uses the Original ID as described in RFC 8945.
  Valid truncated MACs are supported; the optional `mac_length` setting controls
  the signing length and minimum accepted length in octets. Zone transfers
  accept up to 99 unsigned messages between signatures, authenticate the whole
  sequence, and reject decreasing signed timestamps. Reusing a ZoneTransfer
  gives each request a fresh signing time unless one was set explicitly.
  Malformed TSIG records are
  rejected, and configuring a key no longer writes its secret to the log.
* **EDNS.** The default UDP payload size is 1232 bytes, a conservative choice
  permitted by RFC 10001 section 3.2. Explicit sizes such as 4096 still work.
  The smaller default reduces fragmentation risk but may lead to more TCP
  retries. DNSSEC raises smaller limits to 1220 bytes, matching the minimum
  supported size in RFC 4035 section 4.1. Setting DO on an existing OPT preserves
  its size, options and other flags. A TCP FORMERR reply without a question can
  trigger a retry without optional EDNS; UDP still requires a matching question.
  Queries that need local DNSSEC validation keep EDNS enabled.
* **Closed completion queues.** A closed client Queue no longer interrupts
  completion or timeout delivery for other resolvers.
* **DNSSEC input checks.** Numeric type/class constructors and RRSIG
  type-covered setters reject values outside 0–65535. `verify_rrset` accepts
  a single DS/DLV anchor as well as an RRSet.
* **Query cleanup and parsing.** Completion and cancellation use a queue index
  instead of scanning every query. Simple zone-file records parse faster;
  quoted, escaped and multiline records keep the full parser. Parsing preserves
  parentheses, semicolons and quotes inside record values where appropriate.
  Ordinary record lookup no longer slows as numeric class names accumulate,
  and numeric type/class lookups allocate fewer temporary objects.
* **DNS name lengths.** Names longer than 255 octets on the wire now raise
  `ResolvError`, including some 256- and 257-octet names previously accepted.
  [PR #223](https://github.com/alexdalitz/dnsruby/pull/223).
* **simpleidn 0.3.x support.** The supported range is now `>= 0.2.1`, `< 0.4.0`.
  Updating from 0.2.x can change Unicode-to-DNS name conversion. Check the
  results if your application depends on exact converted names.
  [PR #224](https://github.com/alexdalitz/dnsruby/pull/224).

### Compatibility with 1.74.0

* **TSIG algorithms.** Omitting the algorithm now selects HMAC-SHA256 instead
  of HMAC-MD5. If your server uses MD5, either update the key on both sides or
  select MD5 explicitly with `resolver.tsig = key_name, secret, 'hmac-md5'`.
  Existing explicit MD5 settings still work. The
  [README](README.md#updating-tsig-keys) shows both options, including SHA-256
  settings that also work in 1.74.0.
  Selecting MD5 logs a warning once per process. Enable WARN logging before
  configuring TSIG to see it; the default log level is FATAL. MD5 is retained for
  compatibility, although RFC 8945 section 6 prohibits its use. SHA-1 remains
  supported as required by the RFC; SHA-256 is recommended. Dnsruby does not
  fall back to another algorithm automatically.
* **Generated record classes.** Unknown type/class pairs use a bounded cache.
  Records and classes held by an application remain usable, but automatic
  `ClassHash` entries can be evicted and generated classes are no longer
  permanent Ruby constants. Marshal/YAML persistence of these generated records
  is unsupported. Ordinary named classes, such as `Dnsruby::RR::IN::A`, are
  unaffected. To customise a generated class, keep the result of
  `RR.get_class(type, klass)` and use `class_eval`.
  For a fixed set of application-defined types, call `Generic.create(type,
  klass)` before creating records to retain permanent names and normal Marshal
  behavior. These explicit registrations stay in memory, so avoid registering
  arbitrary types received from the network. The 256-class cache limit does
  not include objects held by the application or the response cache.
* **Numeric names.** Numeric spellings keep their presentation on each object,
  but no longer register global aliases or change a code's preferred name.
  Explicit `Types.add_pair` and `Classes.add_pair` aliases still work.
* **SVCB and HTTPS.** Types 64 and 65 now return parsed records and use their
  registered names in text output. The `data` and `rdata` readers still return
  binary RDATA, reflecting changes to `priority`, `target` and `params`;
  `rdlength` reports its length. Use `rdata=`, `data=` or `RR.create` with
  `rdata:` to replace the data, since the readers return snapshots.
  Decoded records also retain their original `@rdata` for callers such as
  JSONDNS that read it directly; this private field does not track later edits.
  Malformed escapes are rejected. ALPN and DoC path lists allow only escaped
  commas and backslashes at their second escape layer. The `mandatory`, `port`,
  `ipv4hint`, `ech` and `ipv6hint` mnemonics do not allow presentation escapes;
  numeric `keyNNNNN` forms still accept escaped wire octets.
* **IPv6 text.** `IPv6#to_s`, `#inspect` and existing record presentations keep
  their 1.74.0 output. Use `IPv6#to_s_canonical` for RFC 5952 formatting.


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
