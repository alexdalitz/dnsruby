# Release Notes

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

