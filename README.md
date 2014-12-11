[![Build Status](https://travis-ci.org/alexdalitz/dnsruby.svg?branch=master)](https://travis-ci.org/alexdalitz/dnsruby)
[![Coverage Status](https://img.shields.io/coveralls/alexdalitz/dnsruby.svg)](https://coveralls.io/r/alexdalitz/dnsruby?branch=master)

Dnsruby
=======

Dnsruby is a pure Ruby DNS client library which implements a
stub resolver. It aims to comply with all DNS RFCs, including
DNSSEC NSEC3 support.

Dnsruby presents an enhanced API for DNS. It is based on Ruby's core
resolv.rb Resolv API, but has been much extended to provide a
complete DNS implementation.

Dnsruby runs a single I/O thread to handle all concurrent
queries. It is therefore suitable for high volume DNS applications.

The following is a (non-exhaustive) list of features :

- Implemented RRs :  A, AAAA, AFSDB, ANY, CERT, CNAME, DNAME,
     HINFO, ISDN, LOC, MB, MG, MINFO, MR, MX, NAPTR, NS, NSAP,
     OPT, PTR, PX, RP, RT, SOA, SPF, SRV, TKEY, TSIG, TXT, WKS,
     X25, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS, DLV

- Generic RR types supported (RFC3597)

- (Signed) Zone transfer (AXFR and IXFR) supported

- (Signed) Dynamic updates supported

- DNSSEC validation supported

Dependencies
------------

Dnsruby can run with no dependencies. However, if you wish to
use TSIG or DNSSEC then the OpenSSL library must be available.
This is a part of the Ruby standard library, but appears not to
be present on all Ruby platforms. If it is not available, then 
the test code will not run the tests which require it. Code which
attempts to use the library (if it is not present) will raise an
exception.

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

Nominet operates a test server which the Dnsruby test code queries.
If this server is not available then some of the online tests will 
not be run.


Usage Help
----------

There are a couple of blog articles that might be helpful
in understanding how to use Dnsruby:

* http://blog.nominet.org.uk/tech/2009/05/19/some-examples-of-dnsruby-in-action/
* http://blog.nominet.org.uk/tech/2009/05/21/examples-of-using-dnsruby-with-dnssec/


Contact
-------

alex@caerkettontech.com
https://github.com/alexdalitz/dnsruby

