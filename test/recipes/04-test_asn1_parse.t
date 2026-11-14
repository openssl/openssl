#! /usr/bin/env perl
# Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw(:DEFAULT srctop_file);
use OpenSSL::Test::Utils;

setup("test_asn1_parse");

plan tests => 5;

$ENV{OPENSSL_CONF} = srctop_file("test", "test_asn1_parse.cnf");

ok(run(app(([ 'openssl', 'asn1parse',
              '-genstr', 'OID:1.2.3.4.1']))));

ok(run(app(([ 'openssl', 'asn1parse',
              '-genstr', 'OID:1.2.3.4.2']))));

ok(run(app(([ 'openssl', 'asn1parse',
              '-genstr', 'OID:1.2.3.4.3']))));

ok(run(app(([ 'openssl', 'asn1parse',
              '-genconf', srctop_file("test", "test_asn1_genconf.cnf")]))));

SKIP: {
    skip "OCSP disabled", 1 if disabled("ocsp");

    # An OCSPResponse with only responseStatus (ENUMERATED, value 1) set
    my $ocspresp = "ocspresp.der";
    open(my $out, ">:raw", $ocspresp) or die "Could not open $ocspresp";
    print $out "\x30\x03\x0a\x01\x01";
    close($out);

    my @out = run(app([ 'openssl', 'asn1parse', '-inform', 'DER',
                        '-in', $ocspresp, '-item', 'OCSP_RESPONSE' ]),
                  capture => 1);
    ok(grep(/^\s+responseStatus: 1$/, @out)
       && grep(/^\s+responseBytes: <ABSENT>$/, @out),
       "asn1parse -item prints an ENUMERATED field");
}
