#! /usr/bin/env perl
# Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_genrsa");

plan tests => 9;

# We want to know that an absurdly small number of bits isn't support
if (disabled("deprecated-3.0")) {
    is(run(app([ 'openssl', 'genpkey', '-out', 'genrsatest.pem',
                 '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:8',
                 '-pkeyopt', 'rsa_keygen_pubexp:3'])),
               0, "genrsa -3 8");
} else {
    is(run(app([ 'openssl', 'genrsa', '-3', '-out', 'genrsatest.pem', '8'])),
               0, "genrsa -3 8");
}

# Depending on the shared library, we might have different lower limits.
# Let's find it!  This is a simple binary search
# ------------------------------------------------------------
# NOTE: $good may need an update in the future
# ------------------------------------------------------------
note "Looking for lowest amount of bits";
my $bad = 3;                    # Log2 of number of bits (2 << 3  == 8)
my $good = 11;                  # Log2 of number of bits (2 << 11 == 2048)
my $fin;
while ($good > $bad + 1) {
    my $checked = int(($good + $bad + 1) / 2);
    my $bits = 2 ** $checked;
    if (disabled("deprecated-3.0")) {
        $fin = run(app([ 'openssl', 'genpkey', '-out', 'genrsatest.pem',
                         '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_pubexp:3',
                         '-pkeyopt', "rsa_keygen_bits:$bits",
                       ], stderr => undef));
    } else {
        $fin = run(app([ 'openssl', 'genrsa', '-3', '-out', 'genrsatest.pem',
                         $bits
                       ], stderr => undef));
    }
    if ($fin) {
        note 2 ** $checked, " bits is good";
        $good = $checked;
    } else {
        note 2 ** $checked, " bits is bad";
        $bad = $checked;
    }
}
$good++ if $good == $bad;
$good = 2 ** $good;
note "Found lowest allowed amount of bits to be $good";

ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'RSA',
             '-pkeyopt', 'rsa_keygen_pubexp:3',
             '-pkeyopt', "rsa_keygen_bits:$good",
             '-out', 'genrsatest.pem' ])),
   "genpkey -3 $good");
ok(run(app([ 'openssl', 'pkey', '-check', '-in', 'genrsatest.pem', '-noout' ])),
   "pkey -check");
ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'RSA',
             '-pkeyopt', 'rsa_keygen_pubexp:65537',
             '-pkeyopt', "rsa_keygen_bits:$good",
             '-out', 'genrsatest.pem' ])),
   "genpkey -f4 $good");
ok(run(app([ 'openssl', 'pkey', '-check', '-in', 'genrsatest.pem', '-noout' ])),
   "pkey -check");

 SKIP: {
    skip "Skipping rsa command line test", 4 if disabled("deprecated-3.0");

    ok(run(app([ 'openssl', 'genrsa', '-3', '-out', 'genrsatest.pem', $good ])),
       "genrsa -3 $good");
    ok(run(app([ 'openssl', 'rsa', '-check', '-in', 'genrsatest.pem', '-noout' ])),
       "rsa -check");
    ok(run(app([ 'openssl', 'genrsa', '-f4', '-out', 'genrsatest.pem', $good ])),
       "genrsa -f4 $good");
    ok(run(app([ 'openssl', 'rsa', '-check', '-in', 'genrsatest.pem', '-noout' ])),
       "rsa -check");
}
