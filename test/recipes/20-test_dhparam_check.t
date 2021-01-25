#! /usr/bin/env perl
# Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_dhparam_check");

plan skip_all => "DH isn't supported in this build"
    if disabled("dh");

=pod Generation script

#!/bin/sh

TESTDIR=test/recipes/20-test_dhparam_check_data/valid
rm -rf $TESTDIR
mkdir -p $TESTDIR

./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt dh_rfc5114:1 -out $TESTDIR/dh5114_1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt dh_rfc5114:2 -out $TESTDIR/dh5114_2.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt dh_rfc5114:3 -out $TESTDIR/dh5114_3.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt pbits:1024 -pkeyopt type:fips186_2 -out $TESTDIR/dh_p1024_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt pbits:2048 -pkeyopt type:fips186_2 -out $TESTDIR/dh_p2048_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt pbits:2048 -pkeyopt type:fips186_4 -out $TESTDIR/dh_p2048_t1864.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DH -pkeyopt pbits:3072 -pkeyopt type:fips186_2 -out $TESTDIR/dh_p3072_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p1024_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:1024 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p1024_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:1024 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p1024_q256_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_4 -out $TESTDIR/dhx_p1024_q160_t1864.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:2048 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p2048_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p2048_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p2048_q256_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_4 -out $TESTDIR/dhx_p2048_q224_t1864.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_4 -out $TESTDIR/dhx_p2048_q256_t1864.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:3072 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p3072_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:3072 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p3072_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DHX -pkeyopt pbits:3072 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/dhx_p3072_q256_t1862.pem

=cut

my @valid = glob(data_file("valid", "*.pem"));
#my @invalid = glob(data_file("invalid", "*.pem"));

my $num_tests = scalar @valid;# + scalar @invalid;
plan tests => 2 * $num_tests;

 SKIP: {
    skip "Skipping DH tests", $num_tests
        if disabled('deprecated-3.0');

    foreach (@valid) {
        ok(run(app([qw{openssl dhparam -noout -check -in}, $_])));
    }

#    foreach (@invalid) {
#        ok(!run(app([qw{openssl dhparam -noout -check -in}, $_])));
#    }
}

foreach (@valid) {
    ok(run(app([qw{openssl pkeyparam -noout -check -in}, $_])));
}

#foreach (@invalid) {
#    ok(!run(app([qw{openssl pkeyparam -noout -check -in}, $_])));
#}
