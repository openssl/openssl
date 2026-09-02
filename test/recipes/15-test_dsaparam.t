#! /usr/bin/env perl
# Copyright 2017-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec;
use File::Copy;
use File::Compare qw/compare_text/;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_dsaparam");

=pod Generation script

#!/bin/sh

TESTDIR=test/recipes/15-test_dsaparam_data/valid
rm -rf $TESTDIR
mkdir -p $TESTDIR

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_4 -out $TESTDIR/p1024_q160_t1864.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_4 -out $TESTDIR/p2048_q224_t1864.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_4 -out $TESTDIR/p2048_q256_t1864.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:256 -pkeyopt type:fips186_4 -out $TESTDIR/p3072_q256_t1864.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_4 -pkeyopt gindex:1 -out $TESTDIR/p1024_q160_t1864_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_4 -pkeyopt gindex:1 -out $TESTDIR/p2048_q224_t1864_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_4 -pkeyopt gindex:1 -out $TESTDIR/p2048_q256_t1864_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:256 -pkeyopt type:fips186_4 -pkeyopt gindex:1 -out $TESTDIR/p3072_q256_t1864_gind1.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/p1024_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/p1024_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/p1024_q256_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/p2048_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/p2048_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/p2048_q256_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -out $TESTDIR/p3072_q160_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -out $TESTDIR/p3072_q224_t1862.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -out $TESTDIR/p3072_q256_t1862.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p1024_q160_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p1024_q224_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p1024_q256_t1862_gind1.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p2048_q160_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p2048_q224_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p2048_q256_t1862_gind1.pem

./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:160 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p3072_q160_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:224 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p3072_q224_t1862_gind1.pem
./util/opensslwrap.sh genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt qbits:256 -pkeyopt type:fips186_2 -pkeyopt gindex:1 -out $TESTDIR/p3072_q256_t1862_gind1.pem

=cut

plan skip_all => "DSA isn't supported in this build"
    if disabled("dsa");

my @valid = glob(data_file("valid", "*.pem"));
my @invalid = glob(data_file("invalid", "*.pem"));

my $num_tests = scalar @valid + scalar @invalid + 4;
plan tests => $num_tests;

foreach (@valid) {
    ok(run(app([qw{openssl pkeyparam -noout -check -in}, $_])));
}

foreach (@invalid) {
    ok(!run(app([qw{openssl pkeyparam -noout -check -in}, $_])));
}

my $input = data_file("valid", "p3072_q256_t1864.pem");
my $inout = "inout.pem";
copy($input, $inout);
ok(run(app(['openssl', 'dsaparam', '-in', $inout, '-out', $inout])),
    "identical infile and outfile");
ok(!compare_text($input, $inout), "converted file $inout did not change");

# Cover the DER (ASN.1) output paths of the dsaparam app.
my $srcparams = data_file("valid", "p1024_q160_t1862.pem");
my $params_der = "dsaparam.der";
my $key_der = "dsakey.der";

subtest "dsaparam DER parameter output" => sub {
    plan tests => 2;

    # Exercises i2d_KeyParams_bio().
    ok(run(app(['openssl', 'dsaparam', '-in', $srcparams,
                '-outform', 'DER', '-out', $params_der])),
       "write DSA parameters in DER form");
    ok(run(app(['openssl', 'dsaparam', '-inform', 'DER', '-in', $params_der,
                '-noout'])),
       "read the DER DSA parameters back");
};

subtest "dsaparam DER private key output with -genkey" => sub {
    plan tests => 2;

    # Exercises i2d_PrivateKey_bio().
    ok(run(app(['openssl', 'dsaparam', '-in', $srcparams, '-genkey',
                '-outform', 'DER', '-out', $key_der])),
       "generate a DSA key and write it in DER form");
    ok(run(app(['openssl', 'pkey', '-inform', 'DER', '-in', $key_der,
                '-noout', '-check'])),
       "read the DER DSA private key back");
};
