#! /usr/bin/env perl
# Copyright 2017-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file/;
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_gendsa");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => "This test is unsupported in a no-dsa build"
    if disabled("dsa");

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests =>
    ($no_fips ? 0 : 2)          # FIPS related tests
    + 18;

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DSA params fips186_4 with verifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DSA params fips186_4 with unverifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'pbits:2048',
             '-pkeyopt', 'qbits:224',
             '-pkeyopt', 'digest:SHA512-256',
             '-pkeyopt', 'type:fips186_4'])),
   "genpkey DSA params fips186_4 with truncated SHA");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_2',
             '-text'])),
   "genpkey DSA params fips186_2");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'type:fips186_2',
             '-pkeyopt', 'dsa_paramgen_bits:1024',
             '-out', 'dsagen.legacy.pem'])),
   "genpkey DSA params fips186_2 PEM");

ok(!run(app([ 'openssl', 'genpkey', '-algorithm', 'DSA',
             '-pkeyopt', 'type:group',
             '-text'])),
   "genpkey DSA does not support groups");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-out', 'dsagen.pem'])),
   "genpkey DSA params fips186_4 PEM");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DSA',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'pbits:2048',
             '-pkeyopt', 'qbits:256',
             '-pkeyopt', 'type:fips186_4',
             '-outform', 'DER',
             '-out', 'dsagen.der'])),
   "genpkey DSA params fips186_4 DER");

ok(run(app([ 'openssl', 'genpkey',
             '-paramfile', 'dsagen.legacy.pem',
             '-pkeyopt', 'type:fips186_2',
             '-text'])),
   "genpkey DSA fips186_2 with PEM params");

# The seed and counter should be the ones generated from the param generation
# Just put some dummy ones in to show it works.
ok(run(app([ 'openssl', 'genpkey',
             '-paramfile', 'dsagen.der',
             '-pkeyopt', 'type:fips186_4',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'hexseed:0102030405060708090A0B0C0D0E0F1011121314',
             '-pkeyopt', 'pcounter:25',
             '-text'])),
   "genpkey DSA fips186_4 with DER params");

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'DSA'])),
   "genpkey DSA with no params should fail");

ok(run(app(["openssl", "gendsa", "-verbose",
            'dsagen.pem'])),
    "gendsa with -verbose option and dsagen parameter");

ok(!run(app(["openssl", "gendsa",
             'dsagen.pem', "-verbose"])),
   "gendsa with extra parameter (at end) should fail");

# test key generation with dsaparam tool
ok(run(app([ 'openssl', 'dsaparam',
             '-genkey',
             '-text',
             '1024',
             ])),
   "dsaparam -genkey DSA 1024 with default qbits");

ok(run(app([ 'openssl', 'dsaparam',
             '-genkey',
             '-text',
             '2048',
             ])),
   "dsaparam -genkey DSA 2048 with default qbits");

ok(run(app([ 'openssl', 'dsaparam',
             '-genkey',
             '-text',
             '1024', '160',
             ])),
   "dsaparam -genkey DSA 1024 with 160 qbits");

ok(run(app([ 'openssl', 'dsaparam',
             '-genkey',
             '-text',
             '2048', '224',
             ])),
   "dsaparam -genkey DSA 2048 with 224 qbits");

ok(run(app([ 'openssl', 'dsaparam',
             '-genkey',
             '-text',
             '2048', '256',
             ])),
   "dsaparam -genkey DSA 2048 with 256 qbits");
# genkey test for 3072 bits keys were removed to speed up the tests

unless ($no_fips) {
    my $provconf = srctop_file("test", "fips-and-base.cnf");
    my $provpath = bldtop_dir("providers");
    my @prov = ( "-provider-path", $provpath,
                 "-config", $provconf);

    $ENV{OPENSSL_TEST_LIBCTX} = "1";

    # DSA signing/keygen is not approved in FIPS 140-3
    run(test(["fips_version_test", "-config", $provconf, "<3.4.0"]),
             capture => 1, statusvar => \my $dsasignpass);

    # Generate params
    is(run(app(['openssl', 'genpkey',
                @prov,
               '-genparam',
               '-algorithm', 'DSA',
               '-pkeyopt', 'pbits:3072',
               '-pkeyopt', 'qbits:256',
               '-out', 'gendsatest3072params.pem'])),
       $dsasignpass,
       "Generating 3072-bit DSA params");

    # Generate keypair
    is(run(app(['openssl', 'genpkey',
                @prov,
               '-paramfile', 'gendsatest3072params.pem',
               '-text',
               '-out', 'gendsatest3072.pem'])),
       $dsasignpass,
       "Generating 3072-bit DSA keypair");

}
