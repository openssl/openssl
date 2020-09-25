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
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_gendsa");

plan skip_all => "This test is unsupported in a no-dsa build"
    if disabled("dsa");

plan tests => 10;

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
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'hexseed:0102030405060708090A0B0C0D0E0F1011121314',
             '-pkeyopt', 'pcounter:25',
             '-text'])),
   "genpkey DSA fips186_4 with DER params");

ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'DSA'])),
   "genpkey DSA with no params should fail");
