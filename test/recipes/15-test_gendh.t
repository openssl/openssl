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

setup("test_gendh");

plan skip_all => "This test is unsupported in a no-dh build" if disabled("dh");

plan tests => 13;

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DH',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DH params fips186_4 with verifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DH',
             '-pkeyopt', 'type:fips186_4',
             '-text'])),
   "genpkey DH params fips186_4 with unverifiable g");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DH',
             '-pkeyopt', 'pbits:2048',
             '-pkeyopt', 'qbits:224',
             '-pkeyopt', 'digest:SHA512-224',
             '-pkeyopt', 'type:fips186_4'])),
   "genpkey DH params fips186_4 with truncated SHA");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DH',
             '-pkeyopt', 'type:fips186_2',
             '-text'])),
   "genpkey DH params fips186_2");

ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'DH',
             '-pkeyopt', 'type:group',
             '-text'])),
   "genpkey DH default group");

ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'DH',
             '-pkeyopt', 'type:group',
             '-pkeyopt', 'group:ffdhe2048',
             '-text'])),
   "genpkey DH group ffdhe2048");

ok(run(app([ 'openssl', 'genpkey', '-genparam',
             '-algorithm', 'DH',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'type:fips186_4',
             '-out', 'dhgen.pem' ])),
   "genpkey DH params fips186_4 PEM");

# The seed and counter should be the ones generated from the param generation
# Just put some dummy ones in to show it works.
ok(run(app([ 'openssl', 'genpkey',
             '-paramfile', 'dhgen.pem',
             '-pkeyopt', 'gindex:1',
             '-pkeyopt', 'hexseed:0102030405060708090A0B0C0D0E0F1011121314',
             '-pkeyopt', 'pcounter:25',
             '-text' ])),
   "genpkey DH fips186_4 with PEM params");

 ok(!run(app([ 'openssl', 'genpkey',
              '-algorithm', 'DH'])),
   "genpkey DH with no params should fail");

 ok(!run(app([ 'openssl', 'genpkey', '-algorithm', 'DH', '-pkeyopt',
               'group:ffdhe3072', '-pkeyopt', 'priv_len:255', '-text'])),
    'genpkey DH with a small private len should fail');

 ok(!run(app([ 'openssl', 'genpkey', '-algorithm', 'DH', '-pkeyopt',
               'group:ffdhe3072', '-pkeyopt', 'priv_len:3072', '-text'])),
    'genpkey DH with a large private len should fail');

 ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'DH', '-pkeyopt',
              'group:ffdhe3072', '-pkeyopt', 'priv_len:256', '-text'])),
    'genpkey DH with a minimum strength private len');

 ok(run(app([ 'openssl', 'genpkey', '-algorithm', 'DH', '-pkeyopt',
              'group:ffdhe2048', '-pkeyopt', 'priv_len:224', '-text'])),
    'genpkey 2048 DH with a minimum strength private len');
