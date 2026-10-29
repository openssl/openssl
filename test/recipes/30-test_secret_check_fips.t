#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Copy;
use OpenSSL::Test qw(:DEFAULT bldtop_dir bldtop_file srctop_file result_dir
                     result_file);
use OpenSSL::Test::Utils;

setup("test_secret_check_fips");

plan skip_all => "This test requires the FIPS provider"
    if disabled("fips") || ($ENV{NO_FIPS} // 0);
plan skip_all => "This test requires ML-DSA"
    if disabled("ml-dsa");

plan tests => 5;

# An ML-DSA-44 key whose seed is all zero bytes
my $key = srctop_file("test", "testmldsa44.pem");

# fips-and-base.cnf includes fipsmodule.cnf from OPENSSL_CONF_INCLUDE
$ENV{OPENSSL_CONF} = srctop_file("test", "fips-and-base.cnf");

# A copy of fipsmodule.cnf, whose only section is the FIPS provider's,
# with secret-check = 0 appended to that section
my $nocheck = result_file("fipsmodule.cnf");
my $fh;
ok(copy(bldtop_file("test", "fipsmodule.cnf"), $nocheck)
   && open($fh, '>>', $nocheck)
   && print($fh "secret-check = 0\n")
   && close($fh),
   "Write a FIPS module configuration with secret-check = 0");

$ENV{OPENSSL_CONF_INCLUDE} = bldtop_dir("test");
my $genkey = result_file("mldsa44.pem");
ok(run(app(['openssl', 'genpkey', '-algorithm', 'ML-DSA-44',
            '-out', $genkey]))
   && run(app(['openssl', 'pkey', '-in', $genkey, '-noout'])),
   "The FIPS provider accepts a generated key by default");

ok(!run(app(['openssl', '-allow-insecure-private-keys', 'pkey',
             '-in', $key, '-noout'])),
   "The FIPS provider rejects the key by default");

$ENV{OPENSSL_CONF_INCLUDE} = result_dir();
ok(run(app(['openssl', '-allow-insecure-private-keys', 'pkey',
            '-in', $key, '-noout'])),
   "The FIPS provider accepts the key with secret-check = 0");

ok(!run(app(['openssl', 'pkey', '-in', $key, '-noout'])),
   "libcrypto rejects the key with secret-check = 0 in the FIPS provider");
