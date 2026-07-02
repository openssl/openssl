#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
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

setup("test_dsa");

plan skip_all => 'DSA is not supported in this build' if disabled('dsa');
plan tests => 9;

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["dsatest"])), "running dsatest");
ok(run(test(["dsa_no_digest_size_test"])),
   "running dsa_no_digest_size_test");

subtest "dsa conversions using 'openssl dsa' -- private key" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-priv',
                 -in => srctop_file("test","testdsa.pem") );
};
subtest "dsa conversions using 'openssl dsa' -- public key" => sub {
    tconversion( -type => 'msb', -prefix => 'dsa-msb-pub',
                 -in => srctop_file("test","testdsapub.pem"),
                 -args => ["dsa", "-pubin", "-pubout"] );
};

subtest "dsa conversions using 'openssl pkey' -- private key PKCS#8" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-pkcs8',
                 -in => srctop_file("test","testdsa.pem"),
                 -args => ["pkey"] );
};
subtest "dsa conversions using 'openssl pkey' -- public key" => sub {
    tconversion( -type => 'dsa', -prefix => 'dsa-pkey-pub',
                 -in => srctop_file("test","testdsapub.pem"),
                 -args => ["pkey", "-pubin", "-pubout"] );
};

SKIP: {
    skip "Skipping PVK conversion test", 1
        if disabled("rc4") || disabled("legacy") || disabled("pvkkdf");

    subtest "dsa conversions using 'openssl dsa' -- PVK" => sub {
        tconversion( -type => 'pvk', -prefix => 'dsa-pvk',
                     -in => srctop_file("test", "testdsa.pem"),
                     -args => ["dsa", "-passin", "pass:testpass",
                               "-passout", "pass:testpass",
                               "-provider", "default",
                               "-provider", "legacy"] );
    };
}

subtest "dsa PVK output is rejected for public key input" => sub {
    plan tests => 1;

    # Note: -noout would short-circuit before the format check, so request
    # an actual encoding to reach the PVK-with-public-key rejection.
    ok(!run(app(['openssl', 'dsa', '-pubin', '-outform', 'PVK',
                 '-in', srctop_file("test", "testdsapub.pem"),
                 '-out', 'dsa-pubin.pvk'])),
       "-outform PVK with -pubin is rejected");
};
