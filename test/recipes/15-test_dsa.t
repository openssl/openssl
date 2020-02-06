#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
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
plan tests => 7;

my $deprecated_dsa =
    disabled('deprecated') || !defined config('api') || config('api') >= 30000;

require_ok(srctop_file('test','recipes','tconversion.pl'));

 SKIP: {
     skip "Skipping initial dsa tests", 2
         if $deprecated_dsa;

     ok(run(test(["dsatest"])), "running dsatest");
     ok(run(test(["dsa_no_digest_size_test"])),
        "running dsa_no_digest_size_test");
}

 SKIP: {
     skip "Skipping dsa conversion test using 'openssl dsa'", 2
         if $deprecated_dsa;

     subtest "dsa conversions using 'openssl dsa' -- private key"> sub {
         tconversion("dsa", srctop_file("test","testdsa.pem"));
     };
     subtest "dsa conversions using 'openssl dsa' -- public key" => sub {
         tconversion("msb", srctop_file("test","testdsapub.pem"), "dsa",
                     "-pubin", "-pubout");
     };
}

subtest "dsa conversions using 'openssl pkey' -- private key PKCS#8" => sub {
    tconversion("dsa", srctop_file("test","testdsa.pem"), "pkey");
};
subtest "dsa conversions using 'openssl pkey' -- public key" => sub {
    tconversion("dsa", srctop_file("test","testdsapub.pem"), "pkey",
                "-pubin", "-pubout");
};
