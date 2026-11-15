#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

setup("test_allocation_reentry");

my @tests = (
    [ "control", "no allocation failure" ],
    [ "tls-master", "TLS master table allocation" ],
    [ "tls-sparse", "TLS sparse-array allocation" ],
    [ "sparse-array", "sparse-array object allocation" ],
    [ "sparse-node", "sparse-array node allocation" ],
);

unshift @tests, [ "lock", "pthread lock allocation" ]
    unless disabled("threads") || $^O =~ /^(MSWin32|msys)$/;

plan tests => scalar @tests;

for my $test (@tests) {
    ok(run(test([ "allocation_reentry_test", $test->[0] ])), $test->[1]);
}
