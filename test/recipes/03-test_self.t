#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT bldtop_file/;
use OpenSSL::Test::Utils;

setup("test_self");

plan skip_all => "Only useful when building shared libraries"
    if disabled("shared");

my @known_selftests =
    ( "selftests/crypto/sha_keccak1600",
      "selftests/crypto/modes_cts128",
      "selftests/crypto/modes_gcm128",
      "selftests/crypto/poly1305_poly1305" );

plan tests => scalar @known_selftests;

foreach (@known_selftests) {
    ok(run(test([$_])), "Running $_");
}
