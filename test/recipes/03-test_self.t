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

my $no_shared = disabled("shared");

my %known_selftests =
    ( "selftests/crypto/sha_keccak1600" => 1,
      "selftests/crypto/modes_cts128" => 1,
      "selftests/crypto/modes_gcm128" => $no_shared,
      "selftests/crypto/poly1305_poly1305" => $no_shared,
      "selftests/crypto/x509v3_tabtest" => $no_shared );

plan tests => scalar keys %known_selftests;

foreach (keys %known_selftests) {
 SKIP:
    {
	skip "Skipping $_, it can only run with no-shared configurations", 1
	    unless $known_selftests{$_};
	ok(run(test([$_])), "Running $_");
    }
}
