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

setup("test_internal");

my %known_internal_tests =
  ( mdc2_internal_test => !disabled("mdc2"),
    poly1305_internal_test => !disabled("poly1305"),
    modes_internal_test => 1,
    asn1_internal_test => 1,
    x509_internal_test => 1 );

plan tests => scalar keys %known_internal_tests;

foreach (keys %known_internal_tests) {
 SKIP:
    {
	skip "Skipping $_, it's disabled in this configuration", 1
	    unless $known_internal_tests{$_};
	ok(run(test([$_])), "Running $_");
    }
}
