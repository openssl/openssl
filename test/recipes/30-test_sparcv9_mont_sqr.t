#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Regression test for SPARCv9 asm bn_sqr_mont bug (sparcv9-mont.pl)

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

my $test_name = "test_sparcv9_mont_sqr";
setup($test_name);

# Determine the platform
my @lines = run(app(["openssl", "version", "-a"]), capture => 1);
my $platform = "";
foreach my $line (@lines) {
    if ($line =~ /platform:\s*(.+)/i) {
        $platform = $1;
    }
}

# Only meaningful on SPARCv9 builds
plan skip_all => "Not a SPARCv9 build"
    unless ($platform =~ /sparcv9|sparc64/i);

plan skip_all => "This build has no asm"
    if disabled("asm");

# Force-disable all SPARC crypto extensions (T4 etc.) to use sparcv9-mont.
# Keep it local to this recipe.
local $ENV{OPENSSL_sparcv9cap} = "0:0";

plan tests => 1;

ok(run(test(["sparcv9_mont_sqr_test"])), "running sparcv9_mont_sqr_test");

