#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir srctop_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_ml_dsa_composite_sig");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'ML DSA Composite signatures are not supported in this build'
    if disabled('ml-dsa-composite');

my $provconf = srctop_file("test", "fips-and-base.cnf");

# 1 C test run + 1 FIPS skip
plan tests => 2;

# ─── C unit test binary ──────────────────────────────────────────────────────
ok(run(test(["ml_dsa_composite_sig_test"])), "running ml_dsa_composite_sig_test");

# ─── FIPS variant ────────────────────────────────────────────────────────────
SKIP: {
    # ML DSA Composite algorithms are not present in the FIPS provider, so the test
    # binary will fail to load them under a FIPS+base library context.
    skip "ML DSA Composite signatures are not available in the FIPS provider", 1;

    ok(run(test(["ml_dsa_composite_sig_test", "-config", $provconf])),
       "running ml_dsa_composite_sig_test with FIPS");
}
