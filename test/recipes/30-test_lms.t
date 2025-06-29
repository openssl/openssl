#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_file srctop_dir bldtop_dir);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_lms");
}

plan skip_all => 'LMS is not supported in this build' if disabled('lms');

my $fipsconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

unless ($no_fips) {
    run(test(["fips_version_test", "-config", $fipsconf, ">=3.6.0"]),
        capture => 1, statusvar => $no_fips);
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan tests => 2;

ok(run(test(["lms_test"])), "running lms_test");

SKIP: {
    skip "No FIPS support for LMS (either no FIPS provider, or it doesn't include LMS)", 1
        if $no_fips;

    ok(run(test(["lms_test", "-config",  $fipsconf])),
       "running lms_test with fips");
}
