#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
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

my $provconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);
my $no_lms = disabled('lms');
my $no_hss = disabled('hss');
my $fips_count = ($no_fips ? 0 : 1);

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'LMS is not supported in this build' if $no_lms && $no_hss;
plan tests => ($no_lms ? 0 : (1 + $fips_count)) + ($no_hss ? 0 : (1 + $fips_count));

unless ($no_lms) {
    ok(run(test(["lms_test"])), "running lms_test (LMS)");
    unless ($no_fips) {
        ok(run(test(["lms_test", "-config",  $provconf])),
           "running lms_test (LMS) with fips");
    }
}

unless ($no_hss) {
    ok(run(test(["lms_test", "-keytype", "HSS"])), "running lms_test (HSS)");
    unless ($no_fips) {
        ok(run(test(["lms_test", "-config",  $provconf, "-keytype", "HSS"])),
           "running lms_test (HSS) with fips");
    }
}
