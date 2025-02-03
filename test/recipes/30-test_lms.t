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

my $provconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

run(test(["fips_version_test", "-config", $provconf, ">=3.6.0"]),
         capture => 1, statusvar => \my $exit);

plan skip_all => "FIPS provider does not support LMS" if !$exit;

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'LMS is not supported in this build' if disabled('lms');
plan tests => 1 + + ($no_fips ? 0 : 1);

ok(run(test(["lms_test"])), "running lms_test");

unless ($no_fips) {
    ok(run(test(["lms_test", "-config",  $provconf])),
       "running lms_test with fips");
}
