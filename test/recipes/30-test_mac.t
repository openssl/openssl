#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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
    setup("test_mac");
}

my $provconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan tests => 2;

ok(run(test(["mac_test"])), "running mac_test");

SKIP: {
    skip "Skipping FIPS tests", 1
        if $no_fips;

    ok(run(test(["mac_test", "-config",  $provconf])),
       "running mac_test with fips");
}
