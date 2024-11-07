#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
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
    setup("test_slh_dsa");
}

my $provconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'SLH-DSA is not supported in this build' if disabled('slh-dsa');
plan tests => ($no_fips ? 0 : 1) + 1;

ok(run(test(["slh_dsa_test"])), "running slh_dsa_test");

unless ($no_fips) {
    ok(run(test(["slh_dsa_test", "-config",  $provconf])),
           "running slh_dsa_test with FIPS");
}
