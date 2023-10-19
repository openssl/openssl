#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file srctop_file srctop_dir bldtop_dir);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_lms");
}

my $provconf = srctop_file("test", "fips-and-base.cnf");
my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan tests => 2 + ($no_fips ? 0 : 1);

ok(run(test(["lms_test"])), "running lms_test");
ok(run(test(["lms_test", "-pub", data_file("pub.bin"), "-sig", data_file("sig.bin")])),
   "running lms_test on file");
unless ($no_fips) {
    ok(run(test(["lms_test", "-config", $provconf, "-pub", data_file("pub.bin"), "-sig", data_file("sig.bin")])),
       "running lms_test on file using fips");
}

