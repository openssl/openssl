#! /usr/bin/env perl
# Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file bldtop_dir srctop_file srctop_dir bldtop_file);
use OpenSSL::Test::Utils;

BEGIN {
setup("test_provider_status");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan skip_all => "provider_status is not supported by this test"
    if $no_fips;

plan tests => 2;

my $infile = bldtop_file('providers', platform->dso('fips'));

ok(run(app(['openssl', 'fipsinstall',
            '-out', bldtop_file('providers', 'fipsmodule.cnf'),
            '-module', $infile])),
   "fipsinstall");

ok(run(test(["provider_status_test", "-config", srctop_file("test","fips.cnf"),
             "-provider_name", "fips"])),
   "running provider_status_test");
