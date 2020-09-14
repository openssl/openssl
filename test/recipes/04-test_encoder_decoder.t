#! /usr/bin/env perl
# Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir bldtop_file/;
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_encoder_decoder");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests =>
    ($no_fips ? 0 : 2)          # FIPS install test + test
    + 1;

my $conf = srctop_file("test", "default-and-legacy.cnf");
ok(run(test(["endecode_test", "-config", $conf])));

unless ($no_fips) {
    my $infile = bldtop_file('providers', platform->dso('fips'));

    ok(run(app(['openssl', 'fipsinstall',
                '-out', bldtop_file('providers', 'fipsmodule.cnf'),
                '-module', $infile])),
       "fipsinstall");

    my $conf = srctop_file("test", "fips.cnf");
    ok(run(test(["endecode_test",
                 "-config", $conf,
                 "-provider", "fips"])));
}
