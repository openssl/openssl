#! /usr/bin/env perl
# Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file data_dir/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
setup("test_threads");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);


plan tests => 1 + ($no_fips ? 0 : 1);

if (!$no_fips) {
    my $infile = bldtop_file('providers', platform->dso('fips'));
    ok(run(app(['openssl', 'fipsinstall',
            '-out', bldtop_file('providers', 'fipsmodule.cnf'),
            '-module', $infile])),
    "fipsinstall");
}

if ($no_fips) {
    $ENV{OPENSSL_CONF} = abs_path(srctop_file("test", "default.cnf"));
    ok(run(test(["threadstest", data_dir()])), "running test_threads");
} else {
    $ENV{OPENSSL_CONF} = abs_path(srctop_file("test", "default-and-fips.cnf"));
    ok(run(test(["threadstest", "-fips", data_dir()])), "running test_threads");
}
