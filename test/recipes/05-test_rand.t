#! /usr/bin/env perl
# Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_dir/;
use Cwd qw(abs_path);

plan tests => 5;
setup("test_rand");

ok(run(test(["rand_test", srctop_file("test", "default.cnf")])));

SKIP: {
    skip "Skipping FIPS test in this build", 1 if disabled('fips');

    ok(run(test(["rand_test", srctop_file("test", "fips.cnf")])));
}

ok(run(test(["drbgtest"])));
ok(run(test(["rand_status_test"])));

SKIP: {
    my $success;
    my @randdata;
    my $expected = '0102030405060708090a0b0c0d0e0f10';

    $ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));
    skip "provider modules are not supported by this OpenSSL build", 1
        if disabled("module");

    @randdata = run(app(['openssl', 'rand', '-provider', 'p_ossltest', '-provider', 'default', '-propquery', '?provider=p_ossltest', '-hex', '16' ]), capture => 1, statusvar => \$success);

    chomp(@randdata);
    ok($success && $randdata[0] eq $expected,
       "rand with ossltest provider: Check rand output is as expected");

    @randdata = run(app(['openssl', 'rand', '-hex', '2K' ]),
                    capture => 1, statusvar => \$success);
    chomp(@randdata);
}
