#! /usr/bin/env perl
# Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_file srctop_file bldtop_dir with/;
use OpenSSL::Test::Utils;

setup("test_cli_list");

plan tests => 3;

sub check_skey_manager_list {
    my $provider = $_[0];
    ok(run(app(["openssl", "list", "-skey-managers"],
               stdout => "listout.txt")),
       "List skey managers - $provider provider");
    open DATA, "listout.txt";
    my @match = grep /secret key/, <DATA>;
    close DATA;
    ok(scalar @match > 1 ? 1 : 0,
       "Several skey managers are listed - $provider provider");
}

check_skey_manager_list("default");

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

subtest fips => sub {
    plan skip_all => "FIPS is disabled"
        if $no_fips;
    plan tests => 2;

    my $fipsconf = srctop_file("test", "fips-and-base.cnf");
    $ENV{OPENSSL_CONF} = $fipsconf;

    check_skey_manager_list("fips");

    my $defaultconf = srctop_file("test", "default.cnf");
    $ENV{OPENSSL_CONF} = $defaultconf;
};
