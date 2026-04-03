#! /usr/bin/env perl
# Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use File::Copy qw(cp);
use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir);
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_internal_provider");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;
my $dir = bldtop_dir("test");

if (!disabled("dso")) {
    my $ext = platform->dsoext();
    my $dso = platform->dso('p_test');
    my $active = platform->dso('p_test_active');
    my $passive = platform->dso('p_test_passive');

    mkdir("active") || die "mkdir(active): $!\n";
    mkdir("passive") || die "mkdir(passive): $!\n";
    cp("$dir/$dso", "active/$active") || die "cp $dir/$active: $!\n";
    cp("$dir/$dso", "passive/$passive") || die "cp $dir/$passive: $!\n";
}

$ENV{OPENSSL_MODULES} = $dir;
$ENV{OPENSSL_CONF} = "$dir/provider_internal_test.cnf";

simple_test("test_internal_provider", "provider_internal_test");
