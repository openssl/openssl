#! /usr/bin/env perl
# Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir bldtop_file with/;
use OpenSSL::Test::Utils;
BEGIN { setup("test_nocache"); }

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

my $no_modules = disabled("module");

plan tests => 4;

ok(run(app(["openssl", "list", "-mac-algorithms"],
        stdout => "listout.txt")),
"List mac algorithms - default configuration");
open DATA, "listout.txt";
my @match = grep /MAC/, <DATA>;
close DATA;
ok(scalar @match > 1 ? 1 : 0, "Several algorithms are listed - default configuration");

SKIP: {
    skip "Tests requiring loadable modules", 2 if $no_modules;

    $ENV{OPENSSL_CONF} = bldtop_file("test", "nocache-and-default.cnf");
    $ENV{OPENSSL_MODULES} = bldtop_dir("test");
    ok(run(app(["openssl", "list", "-mac-algorithms"],
            stdout => "listout.txt")), "List mac algorithms");
    open DATA, "listout.txt";
    @match = grep /MAC/, <DATA>;
    close DATA;
    ok(scalar @match > 1 ? 1 : 0, "Several algorithms are listed - nocache-and-default");
}
