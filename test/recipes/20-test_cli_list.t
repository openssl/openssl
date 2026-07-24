#! /usr/bin/env perl
# Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
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
plan tests => 14;
my $fipsconf = srctop_file("test", "fips-and-base.cnf");
my $defaultconf = srctop_file("test", "default.cnf");

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

my @match;

ok(run(app(["openssl", "list", "-commands"], stdout => "commands.txt")),
   "List standard commands");
open DATA, "commands.txt";
@match = grep /\blist\b/, <DATA>;
close DATA;
ok(scalar @match > 0, "The list command is among the standard commands");

ok(run(app(["openssl", "list", "-1", "-commands"], stdout => "commands1.txt")),
   "List standard commands in one column");
open DATA, "commands1.txt";
@match = grep /^list$/, <DATA>;
close DATA;
ok(scalar @match == 1, "One-column output has one command per line");

SKIP: {
    skip "Deprecated functionality is disabled", 1
        if disabled("deprecated");

    ok(run(app(["openssl", "list", "-digest-commands"])),
       "List digest commands");
}

ok(run(app(["openssl", "list", "-options", "list"], stdout => "options.txt")),
   "List options of the list command");
open DATA, "options.txt";
@match = grep /^select s$/, <DATA>;
close DATA;
ok(scalar @match == 1, "The select option is listed for the list command");

ok(run(app(["openssl", "list", "-disabled"])),
   "List disabled features, algorithms, and protocols");

ok(run(app(["openssl", "list", "-objects"], stdout => "objects.txt")),
   "List built-in objects");
open DATA, "objects.txt";
@match = grep /^CN = commonName, 2\.5\.4\.3$/, <DATA>;
close DATA;
ok(scalar @match == 1, "The commonName OID mapping is listed");

SKIP: {
    my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);
    skip "FIPS provider disabled or not installed", 2
        if $no_fips;

    run(test(["fips_version_test", "-config", $fipsconf, ">=3.6.0"]),
             capture => 1, statusvar => \my $exit);
    skip "FIPS provider version doesn't support skeymgmt", 2
        if !$exit;

    $ENV{OPENSSL_CONF} = $fipsconf;
    check_skey_manager_list("fips");
    $ENV{OPENSSL_CONF} = $defaultconf;
}
