#! /usr/bin/env perl
# Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
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
plan tests => 6;
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

# Checks the key manager list for any disabled algorithms
sub check_key_manager_list {
    my @keymanagers = run(app(["openssl", "list", "-key-managers"]), capture => 1);
    my @disabled = run(app(["openssl", "list", "-disabled"]), capture => 1);

    chomp @keymanagers;
    chomp @disabled;
    my $unmatched = 1;
    foreach my $manager (@keymanagers){
      foreach my $algorithm (@disabled) {
        $unmatched = $unmatched && !($manager =~ /IDs:.*\Q$algorithm\E/);    
      }
    }
    ok($unmatched, "No disabled algorithms appear in key manager list");
}

# Checks the public key algorithms list for any disabled algorithms
sub check_public_key_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-public-key-algorithms"]), capture => 1);
    my @disabled = run(app(["openssl", "list", "-disabled"]), capture => 1);

    chomp @pkalgorithms;
    chomp @disabled;
    my $unmatched = 1;
    foreach my $pkalgorithm (@pkalgorithms){
      foreach my $algorithm (@disabled) {
        $unmatched = $unmatched && !($pkalgorithm =~ /IDs:.*\Q$algorithm\E/);    
      }
    }
    ok($unmatched, "No disabled algorithms appear in public key algorithms list");
}

check_skey_manager_list("default");
check_key_manager_list();
check_public_key_algorithms_list();

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
