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

plan tests => 12;

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

# Checks a list of algorithms for any disabled algorithms
sub check_list_against_disabled {
    my ($algorithms_ref, $validator, $list_name) = @_;
    my @algorithms = @$algorithms_ref;
    my @disabled = run(app(["openssl", "list", "-disabled"]), capture => 1);

    chomp @algorithms;
    chomp @disabled;
    my $unmatched = 1;
    foreach my $manager (@algorithms){
      foreach my $algorithm (@disabled) {
        if (!$validator->($manager, $algorithm)) {
          print "Disabled algorithm found in $list_name list: $algorithm\n";
        }
        $unmatched = $unmatched && $validator->($manager, $algorithm);    
      }
    }
    ok($unmatched, "No disabled algorithms appear in ".$list_name." list");
}

# Checks the key manager list for any disabled algorithms
sub check_key_manager_list {
    my @keymanagers = run(app(["openssl", "list", "-key-managers"]), capture => 1);
    my $validator = sub {return !($_[0] =~ /IDs:.*\b\Q$_[1]\E\b/)};
    check_list_against_disabled(\@keymanagers, $validator, "key manager");
}

# Checks the public key algorithms list for any disabled algorithms
sub check_public_key_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-public-key-algorithms"]), capture => 1);
    my $validator = sub {return !($_[0] =~ /IDs:.*\b\Q$_[1]\E\b/)};
    check_list_against_disabled(\@pkalgorithms, $validator, "public key algorithms");
}

# Checks the key exchange algorithms list for any disabled algorithms
sub check_key_exchange_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-key-exchange-algorithms"]), capture => 1);
    my $validator = sub {return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/)};
    check_list_against_disabled(\@pkalgorithms, $validator, "key exchange algorithms");
}

# Checks the mac algorithms list for any disabled algorithms
sub check_mac_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-mac-algorithms"]), capture => 1);
    my $validator = sub {return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/)};
    check_list_against_disabled(\@pkalgorithms, $validator, "mac algorithms");
}

# Checks the cipher algorithms list for any disabled algorithms
sub check_cipher_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-cipher-algorithms"]), capture => 1);
    my $validator = sub { return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/) };
    check_list_against_disabled(\@pkalgorithms, $validator, "cipher algorithms");
}

# Checks the kem algorithms list for any disabled algorithms
sub check_kem_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-kem-algorithms"]), capture => 1);
    my $validator = sub { return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/) };
    check_list_against_disabled(\@pkalgorithms, $validator, "kem algorithms");
}

# Checks the signature algorithms list for any disabled algorithms
sub check_signature_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-signature-algorithms"]), capture => 1);
    my $validator = sub { return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/) };
    check_list_against_disabled(\@pkalgorithms, $validator, "signature algorithms");
}

# Checks the asymcipher algorithms list for any disabled algorithms
sub check_asymcipher_algorithms_list {
    my @pkalgorithms = run(app(["openssl", "list", "-asymcipher-algorithms"]), capture => 1);
    my $validator = sub { return !($_[0] =~ /{.*[0-9],.*\b\Q$_[1]\E\b/) };
    check_list_against_disabled(\@pkalgorithms, $validator, "asymcipher algorithms");
}

check_skey_manager_list("default");
check_key_manager_list();
check_public_key_algorithms_list();
check_key_exchange_algorithms_list();
check_mac_algorithms_list();
check_cipher_algorithms_list();
check_kem_algorithms_list();
check_signature_algorithms_list();
check_asymcipher_algorithms_list();

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
