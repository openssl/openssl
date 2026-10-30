#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file srctop_dir);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_evp_pqc");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

require(srctop_file("test", "recipes", "evp.pl"));

my $no_ec = disabled("ec");
my $no_ecx = disabled("ecx");
my $no_ml_dsa = disabled("ml-dsa");
my $no_ml_kem = disabled("ml-kem");
my $no_lms = disabled("lms");

# A list of tests that run with both the default and fips provider.
my @files = ();
push @files, qw(
                evpmd_ml_dsa_mu.txt
                evppkey_ml_dsa_keygen.txt
                evppkey_ml_dsa_siggen.txt
                evppkey_ml_dsa_sigver.txt
                evppkey_ml_dsa_44_wycheproof_sign.txt
                evppkey_ml_dsa_44_wycheproof_verify.txt
                evppkey_ml_dsa_65_wycheproof_sign.txt
                evppkey_ml_dsa_65_wycheproof_verify.txt
                evppkey_ml_dsa_87_wycheproof_sign.txt
                evppkey_ml_dsa_87_wycheproof_verify.txt
               ) unless $no_ml_dsa;
push @files, qw(
                evppkey_ml_kem_512_keygen.txt
                evppkey_ml_kem_512_encap.txt
                evppkey_ml_kem_512_decap.txt
                evppkey_ml_kem_768_keygen.txt
                evppkey_ml_kem_768_encap.txt
                evppkey_ml_kem_768_decap.txt
                evppkey_ml_kem_1024_keygen.txt
                evppkey_ml_kem_1024_encap.txt
                evppkey_ml_kem_1024_decap.txt
                evppkey_ml_kem_keygen.txt
                evppkey_ml_kem_encap_decap.txt
               ) unless $no_ml_kem;
push @files, qw(evppkey_mlx_kem_ecx.txt) unless ($no_ml_kem || $no_ecx);
push @files, qw(evppkey_mlx_kem_ec.txt) unless ($no_ml_kem || $no_ec);
push @files, qw(
                evppkey_lms_sigver.txt
               ) unless $no_lms;

evp_tests(files => \@files);
