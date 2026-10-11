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
    setup("test_evp_asym");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

require(srctop_file("test", "recipes", "evp.pl"));

my $no_dh = disabled("dh");
my $no_dsa = disabled("dsa");
my $no_ec = disabled("ec");
my $no_ecx = disabled("ecx");
my $no_sm2 = disabled("sm2") || disabled("x963kdf");
my $no_x942kdf = disabled("x942kdf");
my $no_determinstic_nonce = disabled("hmac-drbg-kdf");

# A list of tests that run with both the default and fips provider.
my @files = qw(
                evppkey_rsa.txt
                evppkey_rsa_common.txt
                evppkey_rsa_kem.txt
                evppkey_rsa_sigalg.txt
              );
push @files, qw(
                evppkey_ffdhe.txt
                evppkey_dh.txt
               ) unless $no_dh;
push @files, qw(evppkey_ffdhe_x942kdf.txt) unless ($no_x942kdf || $no_dh);
push @files, qw(
                evppkey_dsa.txt
                evppkey_dsa_sigalg.txt
               ) unless $no_dsa;
push @files, qw(
                evppkey_ecx.txt
                evppkey_ecx_sigalg.txt
                evppkey_mismatch_ecx.txt
               ) unless $no_ecx;
push @files, qw(
                evppkey_ecc.txt
                evppkey_ecdh.txt
                evppkey_ecdsa.txt
                evppkey_ecdsa_sigalg.txt
                evppkey_kas.txt
                evppkey_mismatch.txt
               ) unless $no_ec;
push @files, qw(
                evppkey_ecdsa_rfc6979.txt
               ) unless ($no_ec || $no_determinstic_nonce);

# A list of tests that only run with the default provider
# (i.e. The algorithms are not present in the fips provider)
my @defltfiles = ();
push @defltfiles, qw(evppkey_brainpool.txt) unless $no_ec;
push @defltfiles, qw(evppkey_ecx_kem.txt) unless $no_ecx;
push @defltfiles, qw(evppkey_dsa_rfc6979.txt) unless ($no_dsa || $no_determinstic_nonce);
push @defltfiles, qw(evppkey_sm2.txt) unless $no_sm2;

evp_tests(files => \@files, default_files => \@defltfiles);
