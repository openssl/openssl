#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_evp_ct");
}

# A subset of the evp_test data files exercising algorithms whose
# implementations carry CONSTTIME_SECRET annotations.
# The CT validation CI workflow runs this recipe under Valgrind
# (OSSL_VALGRIND_CT=yes) to check that those implementations are constant-time.
# Outside such a build/run this is a cheap functional re-run of the same files.
my @files = ();
# Covers crypto/ec/curve25519.c's ossl_x25519 entrypoint
# via Derive stanzas -> EVP_PKEY_derive -> ossl_x25519
push @files, qw(evppkey_ecx.txt) unless disabled("ecx");

plan skip_all => "No CT-annotated algorithms enabled in this build"
    if !@files;

plan tests => scalar(@files);

my $conf = srctop_file("test", "default.cnf");

foreach my $f (@files) {
    ok(run(test(["evp_test",
                 "-config", $conf,
                 srctop_file("test", "recipes", "30-test_evp_data", $f)])),
       "running evp_test -config default.cnf $f");
}
