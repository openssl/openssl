#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# The AES-GCM-SIV provider's POLYVAL has one kernel per CPU tier. Each run
# below masks the capability vector down one tier (the variables are ignored on
# the other architecture), so every kernel present is checked against the
# reference, not just the fastest one. OPENSSL_armcap is an absolute value:
# 61 = ARMV7_NEON | ARMV8_AES | ARMV8_SHA1 | ARMV8_SHA256 | ARMV8_PMULL.

use strict;
use warnings;
use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_internal_polyval");

my @tiers = (
    [ "native",             undef,                                        undef ],
    [ "no AVX-512 / VAES",  "~0:~0xFFFFFFFFD0230000",                     undef ],
    [ "no AVX",             "~0x1000000000000000:~0xFFFFFFFFFFFFFFFF",    undef ],
    [ "ARMv8 + AES/PMULL/SHA2, no SHA512/SHA3 (Cortex-A76 class)", undef, "61" ],
    [ "SSSE3 only / NEON only", "~0x0200000200000000:~0xFFFFFFFFFFFFFFFF", "1" ],
    [ "no SIMD",            "0",                                          "0" ],
);

plan tests => scalar @tiers;

foreach my $t (@tiers) {
    my ($name, $ia32cap, $armcap) = @$t;
    local $ENV{OPENSSL_ia32cap} = $ia32cap if defined $ia32cap;
    local $ENV{OPENSSL_armcap} = $armcap if defined $armcap;
    ok(run(test(["polyval_internal_test"])), "POLYVAL vs reference, tier: $name");
}
