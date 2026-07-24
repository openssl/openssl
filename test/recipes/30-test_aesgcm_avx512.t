#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT/;

setup("test_aesgcm_avx512");

plan tests => 2;

# See the overview comment above setup_tests() in test/aesgcm_avx512_test.c for
# what Test 1 and Test 2 each prove and why both are kept.

# Test 1: correctness across the internal dispatch boundaries against an
# independent reference (decrypt/recovery, split AAD/payload, in-place updates).
# Skips (internally) where VAES/AVX-512 is unavailable.
ok(run(test(["aesgcm_avx512_test", "aesgcm"])),
   "AES-GCM AVX-512 correctness across dispatch boundaries");

#
# Test 2: differential test against OpenSSL's non-VAES (AES-NI/CLMUL) GCM.
#
# The "dump" mode runs a deterministic grid (every dispatch-boundary length x
# key sizes 128/192/256 x IV/AAD lengths; chunked and in-place updates; encrypt
# + decrypt/verify; only the content is seeded-random) under whatever
# implementation libcrypto selects, and prints a SHA-256 digest over all
# outputs. We run it twice with identical inputs: once natively (the VAES/
# AVX-512 path on capable hardware) and once with OPENSSL_ia32cap masked so
# AVX512F is cleared and libcrypto falls back to its non-VAES GCM (the AES-NI +
# CLMUL-GHASH path). Equal digests prove the AVX-512 path is byte-identical to
# that independent, mature implementation.
sub dump_digest {
    my ($ia32cap) = @_;
    my @out;

    if (defined $ia32cap) {
        local $ENV{OPENSSL_ia32cap} = $ia32cap;
        @out = run(test(["aesgcm_avx512_test", "dump"]), capture => 1);
    } else {
        @out = run(test(["aesgcm_avx512_test", "dump"]), capture => 1);
    }
    foreach (@out) {
        return ($1, $2) if /^DIFFDIGEST:\s+VAES=(\d)\s+([0-9a-f]+)/;
    }
    return (undef, undef);
}

 SKIP: {
    my ($nvaes, $ndig) = dump_digest(undef);

    # VAES=1 is emitted only when ossl_vaes_vpclmulqdq_capable() is true, i.e.
    # libcrypto actually dispatched the sweep to the VAES/AVX-512 backend.
    skip "AVX-512/VAES not available on this host", 1
        unless defined $nvaes && $nvaes eq "1";

    # Clear AVX512F (CPUID leaf 7 EBX bit 16) so ossl_vaes_vpclmulqdq_capable()
    # returns 0 and the non-VAES (AES-NI/CLMUL) GCM is used instead. (AES-NI is
    # left enabled, so this is the AES-NI path, not the pure-C generic.)
    my ($gvaes, $gdig) = dump_digest(":~0x10000");

    # Require the two runs to have used different backends (VAES=1 vs VAES=0)
    # AND to have produced byte-identical output. This proves the AVX-512 path
    # was exercised and matches the mature AES-NI implementation.
    ok(defined $ndig && defined $gdig
       && defined $gvaes && $gvaes eq "0"
       && $ndig eq $gdig,
       "AVX-512 GCM (VAES=1) byte-identical to non-VAES AES-NI GCM (VAES=0) "
       . "over sweep");
}
