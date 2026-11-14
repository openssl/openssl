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
use OpenSSL::Test::Utils;

setup("test_internal_chachapoly_fused");

plan skip_all => "ChaCha is not supported by this OpenSSL build"
    if disabled("chacha");
plan skip_all => "Poly1305 is not supported by this OpenSSL build"
    if disabled("poly1305");

plan tests => 2;

# Test 1: kernel and one-shot EVP against the two-pass oracle, at the
# park cutoffs (191/192/193, 959/960/961), the r^n cutoff (255/256/257),
# and the AAD hold limit (127/128/129).
ok(run(test(["chachapoly_fused_test"])),
   "ChaCha20-Poly1305 fused kernel and one-shot EVP vs two-pass oracle");

#
# Test 2: differential dump.  Native IFMA path vs OPENSSL_ia32cap with IFMA
# (CPUID.7:0.EBX bit 21, OPENSSL_ia32cap_P[2] 0x200000) cleared so the
# provider uses two-pass ChaCha20 then Poly1305.  Equal SHA-256 digests over
# the same one-shot edge grid prove the fused and two-pass EVP outputs match.
#
sub ifma_capable {
    my $status = 0;
    my @out = run(test(["chachapoly_fused_test", "probe"]),
                  capture => 1, statusvar => \$status);

    return undef unless $status;
    foreach (@out) {
        return $1 if /^IFMACAP:\s+(\d)/;
    }
    return undef;
}

sub dump_digest {
    my ($ia32cap) = @_;
    my $status = 0;
    my @out;

    {
        local $ENV{OPENSSL_ia32cap} = $ia32cap if defined $ia32cap;
        @out = run(test(["chachapoly_fused_test", "dump"]),
                   capture => 1, statusvar => \$status);
    }
    return (0, undef, undef) unless $status;
    foreach (@out) {
        return (1, $1, $2) if /^DIFFDIGEST:\s+IFMA=(\d)\s+([0-9a-f]+)/;
    }
    return (1, undef, undef);
}

 SKIP: {
    my $cap = ifma_capable();

    skip "AVX-512/IFMA not available on this host", 1
        if defined $cap && $cap ne "1";

    unless (defined $cap) {
        ok(0, "ChaCha20-Poly1305 IFMA capability probe succeeded");
    } else {
        my ($nok, $nifma, $ndig) = dump_digest(undef);

        unless ($nok && defined $nifma && $nifma eq "1") {
            ok(0, "ChaCha20-Poly1305 dump (native) succeeded and printed "
                . "DIFFDIGEST for the IFMA path");
        } else {
            my ($gok, $gifma, $gdig) = dump_digest(":~0x200000");

            ok($gok && defined $gifma && defined $gdig && defined $ndig
               && $gifma eq "0"
               && $ndig eq $gdig,
               "fused ChaCha20-Poly1305 (IFMA=1) byte-identical to two-pass "
               . "EVP (IFMA=0) over fuse-edge sweep");
        }
    }
}
