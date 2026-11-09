#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# AArch64 ML-KEM NTT/INTT, following FIPS 203 Section 4.3, Algorithms 9/10
# and the interfaces in crypto/ml_kem/ml_kem.c.
#
# The transforms operate on 256 coefficients modulo q = 3329.  Seven layers
# leave 128 coefficient pairs: forward lengths 128..2, inverse lengths 2..128.
# Twiddle factors are z = 17^bitrev7(i) mod q; inverse layers use their inverses.
# Each z has a reduction constant c = round(2^15*z/q).
# Inputs and outputs are canonical [0,q); intermediate lanes are signed 16-bit.
# Twiddle multiplication: r = low16(x*z) - q*round(x*c/2^15).
#
# Eight halfword lanes are processed in parallel.  Lengths >= 16 use paired
# vector butterflies; length 8 uses adjacent vectors.  Lengths 4 and 2 batch
# several groups with lane-packed roots.
#
# Forward lazy-reduction bounds after layers 1 through 7:
#
#   [-1702,5030], [-3575,6903], [-5546,8874], [-7625,10953],
#   [-9800,13128], [-12096,15424], [-14520,17848].
#
# These fit signed 16-bit lanes and require only one final canonicalization.
# Inverse sum paths are center-reduced after layers 3 and 6, bounding the final
# layer by [-4421,4421].  Scaling by the inverse of 128 modulo q (3303, or -26)
# is fused with canonicalization.
#
# Long layers are unrolled; lengths 4 and 2 each loop over sixteen batches.
# Final reduction/scaling passes each use eight 64-byte iterations.
# Addresses and branch conditions depend only on public offsets and counters;
# canonicalization uses sign masks.
use strict;
use warnings;

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m|(.*[\\/])[^\\/]+$|;
my $dir = $1;
my $xlate;
($xlate = "${dir}arm-xlate.pl" and -f $xlate) or
($xlate = "${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT, "| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $q = 3329;
my $code = '';

# Register aliases.
my $coeff_base = 'x0';

my ($packed_zc, $q_reg) = ('w9', 'w11');
my $twiddle_ptr = 'x12';
my ($coeff_ptr, $batches_left) = ('x1', 'w2');
my ($a_v, $b_v, $product_v, $tmp_v, $sum_v, $batch_a_v) =
    map("v$_", (0, 1, 2, 3, 5, 4));
my ($a2_v, $b2_v, $product2_v, $tmp2_v, $sum2_v) =
    map("v$_", (16, 17, 18, 19, 20));
my ($a_q, $b_q, $product_q, $sum_q) =
    map("q$_", (0, 1, 2, 5));
my ($a2_q, $b2_q, $product2_q, $sum2_q) =
    map("q$_", (16, 17, 18, 20));
my ($barrett_v, $c_v, $z_v, $q_v) =
    map("v$_", (28, 29, 30, 31));
my ($c_q, $z_q) = map("q$_", (29, 30));
# Indexed halfword operands must use v0-v15.  v6 holds z and c in lanes 0/1.
my ($intt_zc_v, $intt_zc_s) = ('v6', 's6');

# Inverse (z,c) pairs for lengths >= 8; c = round(2^15*z/q).
my %intt_zc_constants = (
    # Layer 3
    8 => [
        -821, -8081, 1355, 13338, 450, 4429, 936, 9213,
        447, 4400, -535, -5266, 1235, 12156, -1426, -14036,
        -1333, -13121, 1089, 10719, -56, -551, 283, 2786,
        -1476, -14529, -1339, -13180, 882, 8682, -296, -2914,
    ],
    # Layer 4
    16 => [
        1583, 15582, -569, -5601, 69, 679, 543, 5345,
        -797, -7845, -193, -1900, 1410, 13879, -1062, -10453,
    ],
    # Layer 5
    32 => [
        -848, -8347, 1432, 14095, -630, -6201, 687, 6762,
    ],
    # Layer 6
    64 => [
        40, 394, 749, 7373,
    ],
    # Layer 7
    128 => [
        1600, 15749,
    ],
);

# Center the first len coefficients of each stride-sized inverse block.
# Only these sum paths can exceed the later signed-16-bit bound.
sub intt_reduce {
    my ($len, $stride) = @_;
    # Product halves are already reduced by twiddle multiplication.
    for (my $base = 0; $base < 256; $base += $stride) {
        for (my $j = 0; $j < $len; $j += 8) {
            my $off = 2 * ($base + $j);
            $code .= <<___;
        ldr     $a_q, [$coeff_base, #$off]

        sqrdmulh $tmp_v.8h, $a_v.8h, $barrett_v.8h
        mls     $a_v.8h, $tmp_v.8h, $q_v.8h

        str     $a_q, [$coeff_base, #$off]
___
        }
    }
}

# Forward Cooley-Tukey butterflies, unrolled for lengths >= 8.
# For each group with twiddle z:
#   for each butterfly pair (a,b):
#       t = b*z mod q
#       (a,b) = (a+t,a-t)
sub ntt_vector_layer {
    my ($len) = @_;

    if ($len == 8) {
        for (my $start = 0; $start < 256; $start += 2 * $len) {
            $code .= <<___;
        ldp     $z_q, $c_q, [$twiddle_ptr], #32
___
            my $a = 2 * $start;
            $code .= <<___;
        ldp     $a_q, $b_q, [$coeff_base, #$a]

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $z_v.8h
        sqrdmulh $tmp_v.8h, $b_v.8h, $c_v.8h
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h

        // Butterfly sum/difference.
        sub     $sum_v.8h, $a_v.8h, $product_v.8h
        add     $a_v.8h, $a_v.8h, $product_v.8h

        stp     $a_q, $sum_q, [$coeff_base, #$a]
___
        }
    } else {
        for (my $start = 0; $start < 256; $start += 2 * $len) {
            $code .= <<___;
        ldp     $z_q, $c_q, [$twiddle_ptr], #32
___
            for (my $j = 0; $j < $len; $j += 16) {
                my $a = 2 * ($start + $j);
                my $b = 2 * ($start + $len + $j);

                $code .= <<___;
        ldp     $a_q, $a2_q, [$coeff_base, #$a]
        ldp     $b_q, $b2_q, [$coeff_base, #$b]

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $z_v.8h
        mul     $product2_v.8h, $b2_v.8h, $z_v.8h
        sqrdmulh $tmp_v.8h, $b_v.8h, $c_v.8h
        sqrdmulh $tmp2_v.8h, $b2_v.8h, $c_v.8h
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h
        mls     $product2_v.8h, $tmp2_v.8h, $q_v.8h

        // Butterfly sum/difference.
        sub     $sum_v.8h, $a_v.8h, $product_v.8h
        sub     $sum2_v.8h, $a2_v.8h, $product2_v.8h
        add     $a_v.8h, $a_v.8h, $product_v.8h
        add     $a2_v.8h, $a2_v.8h, $product2_v.8h

        stp     $a_q, $a2_q, [$coeff_base, #$a]
        stp     $sum_q, $sum2_q, [$coeff_base, #$b]
___
            }
        }
    }
}

# Length 2 batches four [a0,a1 | b0,b1] groups as 32-bit blocks;
# length 4 batches two [a0..a3 | b0..b3] groups as 64-bit blocks.
# For each 32-byte batch:
#   (a,b) = deinterleave(load_batch())
#   z = load_lane_twiddles()
#   t = b*z mod q
#   store_interleaved(a+t,a-t)
sub ntt_interleaved_layer {
    my ($len) = @_;
    my $shape = $len == 2 ? '.4s' : '.2d';
    my $loop = ".Lossl_ml_kem_ntt_armv8_length${len}_loop";
    $code .= <<___;
        mov     $coeff_ptr, $coeff_base
        mov     $batches_left, #16
$loop:
        ldp     $z_q, $c_q, [$twiddle_ptr], #32
        ldp     $a_q, $b_q, [$coeff_ptr]
        uzp1    $batch_a_v$shape, $a_v$shape, $b_v$shape
        uzp2    $b_v$shape, $a_v$shape, $b_v$shape

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $z_v.8h
        sqrdmulh $tmp_v.8h, $b_v.8h, $c_v.8h
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h

        // Butterfly sum/difference.
        sub     $sum_v.8h, $batch_a_v.8h, $product_v.8h
        add     $batch_a_v.8h, $batch_a_v.8h, $product_v.8h

        zip1    $a_v$shape, $batch_a_v$shape, $sum_v$shape
        zip2    $b_v$shape, $batch_a_v$shape, $sum_v$shape
        stp     $a_q, $b_q, [$coeff_ptr], #32

        subs    $batches_left, $batches_left, #1
        b.ne    $loop
___
}

# Barrett-reduce all 256 coefficients in place, then correct negative
# residues to give canonical output in [0,q).
sub ntt_reduce {
    $code .= <<___;
        mov     $coeff_ptr, $coeff_base
        mov     $batches_left, #8
.Lntt_canonical_loop:
___
    for (1..2) {
        $code .= <<___;
        ldp     $a_q, $b_q, [$coeff_ptr]

        sqrdmulh $tmp_v.8h, $a_v.8h, $barrett_v.8h
        mls     $a_v.8h, $tmp_v.8h, $q_v.8h

        sshr    $tmp_v.8h, $a_v.8h, #15
        mls     $a_v.8h, $tmp_v.8h, $q_v.8h

        sqrdmulh $tmp_v.8h, $b_v.8h, $barrett_v.8h
        mls     $b_v.8h, $tmp_v.8h, $q_v.8h

        sshr    $tmp_v.8h, $b_v.8h, #15
        mls     $b_v.8h, $tmp_v.8h, $q_v.8h

        stp     $a_q, $b_q, [$coeff_ptr], #32
___
    }
    $code .= <<___;
        subs    $batches_left, $batches_left, #1
        b.ne    .Lntt_canonical_loop
___
}

# void ossl_ml_kem_ntt_armv8(uint16_t *c);
# Input: x0 points to 256 polynomial coefficients in [0,3329).
# Output: c is overwritten with its forward NTT, also in [0,3329).
# No return value.
sub ntt {
    my $name = 'ossl_ml_kem_ntt_armv8';
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
        adrp    $twiddle_ptr, .Lntt_constants
        add     $twiddle_ptr, $twiddle_ptr, #:lo12:.Lntt_constants
        mov     $q_reg, #$q
        dup     $q_v.8h, $q_reg
        movi    $barrett_v.8h, #10
___
    ntt_vector_layer(128);
    ntt_vector_layer(64);
    ntt_vector_layer(32);
    ntt_vector_layer(16);
    ntt_vector_layer(8);
    ntt_interleaved_layer(4);
    ntt_interleaved_layer(2);

    ntt_reduce();
    $code .= <<___;
        ret
.size   $name,.-$name

___
}

# Inverse Gentleman-Sande butterflies, unrolled for lengths >= 8.
# For each group with inverse twiddle z:
#   for each butterfly pair (a,b):
#       (a,b) = (a+b,(a-b)*z mod q)
sub intt_vector_layer {
    my ($len) = @_;
    my $group = 0;

    if ($len == 8) {
        for (my $start = 0; $start < 256; $start += 2 * $len, ++$group) {
            my ($z, $c) = @{$intt_zc_constants{$len}}[2 * $group, 2 * $group + 1];
            my $z_bits = $z & 0xffff;
            my $c_bits = $c & 0xffff;
            $code .= <<___;
        mov     $packed_zc, #$z_bits
        movk    $packed_zc, #$c_bits, lsl #16
        fmov    $intt_zc_s, $packed_zc
___
            my $a = 2 * $start;
            $code .= <<___;
        ldp     $a_q, $b_q, [$coeff_base, #$a]

        // Butterfly sum/difference.
        add     $sum_v.8h, $a_v.8h, $b_v.8h
        sub     $b_v.8h, $a_v.8h, $b_v.8h

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $intt_zc_v.h[0]
        sqrdmulh $tmp_v.8h, $b_v.8h, $intt_zc_v.h[1]
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h

        stp     $sum_q, $product_q, [$coeff_base, #$a]
___
        }
    } else {
        for (my $start = 0; $start < 256; $start += 2 * $len, ++$group) {
            my ($z, $c) = @{$intt_zc_constants{$len}}[2 * $group, 2 * $group + 1];
            my $z_bits = $z & 0xffff;
            my $c_bits = $c & 0xffff;
            $code .= <<___;
        mov     $packed_zc, #$z_bits
        movk    $packed_zc, #$c_bits, lsl #16
        fmov    $intt_zc_s, $packed_zc
___
            for (my $j = 0; $j < $len; $j += 16) {
                my $a = 2 * ($start + $j);
                my $b = 2 * ($start + $len + $j);

                $code .= <<___;
        ldp     $a_q, $a2_q, [$coeff_base, #$a]
        ldp     $b_q, $b2_q, [$coeff_base, #$b]

        // Butterfly sum/difference.
        add     $sum_v.8h, $a_v.8h, $b_v.8h
        add     $sum2_v.8h, $a2_v.8h, $b2_v.8h
        sub     $b_v.8h, $a_v.8h, $b_v.8h
        sub     $b2_v.8h, $a2_v.8h, $b2_v.8h

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $intt_zc_v.h[0]
        mul     $product2_v.8h, $b2_v.8h, $intt_zc_v.h[0]
        sqrdmulh $tmp_v.8h, $b_v.8h, $intt_zc_v.h[1]
        sqrdmulh $tmp2_v.8h, $b2_v.8h, $intt_zc_v.h[1]
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h
        mls     $product2_v.8h, $tmp2_v.8h, $q_v.8h

        stp     $sum_q, $sum2_q, [$coeff_base, #$a]
        stp     $product_q, $product2_q, [$coeff_base, #$b]
___
            }
        }
    }
}

# Same lane layout as ntt_interleaved_layer().  For each 32-byte batch:
#   (a,b) = deinterleave(load_batch())
#   z = load_lane_twiddles()
#   (a,b) = (a+b,(a-b)*z mod q)
#   store_interleaved(a,b)
sub intt_interleaved_layer {
    my ($len) = @_;
    my $shape = $len == 2 ? '.4s' : '.2d';
    my $loop = ".Lossl_ml_kem_intt_armv8_length${len}_loop";
    $code .= <<___;
        mov     $coeff_ptr, $coeff_base
        mov     $batches_left, #16
$loop:
        ldp     $z_q, $c_q, [$twiddle_ptr], #32
        ldp     $a_q, $b_q, [$coeff_ptr]
        uzp1    $batch_a_v$shape, $a_v$shape, $b_v$shape
        uzp2    $b_v$shape, $a_v$shape, $b_v$shape
        // Butterfly sum/difference.
        add     $sum_v.8h, $batch_a_v.8h, $b_v.8h
        sub     $b_v.8h, $batch_a_v.8h, $b_v.8h

        // Twiddle multiplication.
        mul     $product_v.8h, $b_v.8h, $z_v.8h
        sqrdmulh $tmp_v.8h, $b_v.8h, $c_v.8h
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h

        zip1    $a_v$shape, $sum_v$shape, $product_v$shape
        zip2    $b_v$shape, $sum_v$shape, $product_v$shape
        stp     $a_q, $b_q, [$coeff_ptr], #32

        subs    $batches_left, $batches_left, #1
        b.ne    $loop
___
}

# Normalize all 256 coefficients in place by multiplying by the inverse
# of 128 modulo q, then correct negative residues to give output in [0,q).
sub intt_normalize {
    # Scale by the inverse of 128 modulo q (-26), with reduction constant -256.
    my $z_bits = -26 & 0xffff;
    my $c_bits = -256 & 0xffff;
    $code .= <<___;
        mov     $packed_zc, #$z_bits
        movk    $packed_zc, #$c_bits, lsl #16
        fmov    $intt_zc_s, $packed_zc
        mov     $coeff_ptr, $coeff_base
        mov     $batches_left, #8
.Lintt_scale_loop:
___
    for (1..2) {
        $code .= <<___;
        ldp     $b_q, $b2_q, [$coeff_ptr]

        // Inverse normalization.
        mul     $product_v.8h, $b_v.8h, $intt_zc_v.h[0]
        mul     $product2_v.8h, $b2_v.8h, $intt_zc_v.h[0]
        sqrdmulh $tmp_v.8h, $b_v.8h, $intt_zc_v.h[1]
        sqrdmulh $tmp2_v.8h, $b2_v.8h, $intt_zc_v.h[1]
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h
        mls     $product2_v.8h, $tmp2_v.8h, $q_v.8h

        sshr    $tmp_v.8h, $product_v.8h, #15
        sshr    $tmp2_v.8h, $product2_v.8h, #15
        mls     $product_v.8h, $tmp_v.8h, $q_v.8h
        mls     $product2_v.8h, $tmp2_v.8h, $q_v.8h

        stp     $product_q, $product2_q, [$coeff_ptr], #32
___
    }
    $code .= <<___;
        subs    $batches_left, $batches_left, #1
        b.ne    .Lintt_scale_loop
___
}

# void ossl_ml_kem_intt_armv8(uint16_t *c);
# Input: x0 points to 256 NTT coefficients in [0,3329).
# Output: c is overwritten with its inverse NTT, also in [0,3329).
# No return value.
sub intt {
    my $name = 'ossl_ml_kem_intt_armv8';
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
        adrp    $twiddle_ptr, .Lintt_short_constants
        add     $twiddle_ptr, $twiddle_ptr, #:lo12:.Lintt_short_constants
        mov     $q_reg, #$q
        dup     $q_v.8h, $q_reg
        movi    $barrett_v.8h, #10
___
    intt_interleaved_layer(2);
    intt_interleaved_layer(4);
    intt_vector_layer(8);
    # After layer 3, center sum paths to preserve signed 16-bit headroom.
    intt_reduce(8, 16);
    intt_vector_layer(16);
    intt_vector_layer(32);
    intt_vector_layer(64);
    # After layer 6, center sums before the final layer to avoid 16-bit overflow.
    intt_reduce(64, 128);
    intt_vector_layer(128);

    intt_normalize();
    $code .= <<___;
        ret
.size   $name,.-$name

___
}

$code .= <<___;
#include "arch/arm_arch.h"

.text
___
ntt();
intt();

# Each 32-byte entry holds eight twiddles followed by eight reduction
# constants, c = round(2^15*z/q).
# Entries follow transform consumption order:
#
#   Forward   0..30: lengths 128..8, one root broadcast per entry.
#            31..46: length 4, two roots repeated four times each.
#            47..62: length 2, four roots repeated twice each.
#   Inverse   0..15: length 2, four roots repeated twice each.
#            16..31: length 4, two roots repeated four times each.
$code .= <<___;
.rodata
.align  4
// Forward NTT: broadcast lengths 128..8, then lane-packed lengths 4 and 2.
// 8 twiddles followed by 8 reduction constants per 32-byte entry.
.Lntt_constants:
// Length 128
        .short  -1600, -1600, -1600, -1600, -1600, -1600, -1600, -1600
        .short  -15749, -15749, -15749, -15749, -15749, -15749, -15749, -15749
// Length 64
        .short  -749, -749, -749, -749, -749, -749, -749, -749
        .short  -7373, -7373, -7373, -7373, -7373, -7373, -7373, -7373
        .short  -40, -40, -40, -40, -40, -40, -40, -40
        .short  -394, -394, -394, -394, -394, -394, -394, -394
// Length 32
        .short  -687, -687, -687, -687, -687, -687, -687, -687
        .short  -6762, -6762, -6762, -6762, -6762, -6762, -6762, -6762
        .short  630, 630, 630, 630, 630, 630, 630, 630
        .short  6201, 6201, 6201, 6201, 6201, 6201, 6201, 6201
        .short  -1432, -1432, -1432, -1432, -1432, -1432, -1432, -1432
        .short  -14095, -14095, -14095, -14095, -14095, -14095, -14095, -14095
        .short  848, 848, 848, 848, 848, 848, 848, 848
        .short  8347, 8347, 8347, 8347, 8347, 8347, 8347, 8347
// Length 16
        .short  1062, 1062, 1062, 1062, 1062, 1062, 1062, 1062
        .short  10453, 10453, 10453, 10453, 10453, 10453, 10453, 10453
        .short  -1410, -1410, -1410, -1410, -1410, -1410, -1410, -1410
        .short  -13879, -13879, -13879, -13879, -13879, -13879, -13879, -13879
        .short  193, 193, 193, 193, 193, 193, 193, 193
        .short  1900, 1900, 1900, 1900, 1900, 1900, 1900, 1900
        .short  797, 797, 797, 797, 797, 797, 797, 797
        .short  7845, 7845, 7845, 7845, 7845, 7845, 7845, 7845
        .short  -543, -543, -543, -543, -543, -543, -543, -543
        .short  -5345, -5345, -5345, -5345, -5345, -5345, -5345, -5345
        .short  -69, -69, -69, -69, -69, -69, -69, -69
        .short  -679, -679, -679, -679, -679, -679, -679, -679
        .short  569, 569, 569, 569, 569, 569, 569, 569
        .short  5601, 5601, 5601, 5601, 5601, 5601, 5601, 5601
        .short  -1583, -1583, -1583, -1583, -1583, -1583, -1583, -1583
        .short  -15582, -15582, -15582, -15582, -15582, -15582, -15582, -15582
// Length 8
        .short  296, 296, 296, 296, 296, 296, 296, 296
        .short  2914, 2914, 2914, 2914, 2914, 2914, 2914, 2914
        .short  -882, -882, -882, -882, -882, -882, -882, -882
        .short  -8682, -8682, -8682, -8682, -8682, -8682, -8682, -8682
        .short  1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339
        .short  13180, 13180, 13180, 13180, 13180, 13180, 13180, 13180
        .short  1476, 1476, 1476, 1476, 1476, 1476, 1476, 1476
        .short  14529, 14529, 14529, 14529, 14529, 14529, 14529, 14529
        .short  -283, -283, -283, -283, -283, -283, -283, -283
        .short  -2786, -2786, -2786, -2786, -2786, -2786, -2786, -2786
        .short  56, 56, 56, 56, 56, 56, 56, 56
        .short  551, 551, 551, 551, 551, 551, 551, 551
        .short  -1089, -1089, -1089, -1089, -1089, -1089, -1089, -1089
        .short  -10719, -10719, -10719, -10719, -10719, -10719, -10719, -10719
        .short  1333, 1333, 1333, 1333, 1333, 1333, 1333, 1333
        .short  13121, 13121, 13121, 13121, 13121, 13121, 13121, 13121
        .short  1426, 1426, 1426, 1426, 1426, 1426, 1426, 1426
        .short  14036, 14036, 14036, 14036, 14036, 14036, 14036, 14036
        .short  -1235, -1235, -1235, -1235, -1235, -1235, -1235, -1235
        .short  -12156, -12156, -12156, -12156, -12156, -12156, -12156, -12156
        .short  535, 535, 535, 535, 535, 535, 535, 535
        .short  5266, 5266, 5266, 5266, 5266, 5266, 5266, 5266
        .short  -447, -447, -447, -447, -447, -447, -447, -447
        .short  -4400, -4400, -4400, -4400, -4400, -4400, -4400, -4400
        .short  -936, -936, -936, -936, -936, -936, -936, -936
        .short  -9213, -9213, -9213, -9213, -9213, -9213, -9213, -9213
        .short  -450, -450, -450, -450, -450, -450, -450, -450
        .short  -4429, -4429, -4429, -4429, -4429, -4429, -4429, -4429
        .short  -1355, -1355, -1355, -1355, -1355, -1355, -1355, -1355
        .short  -13338, -13338, -13338, -13338, -13338, -13338, -13338, -13338
        .short  821, 821, 821, 821, 821, 821, 821, 821
        .short  8081, 8081, 8081, 8081, 8081, 8081, 8081, 8081
// Length 4
        .short  289, 289, 289, 289, 331, 331, 331, 331
        .short  2845, 2845, 2845, 2845, 3258, 3258, 3258, 3258
        .short  -76, -76, -76, -76, -1573, -1573, -1573, -1573
        .short  -748, -748, -748, -748, -15483, -15483, -15483, -15483
        .short  1197, 1197, 1197, 1197, -1025, -1025, -1025, -1025
        .short  11782, 11782, 11782, 11782, -10089, -10089, -10089, -10089
        .short  -1052, -1052, -1052, -1052, -1274, -1274, -1274, -1274
        .short  -10355, -10355, -10355, -10355, -12540, -12540, -12540, -12540
        .short  650, 650, 650, 650, -1352, -1352, -1352, -1352
        .short  6398, 6398, 6398, 6398, -13308, -13308, -13308, -13308
        .short  -816, -816, -816, -816, 632, 632, 632, 632
        .short  -8032, -8032, -8032, -8032, 6221, 6221, 6221, 6221
        .short  -464, -464, -464, -464, 33, 33, 33, 33
        .short  -4567, -4567, -4567, -4567, 325, 325, 325, 325
        .short  1320, 1320, 1320, 1320, -1414, -1414, -1414, -1414
        .short  12993, 12993, 12993, 12993, -13918, -13918, -13918, -13918
        .short  -1010, -1010, -1010, -1010, 1435, 1435, 1435, 1435
        .short  -9942, -9942, -9942, -9942, 14125, 14125, 14125, 14125
        .short  807, 807, 807, 807, 452, 452, 452, 452
        .short  7943, 7943, 7943, 7943, 4449, 4449, 4449, 4449
        .short  1438, 1438, 1438, 1438, -461, -461, -461, -461
        .short  14155, 14155, 14155, 14155, -4538, -4538, -4538, -4538
        .short  1534, 1534, 1534, 1534, -927, -927, -927, -927
        .short  15099, 15099, 15099, 15099, -9125, -9125, -9125, -9125
        .short  -682, -682, -682, -682, -712, -712, -712, -712
        .short  -6713, -6713, -6713, -6713, -7008, -7008, -7008, -7008
        .short  1481, 1481, 1481, 1481, 648, 648, 648, 648
        .short  14578, 14578, 14578, 14578, 6378, 6378, 6378, 6378
        .short  -855, -855, -855, -855, -219, -219, -219, -219
        .short  -8416, -8416, -8416, -8416, -2156, -2156, -2156, -2156
        .short  1227, 1227, 1227, 1227, 910, 910, 910, 910
        .short  12078, 12078, 12078, 12078, 8957, 8957, 8957, 8957
// Length 2
        .short  17, 17, -568, -568, 583, 583, -680, -680
        .short  167, 167, -5591, -5591, 5739, 5739, -6693, -6693
        .short  1637, 1637, 723, 723, -1041, -1041, 1100, 1100
        .short  16113, 16113, 7117, 7117, -10247, -10247, 10828, 10828
        .short  1409, 1409, -667, -667, -48, -48, 233, 233
        .short  13869, 13869, -6565, -6565, -472, -472, 2293, 2293
        .short  756, 756, -1173, -1173, -314, -314, -279, -279
        .short  7441, 7441, -11546, -11546, -3091, -3091, -2746, -2746
        .short  -1626, -1626, 1651, 1651, -540, -540, -1540, -1540
        .short  -16005, -16005, 16251, 16251, -5315, -5315, -15159, -15159
        .short  -1482, -1482, 952, 952, 1461, 1461, -642, -642
        .short  -14588, -14588, 9371, 9371, 14381, 14381, -6319, -6319
        .short  939, 939, -1021, -1021, -892, -892, -941, -941
        .short  9243, 9243, -10050, -10050, -8780, -8780, -9262, -9262
        .short  733, 733, -992, -992, 268, 268, 641, 641
        .short  7215, 7215, -9764, -9764, 2638, 2638, 6309, 6309
        .short  1584, 1584, -1031, -1031, -1292, -1292, -109, -109
        .short  15592, 15592, -10148, -10148, -12717, -12717, -1073, -1073
        .short  375, 375, -780, -780, -1239, -1239, 1645, 1645
        .short  3691, 3691, -7678, -7678, -12196, -12196, 16192, 16192
        .short  1063, 1063, 319, 319, -556, -556, 757, 757
        .short  10463, 10463, 3140, 3140, -5473, -5473, 7451, 7451
        .short  -1230, -1230, 561, 561, -863, -863, -735, -735
        .short  -12107, -12107, 5522, 5522, -8495, -8495, -7235, -7235
        .short  -525, -525, 1092, 1092, 403, 403, 1026, 1026
        .short  -5168, -5168, 10749, 10749, 3967, 3967, 10099, 10099
        .short  1143, 1143, -1179, -1179, -554, -554, 886, 886
        .short  11251, 11251, -11605, -11605, -5453, -5453, 8721, 8721
        .short  -1607, -1607, 1212, 1212, -1455, -1455, 1029, 1029
        .short  -15818, -15818, 11930, 11930, -14322, -14322, 10129, 10129
        .short  -1219, -1219, -394, -394, 885, 885, -1175, -1175
        .short  -11999, -11999, -3878, -3878, 8711, 8711, -11566, -11566
.align  4
// Inverse NTT: lane-packed length-2 entries followed by length-4 entries.
// 8 inverse twiddles followed by 8 reduction constants per 32-byte entry.
.Lintt_short_constants:
// Length 2
        .short  1175, 1175, -885, -885, 394, 394, 1219, 1219
        .short  11566, 11566, -8711, -8711, 3878, 3878, 11999, 11999
        .short  -1029, -1029, 1455, 1455, -1212, -1212, 1607, 1607
        .short  -10129, -10129, 14322, 14322, -11930, -11930, 15818, 15818
        .short  -886, -886, 554, 554, 1179, 1179, -1143, -1143
        .short  -8721, -8721, 5453, 5453, 11605, 11605, -11251, -11251
        .short  -1026, -1026, -403, -403, -1092, -1092, 525, 525
        .short  -10099, -10099, -3967, -3967, -10749, -10749, 5168, 5168
        .short  735, 735, 863, 863, -561, -561, 1230, 1230
        .short  7235, 7235, 8495, 8495, -5522, -5522, 12107, 12107
        .short  -757, -757, 556, 556, -319, -319, -1063, -1063
        .short  -7451, -7451, 5473, 5473, -3140, -3140, -10463, -10463
        .short  -1645, -1645, 1239, 1239, 780, 780, -375, -375
        .short  -16192, -16192, 12196, 12196, 7678, 7678, -3691, -3691
        .short  109, 109, 1292, 1292, 1031, 1031, -1584, -1584
        .short  1073, 1073, 12717, 12717, 10148, 10148, -15592, -15592
        .short  -641, -641, -268, -268, 992, 992, -733, -733
        .short  -6309, -6309, -2638, -2638, 9764, 9764, -7215, -7215
        .short  941, 941, 892, 892, 1021, 1021, -939, -939
        .short  9262, 9262, 8780, 8780, 10050, 10050, -9243, -9243
        .short  642, 642, -1461, -1461, -952, -952, 1482, 1482
        .short  6319, 6319, -14381, -14381, -9371, -9371, 14588, 14588
        .short  1540, 1540, 540, 540, -1651, -1651, 1626, 1626
        .short  15159, 15159, 5315, 5315, -16251, -16251, 16005, 16005
        .short  279, 279, 314, 314, 1173, 1173, -756, -756
        .short  2746, 2746, 3091, 3091, 11546, 11546, -7441, -7441
        .short  -233, -233, 48, 48, 667, 667, -1409, -1409
        .short  -2293, -2293, 472, 472, 6565, 6565, -13869, -13869
        .short  -1100, -1100, 1041, 1041, -723, -723, -1637, -1637
        .short  -10828, -10828, 10247, 10247, -7117, -7117, -16113, -16113
        .short  680, 680, -583, -583, 568, 568, -17, -17
        .short  6693, 6693, -5739, -5739, 5591, 5591, -167, -167
// Length 4
        .short  -910, -910, -910, -910, -1227, -1227, -1227, -1227
        .short  -8957, -8957, -8957, -8957, -12078, -12078, -12078, -12078
        .short  219, 219, 219, 219, 855, 855, 855, 855
        .short  2156, 2156, 2156, 2156, 8416, 8416, 8416, 8416
        .short  -648, -648, -648, -648, -1481, -1481, -1481, -1481
        .short  -6378, -6378, -6378, -6378, -14578, -14578, -14578, -14578
        .short  712, 712, 712, 712, 682, 682, 682, 682
        .short  7008, 7008, 7008, 7008, 6713, 6713, 6713, 6713
        .short  927, 927, 927, 927, -1534, -1534, -1534, -1534
        .short  9125, 9125, 9125, 9125, -15099, -15099, -15099, -15099
        .short  461, 461, 461, 461, -1438, -1438, -1438, -1438
        .short  4538, 4538, 4538, 4538, -14155, -14155, -14155, -14155
        .short  -452, -452, -452, -452, -807, -807, -807, -807
        .short  -4449, -4449, -4449, -4449, -7943, -7943, -7943, -7943
        .short  -1435, -1435, -1435, -1435, 1010, 1010, 1010, 1010
        .short  -14125, -14125, -14125, -14125, 9942, 9942, 9942, 9942
        .short  1414, 1414, 1414, 1414, -1320, -1320, -1320, -1320
        .short  13918, 13918, 13918, 13918, -12993, -12993, -12993, -12993
        .short  -33, -33, -33, -33, 464, 464, 464, 464
        .short  -325, -325, -325, -325, 4567, 4567, 4567, 4567
        .short  -632, -632, -632, -632, 816, 816, 816, 816
        .short  -6221, -6221, -6221, -6221, 8032, 8032, 8032, 8032
        .short  1352, 1352, 1352, 1352, -650, -650, -650, -650
        .short  13308, 13308, 13308, 13308, -6398, -6398, -6398, -6398
        .short  1274, 1274, 1274, 1274, 1052, 1052, 1052, 1052
        .short  12540, 12540, 12540, 12540, 10355, 10355, 10355, 10355
        .short  1025, 1025, 1025, 1025, -1197, -1197, -1197, -1197
        .short  10089, 10089, 10089, 10089, -11782, -11782, -11782, -11782
        .short  1573, 1573, 1573, 1573, 76, 76, 76, 76
        .short  15483, 15483, 15483, 15483, 748, 748, 748, 748
        .short  -331, -331, -331, -331, -289, -289, -289, -289
        .short  -3258, -3258, -3258, -3258, -2845, -2845, -2845, -2845
___
print $code;
close STDOUT or die "error closing STDOUT: $!";
