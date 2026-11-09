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
# Roots are z = 17^bitrev7(i) mod q; inverse layers use their inverses.
# Inputs and outputs are canonical [0,q); intermediate lanes are signed 16-bit.
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
# layer by [-4421,4421].  Scaling by 128^-1 = 3303 = -26 (mod q) is fused with
# canonicalization.
#
# Long layers are unrolled; lengths 4 and 2 each loop over sixteen batches.
# Final reduction/scaling passes each use eight 64-byte iterations.
# Addresses and branch conditions depend only on public offsets and counters;
# canonicalization uses sign masks.  Both entry points use caller-saved
# registers and need no stack frame.
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

# Caller-saved register aliases (AAPCS64).
my ($arg, $constants_gpr, $q_gpr) = ('x0', 'w9', 'w11');
my $table_gpr = 'x12';
my ($pass_gpr, $pass_count) = ('x1', 'w2');
my ($vec_a, $vec_b, $vec_product, $vec_tmp, $vec_sum, $vec_batch_a) =
    map("v$_", (0, 1, 2, 3, 5, 4));
my ($vec_a2, $vec_b2, $vec_product2, $vec_tmp2, $vec_sum2) =
    map("v$_", (16, 17, 18, 19, 20));
my ($quad_a, $quad_b, $quad_product, $quad_sum) =
    map("q$_", (0, 1, 2, 5));
my ($quad_a2, $quad_b2, $quad_product2, $quad_sum2) =
    map("q$_", (16, 17, 18, 20));
my ($vec_barrett, $vec_recip, $vec_root, $vec_q) =
    map("v$_", (28, 29, 30, 31));
my ($quad_recip, $quad_root) = map("q$_", (29, 30));
# Indexed halfword operands must use v0-v15.  v6 holds z and c in lanes 0/1.
my ($vec_inverse_constants, $single_inverse_constants) = ('v6', 's6');
my $inverse_root_lane = "$vec_inverse_constants.h[0]";
my $inverse_recip_lane = "$vec_inverse_constants.h[1]";
my $root_8h = "$vec_root.8h";
my $recip_8h = "$vec_recip.8h";

# Inverse (z,c) pairs for lengths >= 8; c = round(2^15*z/q).
my %intt_constants = (
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

# Reduce eight signed lanes using round(2^15/q) = 10; clobbers vec_tmp.
# For the transform bounds above, the result has magnitude less than q.
sub center_vector {
    my ($v) = @_;
    # Subtract q * round(x * 10 / 2^15).
    $code .= <<___;
        sqrdmulh $vec_tmp.8h, $v.8h, $vec_barrett.8h
        mls     $v.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Reduce eight signed lanes to [0,q); clobbers vec_tmp.
sub canonicalize_vector {
    my ($v) = @_;

    center_vector($v);
    # Add q exactly to negative lanes.  SSHR produces zero or -1.
    $code .= <<___;
        sshr    $vec_tmp.8h, $v.8h, #15
        mls     $v.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Pack inverse z/c into lanes 0/1, returning complete arithmetic operands.
sub load_inverse_constants {
    my ($z, $c) = @_;

    my $z_bits = $z & 0xffff;
    my $c_bits = $c & 0xffff;
    $code .= <<___;
        mov     $constants_gpr, #$z_bits
        movk    $constants_gpr, #$c_bits, lsl #16
        fmov    $single_inverse_constants, $constants_gpr
___
    return ($inverse_root_lane, $inverse_recip_lane);
}

# Set vec_product = vec_b*z mod q with signed representatives; clobbers vec_tmp.
# root and recip are complete operands for z and c=round(2^15*z/q).
sub multiply_by_twiddle {
    my ($root, $recip) = @_;
    # r = low16(x*z) - q*round(x*c/2^15), congruent to x*z mod q.
    $code .= <<___;
        mul     $vec_product.8h, $vec_b.8h, $root
        sqrdmulh $vec_tmp.8h, $vec_b.8h, $recip
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Two independent twiddle products; clobbers vec_tmp and vec_tmp2.
sub multiply_pair_by_twiddle {
    my ($root, $recip) = @_;
    $code .= <<___;
        mul     $vec_product.8h, $vec_b.8h, $root
        mul     $vec_product2.8h, $vec_b2.8h, $root
        sqrdmulh $vec_tmp.8h, $vec_b.8h, $recip
        sqrdmulh $vec_tmp2.8h, $vec_b2.8h, $recip
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
        mls     $vec_product2.8h, $vec_tmp2.8h, $vec_q.8h
___
}

# Center the first len coefficients of each stride-sized inverse block.
# Only these sum paths can exceed the later signed-16-bit bound.
sub center_inverse_blocks {
    my ($len, $stride) = @_;
    # Product halves are already reduced by twiddle multiplication.
    for (my $base = 0; $base < 256; $base += $stride) {
        for (my $j = 0; $j < $len; $j += 8) {
            my $off = 2 * ($base + $j);
            $code .= "        ldr     $quad_a, [$arg, #$off]\n";
            center_vector($vec_a);
            $code .= "        str     $quad_a, [$arg, #$off]\n";
        }
    }
}

# Canonicalize all 256 forward coefficients, four vectors per iteration.
sub canonicalize_polynomial {
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #8
.Lntt_canonical_loop:
___
    for (1..2) {
        $code .= "        ldp     $quad_a, $quad_b, [$pass_gpr]\n";
        canonicalize_vector($vec_a);
        canonicalize_vector($vec_b);
        $code .= "        stp     $quad_a, $quad_b, [$pass_gpr], #32\n";
    }
    $code .= <<___;
        subs    $pass_count, $pass_count, #1
        b.ne    .Lntt_canonical_loop
___
}

# Scale by 128^-1 = -26 (mod q).  Products lie in (-q,q), so a sign-mask
# correction gives canonical [0,q) output without a separate centering pass.
sub normalize_inverse {
    # The reciprocal for -26 is -256.
    my ($root, $recip) = load_inverse_constants(-26, -256);
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #8
.Lintt_scale_loop:
___
    for (1..2) {
        $code .= <<___;
        ldp     $quad_b, $quad_b2, [$pass_gpr]
___
        multiply_pair_by_twiddle($root, $recip);
        $code .= <<___;
        sshr    $vec_tmp.8h, $vec_product.8h, #15
        sshr    $vec_tmp2.8h, $vec_product2.8h, #15
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
        mls     $vec_product2.8h, $vec_tmp2.8h, $vec_q.8h
        stp     $quad_product, $quad_product2, [$pass_gpr], #32
___
    }
    $code .= <<___;
        subs    $pass_count, $pass_count, #1
        b.ne    .Lintt_scale_loop
___
}

# Forward (a,b) <- (a+z*b,a-z*b), using two vector butterflies.
sub forward_butterfly_pair {
    my ($a, $b) = @_;
    $code .= <<___;
        ldp     $quad_a, $quad_a2, [$arg, #$a]
        ldp     $quad_b, $quad_b2, [$arg, #$b]
___
    multiply_pair_by_twiddle($root_8h, $recip_8h);
    $code .= <<___;
        sub     $vec_sum.8h, $vec_a.8h, $vec_product.8h
        sub     $vec_sum2.8h, $vec_a2.8h, $vec_product2.8h
        add     $vec_a.8h, $vec_a.8h, $vec_product.8h
        add     $vec_a2.8h, $vec_a2.8h, $vec_product2.8h
        stp     $quad_a, $quad_a2, [$arg, #$a]
        stp     $quad_sum, $quad_sum2, [$arg, #$b]
___
}

# Length 8 has adjacent A/B vectors.
sub forward_butterfly_length8 {
    my ($a) = @_;
    $code .= "        ldp     $quad_a, $quad_b, [$arg, #$a]\n";
    multiply_by_twiddle($root_8h, $recip_8h);
    $code .= <<___;
        sub     $vec_sum.8h, $vec_a.8h, $vec_product.8h
        add     $vec_a.8h, $vec_a.8h, $vec_product.8h
        stp     $quad_a, $quad_sum, [$arg, #$a]
___
}

sub forward_wide_layer {
    my ($len) = @_;

    for (my $start = 0; $start < 256; $start += 2 * $len) {
        $code .= "        ldp     $quad_root, $quad_recip, [$table_gpr], #32\n";
        if ($len == 8) {
            forward_butterfly_length8(2 * $start);
            next;
        }
        for (my $j = 0; $j < $len; $j += 16) {
            my $a = 2 * ($start + $j);
            my $b = 2 * ($start + $len + $j);

            forward_butterfly_pair($a, $b);
        }
    }
}

# Length 2 batches four [a0,a1 | b0,b1] groups as 32-bit blocks;
# length 4 batches two [a0..a3 | b0..b3] groups as 64-bit blocks.
# UZP separates A/B halves; ZIP restores memory order after the butterflies.
sub forward_short_layer {
    my ($len) = @_;
    my $shape = $len == 2 ? '.4s'
              : $len == 4 ? '.2d'
              : die "bad batch length $len";
    my $loop = ".Lossl_ml_kem_ntt_armv8_length${len}_loop";
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #16
$loop:
        ldp     $quad_root, $quad_recip, [$table_gpr], #32
        ldp     $quad_a, $quad_b, [$pass_gpr]
        uzp1    $vec_batch_a$shape, $vec_a$shape, $vec_b$shape
        uzp2    $vec_b$shape, $vec_a$shape, $vec_b$shape
___
    multiply_by_twiddle($root_8h, $recip_8h);
    $code .= <<___;
        sub     $vec_sum.8h, $vec_batch_a.8h, $vec_product.8h
        add     $vec_batch_a.8h, $vec_batch_a.8h, $vec_product.8h
        zip1    $vec_a$shape, $vec_batch_a$shape, $vec_sum$shape
        zip2    $vec_b$shape, $vec_batch_a$shape, $vec_sum$shape
        stp     $quad_a, $quad_b, [$pass_gpr], #32
        subs    $pass_count, $pass_count, #1
        b.ne    $loop
___
}

sub forward_ntt {
    my $name = 'ossl_ml_kem_ntt_armv8';
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
        adrp    $table_gpr, .Lntt_constants
        add     $table_gpr, $table_gpr, #:lo12:.Lntt_constants
        mov     $q_gpr, #$q
        dup     $vec_q.8h, $q_gpr
        movi    $vec_barrett.8h, #10
___
    forward_wide_layer(128);
    forward_wide_layer(64);
    forward_wide_layer(32);
    forward_wide_layer(16);
    forward_wide_layer(8);
    forward_short_layer(4);
    forward_short_layer(2);
    canonicalize_polynomial();
    $code .= <<___;
        ret
.size   $name,.-$name

___
}

# Inverse (a,b) <- (a+b,z*(a-b)), using two vector butterflies.
sub inverse_butterfly_pair {
    my ($a, $b, $root, $recip) = @_;
    $code .= <<___;
        ldp     $quad_a, $quad_a2, [$arg, #$a]
        ldp     $quad_b, $quad_b2, [$arg, #$b]
        add     $vec_sum.8h, $vec_a.8h, $vec_b.8h
        add     $vec_sum2.8h, $vec_a2.8h, $vec_b2.8h
        sub     $vec_b.8h, $vec_a.8h, $vec_b.8h
        sub     $vec_b2.8h, $vec_a2.8h, $vec_b2.8h
___
    multiply_pair_by_twiddle($root, $recip);
    $code .= <<___;
        stp     $quad_sum, $quad_sum2, [$arg, #$a]
        stp     $quad_product, $quad_product2, [$arg, #$b]
___
}

sub inverse_butterfly_length8 {
    my ($a, $root, $recip) = @_;
    $code .= <<___;
        ldp     $quad_a, $quad_b, [$arg, #$a]
        add     $vec_sum.8h, $vec_a.8h, $vec_b.8h
        sub     $vec_b.8h, $vec_a.8h, $vec_b.8h
___
    multiply_by_twiddle($root, $recip);
    $code .= "        stp     $quad_sum, $quad_product, [$arg, #$a]\n";
}

sub inverse_wide_layer {
    my ($len) = @_;
    my $group = 0;

    for (my $start = 0; $start < 256; $start += 2 * $len, ++$group) {
        my ($z, $c) = @{$intt_constants{$len}}[2 * $group, 2 * $group + 1];
        my ($root, $recip) = load_inverse_constants($z, $c);
        if ($len == 8) {
            inverse_butterfly_length8(2 * $start, $root, $recip);
            next;
        }
        for (my $j = 0; $j < $len; $j += 16) {
            my $a = 2 * ($start + $j);
            my $b = 2 * ($start + $len + $j);

            inverse_butterfly_pair($a, $b, $root, $recip);
        }
    }
}

# Same lane layout as forward_short_layer(), with sum/difference before multiply.
sub inverse_short_layer {
    my ($len) = @_;
    my $shape = $len == 2 ? '.4s'
              : $len == 4 ? '.2d'
              : die "bad batch length $len";
    my $loop = ".Lossl_ml_kem_intt_armv8_length${len}_loop";
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #16
$loop:
        ldp     $quad_root, $quad_recip, [$table_gpr], #32
        ldp     $quad_a, $quad_b, [$pass_gpr]
        uzp1    $vec_batch_a$shape, $vec_a$shape, $vec_b$shape
        uzp2    $vec_b$shape, $vec_a$shape, $vec_b$shape
        add     $vec_sum.8h, $vec_batch_a.8h, $vec_b.8h
        sub     $vec_b.8h, $vec_batch_a.8h, $vec_b.8h
___
    multiply_by_twiddle($root_8h, $recip_8h);
    $code .= <<___;
        zip1    $vec_a$shape, $vec_sum$shape, $vec_product$shape
        zip2    $vec_b$shape, $vec_sum$shape, $vec_product$shape
        stp     $quad_a, $quad_b, [$pass_gpr], #32
        subs    $pass_count, $pass_count, #1
        b.ne    $loop
___
}

sub inverse_ntt {
    my $name = 'ossl_ml_kem_intt_armv8';
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
        adrp    $table_gpr, .Lintt_short_constants
        add     $table_gpr, $table_gpr, #:lo12:.Lintt_short_constants
        mov     $q_gpr, #$q
        dup     $vec_q.8h, $q_gpr
        movi    $vec_barrett.8h, #10
___
    inverse_short_layer(2);
    inverse_short_layer(4);
    inverse_wide_layer(8);
    center_inverse_blocks(8, 16);
    inverse_wide_layer(16);
    inverse_wide_layer(32);
    inverse_wide_layer(64);
    center_inverse_blocks(64, 128);
    inverse_wide_layer(128);
    normalize_inverse();
    $code .= <<___;
        ret
.size   $name,.-$name

___
}

$code .= <<___;
#include "arch/arm_arch.h"

.text
___
forward_ntt();
inverse_ntt();

# Each 32-byte table entry holds z[8], then c[8] = round(2^15*z/q).
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
// Each entry is { z[8], round(2^15*z/q)[8] } and occupies 32 bytes.
.Lntt_constants:
        .short  -1600, -1600, -1600, -1600, -1600, -1600, -1600, -1600
        .short  -15749, -15749, -15749, -15749, -15749, -15749, -15749, -15749
        .short  -749, -749, -749, -749, -749, -749, -749, -749
        .short  -7373, -7373, -7373, -7373, -7373, -7373, -7373, -7373
        .short  -40, -40, -40, -40, -40, -40, -40, -40
        .short  -394, -394, -394, -394, -394, -394, -394, -394
        .short  -687, -687, -687, -687, -687, -687, -687, -687
        .short  -6762, -6762, -6762, -6762, -6762, -6762, -6762, -6762
        .short  630, 630, 630, 630, 630, 630, 630, 630
        .short  6201, 6201, 6201, 6201, 6201, 6201, 6201, 6201
        .short  -1432, -1432, -1432, -1432, -1432, -1432, -1432, -1432
        .short  -14095, -14095, -14095, -14095, -14095, -14095, -14095, -14095
        .short  848, 848, 848, 848, 848, 848, 848, 848
        .short  8347, 8347, 8347, 8347, 8347, 8347, 8347, 8347
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
// Each entry is { z^-1[8], round(2^15*z^-1/q)[8] } and occupies 32 bytes.
.Lintt_short_constants:
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
