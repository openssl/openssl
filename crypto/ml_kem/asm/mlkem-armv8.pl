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
# several groups with lane-packed roots (see emit_short_batch()).
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
my @forward_constants;
my @inverse_short_constants;
my $use_forward_table = 0;

# Fixed (z,c) pairs in group order; c = round(2^15*z/q).
my %ntt_constants = (
    # Layer 1
    128 => [
        -1600, -15749,
    ],
    # Layer 2
    64 => [
        -749, -7373, -40, -394,
    ],
    # Layer 3
    32 => [
        -687, -6762, 630, 6201, -1432, -14095, 848, 8347,
    ],
    # Layer 4
    16 => [
        1062, 10453, -1410, -13879, 193, 1900, 797, 7845,
        -543, -5345, -69, -679, 569, 5601, -1583, -15582,
    ],
    # Layer 5
    8 => [
        296, 2914, -882, -8682, 1339, 13180, 1476, 14529,
        -283, -2786, 56, 551, -1089, -10719, 1333, 13121,
        1426, 14036, -1235, -12156, 535, 5266, -447, -4400,
        -936, -9213, -450, -4429, -1355, -13338, 821, 8081,
    ],
    # Layer 6
    4 => [
        289, 2845, 331, 3258, -76, -748, -1573, -15483,
        1197, 11782, -1025, -10089, -1052, -10355, -1274, -12540,
        650, 6398, -1352, -13308, -816, -8032, 632, 6221,
        -464, -4567, 33, 325, 1320, 12993, -1414, -13918,
        -1010, -9942, 1435, 14125, 807, 7943, 452, 4449,
        1438, 14155, -461, -4538, 1534, 15099, -927, -9125,
        -682, -6713, -712, -7008, 1481, 14578, 648, 6378,
        -855, -8416, -219, -2156, 1227, 12078, 910, 8957,
    ],
    # Layer 7
    2 => [
        17, 167, -568, -5591, 583, 5739, -680, -6693,
        1637, 16113, 723, 7117, -1041, -10247, 1100, 10828,
        1409, 13869, -667, -6565, -48, -472, 233, 2293,
        756, 7441, -1173, -11546, -314, -3091, -279, -2746,
        -1626, -16005, 1651, 16251, -540, -5315, -1540, -15159,
        -1482, -14588, 952, 9371, 1461, 14381, -642, -6319,
        939, 9243, -1021, -10050, -892, -8780, -941, -9262,
        733, 7215, -992, -9764, 268, 2638, 641, 6309,
        1584, 15592, -1031, -10148, -1292, -12717, -109, -1073,
        375, 3691, -780, -7678, -1239, -12196, 1645, 16192,
        1063, 10463, 319, 3140, -556, -5473, 757, 7451,
        -1230, -12107, 561, 5522, -863, -8495, -735, -7235,
        -525, -5168, 1092, 10749, 403, 3967, 1026, 10099,
        1143, 11251, -1179, -11605, -554, -5453, 886, 8721,
        -1607, -15818, 1212, 11930, -1455, -14322, 1029, 10129,
        -1219, -11999, -394, -3878, 885, 8711, -1175, -11566,
    ],
);

my %intt_constants = (
    # Layer 1
    2 => [
        1175, 11566, -885, -8711, 394, 3878, 1219, 11999,
        -1029, -10129, 1455, 14322, -1212, -11930, 1607, 15818,
        -886, -8721, 554, 5453, 1179, 11605, -1143, -11251,
        -1026, -10099, -403, -3967, -1092, -10749, 525, 5168,
        735, 7235, 863, 8495, -561, -5522, 1230, 12107,
        -757, -7451, 556, 5473, -319, -3140, -1063, -10463,
        -1645, -16192, 1239, 12196, 780, 7678, -375, -3691,
        109, 1073, 1292, 12717, 1031, 10148, -1584, -15592,
        -641, -6309, -268, -2638, 992, 9764, -733, -7215,
        941, 9262, 892, 8780, 1021, 10050, -939, -9243,
        642, 6319, -1461, -14381, -952, -9371, 1482, 14588,
        1540, 15159, 540, 5315, -1651, -16251, 1626, 16005,
        279, 2746, 314, 3091, 1173, 11546, -756, -7441,
        -233, -2293, 48, 472, 667, 6565, -1409, -13869,
        -1100, -10828, 1041, 10247, -723, -7117, -1637, -16113,
        680, 6693, -583, -5739, 568, 5591, -17, -167,
    ],
    # Layer 2
    4 => [
        -910, -8957, -1227, -12078, 219, 2156, 855, 8416,
        -648, -6378, -1481, -14578, 712, 7008, 682, 6713,
        927, 9125, -1534, -15099, 461, 4538, -1438, -14155,
        -452, -4449, -807, -7943, -1435, -14125, 1010, 9942,
        1414, 13918, -1320, -12993, -33, -325, 464, 4567,
        -632, -6221, 816, 8032, 1352, 13308, -650, -6398,
        1274, 12540, 1052, 10355, 1025, 10089, -1197, -11782,
        1573, 15483, 76, 748, -331, -3258, -289, -2845,
    ],
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
sub emit_center_vec {
    my ($v) = @_;
    # Subtract q * round(x * 10 / 2^15).
    $code .= <<___;
        sqrdmulh $vec_tmp.8h, $v.8h, $vec_barrett.8h
        mls     $v.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Reduce eight signed lanes to [0,q); clobbers vec_tmp.
sub emit_canonical_vec {
    my ($v) = @_;

    emit_center_vec($v);
    # Add q exactly to negative lanes.  SSHR produces zero or -1.
    $code .= <<___;
        sshr    $vec_tmp.8h, $v.8h, #15
        mls     $v.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Prepare z and c=round(2^15*z/q), returning complete arithmetic operands.
# Forward groups load broadcast vectors; inverse groups pack z/c into lanes 0/1.
sub emit_twiddle_constants {
    my ($z, $c) = @_;

    if ($use_forward_table) {
        push @forward_constants, [[($z) x 8], [($c) x 8]];
        $code .= "        ldp     $quad_root, $quad_recip, [$table_gpr], #32\n";
        return ($root_8h, $recip_8h);
    }
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
sub emit_twiddle_vec {
    my ($root, $recip) = @_;
    # r = low16(x*z) - q*round(x*c/2^15), congruent to x*z mod q.
    $code .= <<___;
        mul     $vec_product.8h, $vec_b.8h, $root
        sqrdmulh $vec_tmp.8h, $vec_b.8h, $recip
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
___
}

# Two vector butterflies sharing one twiddle, for lengths >= 16.
# Forward: (a,b) <- (a+z*b,a-z*b); inverse: (a,b) <- (a+b,z*(a-b)).
# Paired loads/stores and independent registers overlap the product chains.
sub emit_bfly_vec_pair {
    my ($a, $b, $inverse, $root, $recip) = @_;
    $code .= <<___;
        ldp     $quad_a, $quad_a2, [$arg, #$a]
        ldp     $quad_b, $quad_b2, [$arg, #$b]
___
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h, $vec_a.8h, $vec_b.8h
        add     $vec_sum2.8h, $vec_a2.8h, $vec_b2.8h
        sub     $vec_b.8h, $vec_a.8h, $vec_b.8h
        sub     $vec_b2.8h, $vec_a2.8h, $vec_b2.8h
___
    }
    $code .= <<___;
        mul     $vec_product.8h, $vec_b.8h, $root
        mul     $vec_product2.8h, $vec_b2.8h, $root
        sqrdmulh $vec_tmp.8h, $vec_b.8h, $recip
        sqrdmulh $vec_tmp2.8h, $vec_b2.8h, $recip
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
        mls     $vec_product2.8h, $vec_tmp2.8h, $vec_q.8h
___
    if ($inverse) {
        $code .= <<___;
        stp     $quad_sum, $quad_sum2, [$arg, #$a]
        stp     $quad_product, $quad_product2, [$arg, #$b]
___
    } else {
        $code .= <<___;
        sub     $vec_sum.8h, $vec_a.8h, $vec_product.8h
        sub     $vec_sum2.8h, $vec_a2.8h, $vec_product2.8h
        add     $vec_a.8h, $vec_a.8h, $vec_product.8h
        add     $vec_a2.8h, $vec_a2.8h, $vec_product2.8h
        stp     $quad_a, $quad_a2, [$arg, #$a]
        stp     $quad_sum, $quad_sum2, [$arg, #$b]
___
    }
}

# A length-8 group has adjacent A/B vectors, loaded and stored as a pair.
sub emit_bfly_vec_contiguous {
    my ($a, $inverse, $root, $recip) = @_;
    $code .= "        ldp     $quad_a, $quad_b, [$arg, #$a]\n";
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h, $vec_a.8h, $vec_b.8h
        sub     $vec_b.8h, $vec_a.8h, $vec_b.8h
___
        emit_twiddle_vec($root, $recip);
        $code .= "        stp     $quad_sum, $quad_product, [$arg, #$a]\n";
    } else {
        emit_twiddle_vec($root, $recip);
        $code .= <<___;
        sub     $vec_sum.8h, $vec_a.8h, $vec_product.8h
        add     $vec_a.8h, $vec_a.8h, $vec_product.8h
        stp     $quad_a, $quad_sum, [$arg, #$a]
___
    }
}

# Batch 32 bytes of adjacent short groups:
#   length 2: four [a0,a1 | b0,b1] groups, permuted as 32-bit blocks;
#   length 4: two [a0..a3 | b0..b3] groups, permuted as 64-bit blocks.
# UZP separates A/B halves; ZIP restores memory order.  Roots repeat once per
# coefficient in each half, preserving group order across all eight lanes.
sub emit_short_batch {
    my ($len, $inverse) = @_;
    my $shape = $len == 2 ? '.4s'
              : $len == 4 ? '.2d'
              : die "bad batch length $len";
    $code .= <<___;
        ldp     $quad_root, $quad_recip, [$table_gpr], #32
        ldp     $quad_a, $quad_b, [$pass_gpr]
        uzp1    $vec_batch_a$shape, $vec_a$shape, $vec_b$shape
        uzp2    $vec_b$shape, $vec_a$shape, $vec_b$shape
___
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h, $vec_batch_a.8h, $vec_b.8h
        sub     $vec_b.8h, $vec_batch_a.8h, $vec_b.8h
___
        emit_twiddle_vec($root_8h, $recip_8h);
        $code .= <<___;
        zip1    $vec_a$shape, $vec_sum$shape, $vec_product$shape
        zip2    $vec_b$shape, $vec_sum$shape, $vec_product$shape
___
    } else {
        emit_twiddle_vec($root_8h, $recip_8h);
        $code .= <<___;
        sub     $vec_sum.8h, $vec_batch_a.8h, $vec_product.8h
        add     $vec_batch_a.8h, $vec_batch_a.8h, $vec_product.8h
        zip1    $vec_a$shape, $vec_batch_a$shape, $vec_sum$shape
        zip2    $vec_b$shape, $vec_batch_a$shape, $vec_sum$shape
___
    }
    $code .= "        stp     $quad_a, $quad_b, [$pass_gpr], #32\n";
}

# Center the first len coefficients of each stride-sized inverse block.
# Only these sum paths can exceed the later signed-16-bit bound.
sub emit_center_blocks {
    my ($len, $stride) = @_;
    # Product halves are already reduced by twiddle multiplication.
    for (my $base = 0; $base < 256; $base += $stride) {
        for (my $j = 0; $j < $len; $j += 8) {
            my $off = 2 * ($base + $j);
            $code .= "        ldr     $quad_a, [$arg, #$off]\n";
            emit_center_vec($vec_a);
            $code .= "        str     $quad_a, [$arg, #$off]\n";
        }
    }
}

# Canonicalize all 256 forward coefficients, four vectors per iteration.
sub emit_canonical_all {
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #8
.Lntt_canonical_loop:
___
    for (1..2) {
        $code .= "        ldp     $quad_a, $quad_b, [$pass_gpr]\n";
        emit_canonical_vec($vec_a);
        emit_canonical_vec($vec_b);
        $code .= "        stp     $quad_a, $quad_b, [$pass_gpr], #32\n";
    }
    $code .= <<___;
        subs    $pass_count, $pass_count, #1
        b.ne    .Lntt_canonical_loop
___
}

# Scale by 128^-1 = -26 (mod q).  Products lie in (-q,q), so a sign-mask
# correction gives canonical [0,q) output without a separate centering pass.
sub emit_inverse_scale {
    # The reciprocal for -26 is -256.
    my ($root, $recip) = emit_twiddle_constants(-26, -256);
    $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #8
.Lintt_scale_loop:
___
    for (1..2) {
        $code .= <<___;
        ldp     $quad_b, $quad_b2, [$pass_gpr]
        mul     $vec_product.8h, $vec_b.8h, $root
        mul     $vec_product2.8h, $vec_b2.8h, $root
        sqrdmulh $vec_tmp.8h, $vec_b.8h, $recip
        sqrdmulh $vec_tmp2.8h, $vec_b2.8h, $recip
        mls     $vec_product.8h, $vec_tmp.8h, $vec_q.8h
        mls     $vec_product2.8h, $vec_tmp2.8h, $vec_q.8h
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

# Emit a complete forward or inverse transform; inverse is a generator flag.
sub emit_transform {
    my ($name, $inverse) = @_;
    $use_forward_table = !$inverse;
    my $constants = $inverse ? \%intt_constants : \%ntt_constants;
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
___
    my $table_label = $inverse ? '.Lintt_short_constants' : '.Lntt_constants';
    $code .= <<___;
        adrp    $table_gpr, $table_label
        add     $table_gpr, $table_gpr, #:lo12:$table_label
        mov     $q_gpr, #$q
        dup     $vec_q.8h, $q_gpr
        movi    $vec_barrett.8h, #10
___
    my @lens = $inverse ? (2, 4, 8, 16, 32, 64, 128)
                       : (128, 64, 32, 16, 8, 4, 2);
    for my $len (@lens) {
        if ($len == 2 || $len == 4) {
            my $groups = 128 / $len;
            my $groups_per_batch = 8 / $len;
            my $short_constants = $inverse ? \@inverse_short_constants
                                           : \@forward_constants;
            for (my $group = 0; $group < $groups;
                 $group += $groups_per_batch) {
                my (@roots, @recips);
                for my $g ($group .. $group + $groups_per_batch - 1) {
                    my ($z, $c) = @{$constants->{$len}}[2 * $g, 2 * $g + 1];
                    push @roots, (($z) x $len);
                    push @recips, (($c) x $len);
                }
                push @$short_constants, [[@roots], [@recips]];
            }
            my $loop = ".L${name}_length${len}_loop";
            my $batches = $groups / $groups_per_batch;
            $code .= <<___;
        mov     $pass_gpr, $arg
        mov     $pass_count, #$batches
$loop:
___
            emit_short_batch($len, $inverse);
            $code .= <<___;
        subs    $pass_count, $pass_count, #1
        b.ne    $loop
___
            next;
        }
        my $group = 0;
        for (my $start = 0; $start < 256; $start += 2 * $len, ++$group) {
            # One root/reciprocal pair serves the whole butterfly group.
            my ($z, $c) = @{$constants->{$len}}[2 * $group, 2 * $group + 1];
            my ($root, $recip) = emit_twiddle_constants($z, $c);
            if ($len == 8) {
                emit_bfly_vec_contiguous(2 * $start, $inverse, $root, $recip);
                next;
            }
            for (my $j = 0; $j < $len; $j += 16) {
                my $a = 2 * ($start + $j);
                my $b = 2 * ($start + $len + $j);

                emit_bfly_vec_pair($a, $b, $inverse, $root, $recip);
            }
        }
        # Only the accumulating half-blocks can threaten signed 16-bit range.
        emit_center_blocks(8, 16) if $inverse && $len == 8;
        emit_center_blocks(64, 128) if $inverse && $len == 64;
    }
    $inverse ? emit_inverse_scale() : emit_canonical_all();
    $code .= <<___;
        ret
.size   $name,.-$name

___
}

$code .= <<___;
#include "arch/arm_arch.h"

.text
___
emit_transform('ossl_ml_kem_ntt_armv8', 0);
emit_transform('ossl_ml_kem_intt_armv8', 1);

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
___
for my $constant (@forward_constants) {
    my ($roots, $recips) = @$constant;
    $code .= "        .short  " . join(', ', @$roots) . "\n";
    $code .= "        .short  " . join(', ', @$recips) . "\n";
}
$code .= <<___;
.align  4
// Inverse NTT: lane-packed length-2 entries followed by length-4 entries.
// Each entry is { z^-1[8], round(2^15*z^-1/q)[8] } and occupies 32 bytes.
.Lintt_short_constants:
___
for my $constant (@inverse_short_constants) {
    my ($roots, $recips) = @$constant;
    $code .= "        .short  " . join(', ', @$roots) . "\n";
    $code .= "        .short  " . join(', ', @$recips) . "\n";
}
print $code;
close STDOUT or die "error closing STDOUT: $!";
