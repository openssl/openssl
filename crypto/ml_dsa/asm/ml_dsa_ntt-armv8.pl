#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You may obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
my $dir = $1;
my $xlate;
($xlate = "${dir}arm-xlate.pl" and -f $xlate) or
($xlate = "${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT, "| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

# The transform follows the canonical FIPS 204 layer order used by
# ml_dsa_ntt.c. Four butterflies are evaluated in parallel with Advanced SIMD.
# The offset-2 and offset-1 layers use zip/uzp permutations so that those
# narrow layers remain vectorized as well.
#
# Constant products are left in [0,2q), and additions and subtractions are
# reduced lazily.  A forward butterfly uses a public 2q bias; every layer can
# increase the upper bound by 4q, so the eight layers end below 33q.  One fixed
# final pass reduces this to [0,q).  In the inverse transform, layer n uses a
# public 2^(n-1)*q bias and produces sums below 2^n*q; products remain below
# 2q.  The final layer is therefore below 256q = 2145386752 < 2^31, and the
# final scaling multiplication returns canonical coefficients.  These bounds
# also keep every input to SQDMULH a nonnegative signed 32-bit value.
#
# Only caller-saved GPRs and vector registers are used, so both entry points
# are leaf functions and require no stack frame.
my ($coeff, $zetas, $group, $evenp, $oddp, $groups, $lanes, $rootp) =
    map("x$_", (0..7));
my ($rootw, $recipw, $qw) = map("w$_", (8..10));
my @data = map("v$_", (0..5));
my ($even2, $odd2, $product2) = map("v$_", (6, 7, 17));
my ($t, $pair_t) = map("v$_", (18, 23));
my $inverse_bias = "v26";
my $twiddle_recip = "v27";
my ($scale_recip, $scale, $q) = map("v$_", (28..30));
my $modulus = 8380417;
my (@forward_constants, @inverse_constants);
my $label = 0;
my $code = <<___;
#include "arch/arm_arch.h"

.text
___

sub bitrev8 {
    my ($value) = @_;
    my $result = 0;

    for (1 .. 8) {
        $result = ($result << 1) | ($value & 1);
        $value >>= 1;
    }
    return $result;
}

sub powmod {
    my ($base, $exponent) = @_;
    my $result = 1;

    while ($exponent != 0) {
        $result = ($result * $base) % $modulus if ($exponent & 1) != 0;
        $base = ($base * $base) % $modulus;
        $exponent >>= 1;
    }
    return $result;
}

sub signed_root {
    my ($index, $inverse) = @_;
    my $root = powmod(1753, bitrev8($index));

    $root = $modulus - $root if $inverse;
    return $root > int($modulus / 2) ? $root - $modulus : $root;
}

sub floor_div {
    my ($numerator, $denominator) = @_;

    return $numerator >= 0
        ? int($numerator / $denominator)
        : -int((-$numerator + $denominator - 1) / $denominator);
}

sub reciprocal_for_root {
    my ($root) = @_;

    return floor_div($root * (1 << 31), $modulus);
}

sub push_constant {
    my ($constants, @roots) = @_;
    my @reciprocals = map { reciprocal_for_root($_) } @roots;

    push @$constants, [[@roots], [@reciprocals]];
}

sub constant_mul_unreduced {
    my ($dst, $a, $root, $reciprocal) = @_;

    # Let z be a signed representative of the constant root and define
    #
    #     c = floor(2^31*z/q),  k = floor(a*c/2^31).
    #
    # SQDMULH computes k.  The MUL/MLS pair forms
    # r = low32(a*z) - k*q, hence r == a*z (mod q).  Since 0 <= a < 256q
    # < 2^31 and 0 <= 2^31*z/q-c < 1, k is either floor(a*z/q)
    # or one less.  Consequently 0 <= r < 2q.
    # Compute k before MUL so that dst is permitted to alias a.  This is used
    # by the final inverse scaling, while the butterfly calls use distinct
    # source and destination registers.
    $code .= <<___;
        sqdmulh $t.4s,$a.4s,$reciprocal.4s
        mul     $dst.4s,$a.4s,$root.4s
        mls     $dst.4s,$t.4s,$q.4s
___
}

sub constant_mul {
    my ($dst, $a, $root, $reciprocal) = @_;

    constant_mul_unreduced($dst, $a, $root, $reciprocal);
    # The unreduced result is in [0,2q); one unsigned conditional subtraction
    # produces the canonical representative in [0,q).
    $code .= <<___;
        sub     $t.4s,$dst.4s,$q.4s
        umin    $dst.4s,$dst.4s,$t.4s
___
}

sub constant_mul_pair_unreduced {
    my ($dst0, $a0, $dst1, $a1, $root, $reciprocal) = @_;

    # Interleave two independent constant products.  Besides exposing two
    # independent instruction chains to the processor, calculating both
    # quotients first preserves a0 and a1 when either destination aliases its
    # source during inverse normalization.
    $code .= <<___;
        sqdmulh $t.4s,$a0.4s,$reciprocal.4s
        sqdmulh $pair_t.4s,$a1.4s,$reciprocal.4s
        mul     $dst0.4s,$a0.4s,$root.4s
        mul     $dst1.4s,$a1.4s,$root.4s
        mls     $dst0.4s,$t.4s,$q.4s
        mls     $dst1.4s,$pair_t.4s,$q.4s
___
}

sub constant_mul_pair {
    my ($dst0, $a0, $dst1, $a1, $root, $reciprocal) = @_;

    constant_mul_pair_unreduced($dst0, $a0, $dst1, $a1,
                                $root, $reciprocal);
    $code .= <<___;
        sub     $t.4s,$dst0.4s,$q.4s
        sub     $pair_t.4s,$dst1.4s,$q.4s
        umin    $dst0.4s,$dst0.4s,$t.4s
        umin    $dst1.4s,$dst1.4s,$pair_t.4s
___
}

sub ct_butterfly {
    my ($even, $odd, $root, $reciprocal) = @_;

    constant_mul_unreduced($data[3], $odd, $root, $reciprocal);
    $code .= <<___;
        add     $odd.4s,$even.4s,$inverse_bias.4s
        add     $even.4s,$odd.4s,$data[3].4s
        sub     $odd.4s,$odd.4s,$data[3].4s
___
}

sub gs_butterfly {
    my ($even, $odd, $root, $reciprocal) = @_;

    $code .= <<___;
        add     $data[3].4s,$even.4s,$inverse_bias.4s
        sub     $data[3].4s,$data[3].4s,$odd.4s
        add     $even.4s,$even.4s,$odd.4s
___
    constant_mul_unreduced($odd, $data[3], $root, $reciprocal);
}

sub ct_butterfly_pair {
    my ($even0, $odd0, $even1, $odd1, $root, $reciprocal) = @_;

    constant_mul_pair_unreduced($data[3], $odd0, $product2, $odd1,
                                $root, $reciprocal);
    $code .= <<___;
        add     $odd0.4s,$even0.4s,$inverse_bias.4s
        add     $odd1.4s,$even1.4s,$inverse_bias.4s
        add     $even0.4s,$odd0.4s,$data[3].4s
        add     $even1.4s,$odd1.4s,$product2.4s
        sub     $odd0.4s,$odd0.4s,$data[3].4s
        sub     $odd1.4s,$odd1.4s,$product2.4s
___
}

sub gs_butterfly_pair {
    my ($even0, $odd0, $even1, $odd1, $root, $reciprocal) = @_;

    $code .= <<___;
        add     $data[3].4s,$even0.4s,$inverse_bias.4s
        add     $product2.4s,$even1.4s,$inverse_bias.4s
        sub     $data[3].4s,$data[3].4s,$odd0.4s
        sub     $product2.4s,$product2.4s,$odd1.4s
        add     $even0.4s,$even0.4s,$odd0.4s
        add     $even1.4s,$even1.4s,$odd1.4s
___
    constant_mul_pair_unreduced($odd0, $data[3], $odd1, $product2,
                                $root, $reciprocal);
}

sub emit_inverse_bias {
    my ($multiplier) = @_;
    my $shift = 0;

    $shift++ while (1 << $shift) < $multiplier;
    die "bias multiplier is not a power of two"
        if (1 << $shift) != $multiplier;
    if ($shift == 0) {
        $code .= "        mov     $inverse_bias.16b,$q.16b\n";
    } else {
        $code .= "        shl     $inverse_bias.4s,$q.4s,#$shift\n";
    }
}

sub emit_constants {
    $code .= <<___;
        mov     $qw,#0xe001
        movk    $qw,#0x7f,lsl#16
        dup     $q.4s,$qw
___
}

sub emit_forward_wide_stage {
    my ($step, $offset) = @_;
    my $outer = ".Lml_dsa_ntt_${label}_outer";
    my $inner = ".Lml_dsa_ntt_${label}_inner";
    my $offset_bytes = 4 * $offset;
    my $group_bytes = 2 * $offset_bytes;
    my $vectors = $offset / 4;
    my $paired = $vectors >= 2;
    my $pair_unroll = 1;
    my $iterations = $paired ? $vectors / (2 * $pair_unroll) : $vectors;
    $label++;

    for my $i (0 .. $step - 1) {
        my $root = signed_root($step + $i, 0);
        push_constant(\@forward_constants, $root);
    }

    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#$step
$outer:
        ldr     d2,[$rootp],#8
        dup     $twiddle_recip.4s,$data[2].s[1]
        dup     $data[2].4s,$data[2].s[0]
        mov     $evenp,$group
        add     $oddp,$group,#$offset_bytes
        mov     $lanes,#$iterations
$inner:
___
    if ($paired) {
        for (1 .. $pair_unroll) {
            $code .= <<___;
        ldp     q0,q6,[$evenp]
        ldp     q1,q7,[$oddp]
___
            ct_butterfly_pair($data[0], $data[1], $even2, $odd2,
                              $data[2], $twiddle_recip);
            $code .= <<___;
        stp     q0,q6,[$evenp],#32
        stp     q1,q7,[$oddp],#32
___
        }
    } else {
        $code .= <<___;
        ldr     q0,[$evenp]
        ldr     q1,[$oddp]
___
        ct_butterfly($data[0], $data[1], $data[2], $twiddle_recip);
        $code .= <<___;
        str     q0,[$evenp],#16
        str     q1,[$oddp],#16
___
    }
    $code .= <<___;
        sub     $lanes,$lanes,#1
        cbnz    $lanes,$inner
        add     $group,$group,#$group_bytes
        sub     $groups,$groups,#1
        cbnz    $groups,$outer
___
}

sub emit_forward_offset2 {
    my $loop = ".Lml_dsa_ntt_${label}_offset2";
    $label++;

    for my $group (0 .. 31) {
        my @roots = map { signed_root($_, 0) }
                    (64 + 2 * $group .. 65 + 2 * $group);
        push_constant(\@forward_constants, @roots);
    }

    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#32
$loop:
        ldp     d2,d27,[$rootp],#16
        zip1    $data[2].4s,$data[2].4s,$data[2].4s
        zip1    $twiddle_recip.4s,$twiddle_recip.4s,$twiddle_recip.4s
        ldr     q0,[$group]
        ldr     q1,[$group,#16]
        zip1    $data[4].2d,$data[0].2d,$data[1].2d
        zip2    $data[5].2d,$data[0].2d,$data[1].2d
___
    ct_butterfly($data[4], $data[5], $data[2], $twiddle_recip);
    $code .= <<___;
        zip1    $data[0].2d,$data[4].2d,$data[5].2d
        zip2    $data[1].2d,$data[4].2d,$data[5].2d
        str     q0,[$group],#16
        str     q1,[$group],#16
        sub     $groups,$groups,#1
        cbnz    $groups,$loop
___
}

sub emit_forward_offset1 {
    my $loop = ".Lml_dsa_ntt_${label}_offset1";
    $label++;

    for my $group (0 .. 31) {
        my @roots = map { signed_root($_, 0) }
                    (128 + 4 * $group .. 131 + 4 * $group);
        push_constant(\@forward_constants, @roots);
    }

    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#32
$loop:
        ldp     q2,q27,[$rootp],#32
        ldr     q0,[$group]
        ldr     q1,[$group,#16]
        uzp1    $data[4].4s,$data[0].4s,$data[1].4s
        uzp2    $data[5].4s,$data[0].4s,$data[1].4s
___
    ct_butterfly($data[4], $data[5], $data[2], $twiddle_recip);
    $code .= <<___;
        zip1    $data[0].4s,$data[4].4s,$data[5].4s
        zip2    $data[1].4s,$data[4].4s,$data[5].4s
        str     q0,[$group],#16
        str     q1,[$group],#16
        sub     $groups,$groups,#1
        cbnz    $groups,$loop
___
}

sub emit_inverse_offset1 {
    my $loop = ".Lml_dsa_intt_${label}_offset1";
    $label++;

    for my $group (0 .. 31) {
        my @roots = map { signed_root($_, 1) }
                    reverse(252 - 4 * $group .. 255 - 4 * $group);
        push_constant(\@inverse_constants, @roots);
    }

    emit_inverse_bias(1);
    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#32
$loop:
        ldp     q2,q27,[$rootp],#32
        ldr     q0,[$group]
        ldr     q1,[$group,#16]
        uzp1    $data[4].4s,$data[0].4s,$data[1].4s
        uzp2    $data[5].4s,$data[0].4s,$data[1].4s
___
    gs_butterfly($data[4], $data[5], $data[2], $twiddle_recip);
    $code .= <<___;
        zip1    $data[0].4s,$data[4].4s,$data[5].4s
        zip2    $data[1].4s,$data[4].4s,$data[5].4s
        str     q0,[$group],#16
        str     q1,[$group],#16
        sub     $groups,$groups,#1
        cbnz    $groups,$loop
___
}

sub emit_inverse_offset2 {
    my $loop = ".Lml_dsa_intt_${label}_offset2";
    $label++;

    for my $group (0 .. 31) {
        my @roots = map { signed_root($_, 1) }
                    reverse(126 - 2 * $group .. 127 - 2 * $group);
        push_constant(\@inverse_constants, @roots);
    }

    emit_inverse_bias(2);
    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#32
$loop:
        ldp     d2,d27,[$rootp],#16
        zip1    $data[2].4s,$data[2].4s,$data[2].4s
        zip1    $twiddle_recip.4s,$twiddle_recip.4s,$twiddle_recip.4s
        ldr     q0,[$group]
        ldr     q1,[$group,#16]
        zip1    $data[4].2d,$data[0].2d,$data[1].2d
        zip2    $data[5].2d,$data[0].2d,$data[1].2d
___
    gs_butterfly($data[4], $data[5], $data[2], $twiddle_recip);
    $code .= <<___;
        zip1    $data[0].2d,$data[4].2d,$data[5].2d
        zip2    $data[1].2d,$data[4].2d,$data[5].2d
        str     q0,[$group],#16
        str     q1,[$group],#16
        sub     $groups,$groups,#1
        cbnz    $groups,$loop
___
}

sub emit_inverse_wide_stage {
    my ($step, $offset, $final) = @_;
    my $outer = ".Lml_dsa_intt_${label}_outer";
    my $inner = ".Lml_dsa_intt_${label}_inner";
    my $offset_bytes = 4 * $offset;
    my $group_bytes = 2 * $offset_bytes;
    my $vectors = $offset / 4;
    my $paired = $vectors >= 2;
    my $pair_unroll = 1;
    my $iterations = $paired ? $vectors / (2 * $pair_unroll) : $vectors;
    $label++;

    for my $i (0 .. $step - 1) {
        my $root = signed_root(2 * $step - 1 - $i, 1);
        push_constant(\@inverse_constants, $root);
    }

    emit_inverse_bias(128 / $step);
    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#$step
$outer:
        ldr     d2,[$rootp],#8
        dup     $twiddle_recip.4s,$data[2].s[1]
        dup     $data[2].4s,$data[2].s[0]
        mov     $evenp,$group
        add     $oddp,$group,#$offset_bytes
        mov     $lanes,#$iterations
$inner:
___
    if ($paired) {
        for (1 .. $pair_unroll) {
            $code .= <<___;
        ldp     q0,q6,[$evenp]
        ldp     q1,q7,[$oddp]
___
            gs_butterfly_pair($data[0], $data[1], $even2, $odd2,
                              $data[2], $twiddle_recip);
            if ($final) {
                constant_mul_pair($data[0], $data[0], $even2, $even2,
                                  $scale, $scale_recip);
                constant_mul_pair($data[1], $data[1], $odd2, $odd2,
                                  $scale, $scale_recip);
            }
            $code .= <<___;
        stp     q0,q6,[$evenp],#32
        stp     q1,q7,[$oddp],#32
___
        }
    } else {
        $code .= <<___;
        ldr     q0,[$evenp]
        ldr     q1,[$oddp]
___
        gs_butterfly($data[0], $data[1], $data[2], $twiddle_recip);
        if ($final) {
            constant_mul($data[0], $data[0], $scale, $scale_recip);
            constant_mul($data[1], $data[1], $scale, $scale_recip);
        }
        $code .= <<___;
        str     q0,[$evenp],#16
        str     q1,[$oddp],#16
___
    }
    $code .= <<___;
        sub     $lanes,$lanes,#1
        cbnz    $lanes,$inner
        add     $group,$group,#$group_bytes
        sub     $groups,$groups,#1
        cbnz    $groups,$outer
___
}

sub emit_forward_canonical {
    my $loop = ".Lml_dsa_ntt_${label}_canonical";
    my $pairs_per_iteration = 2;
    my $iterations = 32 / $pairs_per_iteration;
    $label++;

    # Starting in [0,q), every forward layer can add 4q to the upper bound,
    # so after all eight layers every lane is in [0,33q).  For such x,
    # t=floor(x/2^23) is at most 32 and
    #
    #   r = x - t*q < q + 33*(2^23-q) < 2q.
    #
    # USHR/MLS forms r and one SUB/UMIN makes it canonical.  The pass is
    # unrolled in vector pairs to reduce fixed loop overhead while retaining
    # paired loads and stores.
    $code .= <<___;
        mov     $group,$coeff
        mov     $groups,#$iterations
$loop:
___
    for (1 .. $pairs_per_iteration) {
        $code .= <<___;
        ldp     q0,q1,[$group]
        ushr    $t.4s,$data[0].4s,#23
        ushr    $pair_t.4s,$data[1].4s,#23
        mls     $data[0].4s,$t.4s,$q.4s
        mls     $data[1].4s,$pair_t.4s,$q.4s
        sub     $t.4s,$data[0].4s,$q.4s
        sub     $pair_t.4s,$data[1].4s,$q.4s
        umin    $data[0].4s,$data[0].4s,$t.4s
        umin    $data[1].4s,$data[1].4s,$pair_t.4s
        stp     q0,q1,[$group],#32
___
    }
    $code .= <<___;
        subs    $groups,$groups,#1
        b.ne    $loop
___
}

$code .= <<___;
.globl  ossl_ml_dsa_poly_ntt_armv8
.type   ossl_ml_dsa_poly_ntt_armv8,%function
.p2align 4
ossl_ml_dsa_poly_ntt_armv8:
        AARCH64_VALID_CALL_TARGET
___
emit_constants();
$code .= <<___;
        adrp    $rootp,.Lml_dsa_ntt_constants
        add     $rootp,$rootp,#:lo12:.Lml_dsa_ntt_constants
___
emit_inverse_bias(2);
emit_forward_wide_stage(1, 128);
emit_forward_wide_stage(2, 64);
emit_forward_wide_stage(4, 32);
emit_forward_wide_stage(8, 16);
emit_forward_wide_stage(16, 8);
emit_forward_wide_stage(32, 4);
emit_forward_offset2();
emit_forward_offset1();
emit_forward_canonical();
$code .= <<___;
        ret
.size   ossl_ml_dsa_poly_ntt_armv8,.-ossl_ml_dsa_poly_ntt_armv8

.globl  ossl_ml_dsa_poly_ntt_inverse_armv8
.type   ossl_ml_dsa_poly_ntt_inverse_armv8,%function
.p2align 4
ossl_ml_dsa_poly_ntt_inverse_armv8:
        AARCH64_VALID_CALL_TARGET
___
emit_constants();
my $r_mod_q = (1 << 32) % $modulus;
my $r_inverse = powmod($r_mod_q, $modulus - 2);
my $scale_root = (41978 * $r_inverse) % $modulus;
$scale_root -= $modulus if $scale_root > int($modulus / 2);
my $scale_reciprocal = reciprocal_for_root($scale_root);
my $scale_root_bits = $scale_root & 0xffffffff;
my $scale_reciprocal_bits = $scale_reciprocal & 0xffffffff;
$code .= <<___;
        adrp    $rootp,.Lml_dsa_intt_constants
        add     $rootp,$rootp,#:lo12:.Lml_dsa_intt_constants
        mov     $rootw,#@{[$scale_root_bits & 0xffff]}
        movk    $rootw,#@{[($scale_root_bits >> 16) & 0xffff]},lsl#16
        dup     $scale.4s,$rootw
        mov     $recipw,#@{[$scale_reciprocal_bits & 0xffff]}
        movk    $recipw,#@{[($scale_reciprocal_bits >> 16) & 0xffff]},lsl#16
        dup     $scale_recip.4s,$recipw
___
emit_inverse_offset1();
emit_inverse_offset2();
emit_inverse_wide_stage(32, 4, 0);
emit_inverse_wide_stage(16, 8, 0);
emit_inverse_wide_stage(8, 16, 0);
emit_inverse_wide_stage(4, 32, 0);
emit_inverse_wide_stage(2, 64, 0);
emit_inverse_wide_stage(1, 128, 1);
$code .= <<___;
        ret
.size   ossl_ml_dsa_poly_ntt_inverse_armv8,.-ossl_ml_dsa_poly_ntt_inverse_armv8
___

$code .= <<___;
.rodata
.align  4
# Each forward table record contains the signed ordinary-domain root or roots
# consumed by one loop group, immediately followed by their c values for
# SQDMULH.  The generator derives both halves from root 1753 and the bit-
# reversed layer index; no precomputed transform table is copied here.
.Lml_dsa_ntt_constants:
___
for my $constant (@forward_constants) {
    my ($roots, $reciprocals) = @$constant;
    $code .= "        .word   " . join(',', @$roots) . "\n";
    $code .= "        .word   " . join(',', @$reciprocals) . "\n";
}
$code .= <<___;
.align  4
# The inverse records have the same root/reciprocal layout, in the reverse
# layer order consumed by the Gentleman-Sande loops.  Their roots are the
# signed additive inverses of the corresponding forward roots.
.Lml_dsa_intt_constants:
___
for my $constant (@inverse_constants) {
    my ($roots, $reciprocals) = @$constant;
    $code .= "        .word   " . join(',', @$roots) . "\n";
    $code .= "        .word   " . join(',', @$reciprocals) . "\n";
}

print $code;
close STDOUT or die "error closing output: $!";
