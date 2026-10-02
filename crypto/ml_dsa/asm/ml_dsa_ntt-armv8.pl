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

# The transform follows the standard FIPS 204 layer order used by
# ml_dsa_ntt.c.  Each Neon register holds four 32-bit coefficients, so four
# butterflies are evaluated in parallel.  Layers with offsets of at least four
# can load their even and odd halves directly.  Layers 7 and 8 use ZIP/UZP
# permutations to put butterfly partners in matching lanes.
#
# Constant products are left in [0,2q), and additions and subtractions are
# reduced lazily.  An NTT butterfly uses a public 2q bias; every layer can
# increase the upper bound by 4q, so the eight layers end below 33q.  One fixed
# final pass reduces this to [0,q).  In the iNTT, layer n uses a
# public 2^(n-1)q bias and produces sums below 2^nq; products remain below
# 2q.  The final layer is therefore below 256q (2145386752) < 2^31,
# and the final scaling multiplication reduces coefficients into [0,q).
# In summary:
#
#                       input         after eight layers
#   NTT                 [0,q)         [0,33q)
#   iNTT                [0,q)         [0,256q)
#   twiddle product     [0,256q)      [0,2q)
#
# Since 256q (2145386752) < 2^31, every coefficient operand supplied to
# SQDMULH remains a nonnegative signed 32-bit value.  Its other operand, c,
# uses the signed centred range shown below.
#
# Fixed-point twiddle-multiplication bounds (q = 8380417):
#
#   a   input coefficient          0 <= a < 256q (2145386752) < 2^31
#   z   centred twiddle            -q/2 < z < q/2
#                                  (-4190208 <= z <= 4190208)
#   c   floor(2^31*z/q)           -1073741696 <= c <= 1073741695
#   k   floor(a*c/2^31)           -2^30 <= k < 2^30
#   r   a*z - k*q                  0 <= r < 2q (16760834)
#
# z and c are signed 32-bit values.  a is nonnegative and remains below the
# signed limit.  MUL and MLS retain only the low 32 bits, but this is exact for
# the final r because the mathematical difference a*z-k*q lies in [0,2q).
# The iNTT bias ranges from q through 128q (1072693376), below 2^30.
#
# Only caller-saved GPRs and vector registers are used, so both entry points
# are leaf functions and require no stack frame.
#
# The public ABI supplies a zeta-table pointer in x1.  It is intentionally
# unused: this implementation embeds each z (the twiddle) next to its
# c = floor(2^31*z/q), as required by the Neon multiplication sequence.
my $q = 8380417;
my $q_low_halfword = sprintf("0x%x", $q & 0xffff);
my $q_high_halfword = sprintf("0x%x", ($q >> 16) & 0xffff);
my $polynomial_coefficients = 256;
my $coefficient_bytes = 4;
my $vector_lanes = 4;
my $vector_bytes = $vector_lanes * $coefficient_bytes;
my $vector_pair_bytes = 2 * $vector_bytes;
my $vector_pair_count = $polynomial_coefficients / (2 * $vector_lanes);
my $ntt_reduction_shift = 23;
my $ntt_reduction_coefficients_per_iteration = 4 * $vector_lanes;
my $ntt_reduction_iterations =
    $polynomial_coefficients / $ntt_reduction_coefficients_per_iteration;

my ($inout_coefficients, $unused_zetas, $group_ptr, $even_ptr, $odd_ptr,
    $group_count, $vector_count, $zc_ptr) = map("x$_", (0..7));
my ($z_word, $c_word, $q_word) =
    map("w$_", (8..10));

# Every Neon register alias below holds four 32-bit lanes during arithmetic.
# A few zip and mov instructions view the same 128 bits as two 64-bit lanes
# (.2d) or sixteen bytes (.16b) only to rearrange or copy the four values.
# qN and vN are two names for the same 128-bit register.  In the paired wide
# path, the loads and butterfly arguments therefore map as follows:
#
#   q0/v0 = $even0_q/$even0_v = first four even-side coefficients
#   q6/v6 = $even1_q/$even1_v = next four even-side coefficients
#   q1/v1 = $odd0_q/$odd0_v   = first four odd-side coefficients
#   q7/v7 = $odd1_q/$odd1_v   = next four odd-side coefficients
my ($coeff0_v, $coeff1_v, $z_v, $product_v,
    $butterfly_even, $butterfly_odd) = map("v$_", (0..5));
my ($coeff0_q, $coeff1_q) = map("q$_", (0, 1));
# These aliases name the loaded table layout before its values are broadcast
# into the arithmetic vectors $z_v and $c_v.  A single record shares v2/d2 as
# [z,c]; the final two layers load separate pairs or vectors of z and c values.
my $zc_v = "v2";
my $zc_d = "d2";
my ($z_d, $c_d) = map("d$_", (2, 27));
my ($z_q, $c_q) = map("q$_", (2, 27));
my ($even0_v, $odd0_v,
    $even1_v, $odd1_v) = map("v$_", (0, 1, 6, 7));
my ($even0_q, $odd0_q,
    $even1_q, $odd1_q) =
    map("q$_", (0, 1, 6, 7));
my $product2_v = "v17";
my ($quotient_v, $quotient2_v) = map("v$_", (18, 23));
my $q_bias_v = "v26";
my $c_v = "v27";
my ($scale_c_v, $scale_z_v, $q_vector) = map("v$_", (28..30));
# load_q() broadcasts q into q_vector as [q, q, q, q].
my $code = <<___;
#include "arch/arm_arch.h"

.text
___

##
# @brief Set dst = a*z mod q with dst in [0,2q).
# @param[out] dst Destination vector register.
# @param[in] a Source vector register containing values in [0,256q).
# @param[in] z Vector register containing the centred twiddles.
# @param[in] c Vector register containing each z's reduction constant.
# @return Generated code leaves each dst lane congruent to a*z modulo q in
# [0,2q).
# @note Uses $quotient_v as scratch.
# @details Let z be the centred twiddle and define
#
#     c = floor(2^31*z/q),  k = floor(a*c/2^31).
#
# The variables obey:
#
#     0 <= a < 256q < 2^31
#     -q/2 < z < q/2
#     -2^30 < c < 2^30
#      0 <= 2^31*z/q - c < 1
#
# SQDMULH computes k.  Because a/2^31 < 1, k is either floor(a*z/q) or one
# less.  MUL/MLS then forms r = low32(a*z-k*q), where 0 <= r < 2q.  This bound
# makes the low-32-bit arithmetic the exact integer r, not merely a value
# modulo 2^32.  Computing k before MUL permits dst to alias a during final
# iNTT scaling.
sub barrett_multiply_lazy {
    my ($dst, $a, $z, $c) = @_;
    $code .= <<___;
        sqdmulh $quotient_v.4s, $a.4s, $c.4s
        mul     $dst.4s, $a.4s, $z.4s
        mls     $dst.4s, $quotient_v.4s, $q_vector.4s
___
}

##
# @brief Set dst = a*z mod q with dst in [0,q).
# @param[out] dst Destination vector register.
# @param[in] a Source vector register containing values in [0,256q).
# @param[in] z Vector register containing the centred twiddles.
# @param[in] c Vector register containing each z's reduction constant.
# @return Generated code leaves each dst lane equal to a*z modulo q in [0,q).
# @note Uses $quotient_v as scratch.
# @details The lazy result is in [0,2q), so one unsigned conditional
# subtraction reduces it into [0,q).
sub barrett_multiply {
    my ($dst, $a, $z, $c) = @_;

    barrett_multiply_lazy($dst, $a, $z, $c);
    $code .= <<___;
        sub     $quotient_v.4s, $dst.4s, $q_vector.4s
        umin    $dst.4s, $dst.4s, $quotient_v.4s
___
}

##
# @brief Set (dst0,dst1) = (a0*z,a1*z) mod q in [0,2q).
# @param[out] dst0 First destination vector register.
# @param[in] a0 First source vector register.
# @param[out] dst1 Second destination vector register.
# @param[in] a1 Second source vector register.
# @param[in] z Shared vector register containing the centred twiddles.
# @param[in] c Shared vector register containing each z's reduction constant.
# @return Generated code leaves both destination vectors in [0,2q).
# @note Uses $quotient_v and $quotient2_v as scratch.
# @details Interleaving two independent products exposes both instruction
# chains to the processor.  Computing both quotients first also preserves a0
# and a1 when either destination aliases its source during iNTT normalization.
sub barrett_multiply_pair_lazy {
    my ($dst0, $a0, $dst1, $a1, $z, $c) = @_;

    $code .= <<___;
        sqdmulh $quotient_v.4s, $a0.4s, $c.4s
        sqdmulh $quotient2_v.4s, $a1.4s, $c.4s
        mul     $dst0.4s, $a0.4s, $z.4s
        mul     $dst1.4s, $a1.4s, $z.4s
        mls     $dst0.4s, $quotient_v.4s, $q_vector.4s
        mls     $dst1.4s, $quotient2_v.4s, $q_vector.4s
___
}

##
# @brief Set (dst0,dst1) = (a0*z,a1*z) mod q in [0,q).
# @param[out] dst0 First destination vector register.
# @param[in] a0 First source vector register.
# @param[out] dst1 Second destination vector register.
# @param[in] a1 Second source vector register.
# @param[in] z Shared vector register containing the centred twiddles.
# @param[in] c Shared vector register containing each z's reduction constant.
# @return Generated code leaves both destination vectors in [0,q).
# @note Uses both quotient vectors as scratch.
sub barrett_multiply_pair {
    my ($dst0, $a0, $dst1, $a1, $z, $c) = @_;

    barrett_multiply_pair_lazy($dst0, $a0, $dst1, $a1, $z, $c);
    $code .= <<___;
        sub     $quotient_v.4s, $dst0.4s, $q_vector.4s
        sub     $quotient2_v.4s, $dst1.4s, $q_vector.4s
        umin    $dst0.4s, $dst0.4s, $quotient_v.4s
        umin    $dst1.4s, $dst1.4s, $quotient2_v.4s
___
}

##
# @brief Four-way Cooley-Tukey NTT butterfly.
# @param[in,out] even Vector register containing the even coefficients.
# @param[in,out] odd Vector register containing the odd coefficients.
# @param[in] z Vector register containing the NTT twiddles.
# @param[in] c Vector register containing each z's reduction constant.
# @pre Each input lane is in [0,B), and $q_bias_v contains 2q.
# @return Generated code leaves even in [2q,B+4q) and odd in [0,B+2q).
# Thus, every output lane is in [0,B+4q).
#
# @par Pseudocode
#
#   product = odd * twiddle mod q, with 0 <= product < 2q
#   even'   = even + 2q + product
#   odd'    = even + 2q - product
#
# The 2q bias prevents the subtraction from becoming negative.  It is a
# multiple of q, so it does not change either result modulo q.
sub ntt_butterfly_4way {
    my ($even, $odd, $z, $c) = @_;

    barrett_multiply_lazy($product_v, $odd, $z, $c);
    # Reuse odd as the biased-even value from which both outputs are formed.
    $code .= <<___;
        add     $odd.4s, $even.4s, $q_bias_v.4s
        add     $even.4s, $odd.4s, $product_v.4s
        sub     $odd.4s, $odd.4s, $product_v.4s
___
}

##
# @brief Four-way Gentleman-Sande iNTT butterfly.
# @param[in,out] even Vector register containing the even coefficients.
# @param[in,out] odd Vector register containing the odd coefficients.
# @param[in] z Vector register containing the iNTT twiddles.
# @param[in] c Vector register containing each z's reduction constant.
# @pre Each input lane is in [0,B), and $q_bias_v contains B, a multiple of q.
# @return Generated code leaves even in [0,2B) and odd in [0,2q).
#
# @par Pseudocode
#
#   difference = even + bias - odd
#   even'      = even + odd
#   odd'       = difference * twiddle mod q
#
# Each iNTT layer sets bias to the current coefficient bound.  The bias is
# a multiple of q and keeps difference nonnegative without changing it mod q.
sub intt_butterfly_4way {
    my ($even, $odd, $z, $c) = @_;

    # Reuse product as the nonnegative biased difference consumed by the
    # twiddle multiplication.
    $code .= <<___;
        add     $product_v.4s, $even.4s, $q_bias_v.4s
        sub     $product_v.4s, $product_v.4s, $odd.4s
        add     $even.4s, $even.4s, $odd.4s
___
    barrett_multiply_lazy($odd, $product_v, $z, $c);
}

##
# @brief Eight-way Cooley-Tukey NTT butterfly.
# @param[in,out] even0 First even-coefficient vector register.
# @param[in,out] odd0 First odd-coefficient vector register.
# @param[in,out] even1 Second even-coefficient vector register.
# @param[in,out] odd1 Second odd-coefficient vector register.
# @param[in] z Shared vector register containing the NTT twiddles.
# @param[in] c Shared vector register containing each z's reduction constant.
# @pre Each input lane is in [0,B), and $q_bias_v contains 2q.
# @return Generated code leaves even0 and even1 in [2q,B+4q), and odd0 and
# odd1 in [0,B+2q).  Thus, every output lane is in [0,B+4q).
sub ntt_butterfly_8way {
    my ($even0, $odd0, $even1, $odd1,
        $z, $c) = @_;

    barrett_multiply_pair_lazy($product_v, $odd0, $product2_v, $odd1, $z, $c);
    # Reuse each odd register as the biased-even value from which its two
    # outputs are formed.
    $code .= <<___;
        add     $odd0.4s, $even0.4s, $q_bias_v.4s
        add     $odd1.4s, $even1.4s, $q_bias_v.4s
        add     $even0.4s, $odd0.4s, $product_v.4s
        add     $even1.4s, $odd1.4s, $product2_v.4s
        sub     $odd0.4s, $odd0.4s, $product_v.4s
        sub     $odd1.4s, $odd1.4s, $product2_v.4s
___
}

##
# @brief Eight-way Gentleman-Sande iNTT butterfly.
# @param[in,out] even0 First even-coefficient vector register.
# @param[in,out] odd0 First odd-coefficient vector register.
# @param[in,out] even1 Second even-coefficient vector register.
# @param[in,out] odd1 Second odd-coefficient vector register.
# @param[in] z Shared vector register containing the iNTT twiddles.
# @param[in] c Shared vector register containing each z's reduction constant.
# @pre Each input lane is in [0,B), and $q_bias_v contains B, a multiple of q.
# @return Generated code leaves even0 and even1 in [0,2B), and odd0 and odd1
# in [0,2q).
sub intt_butterfly_8way {
    my ($even0, $odd0, $even1, $odd1,
        $z, $c) = @_;

    # Reuse the product registers as the nonnegative biased differences
    # consumed by the twiddle multiplications.
    $code .= <<___;
        add     $product_v.4s, $even0.4s, $q_bias_v.4s
        add     $product2_v.4s, $even1.4s, $q_bias_v.4s
        sub     $product_v.4s, $product_v.4s, $odd0.4s
        sub     $product2_v.4s, $product2_v.4s, $odd1.4s
        add     $even0.4s, $even0.4s, $odd0.4s
        add     $even1.4s, $even1.4s, $odd1.4s
___
    barrett_multiply_pair_lazy($odd0, $product_v, $odd1, $product2_v, $z, $c);
}

##
# @brief Load q.
# @return Generated code loads q into $q_word and [q,q,q,q] into $q_vector.
# @details MOV and MOVK load the low and high 16-bit halfwords of q.
sub load_q {
    $code .= <<___;
        mov     $q_word, #$q_low_halfword
        movk    $q_word, #$q_high_halfword, lsl #16
        dup     $q_vector.4s, $q_word
___
}

##
# @brief Wide-offset NTT layer.
# @param[in] layer NTT layer number.
# @param[in] groups Number of coefficient groups in the layer.
# @param[in] butterfly_distance Coefficient separation between butterfly
# partners.
# @return Generated code updates all 256 coefficients in place.
# @details Applies when partners are at least one vector apart.  The parameters
# match the scalar FIPS 204 loop structure.
#
# @par Pseudocode
#   for each group in the layer:
#       (z, c) = next table record
#       for each vector of partners separated by butterfly_distance:
#           (even, odd) = ntt_butterfly_4way(even, odd, z, c)
sub ntt_wide_layer {
    my %args = @_;
    my $layer = $args{layer};
    my $groups = $args{groups};
    my $butterfly_distance = $args{butterfly_distance};
    my $outer = ".Lml_dsa_ntt_layer${layer}_outer";
    my $inner = ".Lml_dsa_ntt_layer${layer}_inner";
    my $butterfly_distance_bytes =
        $coefficient_bytes * $butterfly_distance;
    my $group_bytes = 2 * $butterfly_distance_bytes;
    my $vectors = $butterfly_distance / $vector_lanes;
    my $paired = $vectors >= 2;
    my $iterations = $paired ? $vectors / 2 : $vectors;
    $code .= <<___;
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$groups
$outer:
        ldr     $zc_d, [$zc_ptr], #8
        dup     $c_v.4s, $zc_v.s[1]
        dup     $z_v.4s, $zc_v.s[0]
        mov     $even_ptr, $group_ptr
        add     $odd_ptr, $group_ptr, #$butterfly_distance_bytes
        mov     $vector_count, #$iterations
$inner:
___
    if ($paired) {
        # NTT layers 1-5 reach this branch: butterfly distances 128, 64, 32,
        # 16, and 8.  Each iteration handles two vectors from each half.
        $code .= <<___;
        ldp     $even0_q, $even1_q, [$even_ptr]
        ldp     $odd0_q, $odd1_q, [$odd_ptr]
___
        ntt_butterfly_8way($even0_v, $odd0_v,
                           $even1_v, $odd1_v,
                           $z_v, $c_v);
        $code .= <<___;
        stp     $even0_q, $even1_q, [$even_ptr], #$vector_pair_bytes
        stp     $odd0_q, $odd1_q, [$odd_ptr], #$vector_pair_bytes
___
    } else {
        # NTT layer 6 reaches this branch: butterfly distance 4.  Each half
        # contains one vector, so a paired load would cross the group boundary.
        $code .= <<___;
        ldr     $coeff0_q, [$even_ptr]
        ldr     $coeff1_q, [$odd_ptr]
___
        ntt_butterfly_4way($coeff0_v, $coeff1_v, $z_v, $c_v);
        $code .= <<___;
        str     $coeff0_q, [$even_ptr], #$vector_bytes
        str     $coeff1_q, [$odd_ptr], #$vector_bytes
___
    }
    $code .= <<___;
        sub     $vector_count, $vector_count, #1
        cbnz    $vector_count, $inner
        add     $group_ptr, $group_ptr, #$group_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $outer
___
}

##
# @brief NTT layer 7.
# @return Generated code updates all 256 coefficients in place.
# @details Each pair of adjacent 128-bit loads contains interleaved butterfly
# halves.  ZIP on 64-bit elements places partners in matching lanes.
#
# @par Pseudocode
#   for each pair of adjacent vectors:
#       (even, odd) = zip_64_bit_halves(load_two_vectors())
#       (even, odd) = ntt_butterfly_4way(even, odd, z, c)
#       store_two_vectors(unzip_64_bit_halves(even, odd))
sub ntt_layer7 {
    my $loop = ".Lml_dsa_ntt_layer7_loop";

    $code .= <<___;
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$vector_pair_count
$loop:
        ldp     $z_d, $c_d, [$zc_ptr], #16
        zip1    $z_v.4s, $z_v.4s, $z_v.4s
        zip1    $c_v.4s, $c_v.4s, $c_v.4s
        ldr     $coeff0_q, [$group_ptr]
        ldr     $coeff1_q, [$group_ptr, #$vector_bytes]
        zip1    $butterfly_even.2d, $coeff0_v.2d, $coeff1_v.2d
        zip2    $butterfly_odd.2d, $coeff0_v.2d, $coeff1_v.2d
___
    ntt_butterfly_4way($butterfly_even, $butterfly_odd, $z_v, $c_v);
    $code .= <<___;
        zip1    $coeff0_v.2d, $butterfly_even.2d, $butterfly_odd.2d
        zip2    $coeff1_v.2d, $butterfly_even.2d, $butterfly_odd.2d
        str     $coeff0_q, [$group_ptr], #$vector_bytes
        str     $coeff1_q, [$group_ptr], #$vector_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $loop
___
}

##
# @brief NTT layer 8.
# @return Generated code updates all 256 coefficients in place.
# @details UZP separates even and odd coefficients into two vectors; ZIP
# restores the original memory order after the butterflies.
#
# @par Pseudocode
#   for each pair of adjacent vectors:
#       (even, odd) = separate_even_and_odd_lanes(load_two_vectors())
#       (even, odd) = ntt_butterfly_4way(even, odd, z, c)
#       store_two_vectors(interleave_lanes(even, odd))
sub ntt_layer8 {
    my $loop = ".Lml_dsa_ntt_layer8_loop";

    $code .= <<___;
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$vector_pair_count
$loop:
        ldp     $z_q, $c_q, [$zc_ptr], #32
        ldr     $coeff0_q, [$group_ptr]
        ldr     $coeff1_q, [$group_ptr, #$vector_bytes]
        uzp1    $butterfly_even.4s, $coeff0_v.4s, $coeff1_v.4s
        uzp2    $butterfly_odd.4s, $coeff0_v.4s, $coeff1_v.4s
___
    ntt_butterfly_4way($butterfly_even, $butterfly_odd, $z_v, $c_v);
    $code .= <<___;
        zip1    $coeff0_v.4s, $butterfly_even.4s, $butterfly_odd.4s
        zip2    $coeff1_v.4s, $butterfly_even.4s, $butterfly_odd.4s
        str     $coeff0_q, [$group_ptr], #$vector_bytes
        str     $coeff1_q, [$group_ptr], #$vector_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $loop
___
}

##
# @brief iNTT layer 1.
# @return Generated code updates all 256 coefficients in place using bias q.
# @details The first iNTT layer begins undoing the lane permutations used by
# the final two NTT layers.
#
# @par Pseudocode
#   bias = q
#   for each pair of adjacent vectors:
#       (even, odd) = separate_even_and_odd_lanes(load_two_vectors())
#       (even, odd) = intt_butterfly_4way(even, odd, z, c, bias)
#       store_two_vectors(interleave_lanes(even, odd))
sub intt_layer1 {
    my $loop = ".Lml_dsa_intt_layer1_loop";

    $code .= <<___;
        mov     $q_bias_v.16b, $q_vector.16b
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$vector_pair_count
$loop:
        ldp     $z_q, $c_q, [$zc_ptr], #32
        ldr     $coeff0_q, [$group_ptr]
        ldr     $coeff1_q, [$group_ptr, #$vector_bytes]
        uzp1    $butterfly_even.4s, $coeff0_v.4s, $coeff1_v.4s
        uzp2    $butterfly_odd.4s, $coeff0_v.4s, $coeff1_v.4s
___
    intt_butterfly_4way($butterfly_even, $butterfly_odd, $z_v, $c_v);
    $code .= <<___;
        zip1    $coeff0_v.4s, $butterfly_even.4s, $butterfly_odd.4s
        zip2    $coeff1_v.4s, $butterfly_even.4s, $butterfly_odd.4s
        str     $coeff0_q, [$group_ptr], #$vector_bytes
        str     $coeff1_q, [$group_ptr], #$vector_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $loop
___
}

##
# @brief iNTT layer 2.
# @return Generated code updates all 256 coefficients in place using bias 2q.
# @details Uses 64-bit ZIP operations to undo the corresponding NTT lane
# permutation.
#
# @par Pseudocode
#   bias = 2q
#   for each pair of adjacent vectors:
#       (even, odd) = zip_64_bit_halves(load_two_vectors())
#       (even, odd) = intt_butterfly_4way(even, odd, z, c, bias)
#       store_two_vectors(unzip_64_bit_halves(even, odd))
sub intt_layer2 {
    my $loop = ".Lml_dsa_intt_layer2_loop";

    $code .= <<___;
        shl     $q_bias_v.4s, $q_vector.4s, #1
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$vector_pair_count
$loop:
        ldp     $z_d, $c_d, [$zc_ptr], #16
        zip1    $z_v.4s, $z_v.4s, $z_v.4s
        zip1    $c_v.4s, $c_v.4s, $c_v.4s
        ldr     $coeff0_q, [$group_ptr]
        ldr     $coeff1_q, [$group_ptr, #$vector_bytes]
        zip1    $butterfly_even.2d, $coeff0_v.2d, $coeff1_v.2d
        zip2    $butterfly_odd.2d, $coeff0_v.2d, $coeff1_v.2d
___
    intt_butterfly_4way($butterfly_even, $butterfly_odd, $z_v, $c_v);
    $code .= <<___;
        zip1    $coeff0_v.2d, $butterfly_even.2d, $butterfly_odd.2d
        zip2    $coeff1_v.2d, $butterfly_even.2d, $butterfly_odd.2d
        str     $coeff0_q, [$group_ptr], #$vector_bytes
        str     $coeff1_q, [$group_ptr], #$vector_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $loop
___
}

##
# @brief Wide-offset iNTT layer.
# @param[in] layer iNTT layer number.
# @param[in] groups Number of coefficient groups in the layer.
# @param[in] butterfly_distance Coefficient separation between butterfly
# partners.
# @param[in] bias_shift Selects q << bias_shift as the subtraction bias.
# @param[in] normalize_after_layer Whether to apply iNTT normalization and
# reduce the result into [0,q) after the layer.
# @return Generated code updates all 256 coefficients in place.
#
# @par Pseudocode
#   bias = q << bias_shift
#   for each group in the layer:
#       (z, c) = next table record
#       for each vector of partners separated by butterfly_distance:
#           (even, odd) = intt_butterfly_4way(even, odd, z, c, bias)
#           if normalize_after_layer: reduce even and odd to [0,q)
sub intt_wide_layer {
    my %args = @_;
    my $layer = $args{layer};
    my $groups = $args{groups};
    my $butterfly_distance = $args{butterfly_distance};
    my $bias_shift = $args{bias_shift};
    my $normalize_after_layer = $args{normalize_after_layer};
    my $outer = ".Lml_dsa_intt_layer${layer}_outer";
    my $inner = ".Lml_dsa_intt_layer${layer}_inner";
    my $butterfly_distance_bytes =
        $coefficient_bytes * $butterfly_distance;
    my $group_bytes = 2 * $butterfly_distance_bytes;
    my $vectors = $butterfly_distance / $vector_lanes;
    my $paired = $vectors >= 2;
    my $iterations = $paired ? $vectors / 2 : $vectors;
    $code .= <<___;
        shl     $q_bias_v.4s, $q_vector.4s, #$bias_shift
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$groups
$outer:
        ldr     $zc_d, [$zc_ptr], #8
        dup     $c_v.4s, $zc_v.s[1]
        dup     $z_v.4s, $zc_v.s[0]
        mov     $even_ptr, $group_ptr
        add     $odd_ptr, $group_ptr, #$butterfly_distance_bytes
        mov     $vector_count, #$iterations
$inner:
___
    if ($paired) {
        # iNTT layers 4-8 reach this branch: butterfly distances 8, 16, 32,
        # 64, and 128.  Each iteration handles two vectors from each half.
        $code .= <<___;
        ldp     $even0_q, $even1_q, [$even_ptr]
        ldp     $odd0_q, $odd1_q, [$odd_ptr]
___
        intt_butterfly_8way($even0_v, $odd0_v,
                            $even1_v, $odd1_v,
                            $z_v, $c_v);
        if ($normalize_after_layer) {
            barrett_multiply_pair($even0_v, $even0_v,
                                  $even1_v, $even1_v,
                                  $scale_z_v, $scale_c_v);
            barrett_multiply_pair($odd0_v, $odd0_v,
                                  $odd1_v, $odd1_v,
                                  $scale_z_v, $scale_c_v);
        }
        $code .= <<___;
        stp     $even0_q, $even1_q, [$even_ptr], #$vector_pair_bytes
        stp     $odd0_q, $odd1_q, [$odd_ptr], #$vector_pair_bytes
___
    } else {
        # iNTT layer 3 reaches this branch: butterfly distance 4.  Each half
        # contains one vector, so a paired load would cross the group boundary.
        $code .= <<___;
        ldr     $coeff0_q, [$even_ptr]
        ldr     $coeff1_q, [$odd_ptr]
___
        intt_butterfly_4way($coeff0_v, $coeff1_v, $z_v, $c_v);
        if ($normalize_after_layer) {
            barrett_multiply($coeff0_v, $coeff0_v, $scale_z_v,
                            $scale_c_v);
            barrett_multiply($coeff1_v, $coeff1_v, $scale_z_v,
                            $scale_c_v);
        }
        $code .= <<___;
        str     $coeff0_q, [$even_ptr], #$vector_bytes
        str     $coeff1_q, [$odd_ptr], #$vector_bytes
___
    }
    $code .= <<___;
        sub     $vector_count, $vector_count, #1
        cbnz    $vector_count, $inner
        add     $group_ptr, $group_ptr, #$group_bytes
        sub     $group_count, $group_count, #1
        cbnz    $group_count, $outer
___
}

##
# @brief Reduce eight NTT coefficients into [0,q).
# @pre $group_ptr addresses eight coefficients in [0,33q).
# @return Generated code reduces two coefficient vectors and advances
# $group_ptr by 32 bytes.
# @details For each coefficient x, t = floor(x/2^23) is at most 32 and
#
#     r = x - t*q < q + 33*(2^23-q) < 2q.
#
# USHR/MLS forms r, then one SUB/UMIN reduces r from [0,2q) to [0,q).
#
# @par Pseudocode
#   for each vector x:
#       approximate_quotient = x >> 23
#       remainder = x - approximate_quotient*q
#       x = min_unsigned(remainder, remainder-q)
sub ntt_reduce_vector_pair {
    $code .= <<___;
        ldp     $coeff0_q, $coeff1_q, [$group_ptr]
        ushr    $quotient_v.4s, $coeff0_v.4s, #$ntt_reduction_shift
        ushr    $quotient2_v.4s, $coeff1_v.4s, #$ntt_reduction_shift
        mls     $coeff0_v.4s, $quotient_v.4s, $q_vector.4s
        mls     $coeff1_v.4s, $quotient2_v.4s, $q_vector.4s
        sub     $quotient_v.4s, $coeff0_v.4s, $q_vector.4s
        sub     $quotient2_v.4s, $coeff1_v.4s, $q_vector.4s
        umin    $coeff0_v.4s, $coeff0_v.4s, $quotient_v.4s
        umin    $coeff1_v.4s, $coeff1_v.4s, $quotient2_v.4s
        stp     $coeff0_q, $coeff1_q, [$group_ptr], #$vector_pair_bytes
___
}

##
# @brief Reduce NTT coefficients into [0,q).
# @return Generated code reduces all 256 coefficients from [0,33q) to [0,q).
# @details The generated loop reads and writes the polynomial through
# $inout_coefficients.  Starting in [0,q), every NTT layer can add 4q to the
# upper bound, so after eight layers every lane is in [0,33q).  Each iteration
# reduces 16 coefficients using two independent eight-coefficient vector pairs.
sub ntt_reduce_coefficients {
    $code .= <<___;
        mov     $group_ptr, $inout_coefficients
        mov     $group_count, #$ntt_reduction_iterations
.Lml_dsa_ntt_reduce_coefficients_loop:
___
    ntt_reduce_vector_pair();
    ntt_reduce_vector_pair();
    $code .= <<___;
        subs    $group_count, $group_count, #1
        b.ne    .Lml_dsa_ntt_reduce_coefficients_loop
___
}

##
# @brief Compute the 256-coefficient NTT in place.
# @param[in,out] inout_coefficients x0 points to coefficients that enter in
# [0,q) and leave in [0,q).
# @param[in] unused_zetas x1 contains the ABI-provided zeta-table pointer; this
# implementation uses its embedded z and c table instead.
# @return Generated code returns the reduced NTT coefficients in the input
# polynomial.
$code .= <<___;
.globl  ossl_ml_dsa_poly_ntt_armv8
.type   ossl_ml_dsa_poly_ntt_armv8,%function
.p2align 4
ossl_ml_dsa_poly_ntt_armv8:
        AARCH64_VALID_CALL_TARGET
___
load_q();
$code .= <<___;
        adrp    $zc_ptr, .Lml_dsa_ntt_constants
        add     $zc_ptr, $zc_ptr, #:lo12:.Lml_dsa_ntt_constants
        shl     $q_bias_v.4s, $q_vector.4s, #1
___
# Layer  Distance  Groups  Implementation
#   1       128       1    paired vectors
#   2        64       2    paired vectors
#   3        32       4    paired vectors
#   4        16       8    paired vectors
#   5         8      16    paired vectors
#   6         4      32    single vectors
#   7         2      32    64-bit ZIP permutation
#   8         1      32    32-bit UZP permutation
ntt_wide_layer(layer => 1, groups => 1,  butterfly_distance => 128);
ntt_wide_layer(layer => 2, groups => 2,  butterfly_distance => 64);
ntt_wide_layer(layer => 3, groups => 4,  butterfly_distance => 32);
ntt_wide_layer(layer => 4, groups => 8,  butterfly_distance => 16);
ntt_wide_layer(layer => 5, groups => 16, butterfly_distance => 8);
ntt_wide_layer(layer => 6, groups => 32, butterfly_distance => 4);
ntt_layer7();
ntt_layer8();
ntt_reduce_coefficients();
$code .= <<___;
        ret
.size   ossl_ml_dsa_poly_ntt_armv8,.-ossl_ml_dsa_poly_ntt_armv8

___
##
# @brief Compute the 256-coefficient iNTT in place.
# @param[in,out] inout_coefficients x0 points to coefficients that enter in
# [0,q) and leave in [0,q).
# @param[in] unused_zetas x1 contains the ABI-provided zeta-table pointer; this
# implementation uses its embedded z and c table instead.
# @return Generated code returns the reduced polynomial coefficients in the
# input polynomial.
$code .= <<___;
.globl  ossl_ml_dsa_poly_ntt_inverse_armv8
.type   ossl_ml_dsa_poly_ntt_inverse_armv8,%function
.p2align 4
ossl_ml_dsa_poly_ntt_inverse_armv8:
        AARCH64_VALID_CALL_TARGET
___
# The scalar C iNTT finishes with Montgomery multiplication by 41978.  For
# ordinary-domain multiplication the equivalent fixed pair is z = 16382 and
# c = floor(2^31*z/q) = 4197891.
load_q();
my $normalization_z = 16382;
my $normalization_c = 4197891;
$code .= <<___;
        adrp    $zc_ptr, .Lml_dsa_intt_constants
        add     $zc_ptr, $zc_ptr, #:lo12:.Lml_dsa_intt_constants
        mov     $z_word, #@{[$normalization_z & 0xffff]}
        movk    $z_word, #@{[($normalization_z >> 16) & 0xffff]}, lsl #16
        dup     $scale_z_v.4s, $z_word
        mov     $c_word, #@{[$normalization_c & 0xffff]}
        movk    $c_word, #@{[($normalization_c >> 16) & 0xffff]}, lsl #16
        dup     $scale_c_v.4s, $c_word
___
# Layer  Distance  Groups  Bias    Implementation
#   1         1      32      q    32-bit UZP permutation
#   2         2      32     2q    64-bit ZIP permutation
#   3         4      32     4q    single vectors
#   4         8      16     8q    paired vectors
#   5        16       8    16q    paired vectors
#   6        32       4    32q    paired vectors
#   7        64       2    64q    paired vectors
#   8       128       1   128q    paired vectors, then normalize
intt_layer1();                           # bias = q
intt_layer2();                           # bias = 2q
intt_wide_layer(layer => 3, groups => 32, butterfly_distance => 4,
                bias_shift => 2, normalize_after_layer => 0);
intt_wide_layer(layer => 4, groups => 16, butterfly_distance => 8,
                bias_shift => 3, normalize_after_layer => 0);
intt_wide_layer(layer => 5, groups => 8, butterfly_distance => 16,
                bias_shift => 4, normalize_after_layer => 0);
intt_wide_layer(layer => 6, groups => 4, butterfly_distance => 32,
                bias_shift => 5, normalize_after_layer => 0);
intt_wide_layer(layer => 7, groups => 2, butterfly_distance => 64,
                bias_shift => 6, normalize_after_layer => 0);
intt_wide_layer(layer => 8, groups => 1, butterfly_distance => 128,
                bias_shift => 7, normalize_after_layer => 1);
$code .= <<___;
        ret
.size   ossl_ml_dsa_poly_ntt_inverse_armv8,.-ossl_ml_dsa_poly_ntt_inverse_armv8
___

# Fixed NTT table: each record stores one or more centred twiddles z followed
# by their matching c = floor(2^31*z/q) values in NTT layer load order.
# Table rows contain up to 16 values; the comments below define records.
$code .= <<___;
.rodata
.align  4
___
# Each NTT table record contains the signed ordinary-domain root or roots
# consumed by one loop group, immediately followed by their c values for
# SQDMULH.  Records are grouped below in NTT layer load order.
$code .= <<___;
.Lml_dsa_ntt_constants:
___
# NTT layer 1 (distance 128): 1 record, 2 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-3572223, -915382908
___
# NTT layer 2 (distance 64): 2 records, 4 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	3765607, 964937598, 3761513, 963888510
___
# NTT layer 3 (distance 32): 4 records, 8 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-3201494, -820383522, -2883726, -738955405, -3145678, -806080661, -3201430, -820367122
___
# NTT layer 4 (distance 16): 8 records, 16 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-601683, -154181398, 3542485, 907762538, 2682288, 687336873, 2129892, 545785280, 3764867, 964747973, -1005239, -257592709, 557458, 142848731, -1221177, -312926868
___
# NTT layer 5 (distance 8): 16 records, 32 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-3370349, -863652652, -4063053, -1041158200, 2663378, 682491181, -1674615, -429120452, -3524442, -903139017, -434125, -111244625, 676590, 173376332, -1335936, -342333886
.word	-3227876, -827143916, 1714295, 439288460, 2453983, 628833668, 1460718, 374309299, -642628, -164673563, -3585098, -918682130, 2815639, 721508095, 2283733, 585207069
___
# NTT layer 6 (distance 4): 32 records, 64 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	3602218, 923069132, 3182878, 815613168, 2740543, 702264729, -3586446, -919027555, -3110818, -797147778, 2101410, 538486761, 3704823, 949361685, 1159875, 297218216
.word	394148, 101000509, 928749, 237992129, 1095468, 280713909, -3506380, -898510625, 2071829, 530906624, -4018989, -1029866791, 3241972, 830756018, 2156050, 552488273
.word	3415069, 875112161, 1759347, 450833044, -817536, -209493775, -3574466, -915957677, 3756790, 962678240, -1935799, -496048908, -1716988, -439978543, -3950053, -1012201926
.word	-2897314, -742437332, 3192354, 818041395, 556856, 142694469, 3870317, 991769558, 2917338, 747568486, 1853806, 475038183, 3345963, 857403734, 1858416, 476219497
___
# NTT layer 7 (distance 2): 32 records, 128 values total.
# Each record: 2 z values followed by 2 c values.
$code .= <<___;
.word	3073009, 1277625, 787459213, 327391679, -2635473, 3852015, -675340520, 987079667, 4183372, -3222807, 1071989969, -825844983, -3121440, -274060, -799869668, -70227934
.word	2508980, 2028118, 642926661, 519705671, 1937570, -3815725, 496502726, -977780348, 2811291, -2983781, 720393919, -764594520, -1109516, 4158088, -284313713, 1065510939
.word	1528066, 482649, 391567239, 123678909, 1148858, -2962264, 294395108, -759080784, -565603, 169688, -144935890, 43482586, 2462444, -3334383, 631001801, -854436357
.word	-4166425, -3488383, -1067647298, -893898890, 1987814, -3197248, 509377762, -819295484, 1736313, 235407, 444930577, 60323094, -3250154, 3258457, -832852658, 834980302
.word	-2579253, 1787943, -660934133, 458160776, -2391089, -2254727, -612717068, -577774276, 3482206, -4182915, 892316032, -1071872864, -1300016, -2362063, -333129378, -605279149
.word	-1317678, 2461387, -337655270, 630730944, 3035980, 621164, 777970524, 159173407, 3901472, -1226661, 999753034, -314332144, 2925816, 3374250, 749740975, 864652283
.word	1356448, -2775755, 347590090, -711287813, 2683270, -2778788, 687588511, -712065020, -3467665, 2312838, -888589898, 592665231, -653275, -459163, -167401859, -117660617
.word	348812, -327848, 89383149, -84011121, 1011223, -2354215, 259126109, -603268098, -3818627, -1922253, -978523986, -492577743, -2236726, 1744507, -573161516, 447030291
___
# NTT layer 8 (distance 1): 32 records, 256 values total.
# Each record: 4 z values followed by 4 c values.
$code .= <<___;
.word	1753, -1935420, -2659525, -1455890, 449206, -495951789, -681503850, -373072124, 2660408, -1780227, -59148, 2772600, 681730118, -456183550, -15156688, 710479342
.word	1182243, 87208, 636927, -3965306, 302950021, 22347068, 163212679, -1016110511, -3956745, -2296397, -3284915, -3716946, -1013916753, -588452223, -841760172, -952468208
.word	-27812, 822541, 1009365, -2454145, -7126831, 210776307, 258649997, -628875181, -1979497, 1596822, -3956944, -3759465, -507246530, 409185978, -1013967747, -963363711
.word	-1685153, -3410568, 2678278, -3768948, -431820817, -873958780, 686309310, -965793731, -3551006, 635956, -250446, -2455377, -909946047, 162963860, -64176842, -629190882
.word	-4146264, -1772588, 2192938, -1727088, -1062481037, -454226054, 561940831, -442566670, 2387513, -3611750, -268456, -3180456, 611800716, -925511710, -68791908, -814992530
.word	3747250, 2296099, 1239911, -3838479, 960233613, 588375859, 317727458, -983611065, 3195676, 2642980, 1254190, -12417, 818892658, 677264190, 321386455, -3181859
.word	2998219, 141835, -89301, 2513018, 768294259, 36345249, -22883401, 643961399, -1354892, 613238, -1310261, -2218467, -347191365, 157142368, -335754662, -568482644
.word	-458740, -1921994, 4040196, -3472069, -117552224, -492511374, 1035301088, -889718424, 2039144, -1879878, -818761, -2178965, 522531085, -481719140, -209807682, -558360248
.word	-1623354, 2105286, -2374402, -2033807, -415984810, 539479987, -608441021, -521163479, 586241, -1179613, 527981, -2743411, 150224381, -302276084, 135295244, -702999656
.word	-1476985, 1994046, 2491325, -1393159, -378477723, 510974713, 638402563, -356997292, 507927, -1187885, -724804, -1834526, 130156402, -304395786, -185731180, -470097680
.word	-3033742, -338420, 2647994, 3009748, -777397037, -86720198, 678549028, 771248568, -2612853, 4148469, 749577, -4022750, -669544140, 1063046068, 192079266, -1030830548
.word	3980599, 2569011, -1615530, 1723229, 1020029344, 658309618, -413979908, 441577799, 1665318, 2028038, 1163598, -3369273, 426738093, 519685171, 298172236, -863376927
.word	3994671, -11879, -1370517, 3020393, 1023635297, -3043997, -351195275, 773976352, 3363542, 214880, 545376, -770441, 861908356, 55063045, 139752716, -197425671
.word	3105558, -1103344, 508145, -553718, 795799901, -282732136, 130212264, -141890356, 860144, 3430436, 140244, -1514152, 220412083, 879049958, 35937554, -388001774
.word	-2185084, 3123762, 2358373, -2193087, -559928243, 800464680, 604333585, -561979013, -3014420, -1716814, 2926054, -392707, -772445770, -439933955, 749801963, -100631253
.word	-303005, 3531229, -3974485, -3773731, -77645097, 904878186, -1018462632, -967019376, 1900052, -781875, 1054478, -731434, 486888731, -200355636, 270210212, -187430119
.align  4
___
# The iNTT records have the same root/reciprocal layout, in the reverse
# layer order consumed by the Gentleman-Sande loops.  Their roots are the
# signed additive inverses of the corresponding NTT roots.
$code .= <<___;
.Lml_dsa_intt_constants:
___
# iNTT layer 1 (distance 1): 32 records, 256 values total.
# Each record: 4 z values followed by 4 c values.
$code .= <<___;
.word	731434, -1054478, 781875, -1900052, 187430118, -270210213, 200355635, -486888732, 3773731, 3974485, -3531229, 303005, 967019375, 1018462631, -904878187, 77645096
.word	392707, -2926054, 1716814, 3014420, 100631252, -749801964, 439933954, 772445769, 2193087, -2358373, -3123762, 2185084, 561979012, -604333586, -800464681, 559928242
.word	1514152, -140244, -3430436, -860144, 388001773, -35937555, -879049959, -220412084, 553718, -508145, 1103344, -3105558, 141890355, -130212265, 282732135, -795799902
.word	770441, -545376, -214880, -3363542, 197425670, -139752717, -55063046, -861908357, -3020393, 1370517, 11879, -3994671, -773976353, 351195274, 3043996, -1023635298
.word	3369273, -1163598, -2028038, -1665318, 863376926, -298172237, -519685172, -426738094, -1723229, 1615530, -2569011, -3980599, -441577800, 413979907, -658309619, -1020029345
.word	4022750, -749577, -4148469, 2612853, 1030830547, -192079267, -1063046069, 669544139, -3009748, -2647994, 338420, 3033742, -771248569, -678549029, 86720197, 777397036
.word	1834526, 724804, 1187885, -507927, 470097679, 185731179, 304395785, -130156403, 1393159, -2491325, -1994046, 1476985, 356997291, -638402564, -510974714, 378477722
.word	2743411, -527981, 1179613, -586241, 702999655, -135295245, 302276083, -150224382, 2033807, 2374402, -2105286, 1623354, 521163478, 608441020, -539479988, 415984809
.word	2178965, 818761, 1879878, -2039144, 558360247, 209807681, 481719139, -522531086, 3472069, -4040196, 1921994, 458740, 889718423, -1035301089, 492511373, 117552223
.word	2218467, 1310261, -613238, 1354892, 568482643, 335754661, -157142369, 347191364, -2513018, 89301, -141835, -2998219, -643961400, 22883400, -36345250, -768294260
.word	12417, -1254190, -2642980, -3195676, 3181858, -321386456, -677264191, -818892659, 3838479, -1239911, -2296099, -3747250, 983611064, -317727459, -588375860, -960233614
.word	3180456, 268456, 3611750, -2387513, 814992529, 68791907, 925511709, -611800717, 1727088, -2192938, 1772588, 4146264, 442566669, -561940832, 454226053, 1062481036
.word	2455377, 250446, -635956, 3551006, 629190881, 64176841, -162963861, 909946046, 3768948, -2678278, 3410568, 1685153, 965793730, -686309311, 873958779, 431820816
.word	3759465, 3956944, -1596822, 1979497, 963363710, 1013967746, -409185979, 507246529, 2454145, -1009365, -822541, 27812, 628875180, -258649998, -210776308, 7126830
.word	3716946, 3284915, 2296397, 3956745, 952468207, 841760171, 588452222, 1013916752, 3965306, -636927, -87208, -1182243, 1016110510, -163212680, -22347069, -302950022
.word	-2772600, 59148, 1780227, -2660408, -710479343, 15156687, 456183549, -681730119, 1455890, 2659525, 1935420, -1753, 373072123, 681503849, 495951788, -449207
___
# iNTT layer 2 (distance 2): 32 records, 128 values total.
# Each record: 2 z values followed by 2 c values.
$code .= <<___;
.word	-1744507, 2236726, -447030292, 573161515, 1922253, 3818627, 492577742, 978523985, 2354215, -1011223, 603268097, -259126110, 327848, -348812, 84011120, -89383150
.word	459163, 653275, 117660616, 167401858, -2312838, 3467665, -592665232, 888589897, 2778788, -2683270, 712065019, -687588512, 2775755, -1356448, 711287812, -347590091
.word	-3374250, -2925816, -864652284, -749740976, 1226661, -3901472, 314332143, -999753035, -621164, -3035980, -159173408, -777970525, -2461387, 1317678, -630730945, 337655269
.word	2362063, 1300016, 605279148, 333129377, 4182915, -3482206, 1071872863, -892316033, 2254727, 2391089, 577774275, 612717067, -1787943, 2579253, -458160777, 660934132
.word	-3258457, 3250154, -834980303, 832852657, -235407, -1736313, -60323095, -444930578, 3197248, -1987814, 819295483, -509377763, 3488383, 4166425, 893898889, 1067647297
.word	3334383, -2462444, 854436356, -631001802, -169688, 565603, -43482587, 144935889, 2962264, -1148858, 759080783, -294395109, -482649, -1528066, -123678910, -391567240
.word	-4158088, 1109516, -1065510940, 284313712, 2983781, -2811291, 764594519, -720393920, 3815725, -1937570, 977780347, -496502727, -2028118, -2508980, -519705672, -642926662
.word	274060, 3121440, 70227933, 799869667, 3222807, -4183372, 825844982, -1071989970, -3852015, 2635473, -987079668, 675340519, -1277625, -3073009, -327391680, -787459214
___
# iNTT layer 3 (distance 4): 32 records, 64 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-1858416, -476219498, -3345963, -857403735, -1853806, -475038184, -2917338, -747568487, -3870317, -991769559, -556856, -142694470, -3192354, -818041396, 2897314, 742437331
.word	3950053, 1012201925, 1716988, 439978542, 1935799, 496048907, -3756790, -962678241, 3574466, 915957676, 817536, 209493774, -1759347, -450833045, -3415069, -875112162
.word	-2156050, -552488274, -3241972, -830756019, 4018989, 1029866790, -2071829, -530906625, 3506380, 898510624, -1095468, -280713910, -928749, -237992130, -394148, -101000510
.word	-1159875, -297218217, -3704823, -949361686, -2101410, -538486762, 3110818, 797147777, 3586446, 919027554, -2740543, -702264730, -3182878, -815613169, -3602218, -923069133
___
# iNTT layer 4 (distance 8): 16 records, 32 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-2283733, -585207070, -2815639, -721508096, 3585098, 918682129, 642628, 164673562, -1460718, -374309300, -2453983, -628833669, -1714295, -439288461, 3227876, 827143915
.word	1335936, 342333885, -676590, -173376333, 434125, 111244624, 3524442, 903139016, 1674615, 429120451, -2663378, -682491182, 4063053, 1041158199, 3370349, 863652651
___
# iNTT layer 5 (distance 16): 8 records, 16 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	1221177, 312926867, -557458, -142848732, 1005239, 257592708, -3764867, -964747974, -2129892, -545785281, -2682288, -687336874, -3542485, -907762539, 601683, 154181397
___
# iNTT layer 6 (distance 32): 4 records, 8 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	3201430, 820367121, 3145678, 806080660, 2883726, 738955404, 3201494, 820383521
___
# iNTT layer 7 (distance 64): 2 records, 4 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	-3761513, -963888511, -3765607, -964937599
___
# iNTT layer 8 (distance 128): 1 record, 2 values total.
# Each record: 1 z value followed by 1 c value.
$code .= <<___;
.word	3572223, 915382907
___

print $code;
close STDOUT or die "error closing output: $!";
