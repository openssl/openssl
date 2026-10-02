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

# This file is a Perl generator: its helper functions append AArch64 assembly
# to $code; they are not functions called by the generated code at run time.
#
# The transform follows the canonical FIPS 204 layer order used by
# ml_dsa_ntt.c.  Each Neon register holds four 32-bit coefficients, so four
# butterflies are evaluated in parallel.  Stages with offsets of at least four
# can load their even and odd halves directly.  The final offset-2 and offset-1
# stages use ZIP/UZP permutations to put butterfly partners in matching lanes.
#
# Constant products are left in [0,2q), and additions and subtractions are
# reduced lazily.  An NTT butterfly uses a public 2q bias; every layer can
# increase the upper bound by 4q, so the eight layers end below 33q.  One fixed
# final pass reduces this to [0,q).  In the iNTT, layer n uses a
# public 2^(n-1)*q bias and produces sums below 2^n*q; products remain below
# 2q.  The final layer is therefore below 256q (2145386752) < 2^31, and the
# final scaling multiplication returns canonical coefficients.  In summary:
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
# The iNTT bias ranges from q through 128q (1072693376), also below 2^30.
#
# Only caller-saved GPRs and vector registers are used, so both entry points
# are leaf functions and require no stack frame.
#
# The public ABI supplies a zeta-table pointer in x1.  It is intentionally
# unused: this implementation embeds each twiddle next to the fixed-point
# quotient constant needed by the Neon multiplication sequence.
my ($coefficients, $unused_zetas, $group_ptr, $even_ptr, $odd_ptr,
    $group_count, $vector_count, $twiddle_ptr) = map("x$_", (0..7));
my ($twiddle_word, $quotient_constant_word, $q_word) =
    map("w$_", (8..10));

# Every Neon register alias below holds four 32-bit lanes during arithmetic.
# A few zip and mov instructions view the same 128 bits as two 64-bit lanes
# (.2d) or sixteen bytes (.16b) only to rearrange or copy the four values.
my ($coeff_vector0, $coeff_vector1, $twiddle, $product,
    $butterfly_even, $butterfly_odd) = map("v$_", (0..5));
my ($even_vector2, $odd_vector2, $product2) = map("v$_", (6, 7, 17));
my ($quotient, $quotient2) = map("v$_", (18, 23));
my $q_bias = "v26";
my $quotient_constant = "v27";
my ($scale_quotient_constant, $scale, $q_vector) = map("v$_", (28..30));
my $q = 8380417;
# load_modulus() broadcasts q into q_vector as [q, q, q, q].
my $fixed_point_bits = 31;
my (@ntt_twiddle_records, @intt_twiddle_records);
my $label_index = 0;
my $code = <<___;
#include "arch/arm_arch.h"

.text
___

# Reverse the low eight bits of an integer.
# Input: value in [0,256).  Output: its eight-bit bit-reversal in [0,256).
sub bitrev8 {
    my ($value) = @_;
    my $result = 0;

    for (1 .. 8) {
        $result = ($result << 1) | ($value & 1);
        $value >>= 1;
    }
    return $result;
}

# Raise base to exponent modulo the ML-DSA modulus q.
# Inputs: integer base and nonnegative integer exponent.  Output: base^exponent
# modulo q in [0,q).
sub powmod {
    my ($base, $exponent) = @_;
    my $result = 1;

    while ($exponent != 0) {
        $result = ($result * $base) % $q if ($exponent & 1) != 0;
        $base = ($base * $base) % $q;
        $exponent >>= 1;
    }
    return $result;
}

# Calculate the twiddle selected by a bit-reversed table index.
# Inputs: index in [0,256) and intt, which selects the additive inverse used
# by the iNTT.  Output: the centred twiddle z in (-q/2,q/2).
sub centered_twiddle {
    my ($index, $intt) = @_;
    my $root = powmod(1753, bitrev8($index));

    # iNTT layers use the additive inverse of the corresponding NTT twiddle.
    # Centre either representative in [-floor(q/2), floor(q/2)] so both it and
    # its fixed-point quotient constant have small signed bounds.
    $root = $q - $root if $intt;
    return $root > int($q / 2) ? $root - $q : $root;
}

# Perform mathematical floor division rather than Perl's truncation toward
# zero.  Inputs: integer numerator and positive integer denominator.  Output:
# floor(numerator/denominator), including for a negative numerator.
sub floor_div {
    my ($numerator, $denominator) = @_;

    return $numerator >= 0
        ? int($numerator / $denominator)
        : -int((-$numerator + $denominator - 1) / $denominator);
}

# Calculate the fixed-point quotient constant paired with a twiddle.
# Input: centred twiddle z.  Output: c = floor(2^31*z/q), with
# -2^30 < c < 2^30.
sub quotient_constant_for_twiddle {
    my ($twiddle) = @_;

    return floor_div($twiddle * (1 << $fixed_point_bits), $q);
}

# Append the table record consumed by one loop group.
# Inputs: a reference to the NTT or iNTT record array, followed by one or more
# centred twiddles z.  Output: none; appends a record whose first half contains
# the twiddles and whose second half contains c = floor(2^31*z/q) for each z.
# A twiddle and quotient constant are an inseparable pair.
sub append_twiddle_record {
    my ($constants, @twiddles) = @_;
    my @quotient_constants =
        map { quotient_constant_for_twiddle($_) } @twiddles;

    push @$constants, [[@twiddles], [@quotient_constants]];
}

# Generate four parallel multiplications by a constant twiddle.
# Inputs: destination and source vector-register names, plus registers holding
# four twiddles z and their quotient constants c.  Runtime output: each
# destination lane is congruent to a*z modulo q and lies in [0,2q).  Perl
# output: none; appends instructions to $code and uses $quotient as scratch.
sub mul_twiddle_lazy {
    my ($dst, $a, $twiddle, $quotient_constant) = @_;

    # Let z be the centred representative of the constant twiddle and define
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
    # SQDMULH computes k.  Because a/2^31 < 1, k is either floor(a*z/q)
    # or one less.  The MUL/MLS pair forms r = low32(a*z-k*q), and therefore
    # 0 <= r < 2q.  This small nonnegative bound means that the low-32-bit
    # arithmetic is the exact integer r, not merely a value modulo 2^32.
    # Compute k before MUL so that dst is permitted to alias a.  This is used
    # by the final iNTT scaling, while the butterfly calls use distinct
    # source and destination registers.
    $code .= <<___;
        sqdmulh $quotient.4s,$a.4s,$quotient_constant.4s
        mul     $dst.4s,$a.4s,$twiddle.4s
        mls     $dst.4s,$quotient.4s,$q_vector.4s
___
}

# Generate four parallel multiplications followed by canonical reduction.
# Inputs: the same register names as mul_twiddle_lazy().  Runtime output: each
# destination lane is a*z modulo q in [0,q).  Perl output: none; appends
# instructions to $code and uses $quotient as scratch.
sub mul_twiddle_canonical {
    my ($dst, $a, $twiddle, $quotient_constant) = @_;

    mul_twiddle_lazy($dst, $a, $twiddle, $quotient_constant);
    # The unreduced result is in [0,2q); one unsigned conditional subtraction
    # produces the canonical representative in [0,q).
    $code .= <<___;
        sub     $quotient.4s,$dst.4s,$q_vector.4s
        umin    $dst.4s,$dst.4s,$quotient.4s
___
}

# Generate two independent vectors of lazy twiddle multiplications.
# Inputs: two destination/source register pairs and shared twiddle-z and
# quotient-c registers.  Runtime outputs: both destination vectors contain
# products modulo q in [0,2q).  Perl output: none; appends instructions to
# $code and uses $quotient and $quotient2 as scratch.
sub mul_twiddle_pair_lazy {
    my ($dst0, $a0, $dst1, $a1, $twiddle, $quotient_constant) = @_;

    # Interleave two independent constant products.  Besides exposing two
    # independent instruction chains to the processor, calculating both
    # quotients first preserves a0 and a1 when either destination aliases its
    # source during iNTT normalization.
    $code .= <<___;
        sqdmulh $quotient.4s,$a0.4s,$quotient_constant.4s
        sqdmulh $quotient2.4s,$a1.4s,$quotient_constant.4s
        mul     $dst0.4s,$a0.4s,$twiddle.4s
        mul     $dst1.4s,$a1.4s,$twiddle.4s
        mls     $dst0.4s,$quotient.4s,$q_vector.4s
        mls     $dst1.4s,$quotient2.4s,$q_vector.4s
___
}

# Generate two independent vectors of canonical twiddle multiplications.
# Inputs: the same register names as mul_twiddle_pair_lazy().  Runtime outputs:
# both destination vectors contain products modulo q in [0,q).  Perl output:
# none; appends instructions to $code and uses both quotient vectors as scratch.
sub mul_twiddle_pair_canonical {
    my ($dst0, $a0, $dst1, $a1, $twiddle, $quotient_constant) = @_;

    mul_twiddle_pair_lazy($dst0, $a0, $dst1, $a1,
                          $twiddle, $quotient_constant);
    $code .= <<___;
        sub     $quotient.4s,$dst0.4s,$q_vector.4s
        sub     $quotient2.4s,$dst1.4s,$q_vector.4s
        umin    $dst0.4s,$dst0.4s,$quotient.4s
        umin    $dst1.4s,$dst1.4s,$quotient2.4s
___
}

# Cooley-Tukey NTT butterfly:
#
#   product = odd * twiddle mod q, with 0 <= product < 2q
#   even'   = even + 2q + product
#   odd'    = even + 2q - product
#
# The 2q bias prevents the subtraction from becoming negative.  It is a
# multiple of q, so it does not change either result modulo q.
# Inputs: registers containing four even coefficients, four odd coefficients,
# four twiddles z, and their quotient constants c; q_bias must contain 2q.
# Runtime outputs: even and odd are updated in place with the butterfly result.
# Perl output: none; appends instructions to $code.
sub ntt_butterfly {
    my ($even, $odd, $twiddle, $quotient_constant) = @_;

    mul_twiddle_lazy($product, $odd, $twiddle, $quotient_constant);
    $code .= <<___;
        add     $odd.4s,$even.4s,$q_bias.4s
        add     $even.4s,$odd.4s,$product.4s
        sub     $odd.4s,$odd.4s,$product.4s
___
}

# Gentleman-Sande iNTT butterfly:
#
#   difference = even + bias - odd
#   even'      = even + odd
#   odd'       = difference * twiddle mod q
#
# Each iNTT layer sets bias to the current coefficient bound.  The bias is
# a multiple of q and keeps difference nonnegative without changing it mod q.
# Inputs: registers containing four even coefficients, four odd coefficients,
# four inverse twiddles z, and their quotient constants c; q_bias contains the
# layer's bias.  Runtime outputs: even and odd are updated in place.  Perl
# output: none; appends instructions to $code.
sub intt_butterfly {
    my ($even, $odd, $twiddle, $quotient_constant) = @_;

    $code .= <<___;
        add     $product.4s,$even.4s,$q_bias.4s
        sub     $product.4s,$product.4s,$odd.4s
        add     $even.4s,$even.4s,$odd.4s
___
    mul_twiddle_lazy($odd, $product, $twiddle, $quotient_constant);
}

# Generate two independent four-lane Cooley-Tukey NTT butterflies.
# Inputs: two even/odd register pairs and shared twiddle-z and quotient-c
# registers; q_bias must contain 2q.  Runtime outputs: all four coefficient
# registers are updated in place.  Perl output: none; appends to $code.
sub ntt_butterfly_pair {
    my ($even0, $odd0, $even1, $odd1,
        $twiddle, $quotient_constant) = @_;

    mul_twiddle_pair_lazy($product, $odd0, $product2, $odd1,
                          $twiddle, $quotient_constant);
    $code .= <<___;
        add     $odd0.4s,$even0.4s,$q_bias.4s
        add     $odd1.4s,$even1.4s,$q_bias.4s
        add     $even0.4s,$odd0.4s,$product.4s
        add     $even1.4s,$odd1.4s,$product2.4s
        sub     $odd0.4s,$odd0.4s,$product.4s
        sub     $odd1.4s,$odd1.4s,$product2.4s
___
}

# Generate two independent four-lane Gentleman-Sande iNTT butterflies.
# Inputs: two even/odd register pairs and shared inverse-twiddle-z and
# quotient-c registers; q_bias contains the layer's bias.  Runtime outputs:
# all four coefficient registers are updated in place.  Perl output: none;
# appends instructions to $code.
sub intt_butterfly_pair {
    my ($even0, $odd0, $even1, $odd1,
        $twiddle, $quotient_constant) = @_;

    $code .= <<___;
        add     $product.4s,$even0.4s,$q_bias.4s
        add     $product2.4s,$even1.4s,$q_bias.4s
        sub     $product.4s,$product.4s,$odd0.4s
        sub     $product2.4s,$product2.4s,$odd1.4s
        add     $even0.4s,$even0.4s,$odd0.4s
        add     $even1.4s,$even1.4s,$odd1.4s
___
    mul_twiddle_pair_lazy($odd0, $product, $odd1, $product2,
                          $twiddle, $quotient_constant);
}

# Generate the instructions that construct the ML-DSA modulus.
# Input: none.  Runtime output: q_word contains q and q_vector contains
# [q,q,q,q].  Perl output: none; appends instructions to $code.
sub load_modulus {
    $code .= <<___;
        mov     $q_word,#0xe001
        movk    $q_word,#0x7f,lsl#16
        dup     $q_vector.4s,$q_word
___
}

# Generate one NTT stage whose butterfly partners are at least one full
# vector apart.  Inputs: step is the number of groups and offset is the
# coefficient separation within each butterfly, matching the scalar FIPS 204
# loop structure.  Runtime output: the selected stage updates all 256
# coefficients in place.  Perl output: none; appends its twiddle records to
# @ntt_twiddle_records and its instructions to $code.
sub ntt_wide_stage {
    my ($step, $offset) = @_;
    my $outer = ".Lml_dsa_ntt_${label_index}_outer";
    my $inner = ".Lml_dsa_ntt_${label_index}_inner";
    my $offset_bytes = 4 * $offset;
    my $group_bytes = 2 * $offset_bytes;
    my $vectors = $offset / 4;
    my $paired = $vectors >= 2;
    my $pair_unroll = 1;
    my $iterations = $paired ? $vectors / (2 * $pair_unroll) : $vectors;
    $label_index++;

    for my $i (0 .. $step - 1) {
        my $twiddle = centered_twiddle($step + $i, 0);
        append_twiddle_record(\@ntt_twiddle_records, $twiddle);
    }

    $code .= <<___;
        mov     $group_ptr,$coefficients
        mov     $group_count,#$step
$outer:
        ldr     d2,[$twiddle_ptr],#8
        dup     $quotient_constant.4s,$twiddle.s[1]
        dup     $twiddle.4s,$twiddle.s[0]
        mov     $even_ptr,$group_ptr
        add     $odd_ptr,$group_ptr,#$offset_bytes
        mov     $vector_count,#$iterations
$inner:
___
    if ($paired) {
        for (1 .. $pair_unroll) {
            $code .= <<___;
        ldp     q0,q6,[$even_ptr]
        ldp     q1,q7,[$odd_ptr]
___
            ntt_butterfly_pair($coeff_vector0, $coeff_vector1,
                               $even_vector2, $odd_vector2,
                               $twiddle, $quotient_constant);
            $code .= <<___;
        stp     q0,q6,[$even_ptr],#32
        stp     q1,q7,[$odd_ptr],#32
___
        }
    } else {
        $code .= <<___;
        ldr     q0,[$even_ptr]
        ldr     q1,[$odd_ptr]
___
        ntt_butterfly($coeff_vector0, $coeff_vector1, $twiddle,
                      $quotient_constant);
        $code .= <<___;
        str     q0,[$even_ptr],#16
        str     q1,[$odd_ptr],#16
___
    }
    $code .= <<___;
        sub     $vector_count,$vector_count,#1
        cbnz    $vector_count,$inner
        add     $group_ptr,$group_ptr,#$group_bytes
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$outer
___
}

# At offset two, each pair of adjacent 128-bit loads contains interleaved
# butterfly halves.  ZIP on 64-bit elements places partners in matching lanes.
# Input: none.  Runtime output: the offset-two NTT stage updates all 256
# coefficients in place.  Perl output: none; appends 64 twiddles and their
# quotient constants to @ntt_twiddle_records and appends instructions to $code.
sub ntt_offset2_stage {
    my $loop = ".Lml_dsa_ntt_${label_index}_offset2";
    $label_index++;

    for my $group_index (0 .. 31) {
        my @twiddles = map { centered_twiddle($_, 0) }
                        (64 + 2 * $group_index .. 65 + 2 * $group_index);
        append_twiddle_record(\@ntt_twiddle_records, @twiddles);
    }

    $code .= <<___;
        mov     $group_ptr,$coefficients
        mov     $group_count,#32
$loop:
        ldp     d2,d27,[$twiddle_ptr],#16
        zip1    $twiddle.4s,$twiddle.4s,$twiddle.4s
        zip1    $quotient_constant.4s,$quotient_constant.4s,$quotient_constant.4s
        ldr     q0,[$group_ptr]
        ldr     q1,[$group_ptr,#16]
        zip1    $butterfly_even.2d,$coeff_vector0.2d,$coeff_vector1.2d
        zip2    $butterfly_odd.2d,$coeff_vector0.2d,$coeff_vector1.2d
___
    ntt_butterfly($butterfly_even, $butterfly_odd, $twiddle,
                  $quotient_constant);
    $code .= <<___;
        zip1    $coeff_vector0.2d,$butterfly_even.2d,$butterfly_odd.2d
        zip2    $coeff_vector1.2d,$butterfly_even.2d,$butterfly_odd.2d
        str     q0,[$group_ptr],#16
        str     q1,[$group_ptr],#16
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$loop
___
}

# At offset one, UZP separates even and odd coefficients into two vectors;
# ZIP restores the original memory order after the butterflies.
# Input: none.  Runtime output: the offset-one NTT stage updates all 256
# coefficients in place.  Perl output: none; appends 128 twiddles and their
# quotient constants to @ntt_twiddle_records and appends instructions to $code.
sub ntt_offset1_stage {
    my $loop = ".Lml_dsa_ntt_${label_index}_offset1";
    $label_index++;

    for my $group_index (0 .. 31) {
        my @twiddles = map { centered_twiddle($_, 0) }
                        (128 + 4 * $group_index .. 131 + 4 * $group_index);
        append_twiddle_record(\@ntt_twiddle_records, @twiddles);
    }

    $code .= <<___;
        mov     $group_ptr,$coefficients
        mov     $group_count,#32
$loop:
        ldp     q2,q27,[$twiddle_ptr],#32
        ldr     q0,[$group_ptr]
        ldr     q1,[$group_ptr,#16]
        uzp1    $butterfly_even.4s,$coeff_vector0.4s,$coeff_vector1.4s
        uzp2    $butterfly_odd.4s,$coeff_vector0.4s,$coeff_vector1.4s
___
    ntt_butterfly($butterfly_even, $butterfly_odd, $twiddle,
                  $quotient_constant);
    $code .= <<___;
        zip1    $coeff_vector0.4s,$butterfly_even.4s,$butterfly_odd.4s
        zip2    $coeff_vector1.4s,$butterfly_even.4s,$butterfly_odd.4s
        str     q0,[$group_ptr],#16
        str     q1,[$group_ptr],#16
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$loop
___
}

# The iNTT consumes stages in the opposite order.  Its first two stages undo
# the lane permutations used by the final two NTT stages.
# Input: none.  Runtime output: the offset-one iNTT stage updates all 256
# coefficients in place using q as its nonnegative bias.  Perl output: none;
# appends 128 inverse twiddles and their quotient constants to
# @intt_twiddle_records and appends instructions to $code.
sub intt_offset1_stage {
    my $loop = ".Lml_dsa_intt_${label_index}_offset1";
    $label_index++;

    for my $group_index (0 .. 31) {
        my @twiddles = map { centered_twiddle($_, 1) }
                        reverse(252 - 4 * $group_index
                                .. 255 - 4 * $group_index);
        append_twiddle_record(\@intt_twiddle_records, @twiddles);
    }

    $code .= <<___;
        mov     $q_bias.16b,$q_vector.16b
        mov     $group_ptr,$coefficients
        mov     $group_count,#32
$loop:
        ldp     q2,q27,[$twiddle_ptr],#32
        ldr     q0,[$group_ptr]
        ldr     q1,[$group_ptr,#16]
        uzp1    $butterfly_even.4s,$coeff_vector0.4s,$coeff_vector1.4s
        uzp2    $butterfly_odd.4s,$coeff_vector0.4s,$coeff_vector1.4s
___
    intt_butterfly($butterfly_even, $butterfly_odd, $twiddle,
                   $quotient_constant);
    $code .= <<___;
        zip1    $coeff_vector0.4s,$butterfly_even.4s,$butterfly_odd.4s
        zip2    $coeff_vector1.4s,$butterfly_even.4s,$butterfly_odd.4s
        str     q0,[$group_ptr],#16
        str     q1,[$group_ptr],#16
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$loop
___
}

# Generate the offset-two iNTT stage, undoing the corresponding NTT lane
# permutation with 64-bit ZIP operations.  Input: none.  Runtime output: all
# 256 coefficients are updated in place using 2q as the nonnegative bias.
# Perl output: none; appends 64 inverse twiddles and their quotient constants
# to @intt_twiddle_records and appends instructions to $code.
sub intt_offset2_stage {
    my $loop = ".Lml_dsa_intt_${label_index}_offset2";
    $label_index++;

    for my $group_index (0 .. 31) {
        my @twiddles = map { centered_twiddle($_, 1) }
                        reverse(126 - 2 * $group_index
                                .. 127 - 2 * $group_index);
        append_twiddle_record(\@intt_twiddle_records, @twiddles);
    }

    $code .= <<___;
        shl     $q_bias.4s,$q_vector.4s,#1
        mov     $group_ptr,$coefficients
        mov     $group_count,#32
$loop:
        ldp     d2,d27,[$twiddle_ptr],#16
        zip1    $twiddle.4s,$twiddle.4s,$twiddle.4s
        zip1    $quotient_constant.4s,$quotient_constant.4s,$quotient_constant.4s
        ldr     q0,[$group_ptr]
        ldr     q1,[$group_ptr,#16]
        zip1    $butterfly_even.2d,$coeff_vector0.2d,$coeff_vector1.2d
        zip2    $butterfly_odd.2d,$coeff_vector0.2d,$coeff_vector1.2d
___
    intt_butterfly($butterfly_even, $butterfly_odd, $twiddle,
                   $quotient_constant);
    $code .= <<___;
        zip1    $coeff_vector0.2d,$butterfly_even.2d,$butterfly_odd.2d
        zip2    $coeff_vector1.2d,$butterfly_even.2d,$butterfly_odd.2d
        str     q0,[$group_ptr],#16
        str     q1,[$group_ptr],#16
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$loop
___
}

# Generate an iNTT stage with directly loadable even and odd vectors.
# Inputs: step is the number of groups; offset is the coefficient separation;
# bias_shift selects q << bias_shift for the layer's nonnegative difference;
# final requests canonical iNTT scaling after the last butterflies.  Runtime
# output: the selected stage updates all 256 coefficients in place.  Perl
# output: none; appends its inverse-twiddle records to @intt_twiddle_records
# and its instructions to $code.
sub intt_wide_stage {
    my ($step, $offset, $bias_shift, $final) = @_;
    my $outer = ".Lml_dsa_intt_${label_index}_outer";
    my $inner = ".Lml_dsa_intt_${label_index}_inner";
    my $offset_bytes = 4 * $offset;
    my $group_bytes = 2 * $offset_bytes;
    my $vectors = $offset / 4;
    my $paired = $vectors >= 2;
    my $pair_unroll = 1;
    my $iterations = $paired ? $vectors / (2 * $pair_unroll) : $vectors;
    $label_index++;

    for my $i (0 .. $step - 1) {
        my $twiddle = centered_twiddle(2 * $step - 1 - $i, 1);
        append_twiddle_record(\@intt_twiddle_records, $twiddle);
    }

    $code .= <<___;
        shl     $q_bias.4s,$q_vector.4s,#$bias_shift
        mov     $group_ptr,$coefficients
        mov     $group_count,#$step
$outer:
        ldr     d2,[$twiddle_ptr],#8
        dup     $quotient_constant.4s,$twiddle.s[1]
        dup     $twiddle.4s,$twiddle.s[0]
        mov     $even_ptr,$group_ptr
        add     $odd_ptr,$group_ptr,#$offset_bytes
        mov     $vector_count,#$iterations
$inner:
___
    if ($paired) {
        for (1 .. $pair_unroll) {
            $code .= <<___;
        ldp     q0,q6,[$even_ptr]
        ldp     q1,q7,[$odd_ptr]
___
            intt_butterfly_pair($coeff_vector0, $coeff_vector1,
                                $even_vector2, $odd_vector2,
                                $twiddle, $quotient_constant);
            if ($final) {
                mul_twiddle_pair_canonical($coeff_vector0, $coeff_vector0,
                                           $even_vector2, $even_vector2,
                                           $scale,
                                           $scale_quotient_constant);
                mul_twiddle_pair_canonical($coeff_vector1, $coeff_vector1,
                                           $odd_vector2, $odd_vector2,
                                           $scale,
                                           $scale_quotient_constant);
            }
            $code .= <<___;
        stp     q0,q6,[$even_ptr],#32
        stp     q1,q7,[$odd_ptr],#32
___
        }
    } else {
        $code .= <<___;
        ldr     q0,[$even_ptr]
        ldr     q1,[$odd_ptr]
___
        intt_butterfly($coeff_vector0, $coeff_vector1, $twiddle,
                       $quotient_constant);
        if ($final) {
            mul_twiddle_canonical($coeff_vector0, $coeff_vector0, $scale,
                                  $scale_quotient_constant);
            mul_twiddle_canonical($coeff_vector1, $coeff_vector1, $scale,
                                  $scale_quotient_constant);
        }
        $code .= <<___;
        str     q0,[$even_ptr],#16
        str     q1,[$odd_ptr],#16
___
    }
    $code .= <<___;
        sub     $vector_count,$vector_count,#1
        cbnz    $vector_count,$inner
        add     $group_ptr,$group_ptr,#$group_bytes
        sub     $group_count,$group_count,#1
        cbnz    $group_count,$outer
___
}

# Reduce all 256 NTT output coefficients from [0,33q) to [0,q).
# Input: none; generated code reads the polynomial through $coefficients.
# Runtime output: all coefficients in memory are canonical.  Perl output: none;
# appends the reduction loop to $code.
sub ntt_reduce_coefficients {
    my $loop = ".Lml_dsa_ntt_${label_index}_canonical";
    my $pairs_per_iteration = 2;
    my $iterations = 32 / $pairs_per_iteration;
    $label_index++;

    # Starting in [0,q), every NTT layer can add 4q to the upper bound,
    # so after all eight layers every lane is in [0,33q).  For such x,
    # t=floor(x/2^23) is at most 32 and
    #
    #   r = x - t*q < q + 33*(2^23-q) < 2q.
    #
    # USHR/MLS forms r and one SUB/UMIN makes it canonical.  The pass is
    # unrolled in vector pairs to reduce fixed loop overhead while retaining
    # paired loads and stores.
    $code .= <<___;
        mov     $group_ptr,$coefficients
        mov     $group_count,#$iterations
$loop:
___
    for (1 .. $pairs_per_iteration) {
        $code .= <<___;
        ldp     q0,q1,[$group_ptr]
        ushr    $quotient.4s,$coeff_vector0.4s,#23
        ushr    $quotient2.4s,$coeff_vector1.4s,#23
        mls     $coeff_vector0.4s,$quotient.4s,$q_vector.4s
        mls     $coeff_vector1.4s,$quotient2.4s,$q_vector.4s
        sub     $quotient.4s,$coeff_vector0.4s,$q_vector.4s
        sub     $quotient2.4s,$coeff_vector1.4s,$q_vector.4s
        umin    $coeff_vector0.4s,$coeff_vector0.4s,$quotient.4s
        umin    $coeff_vector1.4s,$coeff_vector1.4s,$quotient2.4s
        stp     q0,q1,[$group_ptr],#32
___
    }
    $code .= <<___;
        subs    $group_count,$group_count,#1
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
load_modulus();
$code .= <<___;
        adrp    $twiddle_ptr,.Lml_dsa_ntt_constants
        add     $twiddle_ptr,$twiddle_ptr,#:lo12:.Lml_dsa_ntt_constants
        shl     $q_bias.4s,$q_vector.4s,#1
___
ntt_wide_stage(1, 128);
ntt_wide_stage(2, 64);
ntt_wide_stage(4, 32);
ntt_wide_stage(8, 16);
ntt_wide_stage(16, 8);
ntt_wide_stage(32, 4);
ntt_offset2_stage();
ntt_offset1_stage();
ntt_reduce_coefficients();
$code .= <<___;
        ret
.size   ossl_ml_dsa_poly_ntt_armv8,.-ossl_ml_dsa_poly_ntt_armv8

.globl  ossl_ml_dsa_poly_ntt_inverse_armv8
.type   ossl_ml_dsa_poly_ntt_inverse_armv8,%function
.p2align 4
ossl_ml_dsa_poly_ntt_inverse_armv8:
        AARCH64_VALID_CALL_TARGET
___
# The scalar C iNTT finishes with Montgomery multiplication by
# 41978.  This routine uses ordinary-domain twiddle multiplication, so its
# equivalent embedded scale is 41978*R^-1 mod q, where R = 2^32 mod q.
load_modulus();
my $r_mod_q = (1 << 32) % $q;
my $r_inverse = powmod($r_mod_q, $q - 2);
my $scale_twiddle = (41978 * $r_inverse) % $q;
$scale_twiddle -= $q if $scale_twiddle > int($q / 2);
my $scale_constant = quotient_constant_for_twiddle($scale_twiddle);
my $scale_twiddle_bits = $scale_twiddle & 0xffffffff;
my $scale_constant_bits = $scale_constant & 0xffffffff;
$code .= <<___;
        adrp    $twiddle_ptr,.Lml_dsa_intt_constants
        add     $twiddle_ptr,$twiddle_ptr,#:lo12:.Lml_dsa_intt_constants
        mov     $twiddle_word,#@{[$scale_twiddle_bits & 0xffff]}
        movk    $twiddle_word,#@{[($scale_twiddle_bits >> 16) & 0xffff]},lsl#16
        dup     $scale.4s,$twiddle_word
        mov     $quotient_constant_word,#@{[$scale_constant_bits & 0xffff]}
        movk    $quotient_constant_word,#@{[($scale_constant_bits >> 16) & 0xffff]},lsl#16
        dup     $scale_quotient_constant.4s,$quotient_constant_word
___
intt_offset1_stage();                    # bias = q
intt_offset2_stage();                    # bias = 2q
intt_wide_stage(32, 4,   2, 0);          # bias = 4q
intt_wide_stage(16, 8,   3, 0);          # bias = 8q
intt_wide_stage(8,  16,  4, 0);          # bias = 16q
intt_wide_stage(4,  32,  5, 0);          # bias = 32q
intt_wide_stage(2,  64,  6, 0);          # bias = 64q
intt_wide_stage(1,  128, 7, 1);          # bias = 128q; scale final layer
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
for my $record (@ntt_twiddle_records) {
    my ($twiddles, $quotient_constants) = @$record;
    $code .= "        .word   " . join(',', @$twiddles) . "\n";
    $code .= "        .word   " . join(',', @$quotient_constants) . "\n";
}
$code .= <<___;
.align  4
# The inverse records have the same root/reciprocal layout, in the reverse
# layer order consumed by the Gentleman-Sande loops.  Their roots are the
# signed additive inverses of the corresponding forward roots.
.Lml_dsa_intt_constants:
___
for my $record (@intt_twiddle_records) {
    my ($twiddles, $quotient_constants) = @$record;
    $code .= "        .word   " . join(',', @$twiddles) . "\n";
    $code .= "        .word   " . join(',', @$quotient_constants) . "\n";
}

print $code;
close STDOUT or die "error closing output: $!";
