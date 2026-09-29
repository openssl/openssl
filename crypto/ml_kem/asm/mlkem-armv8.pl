#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# AArch64 ML-KEM NTT/INTT implementation.  The source model is
# crypto/ml_kem/ml_kem.c in the accompanying OpenSSL checkout.
#
# Base algorithms
# ===============
#
# This implements FIPS 203, Section 4.3, Algorithm 9 (NTT) and Algorithm 10
# (NTT^-1), using crypto/ml_kem/ml_kem.c as the concrete interface contract.
# ML-KEM works in R_q = Z_q[X]/(X^256 + 1), q = 3329.  Because q has no
# primitive 512th root of unity, the specified transform stops after seven
# layers and leaves 128 adjacent coefficient pairs representing degree-one
# elements.
#
# The forward transform follows the scalar Algorithm 9 dependency graph.  For
# lengths 128, 64, ..., 2, each group consumes the specified bit-reversed root
# zeta = 17^BitRev7(i) mod q and applies the Cooley-Tukey butterfly
#
#       t = zeta * b (mod q)
#      (a, b) <- (a + t, a - t).
#
# The inverse follows Algorithm 10 in the opposite layer order, lengths
# 2, 4, ..., 128.  Its Gentleman-Sande butterfly is
#
#      (a, b) <- (a + b, zeta * (a - b)),
#
# followed by multiplication of every coefficient by 128^-1 = 3303 (mod q).
# The generator derives every zeta as 17^bitrev7(i) mod q.  It does not copy a
# root table from another implementation.
#
# Assembly schedule
# =================
#
# Coefficients enter and leave in canonical [0,3329) form.  Internally they are
# signed 16-bit representatives.  This permits ordinary ADD/SUB butterflies
# and avoids canonicalization after every operation.
#
# Constant-twiddle multiplication uses three NEON arithmetic instructions:
#
#   r = low16(x*z) - q * round(x*c/2^15), c = round(2^15*z/q)
#
# implemented by MUL, SQRDMULH, MLS.  Since the subtracted term is a multiple
# of q, r is congruent to x*z modulo q.  Exhaustive testing over all ML-KEM
# roots and the proved input ranges verifies the selected signed representative.
# One root/reciprocal setup serves every butterfly in a long-layer group.  A
# short-layer setup carries the roots for several adjacent groups in separate
# lanes.  The forward NTT loads these vectors from a mathematically generated
# read-only table; this measured faster than MOV/DUP construction.  The two
# shortest INTT layers use a separate lane-packed table because batching removes
# their repeated MOV/DUP and EXT/INS sequences.  Longer inverse layers retain
# MOV/DUP setup, which measured slightly faster than a full inverse table.
#
# Layers with length >= 8 use .8h arithmetic, so each MUL/SQRDMULH/MLS sequence
# performs eight modular products at once.  In lengths 128 through 16, adjacent
# vector butterflies share LDP/STP instructions and use independent register
# sets so the processor can overlap their multiplication dependency chains.
# A length-8 group has adjacent A and B vectors and uses one LDP/STP pair.
#
# The forward transform batches adjacent groups in the two shortest layers:
#
#   length 4: two [a0..a3 | b0..b3] groups per 32-byte batch
#   length 2: four [a0,a1 | b0,b1] groups per 32-byte batch
#
# LDP loads a batch, UZP1/UZP2 deinterleave its A and B halves, and ZIP1/ZIP2
# restore memory order before STP.  A generated per-lane root vector contains
# two length-4 roots repeated four times or four length-2 roots repeated twice.
# Thus every .8h multiplication lane is useful.  The inverse uses the same
# physical batching, but performs its sum/difference before multiplying the
# difference.  Neither mapping changes root order, group order, or the
# arithmetic applied to any coefficient.
#
# UZP/ZIP was selected after testing the equivalent LD2/ST2 structured-memory
# mapping.  UZP1 selects the even 64- or 32-bit sub-blocks (all A halves) and
# UZP2 selects the odd sub-blocks (all B halves); ZIP1/ZIP2 are their exact
# inverse for these layouts.  This keeps ordinary LDP/STP memory operations,
# makes the lane permutation explicit, and gave the best repeated median for
# the complete combined schedule on the benchmark machine.
#
# Forward lazy-reduction bounds after layers 1 through 7 are:
#
#   [-1702,5030], [-3575,6903], [-5546,8874], [-7625,10953],
#   [-9800,13128], [-12096,15424], [-14520,17848].
#
# Therefore the forward transform needs only one final canonicalization pass.
# In the inverse transform, addition paths grow faster.  After layers 3 and 6
# only the accumulating half of every block is center-reduced.  The resulting
# range after layer 7 is bounded by [-4421,4421].  Multiplication by
# 128^-1 = 3303 = -26 (mod q) is fused with final canonicalization.
#
# Constant-time properties
# ========================
#
# All layer, group, and lane loops run while generating the assembly, not while
# processing coefficients.  The only runtime loops are the final NTT
# canonicalization and INTT normalization passes.  Each has the public constant
# trip count eight and advances its cursor by exactly 64 bytes per iteration.
# There are no data-dependent branches or instruction choices.  Layer addresses
# are fixed immediate offsets from x0.  The forward constant-table cursor
# advances by exactly 32 bytes for each generated root-vector entry; neither
# the table index nor any address depends on coefficient data.  A short-layer
# entry represents a fixed batch of two or four public groups.
# MUL, SQRDMULH, MLS, ADD, SUB, shifts, loads, and stores have data-independent
# control flow.  Canonicalization uses an arithmetic sign mask, never a branch.
#
# Register allocation uses only caller-saved registers:
#
#   x0       coefficient array
#   x1,w2    fixed-pass cursor and public loop counter
#   w9,w10  twiddle and reciprocal construction
#   w11     q
#   x12     forward root-table cursor
#   v0,v1   primary butterfly operands
#   v2      twiddle product
#   v3      multiplication/reduction temporary
#   v4      deinterleaved short-layer A operand
#   v5      second butterfly output
#   v16-v20 second long-layer butterfly register set
#   v28     round(2^15/q) = 10
#   v29     twiddle reciprocal
#   v30     signed twiddle
#   v31     q
use strict;
use warnings;

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m|(.*[\\/])[^\\/]+$|;
my $dir = $1;
my $xlate;
( $xlate = "${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate = "${dir}../../perlasm/arm-xlate.pl" and -f $xlate ) or
die "can't locate arm-xlate.pl";

open OUT, "| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $q = 3329;
my $code = '';

# Keep the allocation in one place, following other OpenSSL AArch64 perlasm
# generators.  All registers are caller-saved under AAPCS64; these leaf
# functions therefore need neither a stack frame nor register spills.
my ($arg, $root_gpr, $recip_gpr, $q_gpr) = ('x0', 'w9', 'w10', 'w11');
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
my ($double_a, $double_sum) = map("d$_", (0, 5));
my ($vec_barrett, $vec_recip, $vec_root, $vec_q) =
    map("v$_", (28, 29, 30, 31));
my ($quad_recip, $quad_root) = map("q$_", (29, 30));
my @forward_constants;
my @inverse_short_constants;
my $use_forward_table = 0;

# Reverse the low seven bits of an integer.  Generator-time helper used only
# to derive the FIPS 203 exponent ordering; emits no instructions.
sub bitrev7 { my ($v) = @_; my $r = 0; for (1..7) { $r=($r<<1)|($v&1); $v>>=1 } $r }

# Compute b^e modulo q at generator time by square-and-multiply.  The exponent
# is public and this code is never part of the runtime cryptographic path.
sub powmod {
    my ($b, $e) = @_; my $r = 1;
    while ($e) { $r=($r*$b)%$q if $e&1; $b=($b*$b)%$q; $e>>=1 }
    $r;
}

# Return the signed representative in [-1664,1664] of forward root i, or of
# its multiplicative inverse when $inverse is true.
sub sroot {
    my ($i, $inverse) = @_;
    my $e = bitrev7($i);
    $e = (256 - $e) & 255 if $inverse;
    my $z = powmod(17, $e);
    return $z > 1664 ? $z - $q : $z;
}

# Round a signed rational to nearest at generator time.  This derives the
# SQRDMULH reciprocal associated with a public constant twiddle.
sub round_div { my ($n,$d)=@_; return $n >= 0 ? int(($n+$d/2)/$d) : -int((-$n+$d/2)/$d) }

# Emit a two-instruction approximate Barrett centering of eight signed lanes.
# Input and output are the named vector; vec_tmp is clobbered.  The proved
# schedule ranges guarantee the result is a centered representative modulo q.
sub emit_center_vec {
    my ($v) = @_;
    # For the proved transform ranges, round(x * 10 / 2^15) is within one
    # of x/q.  Subtracting that multiple of q leaves a centered representative.
    $code .= <<___;
        sqrdmulh $vec_tmp.8h,$v.8h,$vec_barrett.8h
        mls     $v.8h,$vec_tmp.8h,$vec_q.8h
___
}

# Emit conversion of eight signed representatives to canonical [0,q).  When
# requested, first center lanes that may have magnitude >= q.  vec_tmp is
# clobbered; the named vector contains the canonical result.
sub emit_canonical_vec {
    my ($v, $needs_centering) = @_;
    emit_center_vec($v) if $needs_centering;
    # Add q exactly to negative lanes.  SSHR produces zero or -1.
    $code .= <<___;
        sshr    $vec_tmp.8h,$v.8h,#15
        mls     $v.8h,$vec_tmp.8h,$vec_q.8h
___
}

# Prepare the signed twiddle z and c=round(2^15*z/q) in vec_root/vec_recip.
# Forward long-layer groups consume one fixed sequential table entry; inverse
# groups use MOV/DUP.  The table contents are appended to @forward_constants
# here so the instruction stream and generated data cannot get out of sync.
sub emit_twiddle_constants {
    my ($z) = @_;
    my $c = round_div(32768 * $z, $q);
    if ($use_forward_table) {
        push @forward_constants, [[($z) x 8], [($c) x 8]];
        $code .= "        ldp     $quad_root,$quad_recip,[$table_gpr],#32\n";
        return;
    }
    $code .= <<___;
        mov     $root_gpr,#$z
        dup     $vec_root.8h,$root_gpr
        mov     $recip_gpr,#$c
        dup     $vec_recip.8h,$recip_gpr
___
}

# Prepare one vector containing several public roots and a matching reciprocal
# vector.  Each root is repeated once per useful coefficient lane in its short
# butterfly group.  This allows distinct adjacent groups to share one .8h
# multiplication sequence while retaining the exact scalar root ordering.
sub emit_twiddle_lane_constants {
    my ($roots, $constants) = @_;
    die "short root vector must have eight lanes" unless @$roots == 8;
    my @recips = map { round_div(32768 * $_, $q) } @$roots;
    push @$constants, [[@$roots], [@recips]];
    $code .= "        ldp     $quad_root,$quad_recip,[$table_gpr],#32\n";
}

# Multiply the eight lanes in vec_b by the prepared constant.  This is the
# three-arithmetic-instruction kernel.  vec_product receives a signed result;
# vec_tmp is clobbered and all other butterfly inputs remain live.
sub emit_twiddle_vec {
    my ($shape) = @_;
    $shape = '.8h' unless defined $shape;
    # r = low16(x*z) - q*round(x*c/2^15), congruent to x*z mod q.
    $code .= <<___;
        mul     ${vec_product}${shape},${vec_b}${shape},${vec_root}${shape}
        sqrdmulh ${vec_tmp}${shape},${vec_b}${shape},${vec_recip}${shape}
        mls     ${vec_product}${shape},${vec_tmp}${shape},${vec_q}${shape}
___
}

# Emit eight parallel butterflies at byte offsets $a and $b.  Forward mode
# computes (a+z*b,a-z*b); inverse mode computes (a+b,z*(a-b)).  It loads and
# stores exactly two 128-bit vectors at public, generator-known addresses.
sub emit_bfly_vec {
    my ($a, $b, $inverse) = @_;
    $code .= <<___;
        ldr     $quad_a,[$arg,#$a]
        ldr     $quad_b,[$arg,#$b]
___
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h,$vec_a.8h,$vec_b.8h
        sub     $vec_b.8h,$vec_a.8h,$vec_b.8h
___
        emit_twiddle_vec();
        $code .= <<___;
        str     $quad_sum,[$arg,#$a]
        str     $quad_product,[$arg,#$b]
___
    } else {
        emit_twiddle_vec();
        $code .= <<___;
        sub     $vec_sum.8h,$vec_a.8h,$vec_product.8h
        add     $vec_a.8h,$vec_a.8h,$vec_product.8h
        str     $quad_a,[$arg,#$a]
        str     $quad_sum,[$arg,#$b]
___
    }
}

# Emit two adjacent vector butterflies with one paired load for the A side and
# one for the B side.  Independent register sets let the processor overlap the
# two multiplication dependency chains.  Both vectors use the same group
# twiddle, as required for adjacent j chunks within a length >= 16 group.
sub emit_bfly_vec_pair {
    my ($a, $b, $inverse) = @_;
    $code .= <<___;
        ldp     $quad_a,$quad_a2,[$arg,#$a]
        ldp     $quad_b,$quad_b2,[$arg,#$b]
___
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h,$vec_a.8h,$vec_b.8h
        add     $vec_sum2.8h,$vec_a2.8h,$vec_b2.8h
        sub     $vec_b.8h,$vec_a.8h,$vec_b.8h
        sub     $vec_b2.8h,$vec_a2.8h,$vec_b2.8h
___
    }
    $code .= <<___;
        mul     $vec_product.8h,$vec_b.8h,$vec_root.8h
        mul     $vec_product2.8h,$vec_b2.8h,$vec_root.8h
        sqrdmulh $vec_tmp.8h,$vec_b.8h,$vec_recip.8h
        sqrdmulh $vec_tmp2.8h,$vec_b2.8h,$vec_recip.8h
        mls     $vec_product.8h,$vec_tmp.8h,$vec_q.8h
        mls     $vec_product2.8h,$vec_tmp2.8h,$vec_q.8h
___
    if ($inverse) {
        $code .= <<___;
        stp     $quad_sum,$quad_sum2,[$arg,#$a]
        stp     $quad_product,$quad_product2,[$arg,#$b]
___
    } else {
        $code .= <<___;
        sub     $vec_sum.8h,$vec_a.8h,$vec_product.8h
        sub     $vec_sum2.8h,$vec_a2.8h,$vec_product2.8h
        add     $vec_a.8h,$vec_a.8h,$vec_product.8h
        add     $vec_a2.8h,$vec_a2.8h,$vec_product2.8h
        stp     $quad_a,$quad_a2,[$arg,#$a]
        stp     $quad_sum,$quad_sum2,[$arg,#$b]
___
    }
}

# A length-8 group consists of exactly two adjacent 128-bit halves.  Pairing
# those halves needs no shuffle and halves its data load/store instruction count.
sub emit_bfly_vec_contiguous {
    my ($a, $inverse) = @_;
    $code .= "        ldp     $quad_a,$quad_b,[$arg,#$a]\n";
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h,$vec_a.8h,$vec_b.8h
        sub     $vec_b.8h,$vec_a.8h,$vec_b.8h
___
        emit_twiddle_vec();
        $code .= "        stp     $quad_sum,$quad_product,[$arg,#$a]\n";
    } else {
        emit_twiddle_vec();
        $code .= <<___;
        sub     $vec_sum.8h,$vec_a.8h,$vec_product.8h
        add     $vec_a.8h,$vec_a.8h,$vec_product.8h
        stp     $quad_a,$quad_sum,[$arg,#$a]
___
    }
}

# Emit every butterfly in one length-4 or length-2 group in parallel.  The
# complete group occupies respectively one 128-bit or one 64-bit register.
# EXT places the group's upper half in vec_b; INS rejoins the two result halves.
# Arithmetic in unused length-2 lanes is discarded before the 64-bit store.
sub emit_bfly_short_vec {
    my ($off, $len, $inverse) = @_;
    my ($load, $store, $bytes, $half, $lane);
    if ($len == 4) {
        ($load, $store, $bytes, $half, $lane) =
            ($quad_a, $quad_sum, '.16b', 8, 'd');
    } elsif ($len == 2) {
        ($load, $store, $bytes, $half, $lane) =
            ($double_a, $double_sum, '.8b', 4, 's');
    } else {
        die "unsupported short butterfly length $len";
    }
    $code .= "        ldr     $load,[$arg,#$off]\n";
    # Rotate [a | b] so the low half of vec_b contains b.  Length 2 rotates
    # [a0,a1,b0,b1] and intentionally ignores lanes 2 and 3 afterward.
    $code .= "        ext     ${vec_b}${bytes},${vec_a}${bytes},${vec_a}${bytes},#$half\n";
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.4h,$vec_a.4h,$vec_b.4h
        sub     $vec_b.4h,$vec_a.4h,$vec_b.4h
___
        emit_twiddle_vec('.4h');
        # Low half is a+b; high half is z*(a-b).
        $code .= "        ins     $vec_sum.$lane\[1\],$vec_product.$lane\[0\]\n";
        $code .= "        str     $store,[$arg,#$off]\n";
    } else {
        emit_twiddle_vec('.4h');
        $code .= <<___;
        sub     $vec_sum.4h,$vec_a.4h,$vec_product.4h
        add     $vec_a.4h,$vec_a.4h,$vec_product.4h
___
        # Low half is a+z*b; high half is a-z*b.
        $code .= "        ins     $vec_a.$lane\[1\],$vec_sum.$lane\[0\]\n";
        $code .= "        str     $load,[$arg,#$off]\n";
    }
}

# Emit a 32-byte batch of adjacent short groups.  Length 2 batches four
# groups as eight 32-bit [a0,a1]/[b0,b1] pairs; length 4 batches two groups as
# four 64-bit [a0..a3]/[b0..b3] halves.  UZP1 takes the even sub-blocks and
# UZP2 the odd sub-blocks after LDP; ZIP1/ZIP2 perform the inverse mapping before
# STP.  All eight halfword lanes do useful work.  This explicit permutation was
# also slightly faster in the selected combined schedule than tested LD2/ST2.
sub emit_short_batch {
    my ($len, $roots, $inverse) = @_;
    my $shape = $len == 2 ? '.4s' : $len == 4 ? '.2d'
                                             : die "bad batch length $len";
    my $constants = $inverse ? \@inverse_short_constants
                             : \@forward_constants;
    emit_twiddle_lane_constants($roots, $constants);
    $code .= <<___;
        ldp     q0,q1,[$pass_gpr]
        uzp1    $vec_batch_a$shape,$vec_a$shape,$vec_b$shape
        uzp2    $vec_b$shape,$vec_a$shape,$vec_b$shape
___
    if ($inverse) {
        $code .= <<___;
        add     $vec_sum.8h,$vec_batch_a.8h,$vec_b.8h
        sub     $vec_b.8h,$vec_batch_a.8h,$vec_b.8h
___
        emit_twiddle_vec();
        $code .= <<___;
        zip1    $vec_a$shape,$vec_sum$shape,$vec_product$shape
        zip2    $vec_b$shape,$vec_sum$shape,$vec_product$shape
___
    } else {
        emit_twiddle_vec();
        $code .= <<___;
        sub     $vec_sum.8h,$vec_batch_a.8h,$vec_product.8h
        add     $vec_batch_a.8h,$vec_batch_a.8h,$vec_product.8h
        zip1    $vec_a$shape,$vec_batch_a$shape,$vec_sum$shape
        zip2    $vec_b$shape,$vec_batch_a$shape,$vec_sum$shape
___
    }
    $code .= "        stp     q0,q1,[$pass_gpr],#32\n";
}

# Center only the first $len coefficients of each public $stride-sized inverse
# block.  These are the sum-accumulating paths that would otherwise exceed the
# later signed-16-bit bound.  All offsets are expanded by Perl.
sub emit_center_blocks {
    my ($len, $stride) = @_;
    # Reduce only the sum-producing half of each inverse-transform block.
    # Product-producing halves have already been brought back near zero by
    # the three-instruction twiddle multiplication.
    for (my $base = 0; $base < 256; $base += $stride) {
        for (my $j = 0; $j < $len; $j += 8) {
            my $off = 2 * ($base + $j);
            $code .= "        ldr     $quad_a,[$arg,#$off]\n";
            emit_center_vec($vec_a);
            $code .= "        str     $quad_a,[$arg,#$off]\n";
        }
    }
}

# Emit the forward transform's final fixed pass over all 256 coefficients,
# centering each vector and converting it to canonical [0,q).  Four vectors
# are handled per public iteration.  Paired loads/stores reduce dynamic memory
# instructions while the eight-iteration loop reduces generated text.
sub emit_canonical_all {
    # The final centered range is less than q in magnitude, so one sign-mask
    # correction converts every lane to [0,q).
    $code .= <<___;
        mov     $pass_gpr,$arg
        mov     $pass_count,#8
.Lntt_canonical_loop:
___
    for (1..2) {
        $code .= "        ldp     $quad_a,$quad_b,[$pass_gpr]\n";
        emit_canonical_vec($vec_a, 1);
        emit_canonical_vec($vec_b, 1);
        $code .= "        stp     $quad_a,$quad_b,[$pass_gpr],#32\n";
    }
    $code .= <<___;
        subs    $pass_count,$pass_count,#1
        b.ne    .Lntt_canonical_loop
___
}

# Emit inverse normalization by 128^-1 = -26 (mod q), followed immediately by
# sign canonicalization.  The proved product interval is already within
# (-q,q), so no separate centering pass is required here.  Two independent
# vectors share each LDP/STP pair and interleave their multiply chains.
sub emit_inverse_scale {
    # 128^-1 = 3303 = -26 (mod q).  Its reciprocal constant is -256, allowing
    # normalization to use the same three-instruction multiplication primitive.
    emit_twiddle_constants(-26);
    $code .= <<___;
        mov     $pass_gpr,$arg
        mov     $pass_count,#8
.Lintt_scale_loop:
___
    for (1..2) {
        $code .= <<___;
        ldp     $quad_b,$quad_b2,[$pass_gpr]
        mul     $vec_product.8h,$vec_b.8h,$vec_root.8h
        mul     $vec_product2.8h,$vec_b2.8h,$vec_root.8h
        sqrdmulh $vec_tmp.8h,$vec_b.8h,$vec_recip.8h
        sqrdmulh $vec_tmp2.8h,$vec_b2.8h,$vec_recip.8h
        mls     $vec_product.8h,$vec_tmp.8h,$vec_q.8h
        mls     $vec_product2.8h,$vec_tmp2.8h,$vec_q.8h
        sshr    $vec_tmp.8h,$vec_product.8h,#15
        sshr    $vec_tmp2.8h,$vec_product2.8h,#15
        mls     $vec_product.8h,$vec_tmp.8h,$vec_q.8h
        mls     $vec_product2.8h,$vec_tmp2.8h,$vec_q.8h
        stp     $quad_product,$quad_product2,[$pass_gpr],#32
___
    }
    $code .= <<___;
        subs    $pass_count,$pass_count,#1
        b.ne    .Lintt_scale_loop
___
}

# Emit one complete public entry point.  All layer/group/lane loops execute in
# Perl and become straight-line assembly; only the fixed final pass is looped
# at runtime.  $inverse selects the public forward or inverse dependency graph
# while generating the file; it is not a runtime condition.
sub emit_transform {
    my ($name, $inverse) = @_;
    $use_forward_table = !$inverse;
    $code .= <<___;
.globl  $name
.type   $name,%function
.align  4
$name:
        AARCH64_VALID_CALL_TARGET
___
    my $table_label = $inverse ? '.Lintt_short_constants' : '.Lntt_constants';
    $code .= <<___;
        adrp    $table_gpr,$table_label
        add     $table_gpr,$table_gpr,#:lo12:$table_label
        mov     $q_gpr,#3329
        dup     $vec_q.8h,$q_gpr
        movi    $vec_barrett.8h,#10
___
    my @lens = $inverse ? (2,4,8,16,32,64,128) : (128,64,32,16,8,4,2);
    for my $len (@lens) {
        if ($len == 2 || $len == 4) {
            my $groups = 128 / $len;
            my $groups_per_batch = 8 / $len;
            $code .= "        mov     $pass_gpr,$arg\n";
            for (my $group = 0; $group < $groups;
                 $group += $groups_per_batch) {
                my @roots;
                for my $g ($group .. $group + $groups_per_batch - 1) {
                    my $root_index = 128 / $len + $g;
                    my $z = sroot($root_index, $inverse);
                    push @roots, (($z) x $len);
                }
                emit_short_batch($len, \@roots, $inverse);
            }
            next;
        }
        my $group = 0;
        for (my $start = 0; $start < 256; $start += 2*$len, ++$group) {
            # The scalar inverse table is consumed in 64..127, 32..63, ...
            # order. Forward roots are consumed in ordinary 1..127 order.
            my $root_index = $inverse ? 128 / $len + $group
                                      : 1 + ($group + 0);
            if (!$inverse) {
                for my $prior (@lens) {
                    last if $prior == $len;
                    $root_index += 256 / (2 * $prior);
                }
            }
            my $z = sroot($root_index, $inverse);
            # One root/reciprocal broadcast serves the whole butterfly group.
            emit_twiddle_constants($z);
            if ($len == 8) {
                emit_bfly_vec_contiguous(2 * $start, $inverse);
                next;
            }
            my $j_step = $len >= 16 ? 16 : 8;
            for (my $j = 0; $j < $len; $j += $j_step) {
                my $a = 2 * ($start + $j); my $b = 2 * ($start + $len + $j);
                if ($len >= 16) {
                    emit_bfly_vec_pair($a, $b, $inverse);
                } elsif ($len >= 8) { emit_bfly_vec($a,$b,$inverse) }
                else { emit_bfly_short_vec($a,$len,$inverse) }
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

# Emit the constant tables after the text.  Every 32-byte entry contains eight
# signed roots z followed by eight signed reciprocals
# c = round(2^15*z/q), as consumed by MUL/SQRDMULH/MLS.  All values are derived
# by sroot()/round_div(); these are not copied constant tables.
#
# .Lntt_constants is consumed sequentially by the forward transform:
#
#   entries  0..30: lengths 128, 64, 32, 16, and 8 (1+2+4+8+16 entries).
#                    Each entry broadcasts one root across all eight lanes.
#   entries 31..46: length 4.  Two roots are each repeated across four lanes.
#   entries 47..62: length 2.  Four roots are each repeated across two lanes.
#
# .Lintt_short_constants contains only the two batched inverse short layers:
#
#   entries  0..15: length 2, with four roots repeated across two lanes.
#   entries 16..31: length 4, with two roots repeated across four lanes.
#
# The inverse roots appear in inverse-transform consumption order.  Longer
# inverse layers and the final -26 normalization use MOV/DUP constants because
# that schedule measured faster than loading a complete inverse table.
$code .= <<___;
.rodata
.align  4
// Forward NTT: broadcast lengths 128..8, then lane-packed lengths 4 and 2.
// Each entry is { z[8], round(2^15*z/q)[8] } and occupies 32 bytes.
.Lntt_constants:
___
for my $constant (@forward_constants) {
    my ($roots, $recips) = @$constant;
    $code .= "        .short  " . join(',', @$roots) . "\n";
    $code .= "        .short  " . join(',', @$recips) . "\n";
}
$code .= <<___;
.align  4
// Inverse NTT: lane-packed length-2 entries followed by length-4 entries.
// Each entry is { z^-1[8], round(2^15*z^-1/q)[8] } and occupies 32 bytes.
.Lintt_short_constants:
___
for my $constant (@inverse_short_constants) {
    my ($roots, $recips) = @$constant;
    $code .= "        .short  " . join(',', @$roots) . "\n";
    $code .= "        .short  " . join(',', @$recips) . "\n";
}
print $code;
close STDOUT or die "error closing STDOUT: $!";
