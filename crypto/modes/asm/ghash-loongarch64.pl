#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2026, Julian Zhu <jz531210@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

######################################################################
# GHASH for LoongArch64.
#
# The LSX and LASX code does carry-less multiplication by 4-bit vshuf.b
# table lookup, with Karatsuba.  The LASX code processes two blocks per
# iteration, against H^2 and H.
#
# The lookup tables are rebuilt on every call, so gcm_gmult is scalar
# only and short buffers are handed down LASX -> LSX -> scalar.  All of
# them share the Htable from gcm_init_4bit.
######################################################################

# Scalar register aliases
# Avoid escaping $ everywhere
my ($zero,$ra,$sp)=("\$zero","\$ra","\$sp");
my ($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$a$_",(0..7));
my ($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8)=map("\$t$_",(0..8));

# The low 64 bits of $vr24-$vr31 alias the callee-saved $fs0-$fs7 of
# the LP64D ABI.  The SIMD routines overwrite them when building the
# T_hi table, so they save and restore those FPRs (only the low 64 bits
# need preserving).
my ($fs0,$fs1,$fs2,$fs3,$fs4,$fs5,$fs6,$fs7)=map("\$fs$_",(0..7));

# Vector register aliases
my @vr=map("\$vr$_",(0..31));
my @xr=map("\$xr$_",(0..31));

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
open STDOUT, ">$output" if $output;

my $code=<<___;
.text
___

# Working registers, all in slots that hold zero columns after the
# transpose.
my $BREV  = $vr[31];   # brev8 nibble-reverse lookup table
my $XI    = $vr[29];   # Xi accumulator (128-bit GHASH state)
my $INP   = $vr[27];   # input block / general temp
my $NIBLO = $vr[25];   # low nibbles of current operand
my $NIBHI = $vr[23];   # high nibbles of current operand
my $REVEN = $vr[21];   # even accumulator for clmul64 lookup
my $RODD  = $vr[19];   # odd accumulator for clmul64 lookup
my $PLO   = $vr[15];   # Karatsuba P_lo result
my $PHI   = $vr[13];   # Karatsuba P_hi result
my $PMID  = $vr[11];   # Karatsuba P_mid result
my $T1    = $vr[9];    # temp 1
my $T2    = $vr[7];    # temp 2
my $T3    = $vr[5];    # temp 3
my $T4    = $vr[3];    # temp 4

# After the 16x16 transpose VR[base+i] holds byte column bitrev4(i).
# T[i] is at most 67 bits long, so only columns 0-8 are non-zero.
my @Tcol_lo = @vr[0, 8, 4, 12, 2, 10, 6, 14, 1];
my @Tcol_hi = @vr[16, 24, 20, 28, 18, 26, 22, 30, 17];
my @Tcols = (@Tcol_lo, @Tcol_hi);

# LASX columns: low lane for H, high lane for H^2
my @XTcol_lo = ($xr[0], $xr[8], $xr[4], $xr[12], $xr[2], $xr[10], $xr[6], $xr[14], $xr[1]);
my @XTcol_hi = ($xr[16], $xr[24], $xr[20], $xr[28], $xr[18], $xr[26], $xr[22], $xr[30], $xr[17]);
my @XTcols = (@XTcol_lo, @XTcol_hi);

# LASX working registers, in the same slots
my $XXI    = $xr[29];
my $XINP   = $xr[27];
my $XNIBLO = $xr[25];
my $XNIBHI = $xr[23];
my $XREVEN = $xr[21];
my $XRODD  = $xr[19];
my $XPLO   = $xr[15];
my $XPHI   = $xr[13];
my $XPMID  = $xr[11];
my $XT1    = $xr[9];
my $XT2    = $xr[7];
my $XT3    = $xr[5];
my $XT4    = $xr[3];

# Reverse the bits within each byte, using the nibble table in $brev.
sub emit_brev8 {
    my ($dst, $src, $brev, $tmp) = @_;
    return <<___;
    vandi.b    $tmp, $src, 0x0f
    vsrli.b    $dst, $src, 4
    vshuf.b    $tmp, $brev, $brev, $tmp
    vshuf.b    $dst, $brev, $brev, $dst
    vslli.b    $tmp, $tmp, 4
    vor.v      $dst, $dst, $tmp
___
}

# T[i] = i * b for i = 0..15, in VR[base..base+15].  b is a 64-bit
# value in elem0 of $b_reg, with elem1 zero.
sub emit_build_table {
    my ($base, $b_reg, $tmp) = @_;
    my @v = map { $vr[$base + $_] } (0..15);
    my $vtmp = $vr[$tmp];
    return <<___;
    vxor.v     $v[0], $v[0], $v[0]
    vor.v      $v[1], $b_reg, $b_reg
    # T[2] = b << 1 (128-bit polynomial shift)
    vsrli.d    $vtmp, $b_reg, 63
    vslli.d    $v[2], $b_reg, 1
    vbsll.v    $vtmp, $vtmp, 8
    vor.v      $v[2], $v[2], $vtmp
    # T[4] = b << 2
    vsrli.d    $vtmp, $b_reg, 62
    vslli.d    $v[4], $b_reg, 2
    vbsll.v    $vtmp, $vtmp, 8
    vor.v      $v[4], $v[4], $vtmp
    # T[8] = b << 3
    vsrli.d    $vtmp, $b_reg, 61
    vslli.d    $v[8], $b_reg, 3
    vbsll.v    $vtmp, $vtmp, 8
    vor.v      $v[8], $v[8], $vtmp
    vxor.v     $v[3], $v[1], $v[2]
    vxor.v     $v[5], $v[1], $v[4]
    vxor.v     $v[6], $v[2], $v[4]
    vxor.v     $v[7], $v[1], $v[6]
    vxor.v     $v[9], $v[1], $v[8]
    vxor.v     $v[10], $v[2], $v[8]
    vxor.v     $v[11], $v[1], $v[10]
    vxor.v     $v[12], $v[4], $v[8]
    vxor.v     $v[13], $v[1], $v[12]
    vxor.v     $v[14], $v[2], $v[12]
    vxor.v     $v[15], $v[1], $v[14]
___
}

# In-place 16x16 byte transpose of VR[base..base+15].  Afterwards
# VR[base+i] holds column bitrev4(i).
sub emit_transpose16 {
    my ($base, $tmp) = @_;
    my @v = map { $vr[$base + $_] } (0..15);
    my $vtmp = $vr[$tmp];
    my $out = "";

    # Four interleave passes: pass n pairs the registers whose indices
    # differ only in bit n, at an element width of 2^n bytes.
    my @width = ("b", "h", "w", "d");

    for my $level (0..3) {
        my $stride = 1 << $level;
        my $w = $width[$level];

        $out .= "    # pass $level: interleave by $w, pairing v[i] with v[i+$stride]\n";
        for my $i (0..15) {
            next if $i & $stride;
            my ($a, $b) = ($v[$i], $v[$i + $stride]);
            $out .= "    vilvl.$w    $vtmp, $b, $a\n";
            $out .= "    vilvh.$w    $b, $b, $a\n";
            $out .= "    vor.v      $a, $vtmp, $vtmp\n";
        }
    }

    return $out;
}

# $result = $operand * b, where @cols are the table columns for b and
# $operand is 64 bits in elem0.  Low and high nibbles are looked up
# separately and combined at the end.
sub emit_clmul64 {
    my ($result, $operand, @cols) = @_;
    my $out = <<___;
    vandi.b    $NIBLO, $operand, 0x0f
    vsrli.b    $NIBHI, $operand, 4
    vshuf.b    $REVEN, $cols[0], $cols[0], $NIBLO
    vshuf.b    $RODD, $cols[0], $cols[0], $NIBHI
___
    for my $j (1..8) {
        $out .= <<___;
    vshuf.b    $T1, $cols[$j], $cols[$j], $NIBLO
    vshuf.b    $T2, $cols[$j], $cols[$j], $NIBHI
    vbsll.v    $T1, $T1, $j
    vbsll.v    $T2, $T2, $j
    vxor.v     $REVEN, $REVEN, $T1
    vxor.v     $RODD, $RODD, $T2
___
    }
    # The high nibbles are worth 4 more bits
    $out .= <<___;
    vslli.d    $T1, $RODD, 4
    vsrli.d    $T2, $RODD, 60
    vbsll.v    $T2, $T2, 8
    vor.v      $T1, $T1, $T2
    vxor.v     $result, $REVEN, $T1
___
    return $out;
}

# LASX version of emit_clmul64, on both lanes
sub emit_clmul64_lasx {
    my ($result, $operand, @cols) = @_;
    my $out = <<___;
    xvandi.b   $XNIBLO, $operand, 0x0f
    xvsrli.b   $XNIBHI, $operand, 4
    xvshuf.b   $XREVEN, $cols[0], $cols[0], $XNIBLO
    xvshuf.b   $XRODD, $cols[0], $cols[0], $XNIBHI
___
    for my $j (1..8) {
        $out .= <<___;
    xvshuf.b   $XT1, $cols[$j], $cols[$j], $XNIBLO
    xvshuf.b   $XT2, $cols[$j], $cols[$j], $XNIBHI
    xvbsll.v   $XT1, $XT1, $j
    xvbsll.v   $XT2, $XT2, $j
    xvxor.v    $XREVEN, $XREVEN, $XT1
    xvxor.v    $XRODD, $XRODD, $XT2
___
    }
    $out .= <<___;
    xvslli.d   $XT1, $XRODD, 4
    xvsrli.d   $XT2, $XRODD, 60
    xvbsll.v   $XT2, $XT2, 8
    xvor.v     $XT1, $XT1, $XT2
    xvxor.v    $result, $XREVEN, $XT1
___
    return $out;
}

# As emit_clmul64, for the Karatsuba middle term: the columns for
# H.lo ^ H.hi are formed on the fly.
sub emit_clmul64_mid {
    my ($result, $operand, $cols_lo_ref, $cols_hi_ref) = @_;
    my @lo = @$cols_lo_ref;
    my @hi = @$cols_hi_ref;
    # $INP is free here
    my $TMID = $INP;
    my $out = <<___;
    vandi.b    $NIBLO, $operand, 0x0f
    vsrli.b    $NIBHI, $operand, 4
    vxor.v     $TMID, $lo[0], $hi[0]
    vshuf.b    $REVEN, $TMID, $TMID, $NIBLO
    vshuf.b    $RODD, $TMID, $TMID, $NIBHI
___
    for my $j (1..8) {
        $out .= <<___;
    vxor.v     $TMID, $lo[$j], $hi[$j]
    vshuf.b    $T1, $TMID, $TMID, $NIBLO
    vshuf.b    $T2, $TMID, $TMID, $NIBHI
    vbsll.v    $T1, $T1, $j
    vbsll.v    $T2, $T2, $j
    vxor.v     $REVEN, $REVEN, $T1
    vxor.v     $RODD, $RODD, $T2
___
    }
    $out .= <<___;
    vslli.d    $T1, $RODD, 4
    vsrli.d    $T2, $RODD, 60
    vbsll.v    $T2, $T2, 8
    vor.v      $T1, $T1, $T2
    vxor.v     $result, $REVEN, $T1
___
    return $out;
}

# LASX version of emit_clmul64_mid
sub emit_clmul64_mid_lasx {
    my ($result, $operand, $cols_lo_ref, $cols_hi_ref) = @_;
    my @lo = @$cols_lo_ref;
    my @hi = @$cols_hi_ref;
    my $XTMID = $XINP;
    my $out = <<___;
    xvandi.b   $XNIBLO, $operand, 0x0f
    xvsrli.b   $XNIBHI, $operand, 4
    xvxor.v    $XTMID, $lo[0], $hi[0]
    xvshuf.b   $XREVEN, $XTMID, $XTMID, $XNIBLO
    xvshuf.b   $XRODD, $XTMID, $XTMID, $XNIBHI
___
    for my $j (1..8) {
        $out .= <<___;
    xvxor.v    $XTMID, $lo[$j], $hi[$j]
    xvshuf.b   $XT1, $XTMID, $XTMID, $XNIBLO
    xvshuf.b   $XT2, $XTMID, $XTMID, $XNIBHI
    xvbsll.v   $XT1, $XT1, $j
    xvbsll.v   $XT2, $XT2, $j
    xvxor.v    $XREVEN, $XREVEN, $XT1
    xvxor.v    $XRODD, $XRODD, $XT2
___
    }
    $out .= <<___;
    xvslli.d   $XT1, $XRODD, 4
    xvsrli.d   $XT2, $XRODD, 60
    xvbsll.v   $XT2, $XT2, 8
    xvor.v     $XT1, $XT1, $XT2
    xvxor.v    $result, $XREVEN, $XT1
___
    return $out;
}

# Combine $PLO, $PHI and $PMID into the 256-bit product and reduce it
# into $XI.
sub emit_karatsuba_reduce {
    return <<___;
    # Middle term: P_mid ^ P_lo ^ P_hi, added at x^64
    vxor.v     $T1, $PMID, $PLO
    vxor.v     $T1, $T1, $PHI
    vbsll.v    $T2, $T1, 8
    vbsrl.v    $T3, $T1, 8
    vxor.v     $PLO, $PLO, $T2
    vxor.v     $PHI, $PHI, $T3

    # Reduce: x^(128+i) = x^(i+7) + x^(i+2) + x^(i+1) + x^i
    vslli.d    $T1, $PHI, 1
    vslli.d    $T2, $PHI, 2
    vslli.d    $T3, $PHI, 7
    vxor.v     $T1, $T1, $T2
    vxor.v     $T1, $T1, $T3
    vxor.v     $T1, $T1, $PHI
    vxor.v     $PLO, $PLO, $T1

    # Bits shifted out of each 64-bit element
    vsrli.d    $T1, $PHI, 63
    vsrli.d    $T2, $PHI, 62
    vsrli.d    $T3, $PHI, 57
    vxor.v     $T1, $T1, $T2
    vxor.v     $T1, $T1, $T3

    # ... from elem0 go into elem1
    vbsll.v    $T2, $T1, 8
    vxor.v     $PLO, $PLO, $T2

    # ... from elem1 land at x^128 and up, so reduce them again
    vbsrl.v    $T2, $T1, 8
    vslli.d    $T3, $T2, 1
    vslli.d    $T4, $T2, 2
    vxor.v     $T3, $T3, $T4
    vslli.d    $T4, $T2, 7
    vxor.v     $T3, $T3, $T4
    vxor.v     $T3, $T3, $T2
    vxor.v     $XI, $PLO, $T3
___
}

# LASX version of emit_karatsuba_reduce
sub emit_karatsuba_reduce_lasx {
    return <<___;
    xvxor.v    $XT1, $XPMID, $XPLO
    xvxor.v    $XT1, $XT1, $XPHI
    xvbsll.v   $XT2, $XT1, 8
    xvbsrl.v   $XT3, $XT1, 8
    xvxor.v    $XPLO, $XPLO, $XT2
    xvxor.v    $XPHI, $XPHI, $XT3
    xvslli.d   $XT1, $XPHI, 1
    xvslli.d   $XT2, $XPHI, 2
    xvslli.d   $XT3, $XPHI, 7
    xvxor.v    $XT1, $XT1, $XT2
    xvxor.v    $XT1, $XT1, $XT3
    xvxor.v    $XT1, $XT1, $XPHI
    xvxor.v    $XPLO, $XPLO, $XT1
    xvsrli.d   $XT1, $XPHI, 63
    xvsrli.d   $XT2, $XPHI, 62
    xvsrli.d   $XT3, $XPHI, 57
    xvxor.v    $XT1, $XT1, $XT2
    xvxor.v    $XT1, $XT1, $XT3
    xvbsll.v   $XT2, $XT1, 8
    xvxor.v    $XPLO, $XPLO, $XT2
    xvbsrl.v   $XT2, $XT1, 8
    xvslli.d   $XT3, $XT2, 1
    xvslli.d   $XT4, $XT2, 2
    xvxor.v    $XT3, $XT3, $XT4
    xvslli.d   $XT4, $XT2, 7
    xvxor.v    $XT3, $XT3, $XT4
    xvxor.v    $XT3, $XT3, $XT2
    xvxor.v    $XXI, $XPLO, $XT3
___
}

# Build the column tables for brev8(H) in $INP: @Tcol_lo for H.lo and
# @Tcol_hi for H.hi.  Clobbers every vector register, then reloads $BREV.
sub emit_table_setup {
    my $out = "";

    # H.lo goes in $RODD, which is not touched while T_lo is built
    $out .= <<___;
    vbsll.v    $RODD, $INP, 8
    vbsrl.v    $RODD, $RODD, 8
___

    $out .= emit_build_table(0, $RODD, 16);
    $out .= emit_transpose16(0, 16);

    # H.hi goes in $T3, a zero column of T_lo
    $out .= <<___;
    vbsrl.v    $T3, $INP, 8
___

    $out .= emit_build_table(16, $T3, 3);
    $out .= emit_transpose16(16, 3);

    $out .= <<___;
    la.local   $t0, .Lbrev8
    vld        $BREV, $t0, 0
___

    return $out;
}

# $INP = brev8(H).  gcm_init_4bit() leaves H itself in Htable[8], as
# two host-order 64-bit words, which are byte-swapped back first.
sub emit_load_h {
    my $out = <<___;
    vld        $INP, $a1, 128
    vshuf4i.b  $INP, $INP, 0x1B
    vshuf4i.h  $INP, $INP, 0x4E
___
    $out .= emit_brev8($INP, $INP, $BREV, $T1);

    return $out;
}

# $XI = $XI * H, using the tables from emit_table_setup
sub emit_multiply {
    my $out = "";

    # $T3 = Xi.lo, $T4 = Xi.hi
    $out .= <<___;
    vbsll.v    $T3, $XI, 8
    vbsrl.v    $T3, $T3, 8
    vbsrl.v    $T4, $XI, 8
___

    $out .= emit_clmul64($PLO, $T3, @Tcol_lo);
    $out .= emit_clmul64($PHI, $T4, @Tcol_hi);
    $out .= <<___;
    vxor.v     $T3, $T3, $T4
___
    $out .= emit_clmul64_mid($PMID, $T3, \@Tcol_lo, \@Tcol_hi);
    $out .= emit_karatsuba_reduce();

    return $out;
}

# Multiply the low lane of $XXI by H and the high lane by H^2.  The
# caller XORs the two lanes together.
sub emit_multiply_lasx {
    my $out = "";

    $out .= <<___;
    xvbsll.v   $XT3, $XXI, 8
    xvbsrl.v   $XT3, $XT3, 8
    xvbsrl.v   $XT4, $XXI, 8
___

    $out .= emit_clmul64_lasx($XPLO, $XT3, @XTcol_lo);
    $out .= emit_clmul64_lasx($XPHI, $XT4, @XTcol_hi);
    $out .= <<___;
    xvxor.v    $XT3, $XT3, $XT4
___
    $out .= emit_clmul64_mid_lasx($XPMID, $XT3, \@XTcol_lo, \@XTcol_hi);
    $out .= emit_karatsuba_reduce_lasx();

    return $out;
}

######################################################################
# void gcm_ghash_loongarch64_lsx(u64 Xi[2], const u128 Htable[16],
#                                const u8 *inp, size_t len)
######################################################################

# Shorter buffers go to the scalar code
my $LSX_MIN_LEN = 32;

$code .= <<___;

.globl gcm_ghash_loongarch64_lsx
.type gcm_ghash_loongarch64_lsx, \@function
.align 4
gcm_ghash_loongarch64_lsx:
.Lghash_lsx_entry:
    # Tail call before the frame is set up; this also covers len == 0.
    ori        $t0, $zero, $LSX_MIN_LEN
    bltu       $a3, $t0, .Lghash_4bit_entry

    addi.d     $sp, $sp, -64
    fst.d      $fs0, $sp, 0
    fst.d      $fs1, $sp, 8
    fst.d      $fs2, $sp, 16
    fst.d      $fs3, $sp, 24
    fst.d      $fs4, $sp, 32
    fst.d      $fs5, $sp, 40
    fst.d      $fs6, $sp, 48
    fst.d      $fs7, $sp, 56
    la.local   $t0, .Lbrev8
    vld        $BREV, $t0, 0
___
$code .= emit_load_h();
$code .= emit_table_setup();

$code .= <<___;
    vld        $XI, $a0, 0
___
$code .= emit_brev8($XI, $XI, $BREV, $T1);

$code .= <<___;
.Lghash_lsx_loop:
    vld        $INP, $a2, 0
___
$code .= emit_brev8($INP, $INP, $BREV, $T1);
$code .= <<___;
    vxor.v     $XI, $XI, $INP
___
$code .= emit_multiply();

$code .= <<___;
    addi.d     $a2, $a2, 16
    addi.d     $a3, $a3, -16
    bnez       $a3, .Lghash_lsx_loop
___
$code .= emit_brev8($XI, $XI, $BREV, $T1);
$code .= <<___;
    vst        $XI, $a0, 0
    fld.d      $fs0, $sp, 0
    fld.d      $fs1, $sp, 8
    fld.d      $fs2, $sp, 16
    fld.d      $fs3, $sp, 24
    fld.d      $fs4, $sp, 32
    fld.d      $fs5, $sp, 40
    fld.d      $fs6, $sp, 48
    fld.d      $fs7, $sp, 56
    addi.d     $sp, $sp, 64
    jr         $ra
.size gcm_ghash_loongarch64_lsx, .-gcm_ghash_loongarch64_lsx
___

######################################################################
# void gcm_ghash_loongarch64_lasx(u64 Xi[2], const u128 Htable[16],
#                                 const u8 *inp, size_t len)
#
# Two blocks per iteration: Xi = (Xi ^ A[0]) * H^2 ^ A[1] * H.  There is
# no room for H^2 in the Htable, so it is recomputed on every call.
######################################################################

# Shorter buffers go to the LSX code.  The 2-block loop is entered
# unconditionally, so this must not be less than 32.
my $LASX_MIN_LEN = 96;

$code .= <<___;

.globl gcm_ghash_loongarch64_lasx
.type gcm_ghash_loongarch64_lasx, \@function
.align 4
gcm_ghash_loongarch64_lasx:
    # Tail call before the frame is set up
    ori        $t0, $zero, $LASX_MIN_LEN
    bltu       $a3, $t0, .Lghash_lsx_entry

    # Frame: 18 32-byte column slots, each an H column followed by the
    # matching H^2 column, then $fs0-$fs7, then brev8(H).
    addi.d     $sp, $sp, -656
    fst.d      $fs0, $sp, 576
    fst.d      $fs1, $sp, 584
    fst.d      $fs2, $sp, 592
    fst.d      $fs3, $sp, 600
    fst.d      $fs4, $sp, 608
    fst.d      $fs5, $sp, 616
    fst.d      $fs6, $sp, 624
    fst.d      $fs7, $sp, 632
    la.local   $t0, .Lbrev8
    vld        $BREV, $t0, 0
___
$code .= emit_load_h();
$code .= <<___;
    # Keep brev8(H) for computing H^2
    vst        $INP, $sp, 640
___
$code .= emit_table_setup();

# An LSX write clobbers the high 128 bits of the LASX register,
# since the high 128 bits are unpredictable after writing the 
# low 128 bits via LSX. So the H and H^2 columns are paired via the stack.
for my $i (0..17) {
    my $offset = 32 * $i;
    $code .= <<___;
    vst        $Tcols[$i], $sp, $offset
___
}

$code .= <<___;
    # H^2
    vld        $XI, $sp, 640
___
$code .= emit_multiply();
$code .= <<___;
    vor.v      $INP, $XI, $XI
___
$code .= emit_table_setup();

for my $i (0..17) {
    my $offset = 32 * $i + 16;
    $code .= <<___;
    vst        $Tcols[$i], $sp, $offset
___
}

# Half of these loads are not 32-byte aligned, which is fine on
# LoongArch and cheaper than realigning the frame.
for my $i (0..17) {
    my $offset = 32 * $i;
    $code .= <<___;
    xvld       $XTcols[$i], $sp, $offset
___
}

$code .= <<___;
    vld        $XI, $a0, 0
___
$code .= emit_brev8($XI, $XI, $BREV, $T1);

$code .= <<___;
    ori        $t0, $zero, 32

.Lghash_lasx_loop:
    vld        $T1, $a2, 0
___
$code .= emit_brev8($T1, $T1, $BREV, $T2);
$code .= <<___;
    vxor.v     $T1, $T1, $XI
    vld        $INP, $a2, 16
___
$code .= emit_brev8($INP, $INP, $BREV, $T2);

# $XXI = { Xi ^ A[0] (high lane), A[1] (low lane) }
$code .= <<___;
    vor.v      $XI, $INP, $INP
    xvpermi.q  $XXI, $XT1, 0x02
___
$code .= emit_multiply_lasx();

$code .= <<___;
    # Xi = high lane ^ low lane
    xvpermi.q  $XINP, $XXI, 0x01
    vxor.v     $XI, $XI, $INP

    addi.d     $a2, $a2, 32
    addi.d     $a3, $a3, -32
    bgeu       $a3, $t0, .Lghash_lasx_loop

    # One block left over, if len was an odd number of blocks
    beqz       $a3, .Lghash_lasx_done

    vld        $INP, $a2, 0
___
$code .= emit_brev8($INP, $INP, $BREV, $T1);
$code .= <<___;
    vxor.v     $XI, $XI, $INP
___

# The low lanes of the LASX columns are the tables for H
$code .= emit_multiply();

$code .= <<___;
.Lghash_lasx_done:
___
$code .= emit_brev8($XI, $XI, $BREV, $T1);
$code .= <<___;
    vst        $XI, $a0, 0
    fld.d      $fs0, $sp, 576
    fld.d      $fs1, $sp, 584
    fld.d      $fs2, $sp, 592
    fld.d      $fs3, $sp, 600
    fld.d      $fs4, $sp, 608
    fld.d      $fs5, $sp, 616
    fld.d      $fs6, $sp, 624
    fld.d      $fs7, $sp, 632
    addi.d     $sp, $sp, 656
    jr         $ra
.size gcm_ghash_loongarch64_lasx, .-gcm_ghash_loongarch64_lasx
___

######################################################################
# Scalar code: the generic 4-bit table algorithm, as in gcm128.c, on the
# Htable from gcm_init_4bit.  Xi and the input are handled as 64-bit
# words, and each Htable entry is loaded before the shift and reduction
# that precede its use.
######################################################################

my $Zhi  = $t0;   # Z accumulator high 64 bits
my $Zlo  = $t1;   # Z accumulator low 64 bits
my $rem  = $t2;   # reduction index (4 bits)
my $nlo  = $t3;   # current low nibble
my $nhi  = $t4;   # current high nibble
my $Hhi  = $t5;   # prefetched Htable[n].hi
my $Hlo  = $t6;   # prefetched Htable[n].lo
my $addr = $t7;   # table lookup address
my $tmp  = $t8;   # general temp
my $Xl   = $a4;   # Xi bytes 15..8, after revb.d
my $Xh   = $a5;   # Xi bytes 7..0, after revb.d
my $rp   = $a6;   # rem_4bit table pointer
my $cnt  = $a7;   # byte counter

# One nibble step: Z = (Z >> 4) ^ rem_4bit[Z & 0xf] ^ Htable[n], with
# Htable[n] already loaded into $Hhi/$Hlo.
my $nibble = <<___;
    andi       $rem, $Zlo, 0xf
    srli.d     $Zlo, $Zlo, 4
    slli.d     $tmp, $Zhi, 60
    or         $Zlo, $Zlo, $tmp
    srli.d     $Zhi, $Zhi, 4
    alsl.d     $addr, $rem, $rp, 3
    ld.d       $tmp, $addr, 0
    xor        $Zhi, $Zhi, $tmp
    xor        $Zhi, $Zhi, $Hhi
    xor        $Zlo, $Zlo, $Hlo
___
chomp $nibble;

######################################################################
# void gcm_gmult_loongarch64(u64 Xi[2], const u128 Htable[16])
######################################################################

$code .= <<___;

.globl gcm_gmult_loongarch64
.type gcm_gmult_loongarch64, \@function
.align 4
gcm_gmult_loongarch64:
    # Byte 15 of Xi ends up in the low byte of $Xl
    ld.d       $Xl, $a0, 8
    ld.d       $Xh, $a0, 0
    revb.d     $Xl, $Xl
    revb.d     $Xh, $Xh

    la.local   $rp, .Lrem_4bit

    # Byte 15: Z starts as Htable[nlo]
    andi       $nlo, $Xl, 0xf
    srli.d     $nhi, $Xl, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
    move       $Zhi, $Hhi
    move       $Zlo, $Hlo

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble
    srli.d     $Xl, $Xl, 8

    # Bytes 14..8
    ori        $cnt, $zero, 7
.Lgmult_lo_loop:
    andi       $nlo, $Xl, 0xf
    srli.d     $nhi, $Xl, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    srli.d     $Xl, $Xl, 8
    addi.d     $cnt, $cnt, -1
    bnez       $cnt, .Lgmult_lo_loop

    # Bytes 7..0
    ori        $cnt, $zero, 8
.Lgmult_hi_loop:
    andi       $nlo, $Xh, 0xf
    srli.d     $nhi, $Xh, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    srli.d     $Xh, $Xh, 8
    addi.d     $cnt, $cnt, -1
    bnez       $cnt, .Lgmult_hi_loop

    revb.d     $Zhi, $Zhi
    revb.d     $Zlo, $Zlo
    st.d       $Zhi, $a0, 0
    st.d       $Zlo, $a0, 8

    jr         $ra
.size gcm_gmult_loongarch64, .-gcm_gmult_loongarch64
___

######################################################################
# void gcm_ghash_loongarch64(u64 Xi[2], const u128 Htable[16],
#                            const u8 *inp, size_t len)
######################################################################

$code .= <<___;

.globl gcm_ghash_loongarch64
.type gcm_ghash_loongarch64, \@function
.align 4
gcm_ghash_loongarch64:
.Lghash_4bit_entry:
    # The SIMD code can forward len == 0 here
    beqz       $a3, .Lghash_4bit_ret

    la.local   $rp, .Lrem_4bit

.Lghash_4bit_outer:
    # Xi ^= inp.  Unaligned ld.d is fine on LoongArch64.
    ld.d       $Xl, $a0, 8
    ld.d       $Xh, $a0, 0
    ld.d       $tmp, $a2, 8
    xor        $Xl, $Xl, $tmp
    ld.d       $tmp, $a2, 0
    xor        $Xh, $Xh, $tmp
    revb.d     $Xl, $Xl
    revb.d     $Xh, $Xh

    # Byte 15: Z starts as Htable[nlo]
    andi       $nlo, $Xl, 0xf
    srli.d     $nhi, $Xl, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Zhi, $addr, 0
    ld.d       $Zlo, $addr, 8

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble
    srli.d     $Xl, $Xl, 8

    # Bytes 14..8
    ori        $cnt, $zero, 7
.Lghash_4bit_lo_loop:
    andi       $nlo, $Xl, 0xf
    srli.d     $nhi, $Xl, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    srli.d     $Xl, $Xl, 8
    addi.d     $cnt, $cnt, -1
    bnez       $cnt, .Lghash_4bit_lo_loop

    # Bytes 7..0
    ori        $cnt, $zero, 8
.Lghash_4bit_hi_loop:
    andi       $nlo, $Xh, 0xf
    srli.d     $nhi, $Xh, 4
    andi       $nhi, $nhi, 0xf

    alsl.d     $addr, $nlo, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    alsl.d     $addr, $nhi, $a1, 4
    ld.d       $Hhi, $addr, 0
    ld.d       $Hlo, $addr, 8
$nibble

    srli.d     $Xh, $Xh, 8
    addi.d     $cnt, $cnt, -1
    bnez       $cnt, .Lghash_4bit_hi_loop

    revb.d     $Zhi, $Zhi
    revb.d     $Zlo, $Zlo
    st.d       $Zhi, $a0, 0
    st.d       $Zlo, $a0, 8

    addi.d     $a2, $a2, 16
    addi.d     $a3, $a3, -16
    bnez       $a3, .Lghash_4bit_outer

.Lghash_4bit_ret:
    jr         $ra
.size gcm_ghash_loongarch64, .-gcm_ghash_loongarch64
___

$code .= <<___;

.section .rodata
.align 4
.Lbrev8:
    # bitrev4(i), for brev8
    .byte 0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e
    .byte 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f

.align 3
.Lrem_4bit:
    .dword 0x0000000000000000
    .dword 0x1c20000000000000
    .dword 0x3840000000000000
    .dword 0x2460000000000000
    .dword 0x7080000000000000
    .dword 0x6ca0000000000000
    .dword 0x48c0000000000000
    .dword 0x54e0000000000000
    .dword 0xe100000000000000
    .dword 0xfd20000000000000
    .dword 0xd940000000000000
    .dword 0xc560000000000000
    .dword 0x9180000000000000
    .dword 0x8da0000000000000
    .dword 0xa9c0000000000000
    .dword 0xb5e0000000000000
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
