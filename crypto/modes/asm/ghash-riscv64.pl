#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Christoph Müllner <christoph.muellner@vrull.eu>
# Copyright (c) 2026, Julian Zhu <julian.oerv@isrc.iscas.ac.cn>
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

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code=<<___;
.text
___

################################################################################
# void gcm_init_rv64i_zbc(u128 Htable[16], const u64 H[2]);
# void gcm_init_rv64i_zbc__zbb(u128 Htable[16], const u64 H[2]);
# void gcm_init_rv64i_zbc__zbkb(u128 Htable[16], const u64 H[2]);
#
# input:  H: 128-bit H - secret parameter E(K, 0^128)
# output: Htable: Preprocessed key data for gcm_gmult_rv64i_zbc* and
#                 gcm_ghash_rv64i_zbc*
#
# All callers of this function revert the byte-order unconditionally
# on little-endian machines. So we need to revert the byte-order back.
# Additionally we reverse the bits of each byte.

{
my ($Htable,$H,$VAL0,$VAL1,$TMP0,$TMP1,$TMP2) = ("a0","a1","a2","a3","t0","t1","t2");
my ($z0,$z1,$z2,$z3,$r0,$r1,$polymod) = ("a4","a5","a6","a7","t3","t4","t5");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zbc
.type gcm_init_rv64i_zbc,\@function
gcm_init_rv64i_zbc:
    ld      $VAL0,0($H)
    ld      $VAL1,8($H)
    @{[brev8_rv64i   $VAL0, $TMP0, $TMP1, $TMP2]}
    @{[brev8_rv64i   $VAL1, $TMP0, $TMP1, $TMP2]}
    @{[sd_rev8_rv64i $VAL0, $Htable, 0, $TMP0]}
    @{[sd_rev8_rv64i $VAL1, $Htable, 8, $TMP0]}

    # Compute H^2 = H*H for 2-block ghash aggregation.
    # Re-load H in multiply-ready format.
    ld        $VAL0, 0($Htable)
    ld        $VAL1, 8($Htable)
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)
    # Squaring in GF(2): cross terms cancel, only 4 clmul needed.
    @{[clmulh $z3, $VAL1, $VAL1]}
    @{[clmul  $z2, $VAL1, $VAL1]}
    @{[clmulh $z1, $VAL0, $VAL0]}
    @{[clmul  $z0, $VAL0, $VAL0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 16($Htable)
    sd        $VAL1, 24($Htable)

    # Compute H^3 = H^2 * H for 4-block ghash aggregation.
    ld        $TMP0, 0($Htable)
    ld        $TMP1, 8($Htable)
    @{[clmulh $z3, $VAL1, $TMP1]}
    @{[clmul  $z2, $VAL1, $TMP1]}
    @{[clmulh $r1, $VAL0, $TMP1]}
    @{[clmul  $z1, $VAL0, $TMP1]}
    xor       $z2, $z2, $r1
    @{[clmulh $r1, $VAL1, $TMP0]}
    @{[clmul  $r0, $VAL1, $TMP0]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $VAL0, $TMP0]}
    @{[clmul  $z0, $VAL0, $TMP0]}
    xor       $z1, $z1, $r1
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 32($Htable)
    sd        $VAL1, 40($Htable)

    # Compute H^4 = (H^2)^2.
    ld        $TMP0, 16($Htable)
    ld        $TMP1, 24($Htable)
    @{[clmulh $z3, $TMP1, $TMP1]}
    @{[clmul  $z2, $TMP1, $TMP1]}
    @{[clmulh $z1, $TMP0, $TMP0]}
    @{[clmul  $z0, $TMP0, $TMP0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 48($Htable)
    sd        $VAL1, 56($Htable)

    ret
.size gcm_init_rv64i_zbc,.-gcm_init_rv64i_zbc
___
}

{
my ($Htable,$H,$VAL0,$VAL1,$TMP0,$TMP1,$TMP2) = ("a0","a1","a2","a3","t0","t1","t2");
my ($z0,$z1,$z2,$z3,$r0,$r1,$polymod) = ("a4","a5","a6","a7","t3","t4","t5");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zbc__zbb
.type gcm_init_rv64i_zbc__zbb,\@function
gcm_init_rv64i_zbc__zbb:
    ld      $VAL0,0($H)
    ld      $VAL1,8($H)
    @{[brev8_rv64i $VAL0, $TMP0, $TMP1, $TMP2]}
    @{[brev8_rv64i $VAL1, $TMP0, $TMP1, $TMP2]}
    @{[rev8 $VAL0, $VAL0]}
    @{[rev8 $VAL1, $VAL1]}
    sd      $VAL0,0($Htable)
    sd      $VAL1,8($Htable)

    # Compute H^2. VAL0/VAL1 are already in loaded format.
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)
    @{[clmulh $z3, $VAL1, $VAL1]}
    @{[clmul  $z2, $VAL1, $VAL1]}
    @{[clmulh $z1, $VAL0, $VAL0]}
    @{[clmul  $z0, $VAL0, $VAL0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 16($Htable)
    sd        $VAL1, 24($Htable)

    # Compute H^3 = H^2 * H for 4-block ghash aggregation.
    ld        $TMP0, 0($Htable)
    ld        $TMP1, 8($Htable)
    @{[clmulh $z3, $VAL1, $TMP1]}
    @{[clmul  $z2, $VAL1, $TMP1]}
    @{[clmulh $r1, $VAL0, $TMP1]}
    @{[clmul  $z1, $VAL0, $TMP1]}
    xor       $z2, $z2, $r1
    @{[clmulh $r1, $VAL1, $TMP0]}
    @{[clmul  $r0, $VAL1, $TMP0]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $VAL0, $TMP0]}
    @{[clmul  $z0, $VAL0, $TMP0]}
    xor       $z1, $z1, $r1
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 32($Htable)
    sd        $VAL1, 40($Htable)

    # Compute H^4 = (H^2)^2.
    ld        $TMP0, 16($Htable)
    ld        $TMP1, 24($Htable)
    @{[clmulh $z3, $TMP1, $TMP1]}
    @{[clmul  $z2, $TMP1, $TMP1]}
    @{[clmulh $z1, $TMP0, $TMP0]}
    @{[clmul  $z0, $TMP0, $TMP0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $VAL1, $z1, $r1
    xor       $VAL0, $z0, $r0
    sd        $VAL0, 48($Htable)
    sd        $VAL1, 56($Htable)

    ret
.size gcm_init_rv64i_zbc__zbb,.-gcm_init_rv64i_zbc__zbb
___
}

{
my ($Htable,$H,$TMP0,$TMP1) = ("a0","a1","t0","t1");
my ($z0,$z1,$z2,$z3,$r0,$r1,$polymod) = ("a2","a3","a4","a5","t2","t3","t4");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zbc__zbkb
.type gcm_init_rv64i_zbc__zbkb,\@function
gcm_init_rv64i_zbc__zbkb:
    ld      $TMP0,0($H)
    ld      $TMP1,8($H)
    @{[brev8 $TMP0, $TMP0]}
    @{[brev8 $TMP1, $TMP1]}
    @{[rev8 $TMP0, $TMP0]}
    @{[rev8 $TMP1, $TMP1]}
    sd      $TMP0,0($Htable)
    sd      $TMP1,8($Htable)

    # Compute H^2. TMP0/TMP1 are already in loaded format.
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)
    @{[clmulh $z3, $TMP1, $TMP1]}
    @{[clmul  $z2, $TMP1, $TMP1]}
    @{[clmulh $z1, $TMP0, $TMP0]}
    @{[clmul  $z0, $TMP0, $TMP0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $TMP1, $z1, $r1
    xor       $TMP0, $z0, $r0
    sd        $TMP0, 16($Htable)
    sd        $TMP1, 24($Htable)

    # Compute H^3 = H^2 * H for 4-block ghash aggregation.
    # H^2 is in TMP0:TMP1. Load H into z0:H (a2:a1).
    ld        $z0, 0($Htable)
    ld        $H, 8($Htable)
    # Schoolbook multiply (TMP0:TMP1) * (z0:H).
    # Order: read z0 as input before overwriting as product.
    @{[clmulh $z3, $TMP1, $H]}
    @{[clmul  $z2, $TMP1, $H]}
    @{[clmulh $r1, $TMP0, $H]}
    @{[clmul  $z1, $TMP0, $H]}
    xor       $z2, $z2, $r1
    @{[clmulh $r1, $TMP1, $z0]}
    @{[clmul  $r0, $TMP1, $z0]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $TMP0, $z0]}
    @{[clmul  $z0, $TMP0, $z0]}
    xor       $z1, $z1, $r1
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $TMP1, $z1, $r1
    xor       $TMP0, $z0, $r0
    sd        $TMP0, 32($Htable)
    sd        $TMP1, 40($Htable)

    # Compute H^4 = (H^2)^2.
    ld        $TMP0, 16($Htable)
    ld        $TMP1, 24($Htable)
    @{[clmulh $z3, $TMP1, $TMP1]}
    @{[clmul  $z2, $TMP1, $TMP1]}
    @{[clmulh $z1, $TMP0, $TMP0]}
    @{[clmul  $z0, $TMP0, $TMP0]}
    @{[clmulh $r1, $z3, $polymod]}
    @{[clmul  $r0, $z3, $polymod]}
    xor       $z2, $z2, $r1
    xor       $z1, $z1, $r0
    @{[clmulh $r1, $z2, $polymod]}
    @{[clmul  $r0, $z2, $polymod]}
    xor       $TMP1, $z1, $r1
    xor       $TMP0, $z0, $r0
    sd        $TMP0, 48($Htable)
    sd        $TMP1, 56($Htable)

    ret
.size gcm_init_rv64i_zbc__zbkb,.-gcm_init_rv64i_zbc__zbkb
___
}

################################################################################
# void gcm_gmult_rv64i_zbc(u64 Xi[2], const u128 Htable[16]);
# void gcm_gmult_rv64i_zbc__zbkb(u64 Xi[2], const u128 Htable[16]);
#
# input:  Xi: current hash value
#         Htable: copy of H
# output: Xi: next hash value Xi
#
# Compute GMULT (Xi*H mod f) using the Zbc (clmul) and Zbb (basic bit manip)
# extensions. Using the no-Karatsuba approach and clmul for the final reduction.
# This results in an implementation with minimized number of instructions.
# HW with clmul latencies higher than 2 cycles might observe a performance
# improvement with Karatsuba. HW with clmul latencies higher than 6 cycles
# might observe a performance improvement with additionally converting the
# reduction to shift&xor. For a full discussion of this estimates see
# https://github.com/riscv/riscv-crypto/blob/master/doc/supp/gcm-mode-cmul.adoc
{
my ($Xi,$Htable,$x0,$x1,$y0,$y1) = ("a0","a1","a4","a5","a6","a7");
my ($z0,$z1,$z2,$z3,$t0,$t1,$polymod) = ("t0","t1","t2","t3","t4","t5","t6");

$code .= <<___;
.p2align 3
.globl gcm_gmult_rv64i_zbc
.type gcm_gmult_rv64i_zbc,\@function
gcm_gmult_rv64i_zbc:
    # Load Xi and bit-reverse it
    ld        $x0, 0($Xi)
    ld        $x1, 8($Xi)
    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}

    # Load the key (already bit-reversed)
    ld        $y0, 0($Htable)
    ld        $y1, 8($Htable)

    # Load the reduction constant
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)

    # Multiplication (without Karatsuba)
    @{[clmulh $z3, $x1, $y1]}
    @{[clmul  $z2, $x1, $y1]}
    @{[clmulh $t1, $x0, $y1]}
    @{[clmul  $z1, $x0, $y1]}
    xor       $z2, $z2, $t1
    @{[clmulh $t1, $x1, $y0]}
    @{[clmul  $t0, $x1, $y0]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $x0, $y0]}
    @{[clmul  $z0, $x0, $y0]}
    xor       $z1, $z1, $t1

    # Reduction with clmul
    @{[clmulh $t1, $z3, $polymod]}
    @{[clmul  $t0, $z3, $polymod]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $z2, $polymod]}
    @{[clmul  $t0, $z2, $polymod]}
    xor       $x1, $z1, $t1
    xor       $x0, $z0, $t0

    # Bit-reverse Xi back and store it
    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}
    sd        $x0, 0($Xi)
    sd        $x1, 8($Xi)
    ret
.size gcm_gmult_rv64i_zbc,.-gcm_gmult_rv64i_zbc
___
}

{
my ($Xi,$Htable,$x0,$x1,$y0,$y1) = ("a0","a1","a4","a5","a6","a7");
my ($z0,$z1,$z2,$z3,$t0,$t1,$polymod) = ("t0","t1","t2","t3","t4","t5","t6");

$code .= <<___;
.p2align 3
.globl gcm_gmult_rv64i_zbc__zbkb
.type gcm_gmult_rv64i_zbc__zbkb,\@function
gcm_gmult_rv64i_zbc__zbkb:
    # Load Xi and bit-reverse it
    ld        $x0, 0($Xi)
    ld        $x1, 8($Xi)
    @{[brev8  $x0, $x0]}
    @{[brev8  $x1, $x1]}

    # Load the key (already bit-reversed)
    ld        $y0, 0($Htable)
    ld        $y1, 8($Htable)

    # Load the reduction constant
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)

    # Multiplication (without Karatsuba)
    @{[clmulh $z3, $x1, $y1]}
    @{[clmul  $z2, $x1, $y1]}
    @{[clmulh $t1, $x0, $y1]}
    @{[clmul  $z1, $x0, $y1]}
    xor       $z2, $z2, $t1
    @{[clmulh $t1, $x1, $y0]}
    @{[clmul  $t0, $x1, $y0]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $x0, $y0]}
    @{[clmul  $z0, $x0, $y0]}
    xor       $z1, $z1, $t1

    # Reduction with clmul
    @{[clmulh $t1, $z3, $polymod]}
    @{[clmul  $t0, $z3, $polymod]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $z2, $polymod]}
    @{[clmul  $t0, $z2, $polymod]}
    xor       $x1, $z1, $t1
    xor       $x0, $z0, $t0

    # Bit-reverse Xi back and store it
    @{[brev8  $x0, $x0]}
    @{[brev8  $x1, $x1]}
    sd        $x0, 0($Xi)
    sd        $x1, 8($Xi)
    ret
.size gcm_gmult_rv64i_zbc__zbkb,.-gcm_gmult_rv64i_zbc__zbkb
___
}

################################################################################
# void gcm_ghash_rv64i_zbc(u64 Xi[2], const u128 Htable[16],
#                          const u8 *inp, size_t len);
# void gcm_ghash_rv64i_zbc__zbkb(u64 Xi[2], const u128 Htable[16],
#                                const u8 *inp, size_t len);
#
# input:  Xi: current hash value
#         Htable: copy of H
#         inp: pointer to input data
#         len: length of input data in bytes (multiple of block size)
# output: Xi: Xi+1 (next hash value Xi)
{
my ($Xi,$Htable,$inp,$len) = ("a0","a1","a2","a3");
my ($x0,$x1,$y0,$y1) = ("a4","a5","a6","a7");
my ($z0,$z1,$z2,$z3,$t0,$t1,$polymod) = ("t0","t1","t2","t3","t4","t5","t6");
# Additional regs for 2-block aggregation path
my ($sXi,$sH0,$sH1,$sH2_0,$sH2_1,$sP) = ("s0","s1","s2","s3","s4","s5");
# Additional regs for 4-block aggregation path
my ($sH3_0,$sH3_1,$sH4_0,$sH4_1) = ("s6","s7","s8","s9");

$code .= <<___;
.p2align 3
.globl gcm_ghash_rv64i_zbc
.type gcm_ghash_rv64i_zbc,\@function
gcm_ghash_rv64i_zbc:
    # Fast path: skip s-reg setup for small inputs (< 128 bytes)
    li      $z0, 128
    bge     $len, $z0, Lghash_2x_enter

    # --- Original single-block path (no s-reg overhead) ---
    ld        $x0, 0($Xi)
    ld        $x1, 8($Xi)
    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}
    ld        $y0, 0($Htable)
    ld        $y1, 8($Htable)
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)

Lghash_orig_loop:
    ld        $t0, 0($inp)
    ld        $t1, 8($inp)
    add       $inp, $inp, 16
    add       $len, $len, -16
    @{[brev8_rv64i $t0, $z0, $z1, $z2]}
    @{[brev8_rv64i $t1, $z0, $z1, $z2]}
    xor       $x0, $x0, $t0
    xor       $x1, $x1, $t1

    @{[clmulh $z3, $x1, $y1]}
    @{[clmul  $z2, $x1, $y1]}
    @{[clmulh $t1, $x0, $y1]}
    @{[clmul  $z1, $x0, $y1]}
    xor       $z2, $z2, $t1
    @{[clmulh $t1, $x1, $y0]}
    @{[clmul  $t0, $x1, $y0]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $x0, $y0]}
    @{[clmul  $z0, $x0, $y0]}
    xor       $z1, $z1, $t1

    @{[clmulh $t1, $z3, $polymod]}
    @{[clmul  $t0, $z3, $polymod]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $z2, $polymod]}
    @{[clmul  $t0, $z2, $polymod]}
    xor       $x1, $z1, $t1
    xor       $x0, $z0, $t0

    bnez      $len, Lghash_orig_loop

    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}
    sd        $x0, 0($Xi)
    sd        $x1, 8($Xi)
    ret

Lghash_2x_enter:
    # --- Multi-block aggregation path ---
    addi    sp, sp, -48
    sd      $sXi, 0(sp)
    sd      $sH0, 8(sp)
    sd      $sH1, 16(sp)
    sd      $sH2_0, 24(sp)
    sd      $sH2_1, 32(sp)
    sd      $sP, 40(sp)

    mv      $sXi, $Xi
    ld      $sH0, 0($Htable)
    ld      $sH1, 8($Htable)
    ld      $sH2_0, 16($Htable)
    ld      $sH2_1, 24($Htable)
    la      $sP, Lpolymod
    lbu     $sP, 0($sP)

    ld      $x0, 0($sXi)
    ld      $x1, 8($sXi)
    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}

    # Check if 4-block aggregation is possible (>= 64 bytes = 4 blocks)
    li      $z0, 64
    blt     $len, $z0, Lghash_2x

    # Save additional s6-s9, load H^3 and H^4
    addi    sp, sp, -32
    sd      $sH3_0, 0(sp)
    sd      $sH3_1, 8(sp)
    sd      $sH4_0, 16(sp)
    sd      $sH4_1, 24(sp)
    ld      $sH3_0, 32($Htable)
    ld      $sH3_1, 40($Htable)
    ld      $sH4_0, 48($Htable)
    ld      $sH4_1, 56($Htable)

Lghash_4x:
    # --- 4-block iteration: processes 64 bytes ---
    # Phase 1: A = (Xi^C1)*H^4, B = C2*H^3

    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    @{[brev8_rv64i $z3, $z0, $z1, $z2]}
    @{[brev8_rv64i $t0, $z0, $z1, $z2]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    ld      $y0, 16($inp)
    ld      $y1, 24($inp)
    @{[brev8_rv64i $y0, $z0, $z1, $z2]}
    @{[brev8_rv64i $y1, $z0, $z1, $z2]}

    # Interleaved multiply A = (x1:x0)*H^4, B = (y1:y0)*H^3
    @{[clmulh $z3, $x1, $sH4_1]}
    @{[clmulh $t1, $y1, $sH3_1]}
    @{[clmul  $z2, $x1, $sH4_1]}
    @{[clmul  $t0, $y1, $sH3_1]}
    xor     $z3, $z3, $t1
    xor     $z2, $z2, $t0

    @{[clmulh $t1, $x0, $sH4_1]}
    @{[clmulh $t0, $y0, $sH3_1]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $z1, $x0, $sH4_1]}
    @{[clmul  $t1, $y0, $sH3_1]}
    xor     $z1, $z1, $t1

    @{[clmulh $t1, $x1, $sH4_0]}
    @{[clmulh $t0, $y1, $sH3_0]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $t1, $x1, $sH4_0]}
    @{[clmul  $t0, $y1, $sH3_0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0

    @{[clmulh $t1, $x0, $sH4_0]}
    @{[clmulh $t0, $y0, $sH3_0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0
    @{[clmul  $z0, $x0, $sH4_0]}
    @{[clmul  $t1, $y0, $sH3_0]}
    xor     $z0, $z0, $t1

    # Phase 1 product in z3:z2:z1:z0 = t3:t2:t1:t0.
    # Load C3, C4 — use $t0/$t1/$polymod (t4/t5/t6) as brev8 temps
    # to avoid clobbering Phase 1 product in t0-t3.
    ld      $x0, 32($inp)
    ld      $x1, 40($inp)
    @{[brev8_rv64i $x0, $t0, $t1, $polymod]}
    @{[brev8_rv64i $x1, $t0, $t1, $polymod]}

    ld      $y0, 48($inp)
    ld      $y1, 56($inp)
    @{[brev8_rv64i $y0, $t0, $t1, $polymod]}
    @{[brev8_rv64i $y1, $t0, $t1, $polymod]}

    addi    $inp, $inp, 64
    addi    $len, $len, -64

    # Phase 2: C = C3*H^2, D = C4*H (single-temp interleave)
    # Product in w3:w2:w1:w0 = $t1:$t0:$Htable:$Xi
    # Scratch: $polymod (t6)

    @{[clmulh $t1, $x1, $sH2_1]}
    @{[clmulh $polymod, $y1, $sH1]}
    xor     $t1, $t1, $polymod
    @{[clmul  $t0, $x1, $sH2_1]}
    @{[clmul  $polymod, $y1, $sH1]}
    xor     $t0, $t0, $polymod

    @{[clmulh $polymod, $x0, $sH2_1]}
    xor     $t0, $t0, $polymod
    @{[clmulh $polymod, $y0, $sH1]}
    xor     $t0, $t0, $polymod
    @{[clmul  $Htable, $x0, $sH2_1]}
    @{[clmul  $polymod, $y0, $sH1]}
    xor     $Htable, $Htable, $polymod

    @{[clmulh $polymod, $x1, $sH2_0]}
    xor     $t0, $t0, $polymod
    @{[clmulh $polymod, $y1, $sH0]}
    xor     $t0, $t0, $polymod
    @{[clmul  $polymod, $x1, $sH2_0]}
    xor     $Htable, $Htable, $polymod
    @{[clmul  $polymod, $y1, $sH0]}
    xor     $Htable, $Htable, $polymod

    @{[clmulh $polymod, $x0, $sH2_0]}
    xor     $Htable, $Htable, $polymod
    @{[clmulh $polymod, $y0, $sH0]}
    xor     $Htable, $Htable, $polymod
    @{[clmul  $Xi, $x0, $sH2_0]}
    @{[clmul  $polymod, $y0, $sH0]}
    xor     $Xi, $Xi, $polymod

    # Combine Phase 1 + Phase 2 products
    xor     $z0, $z0, $Xi
    xor     $z1, $z1, $Htable
    xor     $z2, $z2, $t0
    xor     $z3, $z3, $t1

    # Single reduction for all 4 blocks
    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

    li      $z0, 64
    bge     $len, $z0, Lghash_4x

    # Restore s6-s9
    ld      $sH3_0, 0(sp)
    ld      $sH3_1, 8(sp)
    ld      $sH4_0, 16(sp)
    ld      $sH4_1, 24(sp)
    addi    sp, sp, 32

Lghash_2x:
    # Guard: skip 2-block loop if len < 32 (e.g. after 4-block consumed all data)
    li      $z0, 32
    blt     $len, $z0, Lghash_2x_tail_check

    # Load first input block, bit-reverse, XOR with Xi
    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    @{[brev8_rv64i $z3, $z0, $z1, $z2]}
    @{[brev8_rv64i $t0, $z0, $z1, $z2]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    # Load second input block, bit-reverse
    ld      $y0, 16($inp)
    ld      $y1, 24($inp)
    @{[brev8_rv64i $y0, $z0, $z1, $z2]}
    @{[brev8_rv64i $y1, $z0, $z1, $z2]}

    addi    $inp, $inp, 32
    addi    $len, $len, -32

    # Interleaved multiplication (A + B accumulated into z3:z2:z1:z0):
    #   A = (x1:x0) * (sH2_1:sH2_0) = (Xi^C1) * H^2
    #   B = (y1:y0) * (sH1:sH0)      = C2 * H

    # high * high
    @{[clmulh $z3, $x1, $sH2_1]}
    @{[clmulh $t1, $y1, $sH1]}
    @{[clmul  $z2, $x1, $sH2_1]}
    @{[clmul  $t0, $y1, $sH1]}
    xor     $z3, $z3, $t1
    xor     $z2, $z2, $t0

    # low * high
    @{[clmulh $t1, $x0, $sH2_1]}
    @{[clmulh $t0, $y0, $sH1]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $z1, $x0, $sH2_1]}
    @{[clmul  $t1, $y0, $sH1]}
    xor     $z1, $z1, $t1

    # high * low
    @{[clmulh $t1, $x1, $sH2_0]}
    @{[clmulh $t0, $y1, $sH0]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $t1, $x1, $sH2_0]}
    @{[clmul  $t0, $y1, $sH0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0

    # low * low
    @{[clmulh $t1, $x0, $sH2_0]}
    @{[clmulh $t0, $y0, $sH0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0
    @{[clmul  $z0, $x0, $sH2_0]}
    @{[clmul  $t1, $y0, $sH0]}
    xor     $z0, $z0, $t1

    # Reduction with clmul
    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

    li      $z0, 32
    bge     $len, $z0, Lghash_2x

    # Handle remaining single block (if any)
Lghash_2x_tail_check:
    beqz    $len, Lghash_2x_done

Lghash_1x_tail:
    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    addi    $inp, $inp, 16
    addi    $len, $len, -16
    @{[brev8_rv64i $z3, $z0, $z1, $z2]}
    @{[brev8_rv64i $t0, $z0, $z1, $z2]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    @{[clmulh $z3, $x1, $sH1]}
    @{[clmul  $z2, $x1, $sH1]}
    @{[clmulh $t1, $x0, $sH1]}
    @{[clmul  $z1, $x0, $sH1]}
    xor     $z2, $z2, $t1
    @{[clmulh $t1, $x1, $sH0]}
    @{[clmul  $t0, $x1, $sH0]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $x0, $sH0]}
    @{[clmul  $z0, $x0, $sH0]}
    xor     $z1, $z1, $t1

    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

Lghash_2x_done:
    @{[brev8_rv64i $x0, $z0, $z1, $z2]}
    @{[brev8_rv64i $x1, $z0, $z1, $z2]}
    sd      $x0, 0($sXi)
    sd      $x1, 8($sXi)

    ld      $sXi, 0(sp)
    ld      $sH0, 8(sp)
    ld      $sH1, 16(sp)
    ld      $sH2_0, 24(sp)
    ld      $sH2_1, 32(sp)
    ld      $sP, 40(sp)
    addi    sp, sp, 48
    ret
.size gcm_ghash_rv64i_zbc,.-gcm_ghash_rv64i_zbc
___
}

{
my ($Xi,$Htable,$inp,$len) = ("a0","a1","a2","a3");
my ($x0,$x1,$y0,$y1) = ("a4","a5","a6","a7");
my ($z0,$z1,$z2,$z3,$t0,$t1,$polymod) = ("t0","t1","t2","t3","t4","t5","t6");
my ($sXi,$sH0,$sH1,$sH2_0,$sH2_1,$sP) = ("s0","s1","s2","s3","s4","s5");
my ($sH3_0,$sH3_1,$sH4_0,$sH4_1) = ("s6","s7","s8","s9");

$code .= <<___;
.p2align 3
.globl gcm_ghash_rv64i_zbc__zbkb
.type gcm_ghash_rv64i_zbc__zbkb,\@function
gcm_ghash_rv64i_zbc__zbkb:
    # Fast path: skip s-reg setup for small inputs (< 128 bytes)
    li      $z0, 128
    bge     $len, $z0, Lghash_2x_enter_zbkb

    # --- Original single-block path (no s-reg overhead) ---
    ld        $x0, 0($Xi)
    ld        $x1, 8($Xi)
    @{[brev8  $x0, $x0]}
    @{[brev8  $x1, $x1]}
    ld        $y0, 0($Htable)
    ld        $y1, 8($Htable)
    la        $polymod, Lpolymod
    lbu       $polymod, 0($polymod)

Lghash_orig_loop_zbkb:
    ld        $t0, 0($inp)
    ld        $t1, 8($inp)
    add       $inp, $inp, 16
    add       $len, $len, -16
    @{[brev8  $t0, $t0]}
    @{[brev8  $t1, $t1]}
    xor       $x0, $x0, $t0
    xor       $x1, $x1, $t1

    @{[clmulh $z3, $x1, $y1]}
    @{[clmul  $z2, $x1, $y1]}
    @{[clmulh $t1, $x0, $y1]}
    @{[clmul  $z1, $x0, $y1]}
    xor       $z2, $z2, $t1
    @{[clmulh $t1, $x1, $y0]}
    @{[clmul  $t0, $x1, $y0]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $x0, $y0]}
    @{[clmul  $z0, $x0, $y0]}
    xor       $z1, $z1, $t1

    @{[clmulh $t1, $z3, $polymod]}
    @{[clmul  $t0, $z3, $polymod]}
    xor       $z2, $z2, $t1
    xor       $z1, $z1, $t0
    @{[clmulh $t1, $z2, $polymod]}
    @{[clmul  $t0, $z2, $polymod]}
    xor       $x1, $z1, $t1
    xor       $x0, $z0, $t0

    bnez      $len, Lghash_orig_loop_zbkb

    @{[brev8  $x0, $x0]}
    @{[brev8  $x1, $x1]}
    sd        $x0, 0($Xi)
    sd        $x1, 8($Xi)
    ret

Lghash_2x_enter_zbkb:
    # --- Multi-block aggregation path ---
    addi    sp, sp, -48
    sd      $sXi, 0(sp)
    sd      $sH0, 8(sp)
    sd      $sH1, 16(sp)
    sd      $sH2_0, 24(sp)
    sd      $sH2_1, 32(sp)
    sd      $sP, 40(sp)

    mv      $sXi, $Xi
    ld      $sH0, 0($Htable)
    ld      $sH1, 8($Htable)
    ld      $sH2_0, 16($Htable)
    ld      $sH2_1, 24($Htable)
    la      $sP, Lpolymod
    lbu     $sP, 0($sP)

    ld      $x0, 0($sXi)
    ld      $x1, 8($sXi)
    @{[brev8 $x0, $x0]}
    @{[brev8 $x1, $x1]}

    # Check if 4-block aggregation is possible (>= 64 bytes)
    li      $z0, 64
    blt     $len, $z0, Lghash_2x_zbkb

    # Save additional s6-s9, load H^3 and H^4
    addi    sp, sp, -32
    sd      $sH3_0, 0(sp)
    sd      $sH3_1, 8(sp)
    sd      $sH4_0, 16(sp)
    sd      $sH4_1, 24(sp)
    ld      $sH3_0, 32($Htable)
    ld      $sH3_1, 40($Htable)
    ld      $sH4_0, 48($Htable)
    ld      $sH4_1, 56($Htable)

Lghash_4x_zbkb:
    # --- 4-block iteration: processes 64 bytes ---
    # Phase 1: A = (Xi^C1)*H^4, B = C2*H^3

    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    @{[brev8 $z3, $z3]}
    @{[brev8 $t0, $t0]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    ld      $y0, 16($inp)
    ld      $y1, 24($inp)
    @{[brev8 $y0, $y0]}
    @{[brev8 $y1, $y1]}

    # Interleaved multiply A = (x1:x0)*H^4, B = (y1:y0)*H^3
    @{[clmulh $z3, $x1, $sH4_1]}
    @{[clmulh $t1, $y1, $sH3_1]}
    @{[clmul  $z2, $x1, $sH4_1]}
    @{[clmul  $t0, $y1, $sH3_1]}
    xor     $z3, $z3, $t1
    xor     $z2, $z2, $t0

    @{[clmulh $t1, $x0, $sH4_1]}
    @{[clmulh $t0, $y0, $sH3_1]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $z1, $x0, $sH4_1]}
    @{[clmul  $t1, $y0, $sH3_1]}
    xor     $z1, $z1, $t1

    @{[clmulh $t1, $x1, $sH4_0]}
    @{[clmulh $t0, $y1, $sH3_0]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $t1, $x1, $sH4_0]}
    @{[clmul  $t0, $y1, $sH3_0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0

    @{[clmulh $t1, $x0, $sH4_0]}
    @{[clmulh $t0, $y0, $sH3_0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0
    @{[clmul  $z0, $x0, $sH4_0]}
    @{[clmul  $t1, $y0, $sH3_0]}
    xor     $z0, $z0, $t1

    # Phase 1 product in z3:z2:z1:z0.
    # Load C3, C4 — zbkb brev8 is in-place, no temp conflict.
    ld      $x0, 32($inp)
    ld      $x1, 40($inp)
    @{[brev8 $x0, $x0]}
    @{[brev8 $x1, $x1]}

    ld      $y0, 48($inp)
    ld      $y1, 56($inp)
    @{[brev8 $y0, $y0]}
    @{[brev8 $y1, $y1]}

    addi    $inp, $inp, 64
    addi    $len, $len, -64

    # Phase 2: C = C3*H^2, D = C4*H (single-temp interleave)
    # Product in w3:w2:w1:w0 = $t1:$t0:$Htable:$Xi
    # Scratch: $polymod (t6)

    @{[clmulh $t1, $x1, $sH2_1]}
    @{[clmulh $polymod, $y1, $sH1]}
    xor     $t1, $t1, $polymod
    @{[clmul  $t0, $x1, $sH2_1]}
    @{[clmul  $polymod, $y1, $sH1]}
    xor     $t0, $t0, $polymod

    @{[clmulh $polymod, $x0, $sH2_1]}
    xor     $t0, $t0, $polymod
    @{[clmulh $polymod, $y0, $sH1]}
    xor     $t0, $t0, $polymod
    @{[clmul  $Htable, $x0, $sH2_1]}
    @{[clmul  $polymod, $y0, $sH1]}
    xor     $Htable, $Htable, $polymod

    @{[clmulh $polymod, $x1, $sH2_0]}
    xor     $t0, $t0, $polymod
    @{[clmulh $polymod, $y1, $sH0]}
    xor     $t0, $t0, $polymod
    @{[clmul  $polymod, $x1, $sH2_0]}
    xor     $Htable, $Htable, $polymod
    @{[clmul  $polymod, $y1, $sH0]}
    xor     $Htable, $Htable, $polymod

    @{[clmulh $polymod, $x0, $sH2_0]}
    xor     $Htable, $Htable, $polymod
    @{[clmulh $polymod, $y0, $sH0]}
    xor     $Htable, $Htable, $polymod
    @{[clmul  $Xi, $x0, $sH2_0]}
    @{[clmul  $polymod, $y0, $sH0]}
    xor     $Xi, $Xi, $polymod

    # Combine Phase 1 + Phase 2 products
    xor     $z0, $z0, $Xi
    xor     $z1, $z1, $Htable
    xor     $z2, $z2, $t0
    xor     $z3, $z3, $t1

    # Single reduction for all 4 blocks
    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

    li      $z0, 64
    bge     $len, $z0, Lghash_4x_zbkb

    # Restore s6-s9
    ld      $sH3_0, 0(sp)
    ld      $sH3_1, 8(sp)
    ld      $sH4_0, 16(sp)
    ld      $sH4_1, 24(sp)
    addi    sp, sp, 32

Lghash_2x_zbkb:
    # Guard: skip 2-block loop if len < 32
    li      $z0, 32
    blt     $len, $z0, Lghash_2x_tail_check_zbkb

    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    @{[brev8 $z3, $z3]}
    @{[brev8 $t0, $t0]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    ld      $y0, 16($inp)
    ld      $y1, 24($inp)
    @{[brev8 $y0, $y0]}
    @{[brev8 $y1, $y1]}

    addi    $inp, $inp, 32
    addi    $len, $len, -32

    @{[clmulh $z3, $x1, $sH2_1]}
    @{[clmulh $t1, $y1, $sH1]}
    @{[clmul  $z2, $x1, $sH2_1]}
    @{[clmul  $t0, $y1, $sH1]}
    xor     $z3, $z3, $t1
    xor     $z2, $z2, $t0

    @{[clmulh $t1, $x0, $sH2_1]}
    @{[clmulh $t0, $y0, $sH1]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $z1, $x0, $sH2_1]}
    @{[clmul  $t1, $y0, $sH1]}
    xor     $z1, $z1, $t1

    @{[clmulh $t1, $x1, $sH2_0]}
    @{[clmulh $t0, $y1, $sH0]}
    xor     $z2, $z2, $t1
    xor     $z2, $z2, $t0
    @{[clmul  $t1, $x1, $sH2_0]}
    @{[clmul  $t0, $y1, $sH0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0

    @{[clmulh $t1, $x0, $sH2_0]}
    @{[clmulh $t0, $y0, $sH0]}
    xor     $z1, $z1, $t1
    xor     $z1, $z1, $t0
    @{[clmul  $z0, $x0, $sH2_0]}
    @{[clmul  $t1, $y0, $sH0]}
    xor     $z0, $z0, $t1

    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

    li      $z0, 32
    bge     $len, $z0, Lghash_2x_zbkb

Lghash_2x_tail_check_zbkb:
    beqz    $len, Lghash_2x_done_zbkb

    ld      $z3, 0($inp)
    ld      $t0, 8($inp)
    addi    $inp, $inp, 16
    addi    $len, $len, -16
    @{[brev8 $z3, $z3]}
    @{[brev8 $t0, $t0]}
    xor     $x0, $x0, $z3
    xor     $x1, $x1, $t0

    @{[clmulh $z3, $x1, $sH1]}
    @{[clmul  $z2, $x1, $sH1]}
    @{[clmulh $t1, $x0, $sH1]}
    @{[clmul  $z1, $x0, $sH1]}
    xor     $z2, $z2, $t1
    @{[clmulh $t1, $x1, $sH0]}
    @{[clmul  $t0, $x1, $sH0]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $x0, $sH0]}
    @{[clmul  $z0, $x0, $sH0]}
    xor     $z1, $z1, $t1

    @{[clmulh $t1, $z3, $sP]}
    @{[clmul  $t0, $z3, $sP]}
    xor     $z2, $z2, $t1
    xor     $z1, $z1, $t0
    @{[clmulh $t1, $z2, $sP]}
    @{[clmul  $t0, $z2, $sP]}
    xor     $x1, $z1, $t1
    xor     $x0, $z0, $t0

Lghash_2x_done_zbkb:
    @{[brev8 $x0, $x0]}
    @{[brev8 $x1, $x1]}
    sd      $x0, 0($sXi)
    sd      $x1, 8($sXi)

    ld      $sXi, 0(sp)
    ld      $sH0, 8(sp)
    ld      $sH1, 16(sp)
    ld      $sH2_0, 24(sp)
    ld      $sH2_1, 32(sp)
    ld      $sP, 40(sp)
    addi    sp, sp, 48
    ret
.size gcm_ghash_rv64i_zbc__zbkb,.-gcm_ghash_rv64i_zbc__zbkb
___
}

$code .= <<___;
.p2align 3
Lbrev8_const:
    .dword  0xAAAAAAAAAAAAAAAA
    .dword  0xCCCCCCCCCCCCCCCC
    .dword  0xF0F0F0F0F0F0F0F0
.size Lbrev8_const,.-Lbrev8_const

Lpolymod:
    .byte 0x87
.size Lpolymod,.-Lpolymod
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
