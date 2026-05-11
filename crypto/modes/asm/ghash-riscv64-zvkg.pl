#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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

# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector GCM/GMAC extension ('Zvkg')
#
# Optional:
# - RISC-V Vector Cryptography Bit-manipulation extension ('Zvkb')

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

my ($V0, $V1, $V2, $V3, $V4, $V5, $V6, $V7,
    $V8, $V9, $V10, $V11, $V12, $V13, $V14, $V15,
    $V16, $V17, $V18, $V19, $V20, $V21, $V22, $V23,
    $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map("v$_",(0..31));

################################################################################
# void gcm_init_rv64i_zvkg(u128 Htable[16], const u64 H[2]);
# void gcm_init_rv64i_zvkg_zvkb(u128 Htable[16], const u64 H[2]);
#
# input: H: 128-bit H - secret parameter E(K, 0^128)
# output: Htable: Copy of secret parameter (in normalized byte order)
#
# All callers of this function revert the byte-order unconditionally
# on little-endian machines. So we need to revert the byte-order back.
{
my ($Htable,$H,$VAL0,$VAL1,$TMP0) = ("a0","a1","a2","a3","t0");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zvkg
.type gcm_init_rv64i_zvkg,\@function
gcm_init_rv64i_zvkg:
    # Store byte-reversed H at Htable[0]
    ld     $VAL0, 0($H)
    ld     $VAL1, 8($H)
    @{[sd_rev8_rv64i $VAL0, $Htable, 0, $TMP0]}
    @{[sd_rev8_rv64i $VAL1, $Htable, 8, $TMP0]}

    # Precompute H^2, H^3, H^4 for multi-block aggregation
    @{[vsetivli__x0_4_e32_m1_tu_mu]}
    @{[vle32_v $V1, $Htable]}         # v1 = H
    @{[vmv_v_v $V2, $V1]}
    @{[vgmul_vv $V2, $V1]}           # v2 = H * H = H^2
    addi $TMP0, $Htable, 16
    @{[vse32_v $V2, $TMP0]}           # Htable[16] = H^2
    @{[vmv_v_v $V3, $V2]}
    @{[vgmul_vv $V3, $V1]}           # v3 = H^2 * H = H^3
    addi $TMP0, $TMP0, 16
    @{[vse32_v $V3, $TMP0]}           # Htable[32] = H^3
    @{[vmv_v_v $V4, $V2]}
    @{[vgmul_vv $V4, $V2]}           # v4 = H^2 * H^2 = H^4
    addi $TMP0, $TMP0, 16
    @{[vse32_v $V4, $TMP0]}           # Htable[48] = H^4
    ret
.size gcm_init_rv64i_zvkg,.-gcm_init_rv64i_zvkg
___
}

{
my ($Htable,$H) = ("a0","a1");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zvkg_zvkb
.type gcm_init_rv64i_zvkg_zvkb,\@function
gcm_init_rv64i_zvkg_zvkb:
    # Store byte-reversed H at Htable[0]
    @{[vsetivli__x0_2_e64_m1_tu_mu]}
    @{[vle64_v $V0, $H]}
    @{[vrev8_v $V0, $V0]}
    @{[vse64_v $V0, $Htable]}

    # Precompute H^2, H^3, H^4 for multi-block aggregation
    @{[vsetivli__x0_4_e32_m1_tu_mu]}
    # v0 already holds H (same bits, reinterpreted as 4×e32)
    @{[vmv_v_v $V1, $V0]}
    @{[vgmul_vv $V1, $V0]}           # v1 = H^2
    addi t0, $Htable, 16
    @{[vse32_v $V1, "t0"]}           # Htable[16] = H^2
    @{[vmv_v_v $V2, $V1]}
    @{[vgmul_vv $V2, $V0]}           # v2 = H^2 * H = H^3
    addi t0, t0, 16
    @{[vse32_v $V2, "t0"]}           # Htable[32] = H^3
    @{[vmv_v_v $V3, $V1]}
    @{[vgmul_vv $V3, $V1]}          # v3 = H^2 * H^2 = H^4
    addi t0, t0, 16
    @{[vse32_v $V3, "t0"]}           # Htable[48] = H^4
    ret
.size gcm_init_rv64i_zvkg_zvkb,.-gcm_init_rv64i_zvkg_zvkb
___
}

################################################################################
# void gcm_gmult_rv64i_zvkg(u64 Xi[2], const u128 Htable[16]);
#
# input: Xi: current hash value
#       Htable: copy of H
# output: Xi: next hash value Xi
{
my ($Xi,$Htable) = ("a0","a1");
my ($VD,$VS2) = ("v1","v2");

$code .= <<___;
.p2align 3
.globl gcm_gmult_rv64i_zvkg
.type gcm_gmult_rv64i_zvkg,\@function
gcm_gmult_rv64i_zvkg:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}
    @{[vle32_v $VS2, $Htable]}
    @{[vle32_v $VD, $Xi]}
    @{[vgmul_vv $VD, $VS2]}
    @{[vse32_v $VD, $Xi]}
    ret
.size gcm_gmult_rv64i_zvkg,.-gcm_gmult_rv64i_zvkg
___
}

################################################################################
# void gcm_ghash_rv64i_zvkg(u64 Xi[2], const u128 Htable[16],
#                      const u8 *inp, size_t len);
#
# input: Xi: current hash value
#       Htable: copy of H, H^2, H^3, H^4
#       inp: pointer to input data
#       len: length of input data in bytes (multiple of block size)
# output: Xi: Xi+1 (next hash value Xi)
#
# Uses 4-block aggregation when len >= 64:
#   4 independent accumulators (v20-v23), each using vghsh.vv with m1.
#   Main loop: all 4 lanes multiply by H^4.
#   Last 4-block set: lanes multiply by [H^4, H^3, H^2, H].
#   Result = XOR of all 4 lanes.
#   Tail: single-block loop for remaining 1-3 blocks.
#   This approach is VLEN-independent (always uses m1 with vl=4).
{
my ($Xi,$Htable,$inp,$len) = ("a0","a1","a2","a3");
my ($vXi,$vH,$vinp) = ("v1","v2","v3");

$code .= <<___;
.p2align 3
.globl gcm_ghash_rv64i_zvkg
.type gcm_ghash_rv64i_zvkg,\@function
gcm_ghash_rv64i_zvkg:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}
    @{[vle32_v $vH, $Htable]}          # v2 = H
    @{[vle32_v $vXi, $Xi]}            # v1 = Xi

    # Check for 4-block path (need at least 64 bytes)
    li     t0, 64
    blt    $len, t0, .Lstep_zvkg

    # --- 4-block aggregation path ---
    # Load H powers: H^4, H^3, H^2 (H already in v2)
    addi    t0, $Htable, 48
    @{[vle32_v $V5, "t0"]}            # v5 = H^4
    addi    t0, $Htable, 32
    @{[vle32_v $V6, "t0"]}            # v6 = H^3
    addi    t0, $Htable, 16
    @{[vle32_v $V7, "t0"]}            # v7 = H^2

    # Initialize 4 accumulator lanes: v20=Xi, v21=v22=v23=0
    @{[vmv_v_v $V20, $vXi]}
    @{[vmv_v_i $V21, 0]}
    @{[vmv_v_i $V22, 0]}
    @{[vmv_v_i $V23, 0]}

    # Need >= 128 bytes for main loop (at least 2 sets of 4 blocks)
    li     t0, 128
    blt    $len, t0, .Llast_4x_zvkg

.Lghash_4x_zvkg:
    # Load 4 blocks
    @{[vle32_v $V8, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V9, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V10, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V11, $inp]}
    addi    $inp, $inp, 16
    add     $len, $len, -64
    # 4 independent GHASH operations with H^4
    @{[vghsh_vv $V20, $V5, $V8]}
    @{[vghsh_vv $V21, $V5, $V9]}
    @{[vghsh_vv $V22, $V5, $V10]}
    @{[vghsh_vv $V23, $V5, $V11]}
    li     t0, 128
    bge    $len, t0, .Lghash_4x_zvkg

.Llast_4x_zvkg:
    # Process last 4-block set with [H^4, H^3, H^2, H]
    @{[vle32_v $V8, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V9, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V10, $inp]}
    addi    $inp, $inp, 16
    @{[vle32_v $V11, $inp]}
    addi    $inp, $inp, 16
    add     $len, $len, -64
    @{[vghsh_vv $V20, $V5, $V8]}     # lane 0 x H^4
    @{[vghsh_vv $V21, $V6, $V9]}     # lane 1 x H^3
    @{[vghsh_vv $V22, $V7, $V10]}    # lane 2 x H^2
    @{[vghsh_vv $V23, $vH, $V11]}    # lane 3 x H

    # Combine 4 lanes: result = S0 ^ S1 ^ S2 ^ S3
    @{[vxor_vv $V20, $V20, $V21]}
    @{[vxor_vv $V20, $V20, $V22]}
    @{[vxor_vv $V20, $V20, $V23]}

    @{[vmv_v_v $vXi, $V20]}          # v1 = combined result
    beqz    $len, .Ldone_zvkg

.Lstep_zvkg:
    # Single-block loop for remaining 1-3 blocks
    @{[vle32_v $vinp, $inp]}
    add    $inp, $inp, 16
    add    $len, $len, -16
    @{[vghsh_vv $vXi, $vH, $vinp]}
    bnez    $len, .Lstep_zvkg

.Ldone_zvkg:
    @{[vse32_v $vXi, $Xi]}
    ret

.size gcm_ghash_rv64i_zvkg,.-gcm_ghash_rv64i_zvkg
___
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
