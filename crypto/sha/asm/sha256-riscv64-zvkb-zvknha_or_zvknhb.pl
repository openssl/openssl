#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Christoph Müllner <christoph.muellner@vrull.eu>
# Copyright (c) 2023, Phoebe Chen <phoebe.chen@sifive.com>
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

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector Cryptography Bit-manipulation extension ('Zvkb')
# - RISC-V Vector SHA-2 Secure Hash extension ('Zvknha' or 'Zvknhb')

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

my $K256 = "K256";

# Function arguments
my ($H, $INP, $LEN, $KT, $H2, $INDEX_PATTERN) = ("a0", "a1", "a2", "a3", "t3", "t4");

sub sha_256_load_constant {
    my $code=<<___;
    la $KT, $K256 # Load round constants K256
    @{[vle32_v $V10, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V11, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V12, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V13, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V14, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V16, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V17, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V18, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V19, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V20, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V21, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V22, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V23, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V24, $KT]}
    addi $KT, $KT, 16
    @{[vle32_v $V25, $KT]}
___

    return $code;
}

################################################################################
# void sha256_block_data_order_zvkb_zvknha_or_zvknhb(void *c, const void *p, size_t len)
$code .= <<___;
.p2align 2
.globl sha256_block_data_order_zvkb_zvknha_or_zvknhb
.type   sha256_block_data_order_zvkb_zvknha_or_zvknhb,\@function
sha256_block_data_order_zvkb_zvknha_or_zvknhb:
    @{[vsetivli "zero", 4, "e32", "mf2", "ta", "ma"]}

    @{[sha_256_load_constant]}

    # H is stored as {a,b,c,d},{e,f,g,h}, but we need {f,e,b,a},{h,g,d,c}
    # The dst vtype is e32m1 and the index vtype is e8mf4.
    # We use index-load with the following index pattern at v26.
    #   i8 index:
    #     20, 16, 4, 0
    # Instead of setting the i8 index, we could use a single 32bit
    # little-endian value to cover the 4xi8 index.
    #   i32 value:
    #     0x 00 04 10 14
    li $INDEX_PATTERN, 0x00041014
    @{[vsetivli "zero", 1, "e32", "mf2", "ta", "ma"]}
    @{[vmv_v_x $V26, $INDEX_PATTERN]}

    addi $H2, $H, 8

    # Use index-load to get {f,e,b,a},{h,g,d,c}
    @{[vsetivli "zero", 4, "e32", "mf2", "ta", "ma"]}
    @{[vluxei8_v $V6, $H, $V26]}
    @{[vluxei8_v $V7, $H2, $V26]}

    # Setup v0 mask for the vmerge to replace the first word (idx==0) in key-scheduling.
    # The AVL is 4 in SHA, so we could use a single e8(8 element masking) for masking.
    @{[vsetivli "zero", 1, "e8", "mf2", "ta", "ma"]}
    @{[vmv_v_i $V0, 0x01]}

    @{[vsetivli "zero", 4, "e32", "mf2", "ta", "ma"]}

    # ===== Prologue: load first block, byte-swap, pre-compute =====
    add $LEN, $LEN, -1

    # Load the 512-bit message block in v1-v4, endian swap each word.
    @{[vle32_v $V1, $INP]}
    addi $INP, $INP, 16
    @{[vle32_v $V2, $INP]}
    addi $INP, $INP, 16
    @{[vle32_v $V3, $INP]}
    addi $INP, $INP, 16
    @{[vle32_v $V4, $INP]}
    addi $INP, $INP, 16
    @{[vrev8_v $V1, $V1]}
    @{[vrev8_v $V2, $V2]}
    @{[vrev8_v $V3, $V3]}
    @{[vrev8_v $V4, $V4]}

    # Pre-compute round keys for rounds 0 and 1
    @{[vadd_vv $V5, $V10, $V1]}
    @{[vadd_vv $V8, $V11, $V2]}

    # Single block? Go directly to epilogue.
    beqz $LEN, .L_sha256_epilogue

    # ===== Steady-state loop: process current block + load next =====
.L_sha256_loop:
    add $LEN, $LEN, -1

    # Save V7 BEFORE vsha2cl destroys it
    @{[vmv_v_v $V31, $V7]}

    # Quad-round 0 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmv_v_v $V30, $V6]}               # Save V6 (intact after vsha2cl)
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vadd_vv $V9, $V12, $V3]}          # Pre-compute round 2
    @{[vsha2ms_vv $V1, $V29, $V4]}       # W[19:16]

    # Quad-round 1 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V13, $V4]}         # Pre-compute round 3
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}       # W[23:20]

    # Quad-round 2 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V14, $V1]}          # Pre-compute round 4
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}       # W[27:24]

    # Quad-round 3 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V15, $V2]}          # Pre-compute round 5
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}       # W[31:28]

    # Quad-round 4 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vadd_vv $V9, $V16, $V3]}          # Pre-compute round 6
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vsha2ms_vv $V1, $V29, $V4]}       # W[35:32]

    # Quad-round 5 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V17, $V4]}         # Pre-compute round 7
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}       # W[39:36]

    # Quad-round 6 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V18, $V1]}          # Pre-compute round 8
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}       # W[43:40]

    # Quad-round 7 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V19, $V2]}          # Pre-compute round 9
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}       # W[47:44]

    # Quad-round 8 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vadd_vv $V9, $V20, $V3]}          # Pre-compute round 10
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vsha2ms_vv $V1, $V29, $V4]}       # W[51:48]

    # Quad-round 9 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V21, $V4]}         # Pre-compute round 11
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}       # W[55:52]

    # Quad-round 10 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V22, $V1]}          # Pre-compute round 12
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}       # W[59:56]

    # Quad-round 11 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V23, $V2]}          # Pre-compute round 13
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}       # W[63:60]

    # Quad-round 12 (+0) — interleave next-block load
    @{[vadd_vv $V9, $V24, $V3]}          # Pre-compute round 14
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vle32_v $V1, $INP]}               # Next block word 0
    addi $INP, $INP, 16
    @{[vsha2ch_vv $V6, $V7, $V5]}

    # Quad-round 13 (+1) — interleave next-block load
    @{[vadd_vv $V28, $V25, $V4]}         # Pre-compute round 15
    @{[vrev8_v $V1, $V1]}                # Byte-swap word 0
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vle32_v $V2, $INP]}               # Next block word 1
    addi $INP, $INP, 16
    @{[vsha2ch_vv $V6, $V7, $V8]}

    # Quad-round 14 (+2) — interleave next-block load + pre-compute
    @{[vrev8_v $V2, $V2]}                # Byte-swap word 1
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vle32_v $V3, $INP]}               # Next block word 2
    addi $INP, $INP, 16
    @{[vadd_vv $V5, $V10, $V1]}          # Pre-compute NEXT block round 0
    @{[vsha2ch_vv $V6, $V7, $V9]}

    # Quad-round 15 (+3) — interleave next-block load + pre-compute
    @{[vrev8_v $V3, $V3]}                # Byte-swap word 2
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vle32_v $V4, $INP]}               # Next block word 3
    addi $INP, $INP, 16
    @{[vadd_vv $V8, $V11, $V2]}          # Pre-compute NEXT block round 1
    @{[vsha2ch_vv $V6, $V7, $V28]}

    # H' = H + compress(H, M)
    @{[vrev8_v $V4, $V4]}                # Byte-swap word 3
    @{[vadd_vv $V6, $V30, $V6]}
    @{[vadd_vv $V7, $V31, $V7]}
    bnez $LEN, .L_sha256_loop

    # ===== Epilogue: process last block (no next-block loading) =====
.L_sha256_epilogue:
    # Save hash state for final accumulation
    @{[vmv_v_v $V30, $V6]}
    @{[vmv_v_v $V31, $V7]}

    # Quad-round 0 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vadd_vv $V9, $V12, $V3]}
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vsha2ms_vv $V1, $V29, $V4]}

    # Quad-round 1 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V13, $V4]}
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}

    # Quad-round 2 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V14, $V1]}
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}

    # Quad-round 3 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V15, $V2]}
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}

    # Quad-round 4 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vadd_vv $V9, $V16, $V3]}
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vsha2ms_vv $V1, $V29, $V4]}

    # Quad-round 5 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V17, $V4]}
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}

    # Quad-round 6 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V18, $V1]}
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}

    # Quad-round 7 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V19, $V2]}
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}

    # Quad-round 8 (+0, v1->v2->v3->v4)
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vmerge_vvm $V29, $V3, $V2, $V0]}
    @{[vadd_vv $V9, $V20, $V3]}
    @{[vsha2ch_vv $V6, $V7, $V5]}
    @{[vsha2ms_vv $V1, $V29, $V4]}

    # Quad-round 9 (+1, v2->v3->v4->v1)
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vmerge_vvm $V29, $V4, $V3, $V0]}
    @{[vadd_vv $V28, $V21, $V4]}
    @{[vsha2ch_vv $V6, $V7, $V8]}
    @{[vsha2ms_vv $V2, $V29, $V1]}

    # Quad-round 10 (+2, v3->v4->v1->v2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vmerge_vvm $V29, $V1, $V4, $V0]}
    @{[vadd_vv $V5, $V22, $V1]}
    @{[vsha2ch_vv $V6, $V7, $V9]}
    @{[vsha2ms_vv $V3, $V29, $V2]}

    # Quad-round 11 (+3, v4->v1->v2->v3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vmerge_vvm $V29, $V2, $V1, $V0]}
    @{[vadd_vv $V8, $V23, $V2]}
    @{[vsha2ch_vv $V6, $V7, $V28]}
    @{[vsha2ms_vv $V4, $V29, $V3]}

    # Quad-round 12 (+0) — no message schedule, pre-compute round 14
    @{[vadd_vv $V9, $V24, $V3]}
    @{[vsha2cl_vv $V7, $V6, $V5]}
    @{[vsha2ch_vv $V6, $V7, $V5]}

    # Quad-round 13 (+1) — pre-compute round 15
    @{[vadd_vv $V28, $V25, $V4]}
    @{[vsha2cl_vv $V7, $V6, $V8]}
    @{[vsha2ch_vv $V6, $V7, $V8]}

    # Quad-round 14 (+2)
    @{[vsha2cl_vv $V7, $V6, $V9]}
    @{[vsha2ch_vv $V6, $V7, $V9]}

    # Quad-round 15 (+3)
    @{[vsha2cl_vv $V7, $V6, $V28]}
    @{[vsha2ch_vv $V6, $V7, $V28]}

    # H' = H + compress(H, M)
    @{[vadd_vv $V6, $V30, $V6]}
    @{[vadd_vv $V7, $V31, $V7]}

    # Store {f,e,b,a},{h,g,d,c} back to {a,b,c,d},{e,f,g,h}.
    @{[vsuxei8_v $V6, $H, $V26]}
    @{[vsuxei8_v $V7, $H2, $V26]}

    ret
.size sha256_block_data_order_zvkb_zvknha_or_zvknhb,.-sha256_block_data_order_zvkb_zvknha_or_zvknhb

.p2align 2
.type $K256,\@object
$K256:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
.size $K256,.-$K256
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
