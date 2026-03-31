#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Jerry Shih <jerry.shih@sifive.com>
# All rights reserved.
#
#This module implements hardware instruction acceleration
#for SM4-XTS encryption and decryption calculations.
#author is <xxcui@linux.alibaba.com>
#author is <zhou.lu1@zte.com.cn>
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
# - RISC-V Vector Bit-manipulation extension ('Zvbb')
# - RISC-V Vector GCM/GMAC extension ('Zvkg')
# - RISC-V Vector SM4 block cipher extension ('Zvksed')
# - RISC-V Zicclsm(Main memory supports misaligned loads/stores)

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

{
################################################################################
# void rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt(const unsigned char *in,
#                                             unsigned char *out, size_t length,
#                                             const SM4_KEY *key1,
#                                             const SM4_KEY *key2,
#                                             const unsigned char iv[16],
#                                             const int enc)
my ($INPUT, $OUTPUT, $LENGTH, $KEY1, $KEY2, $IV) = ("a0", "a1", "a2", "a3", "a4", "a5");
my ($TAIL_LENGTH) = ("a6");
my ($VL) = ("a7");
my ($T0, $T1, $T2) = ("t0", "t1", "t2");
my ($STORE_LEN32) = ("t3");
my ($LEN32) = ("t4");
my ($V0, $V1, $V2, $V3, $V4, $V5, $V6, $V7,
    $V8, $V9, $V10, $V11, $V12, $V13, $V14, $V15,
    $V16, $V17, $V18, $V19, $V20, $V21, $V22, $V23,
    $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map("v$_",(0..31));

sub compute_xts_iv0 {
    my $code=<<___;
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    la $T0, ORDERH
    @{[vle32_v $V8, $T0]}
    @{[vle32_v $V28, $IV]}
    @{[vle32_v $V0, $KEY2]} # rk[0:3]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V1, $KEY2]} # rk[4:7]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V2, $KEY2]} # rk[8:11]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V3, $KEY2]} # rk[12:15]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V4, $KEY2]} # rk[16:19]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V5, $KEY2]} # rk[20:23]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V6, $KEY2]} # rk[24:27]
    addi $KEY2, $KEY2, 16
    @{[vle32_v $V7, $KEY2]} # rk[28:31]
    @{[vrev8_v $V12, $V28]}
    @{[vsm4r_vs $V12, $V0]}
    @{[vsm4r_vs $V12, $V1]}
    @{[vsm4r_vs $V12, $V2]}
    @{[vsm4r_vs $V12, $V3]}
    @{[vsm4r_vs $V12, $V4]}
    @{[vsm4r_vs $V12, $V5]}
    @{[vsm4r_vs $V12, $V6]}
    @{[vsm4r_vs $V12, $V7]}
    @{[vrev8_v $V12, $V12]}
    @{[vrgatherei16_vv $V28, $V12, $V8]}
___

    return $code;
}

# prepare input data(v24), iv(v28), bit-reversed-iv(v16), bit-reversed-iv-multiplier(v20)
sub init_first_round {
    my $code=<<___;
    # load input
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vle32_v $V24, $INPUT]}

    li $T0, 5
    # We could simplify the initialization steps if we have `block<=1`.
    blt $LEN32, $T0, 1f

    # Note: We use `vgmul` for GF(2^128) multiplication. The `vgmul` uses
    # different order of coefficients. We should use`vbrev8` to reverse the
    # data when we use `vgmul`.
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vbrev8_v $V0, $V28]}
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vmv_v_i $V16, 0]}
    # v16: [r-IV0, r-IV0, ...]
    @{[vid_v $V20]}                     # v20 = 0,1,2,3,4,5,...
    @{[vand_vi  $V20, $V20, 3]}         # v20 = 0,1,2,3,0,1,2,3,...
    @{[vrgather_vv $V16, $V0, $V20]}    # v16[i] = v0[v20[i]]
    # Prepare GF(2^128) multiplier [1, x, x^2, x^3, ...] in v8.
    slli $T0, $LEN32, 2
    @{[vsetvli "zero", $T0, "e32", "m1", "ta", "ma"]}
    # v2: [`1`, `1`, `1`, `1`, ...]
    @{[vmv_v_i $V2, 1]}
    # v3: [`0`, `1`, `2`, `3`, ...]
    @{[vid_v $V3]}
    @{[vsetvli "zero", $T0, "e64", "m2", "ta", "ma"]}
    # v4: [`1`, 0, `1`, 0, `1`, 0, `1`, 0, ...]
    @{[vzext_vf2 $V4, $V2]}
    # v6: [`0`, 0, `1`, 0, `2`, 0, `3`, 0, ...]
    @{[vzext_vf2 $V6, $V3]}
    slli $T0, $LEN32, 1
    @{[vsetvli "zero", $T0, "e32", "m2", "ta", "ma"]}
    # v8: [1<<0=1, 0, 0, 0, 1<<1=x, 0, 0, 0, 1<<2=x^2, 0, 0, 0, ...]
    @{[vwsll_vv $V8, $V4, $V6]}

    # Compute [r-IV0*1, r-IV0*x, r-IV0*x^2, r-IV0*x^3, ...] in v16
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vbrev8_v $V8, $V8]}
    @{[vgmul_vv $V16, $V8]}

    # Compute [IV0*1, IV0*x, IV0*x^2, IV0*x^3, ...] in v28.
    # Reverse the bits order back.
    @{[vbrev8_v $V28, $V16]}

    # Prepare the x^n multiplier in v20. The `n` is the sm4-xts block number
    # in a LMUL=4 register group.
    #   n = ((VLEN*LMUL)/(32*4)) = ((VLEN*4)/(32*4))
    #     = (VLEN/32)
    # We could use vsetvli with `e32, m1` to compute the `n` number.
    @{[vsetvli $T0, "zero", "e32", "m1", "ta", "ma"]}
    li $T1, 1
    sll $T0, $T1, $T0
    @{[vsetivli "zero", 2, "e64", "m1", "ta", "ma"]}
    @{[vmv_v_i $V0, 0]}
    @{[vsetivli "zero", 1, "e64", "m1", "tu", "ma"]}
    @{[vmv_v_x $V0, $T0]}
    @{[vsetivli "zero", 2, "e64", "m1", "ta", "ma"]}
    @{[vbrev8_v $V0, $V0]}
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vmv_v_i $V20, 0]}
    @{[vid_v $V12]}                     # v12 = 0,1,2,3,4,5,...
    @{[vand_vi  $V12, $V12, 3]}         # v12 = 0,1,2,3,0,1,2,3,...
    @{[vrgather_vv $V20, $V0, $V12]}    # v20[i] = v0[v12[i]]

    j 2f
1:
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vbrev8_v $V16, $V28]}
2:
___

    return $code;
}

# prepare xts enc last block's input(v24) and iv(v28)
sub handle_xts_enc_last_block {
    my $code=<<___;
    bnez $TAIL_LENGTH, 1f
    ret
1:
    # slidedown second to last block
    addi $VL, $VL, -4
    @{[vsetivli "zero", 4, "e32", "m4", "ta", "ma"]}
    # ciphertext
    @{[vslidedown_vx $V24, $V24, $VL]}
    # multiplier
    @{[vslidedown_vx $V16, $V16, $VL]}

    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_v $V25, $V24]}

    # load last block into v24
    # note: We should load the last block before store the second to last block
    #       for in-place operation.
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "tu", "ma"]}
    @{[vle8_v $V24, $INPUT]}

    # setup `x` multiplier with byte-reversed order
    # 0b00000010 => 0b01000000 (0x40)
    li $T0, 0x40
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_i $V28, 0]}
    @{[vsetivli "zero", 1, "e8", "m1", "tu", "ma"]}
    @{[vmv_v_x $V28, $T0]}

    # compute IV for last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V28]}
    @{[vbrev8_v $V28, $V16]}

    # store second to last block
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "ta", "ma"]}
    @{[vse8_v $V25, $OUTPUT]}
___

    return $code;
}

# prepare xts dec second to last block's input(v24) and iv(v29) and
# last block's and iv(v28)
sub handle_xts_dec_last_block {
    my $code=<<___;
    bnez $TAIL_LENGTH, 1f
    ret
1:
    # load second to last block's ciphertext
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vle32_v $V24, $INPUT]}
    addi $INPUT, $INPUT, 16

    # setup `x` multiplier with byte-reversed order
    # 0b00000010 => 0b01000000 (0x40)
    li $T0, 0x40
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_i $V20, 0]}
    @{[vsetivli "zero", 1, "e8", "m1", "tu", "ma"]}
    @{[vmv_v_x $V20, $T0]}

    beqz $LENGTH, 1f
    # slidedown third to last block
    addi $VL, $VL, -4
    @{[vsetivli "zero", 4, "e32", "m4", "ta", "ma"]}
    # multiplier
    @{[vslidedown_vx $V16, $V16, $VL]}

    # compute IV for last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V20]}
    @{[vbrev8_v $V28, $V16]}

    # compute IV for second to last block
    @{[vgmul_vv $V16, $V20]}
    @{[vbrev8_v $V29, $V16]}
    j 2f
1:
    # compute IV for second to last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V20]}
    @{[vbrev8_v $V29, $V16]}
2:
___

    return $code;
}

# Load all 11 round keys to v0-v7 registers.
sub sm4_load_key {
    my $code=<<___;
    csrr $T0, vlenb
    srli $T0, $T0, 1
    @{[vsetvli "zero", $T0, "e32", "m2", "ta", "mu"]}
    la $T0, ORDERH
    @{[vle32_v $V8, $T0]}
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vle32_v $V0, $KEY1]} # rk[0:3]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V1, $KEY1]} # rk[4:7]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V2, $KEY1]} # rk[8:11]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V3, $KEY1]} # rk[12:15]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V4, $KEY1]} # rk[16:19]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V5, $KEY1]} # rk[20:23]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V6, $KEY1]} # rk[24:27]
    addi $KEY1, $KEY1, 16
    @{[vle32_v $V7, $KEY1]} # rk[28:31]
___

    return $code;
}

# sm4 enc with round keys v1-v11
sub sm4_enc {
    my $code=<<___;
    @{[vrev8_v $V12, $V24]}
    @{[vsm4r_vs $V12, $V0]}
    @{[vsm4r_vs $V12, $V1]}
    @{[vsm4r_vs $V12, $V2]}
    @{[vsm4r_vs $V12, $V3]}
    @{[vsm4r_vs $V12, $V4]}
    @{[vsm4r_vs $V12, $V5]}
    @{[vsm4r_vs $V12, $V6]}
    @{[vsm4r_vs $V12, $V7]}
    @{[vrev8_v $V12, $V12]}
    @{[vrgatherei16_vv $V24, $V12, $V8]}
___

    return $code;
}

# sm4 dec with round keys v1-v11
sub sm4_dec {
    my $code=<<___;
    @{[vrev8_v $V12, $V24]}
    @{[vsm4r_vs $V12, $V0]}
    @{[vsm4r_vs $V12, $V1]}
    @{[vsm4r_vs $V12, $V2]}
    @{[vsm4r_vs $V12, $V3]}
    @{[vsm4r_vs $V12, $V4]}
    @{[vsm4r_vs $V12, $V5]}
    @{[vsm4r_vs $V12, $V6]}
    @{[vsm4r_vs $V12, $V7]}
    @{[vrev8_v $V12, $V12]}
    @{[vrgatherei16_vv $V24, $V12, $V8]}
___

    return $code;
}

$code .= <<___;
.p2align 3
.globl rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt
.type rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt,\@function
rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt:
    @{[compute_xts_iv0]}

    # sm4 block size is 16
    andi $TAIL_LENGTH, $LENGTH, 15
    mv $STORE_LEN32, $LENGTH
    beqz $TAIL_LENGTH, 1f
    sub $LENGTH, $LENGTH, $TAIL_LENGTH
    addi $STORE_LEN32, $LENGTH, -16
1:
    # We make the `LENGTH` become e32 length here.
    srli $LEN32, $LENGTH, 2
    srli $STORE_LEN32, $STORE_LEN32, 2

    j sm4_xts_enc_128
.size rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt,.-rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt
___

$code .= <<___;
.p2align 3
sm4_xts_enc_128:
    @{[init_first_round]}
    @{[sm4_load_key]}
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    j 1f

.Lenc_blocks_128:
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    # load plaintext into v24
    @{[vle32_v $V24, $INPUT]}
    # update iv
    @{[vgmul_vv $V16, $V20]}
    # reverse the iv's bits order back
    @{[vbrev8_v $V28, $V16]}
1:
    @{[vxor_vv $V24, $V24, $V28]}
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL
    add $INPUT, $INPUT, $T0
    @{[sm4_enc]}
    @{[vxor_vv $V24, $V24, $V28]}

    # store ciphertext
    @{[vsetvli "zero", $STORE_LEN32, "e32", "m4", "ta", "ma"]}
    @{[vse32_v $V24, $OUTPUT]}
    add $OUTPUT, $OUTPUT, $T0
    sub $STORE_LEN32, $STORE_LEN32, $VL

    bnez $LEN32, .Lenc_blocks_128

    @{[handle_xts_enc_last_block]}

    # xts last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V28]}
    @{[sm4_enc]}
    @{[vxor_vv $V24, $V24, $V28]}

    # store last block ciphertext
    addi $OUTPUT, $OUTPUT, -16
    @{[vse32_v $V24, $OUTPUT]}

    ret
.size sm4_xts_enc_128,.-sm4_xts_enc_128
___

################################################################################
# void rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt(const unsigned char *in,
#                                             unsigned char *out, size_t length,
#                                             const SM4_KEY *key1,
#                                             const SM4_KEY *key2,
#                                             const unsigned char iv[16],
#                                             const int enc)
$code .= <<___;
.p2align 3
.globl rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt
.type rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt,\@function
rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt:
    @{[compute_xts_iv0]}

    # sm4 block size is 16
    andi $TAIL_LENGTH, $LENGTH, 15
    beqz $TAIL_LENGTH, 1f
    sub $LENGTH, $LENGTH, $TAIL_LENGTH
    addi $LENGTH, $LENGTH, -16
1:
    # We make the `LENGTH` become e32 length here.
    srli $LEN32, $LENGTH, 2

    j sm4_xts_dec_128
.size rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt,.-rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt
___

$code .= <<___;
.p2align 3
sm4_xts_dec_128:
    @{[init_first_round]}
    @{[sm4_load_key]}
    beqz $LEN32, 2f

    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    j 1f

.Ldec_blocks_128:
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    # load ciphertext into v24
    @{[vle32_v $V24, $INPUT]}
    # update iv
    @{[vgmul_vv $V16, $V20]}
    # reverse the iv's bits order back
    @{[vbrev8_v $V28, $V16]}
1:
    @{[vxor_vv $V24, $V24, $V28]}
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL
    add $INPUT, $INPUT, $T0
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V28]}

    # store plaintext
    @{[vse32_v $V24, $OUTPUT]}
    add $OUTPUT, $OUTPUT, $T0

    bnez $LEN32, .Ldec_blocks_128

2:
    @{[handle_xts_dec_last_block]}

    ## xts second to last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V29]}
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V29]}
    @{[vmv_v_v $V25, $V24]}

    # load last block ciphertext
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "tu", "ma"]}
    @{[vle8_v $V24, $INPUT]}

    # store second to last block plaintext
    addi $T0, $OUTPUT, 16
    @{[vse8_v $V25, $T0]}

    ## xts last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V28]}
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V28]}

    # store second to last block plaintext
    @{[vse32_v $V24, $OUTPUT]}

    ret
.size sm4_xts_dec_128,.-sm4_xts_dec_128
___
}

{
################################################################################
# void rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt(const unsigned char *in,
#                                             unsigned char *out, size_t length,
#                                             const SM4_KEY *key1,
#                                             const SM4_KEY *key2,
#                                             const unsigned char iv[16],
#                                             const int enc)
my ($INPUT, $OUTPUT, $LENGTH, $KEY1, $KEY2, $IV) = ("a0", "a1", "a2", "a3", "a4", "a5");
my ($TAIL_LENGTH) = ("a6");
my ($VL) = ("a7");
my ($T0, $T1, $T2) = ("t0", "t1", "t2");
my ($STORE_LEN32) = ("t3");
my ($LEN32) = ("t4");
my ($V0, $V1, $V2, $V3, $V4, $V5, $V6, $V7,
    $V8, $V9, $V10, $V11, $V12, $V13, $V14, $V15,
    $V16, $V17, $V18, $V19, $V20, $V21, $V22, $V23,
    $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map("v$_",(0..31));

# prepare input data(v24), iv(v28), iv-multiplier(v20)
sub initgb_first_round {
    my $code=<<___;
    @{[vmv_v_v $V16, $V28]}
    # load input
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vle32_v $V24, $INPUT]}

    li $T0, 5
    # We could simplify the initialization steps if we have `block<=1`.
    blt $LEN32, $T0, 1f

    # Note: We use `vgmul` for GF(2^128) multiplication.
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vmv_v_i $V16, 0]}
    # v16: [IV0, IV0, ...]
    @{[vid_v $V20]}                     # v20 = 0,1,2,3,4,5,...
    @{[vand_vi  $V20, $V20, 3]}         # v20 = 0,1,2,3,0,1,2,3,...
    @{[vrgather_vv $V16, $V28, $V20]}   # v16[i] = v0[v20[i]]

    # Prepare GF(2^128) multiplier [1, x, x^2, x^3, ...] in v8.
    slli $T0, $LEN32, 2
    @{[vsetvli "zero", $T0, "e32", "m1", "ta", "ma"]}
    # v2: [`1`, `1`, `1`, `1`, ...]
    @{[vmv_v_i $V2, 1]}
    # v3: [`0`, `1`, `2`, `3`, ...]
    @{[vid_v $V3]}
    @{[vsetvli "zero", $T0, "e64", "m2", "ta", "ma"]}
    # v4: [`1`, 0, `1`, 0, `1`, 0, `1`, 0, ...]
    @{[vzext_vf2 $V4, $V2]}
    # v6: [`0`, 0, `1`, 0, `2`, 0, `3`, 0, ...]
    @{[vzext_vf2 $V6, $V3]}
    slli $T0, $LEN32, 1
    @{[vsetvli "zero", $T0, "e32", "m2", "ta", "ma"]}
    # v8: [1<<0=1, 0, 0, 0, 1<<1=x, 0, 0, 0, 1<<2=x^2, 0, 0, 0, ...]
    @{[vwsll_vv $V8, $V4, $V6]}

    # Compute [IV0*1, IV0*x, IV0*x^2, IV0*x^3, ...] in v16
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vbrev8_v $V8, $V8]}
    @{[vgmul_vv $V16, $V8]}

    # Prepare the x^n multiplier in v20. The `n` is the sm4-xts block number
    # in a LMUL=4 register group.
    #   n = ((VLEN*LMUL)/(32*4)) = ((VLEN*4)/(32*4))
    #     = (VLEN/32)
    # We could use vsetvli with `e32, m1` to compute the `n` number.
    @{[vsetvli $T0, "zero", "e32", "m1", "ta", "ma"]}
    li $T1, 1
    sll $T0, $T1, $T0
    @{[vsetivli "zero", 2, "e64", "m1", "ta", "ma"]}
    @{[vmv_v_i $V0, 0]}
    @{[vsetivli "zero", 1, "e64", "m1", "tu", "ma"]}
    @{[vmv_v_x $V0, $T0]}
    @{[vsetivli "zero", 2, "e64", "m1", "ta", "ma"]}
    @{[vbrev8_v $V0, $V0]}
    @{[vsetvli "zero", $LEN32, "e32", "m4", "ta", "ma"]}
    @{[vmv_v_i $V20, 0]}
    @{[vid_v $V12]}                     # v12 = 0,1,2,3,4,5,...
    @{[vand_vi  $V12, $V12, 3]}         # v12 = 0,1,2,3,0,1,2,3,...
    @{[vrgather_vv $V20, $V0, $V12]}    # v20[i] = v0[v12[i]]
1:
___

    return $code;
}

# prepare xts enc last block's input(v24) and iv(v28)
sub handle_xtsgb_enc_last_block {
    my $code=<<___;
    bnez $TAIL_LENGTH, 1f
    ret
1:
    # slidedown second to last block
    addi $VL, $VL, -4
    @{[vsetivli "zero", 4, "e32", "m4", "ta", "ma"]}
    # ciphertext
    @{[vslidedown_vx $V24, $V24, $VL]}
    # multiplier
    @{[vslidedown_vx $V16, $V16, $VL]}

    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_v $V25, $V24]}

    # load last block into v24
    # note: We should load the last block before store the second to last block
    #       for in-place operation.
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "tu", "ma"]}
    @{[vle8_v $V24, $INPUT]}

    # setup `x` multiplier with byte-reversed order
    # 0b00000010 => 0b01000000 (0x40)
    li $T0, 0x40
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_i $V28, 0]}
    @{[vsetivli "zero", 1, "e8", "m1", "tu", "ma"]}
    @{[vmv_v_x $V28, $T0]}

    # compute IV for last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V28]}

    # store second to last block
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "ta", "ma"]}
    @{[vse8_v $V25, $OUTPUT]}
___

    return $code;
}

# prepare xts dec second to last block's input(v24) and iv(v29) and
# last block's and iv(v28)
sub handle_xtsgb_dec_last_block {
    my $code=<<___;
    bnez $TAIL_LENGTH, 1f
    ret
1:
    # load second to last block's ciphertext
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vle32_v $V24, $INPUT]}
    addi $INPUT, $INPUT, 16

    # setup `x` multiplier with byte-reversed order
    # 0b00000010 => 0b01000000 (0x40)
    li $T0, 0x40
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vmv_v_i $V20, 0]}
    @{[vsetivli "zero", 1, "e8", "m1", "tu", "ma"]}
    @{[vmv_v_x $V20, $T0]}

    beqz $LENGTH, 1f
    # slidedown third to last block
    addi $VL, $VL, -4
    @{[vsetivli "zero", 4, "e32", "m4", "ta", "ma"]}
    # multiplier
    @{[vslidedown_vx $V16, $V16, $VL]}

    # compute IV for last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V20]}
    @{[vmv_v_v $V28, $V16]}

    # compute IV for second to last block
    @{[vgmul_vv $V16, $V20]}
    j 2f
1:
    # compute IV for second to last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vgmul_vv $V16, $V20]}
2:
___

    return $code;
}

$code .= <<___;
.p2align 3
.globl rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt
.type rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt,\@function
rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt:
    @{[compute_xts_iv0]}

    # sm4 block size is 16
    andi $TAIL_LENGTH, $LENGTH, 15
    mv $STORE_LEN32, $LENGTH
    beqz $TAIL_LENGTH, 1f
    sub $LENGTH, $LENGTH, $TAIL_LENGTH
    addi $STORE_LEN32, $LENGTH, -16
1:
    # We make the `LENGTH` become e32 length here.
    srli $LEN32, $LENGTH, 2
    srli $STORE_LEN32, $STORE_LEN32, 2

    j sm4_xtsgb_enc_128
.size rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt,.-rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt
___

$code .= <<___;
.p2align 3
sm4_xtsgb_enc_128:
    @{[initgb_first_round]}
    @{[sm4_load_key]}
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    j 1f

.Lencgb_blocks_128:
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    # load plaintext into v24
    @{[vle32_v $V24, $INPUT]}
    # update iv
    @{[vgmul_vv $V16, $V20]}
1:
    @{[vxor_vv $V24, $V24, $V16]}
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL
    add $INPUT, $INPUT, $T0
    @{[sm4_enc]}
    @{[vxor_vv $V24, $V24, $V16]}

    # store ciphertext
    @{[vsetvli "zero", $STORE_LEN32, "e32", "m4", "ta", "ma"]}
    @{[vse32_v $V24, $OUTPUT]}
    add $OUTPUT, $OUTPUT, $T0
    sub $STORE_LEN32, $STORE_LEN32, $VL

    bnez $LEN32, .Lencgb_blocks_128

    @{[handle_xtsgb_enc_last_block]}

    # xts last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V16]}
    @{[sm4_enc]}
    @{[vxor_vv $V24, $V24, $V16]}

    # store last block ciphertext
    addi $OUTPUT, $OUTPUT, -16
    @{[vse32_v $V24, $OUTPUT]}

    ret
.size sm4_xtsgb_enc_128,.-sm4_xtsgb_enc_128
___

################################################################################
# void rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt(const unsigned char *in,
#                                             unsigned char *out, size_t length,
#                                             const SM4_KEY *key1,
#                                             const SM4_KEY *key2,
#                                             const unsigned char iv[16],
#                                             const int enc)
$code .= <<___;
.p2align 3
.globl rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt
.type rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt,\@function
rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt:
    @{[compute_xts_iv0]}

    # sm4 block size is 16
    andi $TAIL_LENGTH, $LENGTH, 15
    beqz $TAIL_LENGTH, 1f
    sub $LENGTH, $LENGTH, $TAIL_LENGTH
    addi $LENGTH, $LENGTH, -16
1:
    # We make the `LENGTH` become e32 length here.
    srli $LEN32, $LENGTH, 2

    j sm4_xtsgb_dec_128
.size rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt,.-rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt
___

$code .= <<___;
.p2align 3
sm4_xtsgb_dec_128:
    @{[initgb_first_round]}
    @{[sm4_load_key]}
    beqz $LEN32, 2f

    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    j 1f

.Ldecgb_blocks_128:
    @{[vsetvli $VL, $LEN32, "e32", "m4", "ta", "ma"]}
    # load ciphertext into v24
    @{[vle32_v $V24, $INPUT]}
    # update iv
    @{[vgmul_vv $V16, $V20]}
1:
    @{[vxor_vv $V24, $V24, $V16]}
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL
    add $INPUT, $INPUT, $T0
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V16]}

    # store plaintext
    @{[vse32_v $V24, $OUTPUT]}
    add $OUTPUT, $OUTPUT, $T0

    bnez $LEN32, .Ldecgb_blocks_128

2:
    @{[handle_xtsgb_dec_last_block]}

    ## xts second to last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V16]}
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V16]}
    @{[vmv_v_v $V25, $V24]}

    # load last block ciphertext
    @{[vsetvli "zero", $TAIL_LENGTH, "e8", "m1", "tu", "ma"]}
    @{[vle8_v $V24, $INPUT]}

    # store second to last block plaintext
    addi $T0, $OUTPUT, 16
    @{[vse8_v $V25, $T0]}

    ## xts last block
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    @{[vxor_vv $V24, $V24, $V28]}
    @{[sm4_dec]}
    @{[vxor_vv $V24, $V24, $V28]}

    # store second to last block plaintext
    @{[vse32_v $V24, $OUTPUT]}

    ret
.size sm4_xtsgb_dec_128,.-sm4_xtsgb_dec_128
___
}

$code .= <<___;
.p2align 3
.globl ORDERH
ORDERH:
    .half 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50, 49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60
.size ORDERH,.-ORDERH
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
