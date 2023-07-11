#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Jerry Shih <jerry.shih@sifive.com>
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
# - RISC-V Vector Cryptography Bit-manipulation extension ('Zvkb')
# - RISC-V Zicclsm(Main memory supports misaligned loads/stores)

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output  = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop   : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.|          ? shift : undef;

$output and open STDOUT, ">$output";

my $code = <<___;
.text
___

# void ChaCha20_ctr32_zvkb(unsigned char *out, const unsigned char *inp,
#                          size_t len, const unsigned int key[8],
#                          const unsigned int counter[4]);
################################################################################
my ( $OUTPUT, $INPUT, $LEN, $KEY, $COUNTER ) = ( "a0", "a1", "a2", "a3", "a4" );
my ( $T0 ) = ( "t0" );
my ( $CONST_DATA0, $CONST_DATA1, $CONST_DATA2, $CONST_DATA3 ) =
  ( "a5", "a6", "a7", "t1" );
my ( $KEY0, $KEY1, $KEY2,$KEY3, $KEY4, $KEY5, $KEY6, $KEY7,
     $COUNTER0, $COUNTER1, $NONCE0, $NONCE1
) = ( "s0", "s1", "s2", "s3", "s4", "s5", "s6",
    "s7", "s8", "s9", "s10", "s11" );
my ( $VL, $STRIDE, $CHACHA_LOOP_COUNT ) = ( "t2", "t3", "t4" );
my (
    $V0,  $V1,  $V2,  $V3,  $V4,  $V5,  $V6,  $V7,  $V8,  $V9,  $V10,
    $V11, $V12, $V13, $V14, $V15, $V16, $V17, $V18, $V19, $V20, $V21,
    $V22, $V23, $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map( "v$_", ( 0 .. 31 ) );

sub chacha_quad_round_group {
    my (
        $A0, $B0, $C0, $D0, $A1, $B1, $C1, $D1,
        $A2, $B2, $C2, $D2, $A3, $B3, $C3, $D3
    ) = @_;

    my $code = <<___;
    # a += b; d ^= a; d <<<= 16;
    @{[vadd_vv $A0, $A0, $B0]}
    @{[vadd_vv $A1, $A1, $B1]}
    @{[vadd_vv $A2, $A2, $B2]}
    @{[vadd_vv $A3, $A3, $B3]}
    @{[vxor_vv $D0, $D0, $A0]}
    @{[vxor_vv $D1, $D1, $A1]}
    @{[vxor_vv $D2, $D2, $A2]}
    @{[vxor_vv $D3, $D3, $A3]}
    @{[vror_vi $D0, $D0, 32 - 16]}
    @{[vror_vi $D1, $D1, 32 - 16]}
    @{[vror_vi $D2, $D2, 32 - 16]}
    @{[vror_vi $D3, $D3, 32 - 16]}
    # c += d; b ^= c; b <<<= 12;
    @{[vadd_vv $C0, $C0, $D0]}
    @{[vadd_vv $C1, $C1, $D1]}
    @{[vadd_vv $C2, $C2, $D2]}
    @{[vadd_vv $C3, $C3, $D3]}
    @{[vxor_vv $B0, $B0, $C0]}
    @{[vxor_vv $B1, $B1, $C1]}
    @{[vxor_vv $B2, $B2, $C2]}
    @{[vxor_vv $B3, $B3, $C3]}
    @{[vror_vi $B0, $B0, 32 - 12]}
    @{[vror_vi $B1, $B1, 32 - 12]}
    @{[vror_vi $B2, $B2, 32 - 12]}
    @{[vror_vi $B3, $B3, 32 - 12]}
    # a += b; d ^= a; d <<<= 8;
    @{[vadd_vv $A0, $A0, $B0]}
    @{[vadd_vv $A1, $A1, $B1]}
    @{[vadd_vv $A2, $A2, $B2]}
    @{[vadd_vv $A3, $A3, $B3]}
    @{[vxor_vv $D0, $D0, $A0]}
    @{[vxor_vv $D1, $D1, $A1]}
    @{[vxor_vv $D2, $D2, $A2]}
    @{[vxor_vv $D3, $D3, $A3]}
    @{[vror_vi $D0, $D0, 32 - 8]}
    @{[vror_vi $D1, $D1, 32 - 8]}
    @{[vror_vi $D2, $D2, 32 - 8]}
    @{[vror_vi $D3, $D3, 32 - 8]}
    # c += d; b ^= c; b <<<= 7;
    @{[vadd_vv $C0, $C0, $D0]}
    @{[vadd_vv $C1, $C1, $D1]}
    @{[vadd_vv $C2, $C2, $D2]}
    @{[vadd_vv $C3, $C3, $D3]}
    @{[vxor_vv $B0, $B0, $C0]}
    @{[vxor_vv $B1, $B1, $C1]}
    @{[vxor_vv $B2, $B2, $C2]}
    @{[vxor_vv $B3, $B3, $C3]}
    @{[vror_vi $B0, $B0, 32 - 7]}
    @{[vror_vi $B1, $B1, 32 - 7]}
    @{[vror_vi $B2, $B2, 32 - 7]}
    @{[vror_vi $B3, $B3, 32 - 7]}
___

    return $code;
}

$code .= <<___;
.p2align 3
.globl ChaCha20_ctr32_zvkb
.type ChaCha20_ctr32_zvkb,\@function
ChaCha20_ctr32_zvkb:
    srli $LEN, $LEN, 6
    beqz $LEN, .Lend

    addi sp, sp, -96
    sd s0, 0(sp)
    sd s1, 8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s4, 32(sp)
    sd s5, 40(sp)
    sd s6, 48(sp)
    sd s7, 56(sp)
    sd s8, 64(sp)
    sd s9, 72(sp)
    sd s10, 80(sp)
    sd s11, 88(sp)

    li $STRIDE, 64

    #### chacha block data
    # "expa" little endian
    li $CONST_DATA0, 0x61707865
    # "nd 3" little endian
    li $CONST_DATA1, 0x3320646e
    # "2-by" little endian
    li $CONST_DATA2, 0x79622d32
    # "te k" little endian
    li $CONST_DATA3, 0x6b206574

    lw $KEY0, 0($KEY)
    lw $KEY1, 4($KEY)
    lw $KEY2, 8($KEY)
    lw $KEY3, 12($KEY)
    lw $KEY4, 16($KEY)
    lw $KEY5, 20($KEY)
    lw $KEY6, 24($KEY)
    lw $KEY7, 28($KEY)

    lw $COUNTER0, 0($COUNTER)
    lw $COUNTER1, 4($COUNTER)
    lw $NONCE0, 8($COUNTER)
    lw $NONCE1, 12($COUNTER)

.Lblock_loop:
    @{[vsetvli $VL, $LEN, "e32", "m1", "ta", "ma"]}

    # init chacha const states
    @{[vmv_v_x $V0, $CONST_DATA0]}
    @{[vmv_v_x $V1, $CONST_DATA1]}
    @{[vmv_v_x $V2, $CONST_DATA2]}
    @{[vmv_v_x $V3, $CONST_DATA3]}

    # init chacha key states
    @{[vmv_v_x $V4, $KEY0]}
    @{[vmv_v_x $V5, $KEY1]}
    @{[vmv_v_x $V6, $KEY2]}
    @{[vmv_v_x $V7, $KEY3]}
    @{[vmv_v_x $V8, $KEY4]}
    @{[vmv_v_x $V9, $KEY5]}
    @{[vmv_v_x $V10, $KEY6]}
    @{[vmv_v_x $V11, $KEY7]}

    # init chacha key states
    @{[vid_v $V12]}
    @{[vadd_vx $V12, $V12, $COUNTER0]}
    @{[vmv_v_x $V13, $COUNTER1]}

    # init chacha nonce states
    @{[vmv_v_x $V14, $NONCE0]}
    @{[vmv_v_x $V15, $NONCE1]}

    # load the top-half of input data
    @{[vlsseg_nf_e32_v 8, $V16, $INPUT, $STRIDE]}

    li $CHACHA_LOOP_COUNT, 10
.Lround_loop:
    addi $CHACHA_LOOP_COUNT, $CHACHA_LOOP_COUNT, -1
    @{[chacha_quad_round_group
      $V0, $V4, $V8, $V12,
      $V1, $V5, $V9, $V13,
      $V2, $V6, $V10, $V14,
      $V3, $V7, $V11, $V15]}
    @{[chacha_quad_round_group
      $V0, $V5, $V10, $V15,
      $V1, $V6, $V11, $V12,
      $V2, $V7, $V8, $V13,
      $V3, $V4, $V9, $V14]}
    bnez $CHACHA_LOOP_COUNT, .Lround_loop

    # load the bottom-half of input data
    addi $T0, $INPUT, 32
    @{[vlsseg_nf_e32_v 8, $V24, $T0, $STRIDE]}

    # add chacha top-half initial block states
    @{[vadd_vx $V0, $V0, $CONST_DATA0]}
    @{[vadd_vx $V1, $V1, $CONST_DATA1]}
    @{[vadd_vx $V2, $V2, $CONST_DATA2]}
    @{[vadd_vx $V3, $V3, $CONST_DATA3]}
    @{[vadd_vx $V4, $V4, $KEY0]}
    @{[vadd_vx $V5, $V5, $KEY1]}
    @{[vadd_vx $V6, $V6, $KEY2]}
    @{[vadd_vx $V7, $V7, $KEY3]}
    # xor with the top-half input
    @{[vxor_vv $V16, $V16, $V0]}
    @{[vxor_vv $V17, $V17, $V1]}
    @{[vxor_vv $V18, $V18, $V2]}
    @{[vxor_vv $V19, $V19, $V3]}
    @{[vxor_vv $V20, $V20, $V4]}
    @{[vxor_vv $V21, $V21, $V5]}
    @{[vxor_vv $V22, $V22, $V6]}
    @{[vxor_vv $V23, $V23, $V7]}

    # save the top-half of output
    @{[vssseg_nf_e32_v 8, $V16, $OUTPUT, $STRIDE]}

    # add chacha bottom-half initial block states
    @{[vadd_vx $V8, $V8, $KEY4]}
    @{[vadd_vx $V9, $V9, $KEY5]}
    @{[vadd_vx $V10, $V10, $KEY6]}
    @{[vadd_vx $V11, $V11, $KEY7]}
    @{[vid_v $V0]}
    @{[vadd_vx $V12, $V12, $COUNTER0]}
    @{[vadd_vx $V13, $V13, $COUNTER1]}
    @{[vadd_vx $V14, $V14, $NONCE0]}
    @{[vadd_vx $V15, $V15, $NONCE1]}
    @{[vadd_vv $V12, $V12, $V0]}
    # xor with the bottom-half input
    @{[vxor_vv $V24, $V24, $V8]}
    @{[vxor_vv $V25, $V25, $V9]}
    @{[vxor_vv $V26, $V26, $V10]}
    @{[vxor_vv $V27, $V27, $V11]}
    @{[vxor_vv $V29, $V29, $V13]}
    @{[vxor_vv $V28, $V28, $V12]}
    @{[vxor_vv $V30, $V30, $V14]}
    @{[vxor_vv $V31, $V31, $V15]}

    # save the bottom-half of output
    addi $T0, $OUTPUT, 32
    @{[vssseg_nf_e32_v 8, $V24, $T0, $STRIDE]}

    # update counter
    add $COUNTER0, $COUNTER0, $VL
    sub $LEN, $LEN, $VL
    # increase offset for `4 * 16 * VL = 64 * VL`
    slli $T0, $VL, 6
    add $INPUT, $INPUT, $T0
    add $OUTPUT, $OUTPUT, $T0
    bnez $LEN, .Lblock_loop

    ld s0, 0(sp)
    ld s1, 8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s4, 32(sp)
    ld s5, 40(sp)
    ld s6, 48(sp)
    ld s7, 56(sp)
    ld s8, 64(sp)
    ld s9, 72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)
    addi sp, sp, 96

.Lend:
    ret
.size ChaCha20_ctr32_zvkb,.-ChaCha20_ctr32_zvkb
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
