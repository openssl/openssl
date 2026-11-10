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

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Basic Bit-manipulation extension ('Zbb')

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

# Function arguments
my ($INP, $LEN) = ("a1", "a2");
# The entire 16-word message schedule is kept in registers
my @W = ("t0", "t1", "t2", "t3", "t4", "t5", "t6", "a3",
         "a4", "a5", "a6", "a7", "s0", "s1", "s2", "s3");
my ($A, $B, $C, $D, $E) = ("s4", "s5", "s6", "s7", "s8");
my ($K, $T1, $T2, $T3) = ("s9", "s10", "s11", "ra");
# No register is left for the length, so the block count is kept on the
# stack, freeing a2 and ra for the shift amounts of misaligned input
my ($SHL, $SHR) = ($LEN, $T3);
my ($MISALIGNED_INPUT, $ALIGNED_INPUT) = (0, 1);
my @K = ("0x5a827999", "0x6ed9eba1", "0x8f1bbcdc", "0xca62c1d6");

# Misaligned: $dst = (lo >> SHL) | (hi << SHR) from two aligned loads
sub loadDword {
    my ($ALIGNED, $dst, $off) = @_;
    if ($ALIGNED) {
        return "ld $dst, $off($INP)";
    }
    my $code=<<___;
    ld $T1, $off($INP)
    ld $T2, ($off+8)($INP)
    srl $dst, $T1, $SHL
    sll $T2, $T2, $SHR
    or $dst, $dst, $T2
___

    return $code;
}

sub MSGSCHEDULE0 {
    my ($ALIGNED, $INDEX) = @_;
    # Odd rounds: W[i] was loaded by the previous even round
    if ($INDEX & 1) {
        return "";
    }
    # One doubleword holds W[i] (high word) and W[i+1] (low word)
    my $Wi = $W[$INDEX];
    my $Wi1 = $W[$INDEX+1];
    my $code=<<___;
    @{[loadDword $ALIGNED, $Wi1, "4*$INDEX"]}
    @{[rev8 $Wi1, $Wi1]}
    srli $Wi, $Wi1, 32
___

    return $code;
}

# W[i] = ROTL1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), overwriting W[i-16]
sub MSGSCHEDULE1 {
    my ($INDEX) = @_;
    my $Wi = $W[$INDEX & 0x0f];
    my $code=<<___;
    xor $Wi, $Wi, $W[($INDEX-3)&0x0f]
    xor $Wi, $Wi, $W[($INDEX-8)&0x0f]
    xor $Wi, $Wi, $W[($INDEX-14)&0x0f]
    @{[roriw $Wi, $Wi, 31]}
___

    return $code;
}

# Round function: Ch (0..19), Parity (20..39, 60..79), Maj (40..59)
sub sha1_F {
    my ($INDEX, $b, $c, $d) = @_;
    my $code;
    if ($INDEX < 20) {
        $code=<<___;
    xor $T1, $c, $d
    and $T1, $T1, $b
    xor $T1, $T1, $d
___
    } elsif ($INDEX < 40 || $INDEX >= 60) {
        $code=<<___;
    xor $T1, $b, $c
    xor $T1, $T1, $d
___
    } else {
        $code=<<___;
    or $T1, $b, $c
    and $T2, $b, $c
    and $T1, $T1, $d
    or $T1, $T1, $T2
___
    }

    return $code;
}

sub SHA1ROUND {
    my ($INDEX, $a, $b, $c, $d, $e) = @_;
    my $Wi = $W[$INDEX & 0x0f];
    my $code=<<___;
    # e += W[i] + K + ROTL5(a) + F(b, c, d)
    addw $e, $e, $Wi
    @{[roriw $T1, $a, 27]}
    addw $e, $e, $K
    addw $e, $e, $T1
    @{[sha1_F $INDEX, $b, $c, $d]}
    addw $e, $e, $T1
    # b = ROTL30(b)
    @{[roriw $b, $b, 2]}
___

    return $code;
}

sub SHA1ROUND0 {
    my ($ALIGNED, $INDEX, $a, $b, $c, $d, $e) = @_;
    my $code=<<___;
    @{[MSGSCHEDULE0 $ALIGNED, $INDEX]}
    @{[SHA1ROUND $INDEX, $a, $b, $c, $d, $e]}
___

    return $code;
}

sub SHA1ROUND1 {
    my ($INDEX, $a, $b, $c, $d, $e) = @_;
    my $code=<<___;
    @{[MSGSCHEDULE1 $INDEX]}
    @{[SHA1ROUND $INDEX, $a, $b, $c, $d, $e]}
___

    return $code;
}

################################################################################
# void sha1_block_data_order_zbb(void *c, const void *p, size_t len)
$code .= <<___;
.p2align 3
.globl sha1_block_data_order_zbb
.type   sha1_block_data_order_zbb,\@function
sha1_block_data_order_zbb:

    addi sp, sp, -112

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
    sd ra, 96(sp)

    # load ctx
    lw $A, 0(a0)
    lw $B, 4(a0)
    lw $C, 8(a0)
    lw $D, 12(a0)
    lw $E, 16(a0)

    # Save the block count, a2 is reused as SHL
    sd $LEN, 104(sp)

    andi $SHL, $INP, 7
    beqz $SHL, L_round_loop
    andi $INP, $INP, -8
    slli $SHL, $SHL, 3
    li $T1, 64
    sub $SHR, $T1, $SHL

L_round_loop:
    # K is overwritten by rounds 20..79 of the previous block
    li $K, $K[0]

    bnez $SHL, L_load_misaligned
___

# Rounds 0..15, once for aligned and once for misaligned input
for (my $i = 0; $i < 15; $i += 5) {
    $code .= <<___;
    @{[SHA1ROUND0 $ALIGNED_INPUT, $i, $A, $B, $C, $D, $E]}
    @{[SHA1ROUND0 $ALIGNED_INPUT, $i+1, $E, $A, $B, $C, $D]}
    @{[SHA1ROUND0 $ALIGNED_INPUT, $i+2, $D, $E, $A, $B, $C]}
    @{[SHA1ROUND0 $ALIGNED_INPUT, $i+3, $C, $D, $E, $A, $B]}
    @{[SHA1ROUND0 $ALIGNED_INPUT, $i+4, $B, $C, $D, $E, $A]}
___
}

$code .= <<___;
    @{[SHA1ROUND0 $ALIGNED_INPUT, 15, $A, $B, $C, $D, $E]}
    j L_message_schedule
L_load_misaligned:
___

for (my $i = 0; $i < 15; $i += 5) {
    $code .= <<___;
    @{[SHA1ROUND0 $MISALIGNED_INPUT, $i, $A, $B, $C, $D, $E]}
    @{[SHA1ROUND0 $MISALIGNED_INPUT, $i+1, $E, $A, $B, $C, $D]}
    @{[SHA1ROUND0 $MISALIGNED_INPUT, $i+2, $D, $E, $A, $B, $C]}
    @{[SHA1ROUND0 $MISALIGNED_INPUT, $i+3, $C, $D, $E, $A, $B]}
    @{[SHA1ROUND0 $MISALIGNED_INPUT, $i+4, $B, $C, $D, $E, $A]}
___
}

$code .= <<___;
    @{[SHA1ROUND0 $MISALIGNED_INPUT, 15, $A, $B, $C, $D, $E]}

L_message_schedule:
    # Rounds 0..19 share the K loaded at the start of the block
    @{[SHA1ROUND1 16, $E, $A, $B, $C, $D]}
    @{[SHA1ROUND1 17, $D, $E, $A, $B, $C]}
    @{[SHA1ROUND1 18, $C, $D, $E, $A, $B]}
    @{[SHA1ROUND1 19, $B, $C, $D, $E, $A]}
___

for (my $i = 20; $i < 80; $i += 5) {
    if ($i % 20 == 0) {
        $code .= <<___;
    li $K, $K[$i/20]
___
    }
    $code .= <<___;
    @{[SHA1ROUND1 $i, $A, $B, $C, $D, $E]}
    @{[SHA1ROUND1 $i+1, $E, $A, $B, $C, $D]}
    @{[SHA1ROUND1 $i+2, $D, $E, $A, $B, $C]}
    @{[SHA1ROUND1 $i+3, $C, $D, $E, $A, $B]}
    @{[SHA1ROUND1 $i+4, $B, $C, $D, $E, $A]}
___
}

$code .= <<___;
    lw $T1, 0(a0)
    lw $T2, 4(a0)

    addw $A, $A, $T1
    addw $B, $B, $T2

    sw $A, 0(a0)
    sw $B, 4(a0)

    lw $T1, 8(a0)
    lw $T2, 12(a0)

    addw $C, $C, $T1
    addw $D, $D, $T2

    sw $C, 8(a0)
    sw $D, 12(a0)

    lw $T1, 16(a0)
    addw $E, $E, $T1
    sw $E, 16(a0)

    addi $INP, $INP, 64

    # Decrement the block count saved on the stack
    ld $T1, 104(sp)
    addi $T1, $T1, -1
    sd $T1, 104(sp)

    bnez $T1, L_round_loop

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
    ld ra, 96(sp)

    addi sp, sp, 112

    ret
.size sha1_block_data_order_zbb,.-sha1_block_data_order_zbb
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
