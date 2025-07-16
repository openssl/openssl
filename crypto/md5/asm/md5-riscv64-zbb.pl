#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2025, Julian Zhu <julian.oerv@isrc.iscas.ac.cn>
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
# Optional:
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

my $use_zbb = $flavour && $flavour =~ /zbb/i ? 1 : 0;
my $isaext = "_" . ( $use_zbb ? "zbb" : "riscv64" );

$output and open STDOUT,">$output";

my $code=<<___;
.text
___

# Function arguments
my ($INP, $LEN, $ADDR, $A, $B, $C, $D) = ("a1", "a2", "sp", "a4", "a5", "a6", "a7");
my ($KT, $T0, $T1, $T2, $lA, $lB, $lC, $lD) = ("a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6");
my ($C1, $C2, $C3, $C4, $C5, $C6, $C7, $C8) = ("s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7");

sub ROUND1EVN {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $x
    addw $a, $a, $T0
    xor $T0, $c, $d
    and $T0, $T0, $b
    xor $T0, $T0, $d
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND1ODD {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $T0
    srli $T0, $x, 32
    addw $a, $a, $T0
    xor $T0, $c, $d
    and $T0, $T0, $b
    xor $T0, $T0, $d
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b

___
    return $code;
}

sub ROUND2EVN {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $x
    addw $a, $a, $T0
    xor $T0, $b, $c
    and $T0, $T0, $d
    xor $T0, $T0, $c
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND2ODD {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $T0
    srli $T0, $x, 32
    addw $a, $a, $T0
    xor $T0, $b, $c
    and $T0, $T0, $d
    xor $T0, $T0, $c
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND3EVN {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $x
    addw $a, $a, $T0
    xor $T0, $c, $d
    xor $T0, $T0, $b
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND3ODD {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $T0
    srli $T0, $x, 32
    addw $a, $a, $T0
    xor $T0, $c, $d
    xor $T0, $T0, $b
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND4EVN {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $x
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $orn_part = <<___;
        @{[orn $T0, $b, $d]}
___
        $code .= $orn_part;
    } else { 
        my $orn_part = <<___;
        @{[orn_rv64i $T0, $b, $d]}
___
        $code .= $orn_part;
    }
    $code .= <<___;
    xor $T0, $T0, $c
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

sub ROUND4ODD {
    my ($a, $b, $c, $d, $x, $const, $shift) = @_;
    my $code=<<___;
    li $T0, $const
    addw $a, $a, $T0
    srli $T0, $x, 32
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $orn_part = <<___;
        @{[orn $T0, $b, $d]}
___
        $code .= $orn_part;
    } else {
        my $orn_part = <<___;
        @{[orn_rv64i $T0, $b, $d]}
___
        $code .= $orn_part;
    }
    $code .= <<___;
    xor $T0, $T0, $c
    addw $a, $a, $T0
___
    if ($use_zbb) {
        my $ror_part = <<___;
        @{[roriw $a, $a, 32 - $shift]}
___
        $code .= $ror_part;
    } else {
        my $ror_part = <<___;
        @{[roriw_rv64i $a, $a, $T1, $T2, 32 - $shift]}
___
        $code .= $ror_part;
    }
    $code .= <<___;
    addw $a, $a, $b
___
    return $code;
}

################################################################################
# void ossl_md5_block_asm_data_order@{[$isaext]}(MD5_CTX *c, const void *p, size_t num)
$code .= <<___;
.p2align 3
.globl ossl_md5_block_asm_data_order@{[$isaext]}
.type ossl_md5_block_asm_data_order@{[$isaext]},\@function
ossl_md5_block_asm_data_order@{[$isaext]}:

    addi sp, sp, -64

    sd s0, 0(sp)
    sd s1, 8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s4, 32(sp)
    sd s5, 40(sp)
    sd s6, 48(sp)
    sd s7, 56(sp)

    # load ctx
    lw $A, 0(a0)
    lw $B, 4(a0)
    lw $C, 8(a0)
    lw $D, 12(a0)

L_round_loop:

    addi $LEN, $LEN, -1

    ld s0, 0($INP)
    ld s1, 8($INP)
    ld s2, 16($INP)
    ld s3, 24($INP)
    ld s4, 32($INP)
    ld s5, 40($INP)
    ld s6, 48($INP)
    ld s7, 56($INP)

    mv $lA, $A
    mv $lB, $B
    mv $lC, $C
    mv $lD, $D

    @{[ROUND1EVN $A, $B, $C, $D, $C1, -680876936, 7]} # 0xd76aa478
    @{[ROUND1ODD $D, $A, $B, $C, $C1, -389564586,12]} # 0xe8c7b756
    @{[ROUND1EVN $C, $D, $A, $B, $C2, 0x242070db,17]} # 0x242070db
    @{[ROUND1ODD $B, $C, $D, $A, $C2,-1044525330,22]} # 0xc1bdceee
    @{[ROUND1EVN $A, $B, $C, $D, $C3, -176418897, 7]} # 0xf57c0faf
    @{[ROUND1ODD $D, $A, $B, $C, $C3, 0x4787c62a,12]} # 0x4787c62a
    @{[ROUND1EVN $C, $D, $A, $B, $C4,-1473231341,17]} # 0xa8304613
    @{[ROUND1ODD $B, $C, $D, $A, $C4,  -45705983,22]} # 0xfd469501
    @{[ROUND1EVN $A, $B, $C, $D, $C5, 0x698098d8, 7]} # 0x698098d8
    @{[ROUND1ODD $D, $A, $B, $C, $C5,-1958414417,12]} # 0x8b44f7af
    @{[ROUND1EVN $C, $D, $A, $B, $C6,    -42063, 17]} # 0xffff5bb1
    @{[ROUND1ODD $B, $C, $D, $A, $C6,-1990404162,22]} # 0x895cd7be
    @{[ROUND1EVN $A, $B, $C, $D, $C7, 0x6b901122, 7]} # 0x6b901122
    @{[ROUND1ODD $D, $A, $B, $C, $C7, -40341101, 12]} # 0xfd987193
    @{[ROUND1EVN $C, $D, $A, $B, $C8,-1502002290,17]} # 0xa679438e
    @{[ROUND1ODD $B, $C, $D, $A, $C8, 0x49b40821,22]} # 0x49b40821

    @{[ROUND2ODD $A, $B, $C, $D, $C1, -165796510, 5]} # 0xf61e2562
    @{[ROUND2EVN $D, $A, $B, $C, $C4,-1069501632, 9]} # 0xc040b340
    @{[ROUND2ODD $C, $D, $A, $B, $C6, 0x265e5a51,14]} # 0x265e5a51
    @{[ROUND2EVN $B, $C, $D, $A, $C1, -373897302,20]} # 0xe9b6c7aa
    @{[ROUND2ODD $A, $B, $C, $D, $C3, -701558691, 5]} # 0xd62f105d
    @{[ROUND2EVN $D, $A, $B, $C, $C6,  0x2441453, 9]} # 0x2441453
    @{[ROUND2ODD $C, $D, $A, $B, $C8, -660478335,14]} # 0xd8a1e681
    @{[ROUND2EVN $B, $C, $D, $A, $C3, -405537848,20]} # 0xe7d3fbc8
    @{[ROUND2ODD $A, $B, $C, $D, $C5, 0x21e1cde6, 5]} # 0x21e1cde6
    @{[ROUND2EVN $D, $A, $B, $C, $C8,-1019803690, 9]} # 0xc33707d6
    @{[ROUND2ODD $C, $D, $A, $B, $C2, -187363961,14]} # 0xf4d50d87
    @{[ROUND2EVN $B, $C, $D, $A, $C5, 0x455a14ed,20]} # 0x455a14ed
    @{[ROUND2ODD $A, $B, $C, $D, $C7,-1444681467, 5]} # 0xa9e3e905
    @{[ROUND2EVN $D, $A, $B, $C, $C2,  -51403784, 9]} # 0xfcefa3f8
    @{[ROUND2ODD $C, $D, $A, $B, $C4, 0x676f02d9,14]} # 0x676f02d9
    @{[ROUND2EVN $B, $C, $D, $A, $C7,-1926607734,20]} # 0x8d2a4c8a

    @{[ROUND3ODD $A, $B, $C, $D, $C3,    -378558, 4]} # 0xfffa3942
    @{[ROUND3EVN $D, $A, $B, $C, $C5,-2022574463,11]} # 0x8771f681
    @{[ROUND3ODD $C, $D, $A, $B, $C6, 0x6d9d6122,16]} # 0x6d9d6122
    @{[ROUND3EVN $B, $C, $D, $A, $C8,  -35309556,23]} # 0xfde5380c
    @{[ROUND3ODD $A, $B, $C, $D, $C1,-1530992060, 4]} # 0xa4beea44
    @{[ROUND3EVN $D, $A, $B, $C, $C3, 0x4bdecfa9,11]} # 0x4bdecfa9
    @{[ROUND3ODD $C, $D, $A, $B, $C4, -155497632,16]} # 0xf6bb4b60
    @{[ROUND3EVN $B, $C, $D, $A, $C6,-1094730640,23]} # 0xbebfbc70
    @{[ROUND3ODD $A, $B, $C, $D, $C7, 0x289b7ec6, 4]} # 0x289b7ec6
    @{[ROUND3EVN $D, $A, $B, $C, $C1, -358537222,11]} # 0xeaa127fa
    @{[ROUND3ODD $C, $D, $A, $B, $C2, -722521979,16]} # 0xd4ef3085
    @{[ROUND3EVN $B, $C, $D, $A, $C4,  0x4881d05,23]} # 0x4881d05
    @{[ROUND3ODD $A, $B, $C, $D, $C5, -640364487, 4]} # 0xd9d4d039
    @{[ROUND3EVN $D, $A, $B, $C, $C7,-421815835, 11]} # 0xe6db99e5
    @{[ROUND3ODD $C, $D, $A, $B, $C8,0x1fa27cf8, 16]} # 0x1fa27cf8
    @{[ROUND3EVN $B, $C, $D, $A, $C2, -995338651,23]} # 0xc4ac5665

    @{[ROUND4EVN $A, $B, $C, $D, $C1, -198630844, 6]} # 0xf4292244
    @{[ROUND4ODD $D, $A, $B, $C, $C4, 0x432aff97,10]} # 0x432aff97
    @{[ROUND4EVN $C, $D, $A, $B, $C8,-1416354905,15]} # 0xab9423a7
    @{[ROUND4ODD $B, $C, $D, $A, $C3,  -57434055,21]} # 0xfc93a039
    @{[ROUND4EVN $A, $B, $C, $D, $C7, 0x655b59c3, 6]} # 0x655b59c3
    @{[ROUND4ODD $D, $A, $B, $C, $C2,-1894986606,10]} # 0x8f0ccc92
    @{[ROUND4EVN $C, $D, $A, $B, $C6,   -1051523,15]} # 0xffeff47d
    @{[ROUND4ODD $B, $C, $D, $A, $C1,-2054922799,21]} # 0x85845dd1
    @{[ROUND4EVN $A, $B, $C, $D, $C5, 0x6fa87e4f, 6]} # 0x6fa87e4f
    @{[ROUND4ODD $D, $A, $B, $C, $C8, -30611744, 10]} # 0xfe2ce6e0
    @{[ROUND4EVN $C, $D, $A, $B, $C4,-1560198380,15]} # 0xa3014314
    @{[ROUND4ODD $B, $C, $D, $A, $C7,0x4e0811a1, 21]} # 0x4e0811a1
    @{[ROUND4EVN $A, $B, $C, $D, $C3, -145523070, 6]} # 0xf7537e82
    @{[ROUND4ODD $D, $A, $B, $C, $C6,-1120210379,10]} # 0xbd3af235
    @{[ROUND4EVN $C, $D, $A, $B, $C2, 0x2ad7d2bb,15]} # 0x2ad7d2bb
    @{[ROUND4ODD $B, $C, $D, $A, $C5, -343485551,21]} # 0xeb86d391

    addw $A, $A, $lA
    addw $B, $B, $lB
    addw $C, $C, $lC
    addw $D, $D, $lD

    addi $INP, $INP, 64

    bnez $LEN, L_round_loop

    sw $A, 0(a0)
    sw $B, 4(a0)
    sw $C, 8(a0)
    sw $D, 12(a0)

    ld s0, 0(sp)
    ld s1, 8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s4, 32(sp)
    ld s5, 40(sp)
    ld s6, 48(sp)
    ld s7, 56(sp)

    addi sp, sp, 64

    ret
.size ossl_md5_block_asm_data_order@{[$isaext]},.-ossl_md5_block_asm_data_order@{[$isaext]}
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
