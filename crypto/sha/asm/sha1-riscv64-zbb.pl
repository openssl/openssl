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
# Copyright (c) 2026, YuanSheng <yuansheng@isrc.iscas.ac.cn>
#                     Wang Yang <yangwang@iscas.ac.cn>
#                     ixgbe <1113177880@qq.com>
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

#
# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Basic Bit-manipulation extension ('Zbb')   [REQUIRED]
#
# This generator only emits the Zbb variant (sha1_block_data_order_zbb): the
# 16-word message schedule is kept entirely in general-purpose registers (RV64
# has 32 GPRs), so there is no per-round store/load of the schedule to the
# stack.  When Zbb is not available at run time, the dispatcher in sha_riscv.c
# falls back to the generic C implementation (sha1_block_data_order_c), which
# is faster than a scalar RV64I assembly fallback would be.

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

# This generator only emits the Zbb variant, so $flavour is parsed (to keep the
# standard $output/$flavour argument split above) but otherwise unused -- the
# emitted symbol is always sha1_block_data_order_zbb.  This mirrors
# sha512-riscv64-zbb.pl, which is likewise invoked without a flavour argument.
my $isaext = "_zbb";

$output and open STDOUT,">$output";

my $code=<<___;
.text
___

################################################################################
# Register-resident SHA-1 (Zbb).
#
# The 16-word message schedule never touches memory: each W[i] lives in a GPR
# for its whole lifetime, and the schedule recurrence is computed in place
# (the register holding W[i-16] is overwritten with W[i], since they share the
# same ring-buffer slot i&15).  Round constants are materialised with `li`,
# which avoids spending a register on a K-table pointer.
################################################################################

# Function arguments / loop scalars
my ($CTX, $INP, $LEN) = ("a0", "a1", "a2");
my $K = "a3";                       # current round constant
my ($T1, $T2) = ("t1", "t2");       # round scratch

# 5 working-state words (callee-saved)
my ($A, $B, $C, $D, $E) = ("s0", "s1", "s2", "s3", "s4");

# 16-word message schedule, fully register-resident
my @W = ("s5", "s6", "s7", "s8", "s9", "s10", "s11",
         "t0", "t3", "t4", "t5", "t6", "a4", "a5", "a6", "a7");

# Per-group round constants K_00_19, K_20_39, K_40_59, K_60_79
my @KC = ("0x5a827999", "0x6ed9eba1", "0x8f1bbcdc", "0xca62c1d6");

# rol32(rs, n) == ror32(rs, (32-n)&31), single-instruction on Zbb.
my $ROL = sub {
    my ($rd, $rs, $rol) = @_;
    my $ror = (32 - $rol) & 31;
    return "    @{[roriw $rd, $rs, $ror]}\n";
};

# F(b,c,d): Ch for 0..19, Parity for 20..39/60..79, Maj for 40..59 -> $T1.
my $F = sub {
    my ($i, $b, $c, $d) = @_;
    if ($i < 20) {
        return <<___;
    xor $T1, $c, $d
    and $T1, $T1, $b
    xor $T1, $T1, $d
___
    } elsif ($i < 40 || $i >= 60) {
        return <<___;
    xor $T1, $b, $c
    xor $T1, $T1, $d
___
    } else {
        return <<___;
    xor $T1, $b, $c
    and $T2, $b, $c
    and $T1, $T1, $d
    or  $T1, $T1, $T2
___
    }
};

# W[i] = big-endian input word i, loaded straight into its schedule register.
my $MSGLOAD = sub {
    my ($i, $w) = @_;
    my $off = 4 * $i;
    return <<___;
    lw    $w, $off($INP)
    @{[rev8 $w, $w]}
    srli  $w, $w, 32
___
};

# W[i] = rol32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1), computed in place.
# The destination register currently holds W[i-16] (same ring slot i&15),
# so no temporary and no memory access are needed.
my $MSGUPDATE = sub {
    my ($i) = @_;
    my $w   = $W[ $i        % 16];   # holds W[i-16] on entry, W[i] on exit
    my $w14 = $W[($i - 14)  % 16];
    my $w8  = $W[($i - 8)   % 16];
    my $w3  = $W[($i - 3)   % 16];
    return <<___;
    xor   $w, $w, $w14
    xor   $w, $w, $w8
    xor   $w, $w, $w3
    @{[roriw $w, $w, 31]}
___
};

# One SHA-1 round:
# {a,b,c,d,e} = {rol32(a,5)+F(b,c,d)+e+K+W[i], a, rol32(b,30), c, d}
my $ROUND = sub {
    my ($i, $a, $b, $c, $d, $e) = @_;
    my $w = $W[$i % 16];
    my $r = "";
    if ($i % 20 == 0) {
        $r .= "    li $K, $KC[$i / 20]\n";
    }
    $r .= $F->($i, $b, $c, $d);          # F -> $T1
    $r .= $ROL->($T2, $a, 5);            # $T2 = rol32(a,5)
    $r .= <<___;
    addw $e, $e, $T2
    addw $e, $e, $T1
    addw $e, $e, $K
    addw $e, $e, $w
___
    $r .= $ROL->($b, $b, 30);            # b = rol32(b,30)
    return $r;
};

################################################################################
# void sha1_block_data_order_zbb(SHA_CTX *c, const void *p, size_t num)
$code .= <<___;
.p2align 3
.globl sha1_block_data_order$isaext
.type   sha1_block_data_order$isaext,\@function
sha1_block_data_order$isaext:

    # Save callee-saved registers (s0-s11). No stack buffer for W is needed.
    addi sp, sp, -96
    sd s0,   0(sp)
    sd s1,   8(sp)
    sd s2,  16(sp)
    sd s3,  24(sp)
    sd s4,  32(sp)
    sd s5,  40(sp)
    sd s6,  48(sp)
    sd s7,  56(sp)
    sd s8,  64(sp)
    sd s9,  72(sp)
    sd s10, 80(sp)
    sd s11, 88(sp)

    # Load state A..E from ctx.
    lw $A,  0($CTX)
    lw $B,  4($CTX)
    lw $C,  8($CTX)
    lw $D, 12($CTX)
    lw $E, 16($CTX)

L_block_loop$isaext:
    # Decrement block counter.
    addi $LEN, $LEN, -1
___

# Rounds 0..15: load W[i] from input, then run the round.
my @V = ($A, $B, $C, $D, $E);
for (my $i = 0; $i < 16; $i++) {
    $code .= $MSGLOAD->($i, $W[$i]);
    $code .= $ROUND->($i, @V);
    unshift(@V, pop(@V));
}
# Rounds 16..79: extend W[i] in place, then run the round.
for (my $i = 16; $i < 80; $i++) {
    $code .= $MSGUPDATE->($i);
    $code .= $ROUND->($i, @V);
    unshift(@V, pop(@V));
}

$code .= <<___;
    # Add the working state back into ctx.
    lw $T1,  0($CTX)
    lw $T2,  4($CTX)
    addw $A, $A, $T1
    addw $B, $B, $T2
    lw $T1,  8($CTX)
    lw $T2, 12($CTX)
    addw $C, $C, $T1
    addw $D, $D, $T2
    lw $T1, 16($CTX)
    addw $E, $E, $T1

    sw $A,  0($CTX)
    sw $B,  4($CTX)
    sw $C,  8($CTX)
    sw $D, 12($CTX)
    sw $E, 16($CTX)

    addi $INP, $INP, 64
    bnez $LEN, L_block_loop$isaext

    ld s0,   0(sp)
    ld s1,   8(sp)
    ld s2,  16(sp)
    ld s3,  24(sp)
    ld s4,  32(sp)
    ld s5,  40(sp)
    ld s6,  48(sp)
    ld s7,  56(sp)
    ld s8,  64(sp)
    ld s9,  72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)
    addi sp, sp, 96

    ret
.size sha1_block_data_order$isaext,.-sha1_block_data_order$isaext
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
