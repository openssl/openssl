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
# Copyright (c) 2022, Hongren (Zenithal) Zheng <i@zenithal.me>
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

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT, ">$output";

my $is_rv32 = defined($output) && $output =~ /riscv32/i;
my $slot_size = $is_rv32 ? 4 : 8;
my $store_insn = $is_rv32 ? "sw" : "sd";
my $load_insn = $is_rv32 ? "lw" : "ld";
my $sm4_prefix = $is_rv32 ? "rv32i_zksed_sm4" : "rv64i_zksed_sm4";

################################################################################
# Utility functions to help with keeping track of which registers to stack/
# unstack when entering / exiting routines.
################################################################################
{
    # Callee-saved registers
    my @callee_saved = map("x$_", (2, 8, 9, 18 .. 27));
    # Caller-saved registers
    my @caller_saved = map("x$_", (1, 5 .. 7, 10 .. 17, 28 .. 31));
    my @must_save;
    sub use_reg {
        my $reg = shift;
        if (grep(/^$reg$/, @callee_saved)) {
            push(@must_save, $reg);
        } elsif (!grep(/^$reg$/, @caller_saved)) {
            die("Unusable register " . $reg);
        }
        return $reg;
    }
    sub use_regs {
        return map(use_reg("x$_"), @_);
    }
    sub save_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * $slot_size;
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) {
            $stack_reservation += 16 - ($stack_reservation % 16);
        }
        $ret .= "    addi    sp,sp,-$stack_reservation\n";
        foreach (@must_save) {
            $stack_offset -= $slot_size;
            $ret .= "    $store_insn      $_,$stack_offset(sp)\n";
        }
        return $ret;
    }
    sub load_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * $slot_size;
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) {
            $stack_reservation += 16 - ($stack_reservation % 16);
        }
        foreach (@must_save) {
            $stack_offset -= $slot_size;
            $ret .= "    $load_insn      $_,$stack_offset(sp)\n";
        }
        $ret .= "    addi    sp,sp,$stack_reservation\n";
        return $ret;
    }
    sub clear_regs {
        @must_save = ();
    }
}

################################################################################
# Util for encoding scalar crypto extension instructions
################################################################################

my @regs = map("x$_", (0 .. 31));
my %reglookup;
@reglookup{@regs} = @regs;

sub read_reg {
    my $reg = lc shift;
    if (!exists($reglookup{$reg})) {
        die("Unknown register " . $reg);
    }
    my $regstr = $reglookup{$reg};
    if (!($regstr =~ /^x([0-9]+)$/)) {
        die("Could not process register " . $reg);
    }
    return $1;
}

sub sm4ed {
    my $template = 0b00_11000_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    my $bs = shift;

    return ".word " . ($template | ($bs << 30) | ($rs2 << 20)
        | ($rs1 << 15) | ($rd << 7));
}

sub sm4ks {
    my $template = 0b00_11010_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    my $bs = shift;

    return ".word " . ($template | ($bs << 30) | ($rs2 << 20)
        | ($rs1 << 15) | ($rd << 7));
}

################################################################################
# Register assignment for ${sm4_prefix}_encrypt / decrypt
################################################################################

my ($Q0, $Q1, $Q2, $Q3) = use_regs(6 .. 7, 28 .. 29);
my ($INP, $OUTP, $KEYP) = use_regs(10 .. 12);
my ($T0, $T1, $T2, $T3) = use_regs(13 .. 16);
my ($T) = use_regs(17);
my ($XOR) = use_regs(31);

################################################################################
# Utility for ${sm4_prefix}_encrypt / decrypt
################################################################################

sub input {
    my $ret = '';
$ret .= <<___;
    lw      $Q0,0($INP)
    lw      $Q1,4($INP)
    lw      $Q2,8($INP)
    lw      $Q3,12($INP)
___
    return $ret;
}

sub key {
    my $ret = '';
$ret .= <<___;
    lw      $T0,0($KEYP)
    lw      $T1,4($KEYP)
    lw      $T2,8($KEYP)
    lw      $T3,12($KEYP)
___
    return $ret;
}

sub output {
    my $ret = '';
$ret .= <<___;
    sw      $Q3,0($OUTP)
    sw      $Q2,4($OUTP)
    sw      $Q1,8($OUTP)
    sw      $Q0,12($OUTP)
___
    return $ret;
}

sub sm4ed4 {
    my $rd = shift;
    my $rs1 = shift;
    my $rs2 = shift;
    my $ret = '';
$ret .= <<___;
    @{[sm4ed $rd,$rs1,$rs2,0]}
    @{[sm4ed $rd,$rs1,$rs2,1]}
    @{[sm4ed $rd,$rs1,$rs2,2]}
    @{[sm4ed $rd,$rs1,$rs2,3]}
___
    return $ret;
}

sub sm4ed4r {
    my $ret = '';
$ret .= <<___;
    xor     $XOR,$Q2,$Q3
    xor     $T,$Q1,$T0
    xor     $T,$T,$XOR
    @{[sm4ed4 $Q0,$Q0,$T]}

    xor     $T,$Q0,$T1
    xor     $T,$T,$XOR
    @{[sm4ed4 $Q1,$Q1,$T]}

    xor     $XOR,$Q0,$Q1
    xor     $T,$Q3,$T2
    xor     $T,$T,$XOR
    @{[sm4ed4 $Q2,$Q2,$T]}

    xor     $T,$Q2,$T3
    xor     $T,$T,$XOR
    @{[sm4ed4 $Q3,$Q3,$T]}
___
    return $ret;
}

sub sm4ed32r {
    my $ret = '';
    my $i = 0;
    while ($i < 8) {
$ret .= <<___;
    @{[key]}
    @{[sm4ed4r]}
    add     $KEYP,$KEYP,16
___
        $i++;
    }
    return $ret;
}

my $code = <<___;
.text
.balign 16
.globl ${sm4_prefix}_encrypt
.type   ${sm4_prefix}_encrypt,\@function
${sm4_prefix}_encrypt:
___
$code .= save_regs();
$code .= <<___;
    @{[input]}
    @{[sm4ed32r]}
    @{[output]}
___
$code .= load_regs();
$code .= <<___;
    ret
___

$code .= <<___;
.text
.balign 16
.globl ${sm4_prefix}_decrypt
.type   ${sm4_prefix}_decrypt,\@function
${sm4_prefix}_decrypt:
___
$code .= save_regs();
$code .= <<___;
    @{[input]}
    @{[sm4ed32r]}
    @{[output]}
___
$code .= load_regs();
$code .= <<___;
    ret
___

clear_regs();

################################################################################
# Register assignment for ${sm4_prefix}_set_[en/de]crypt_key
################################################################################

my ($UKEY, $KS) = use_regs(10 .. 11);
my ($KQ0, $KQ1, $KQ2, $KQ3) = use_regs(6 .. 7, 28 .. 29);
my ($CKP) = use_regs(31);
my ($KT0, $KT1, $KT2, $KT3) = use_regs(13 .. 16);
my ($KT) = use_regs(17);
my ($KXOR) = use_regs(30);

sub ukey {
    my $ret = '';
$ret .= <<___;
    lw      $KQ0,0($UKEY)
    lw      $KQ1,4($UKEY)
    lw      $KQ2,8($UKEY)
    lw      $KQ3,12($UKEY)
    li      $KT,0xC6BAB1A3
    xor     $KQ0,$KQ0,$KT
    li      $KT,0x5033AA56
    xor     $KQ1,$KQ1,$KT
    li      $KT,0x97917D67
    xor     $KQ2,$KQ2,$KT
    li      $KT,0xDC2270B2
    xor     $KQ3,$KQ3,$KT
___
    return $ret;
}

sub ckey {
    my $ret = '';
$ret .= <<___;
    lw      $KT0,0($CKP)
    lw      $KT1,4($CKP)
    lw      $KT2,8($CKP)
    lw      $KT3,12($CKP)
___
    return $ret;
}

sub keypenc {
    my $ret = '';
$ret .= <<___;
    sw      $KQ0,0($KS)
    sw      $KQ1,4($KS)
    sw      $KQ2,8($KS)
    sw      $KQ3,12($KS)
___
    return $ret;
}

sub keypdec {
    my $ret = '';
$ret .= <<___;
    sw      $KQ3,0($KS)
    sw      $KQ2,4($KS)
    sw      $KQ1,8($KS)
    sw      $KQ0,12($KS)
___
    return $ret;
}

sub sm4ks4 {
    my $rd = shift;
    my $rs1 = shift;
    my $rs2 = shift;
    my $ret = '';
$ret .= <<___;
    @{[sm4ks $rd,$rs1,$rs2,0]}
    @{[sm4ks $rd,$rs1,$rs2,1]}
    @{[sm4ks $rd,$rs1,$rs2,2]}
    @{[sm4ks $rd,$rs1,$rs2,3]}
___
    return $ret;
}

sub sm4ks4r {
    my $ret = '';
$ret .= <<___;
    xor     $KXOR,$KQ2,$KQ3
    xor     $KT,$KQ1,$KT0
    xor     $KT,$KT,$KXOR
    @{[sm4ks4 $KQ0,$KQ0,$KT]}

    xor     $KT,$KQ0,$KT1
    xor     $KT,$KT,$KXOR
    @{[sm4ks4 $KQ1,$KQ1,$KT]}

    xor     $KXOR,$KQ0,$KQ1
    xor     $KT,$KQ3,$KT2
    xor     $KT,$KT,$KXOR
    @{[sm4ks4 $KQ2,$KQ2,$KT]}

    xor     $KT,$KQ2,$KT3
    xor     $KT,$KT,$KXOR
    @{[sm4ks4 $KQ3,$KQ3,$KT]}
___
    return $ret;
}

sub sm4ks32r {
    my $ret = '';
    my $i = 0;
    my $save = shift;
    while ($i < 8) {
$ret .= <<___;
    @{[ckey]}
    @{[sm4ks4r]}
    add     $CKP,$CKP,16
    $save
___
        $i++;
    }
    return $ret;
}

sub sm4ksenc {
    my $save = <<___;
    @{[keypenc]}
    add     $KS,$KS,16
___
    return sm4ks32r($save);
}

sub sm4ksdec {
    my $save = <<___;
    @{[keypdec]}
    add     $KS,$KS,-16
___
    return sm4ks32r($save);
}

$code .= <<___;
.text
.balign 16
.globl ${sm4_prefix}_set_encrypt_key
.type   ${sm4_prefix}_set_encrypt_key,\@function
${sm4_prefix}_set_encrypt_key:
___
$code .= save_regs();
$code .= <<___;
    @{[ukey]}
    la      $CKP,CK
    @{[sm4ksenc]}
___
$code .= load_regs();
$code .= <<___;
    li      a0,0
    ret
___

$code .= <<___;
.text
.balign 16
.globl ${sm4_prefix}_set_decrypt_key
.type   ${sm4_prefix}_set_decrypt_key,\@function
${sm4_prefix}_set_decrypt_key:
___
$code .= save_regs();
$code .= <<___;
    @{[ukey]}
    la      $CKP,CK
    add     $KS,$KS,112
    @{[sm4ksdec]}
___
$code .= load_regs();
$code .= <<___;
    li      a0,0
    ret
___

$code .= <<___;
.section .rodata
.p2align    12
.type   CK,\@object
CK:
.word 0x150E0700U, 0x312A231CU, 0x4D463F38U, 0x69625B54U
.word 0x857E7770U, 0xA19A938CU, 0xBDB6AFA8U, 0xD9D2CBC4U
.word 0xF5EEE7E0U, 0x110A03FCU, 0x2D261F18U, 0x49423B34U
.word 0x655E5750U, 0x817A736CU, 0x9D968F88U, 0xB9B2ABA4U
.word 0xD5CEC7C0U, 0xF1EAE3DCU, 0x0D06FFF8U, 0x29221B14U
.word 0x453E3730U, 0x615A534CU, 0x7D766F68U, 0x99928B84U
.word 0xB5AEA7A0U, 0xD1CAC3BCU, 0xEDE6DFD8U, 0x0902FBF4U
.word 0x251E1710U, 0x413A332CU, 0x5D564F48U, 0x79726B64U
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
