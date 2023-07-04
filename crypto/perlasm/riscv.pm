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

# Set $have_stacktrace to 1 if we have Devel::StackTrace
my $have_stacktrace = 0;
if (eval {require Devel::StackTrace;1;}) {
    $have_stacktrace = 1;
}

my @regs = map("x$_",(0..31));
# Mapping from the RISC-V psABI ABI mnemonic names to the register number.
my @regaliases = ('zero','ra','sp','gp','tp','t0','t1','t2','s0','s1',
    map("a$_",(0..7)),
    map("s$_",(2..11)),
    map("t$_",(3..6))
);

my %reglookup;
@reglookup{@regs} = @regs;
@reglookup{@regaliases} = @regs;

# Takes a register name, possibly an alias, and converts it to a register index
# from 0 to 31
sub read_reg {
    my $reg = lc shift;
    if (!exists($reglookup{$reg})) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Unknown register ".$reg."\n".$trace);
    }
    my $regstr = $reglookup{$reg};
    if (!($regstr =~ /^x([0-9]+)$/)) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Could not process register ".$reg."\n".$trace);
    }
    return $1;
}

# Helper functions

sub brev8_rv64i {
    # brev8 without `brev8` instruction (only in Zbkb)
    # Bit-reverses the first argument and needs two scratch registers
    my $val = shift;
    my $t0 = shift;
    my $t1 = shift;
    my $brev8_const = shift;
    my $seq = <<___;
        la      $brev8_const, Lbrev8_const

        ld      $t0, 0($brev8_const)  # 0xAAAAAAAAAAAAAAAA
        slli    $t1, $val, 1
        and     $t1, $t1, $t0
        and     $val, $val, $t0
        srli    $val, $val, 1
        or      $val, $t1, $val

        ld      $t0, 8($brev8_const)  # 0xCCCCCCCCCCCCCCCC
        slli    $t1, $val, 2
        and     $t1, $t1, $t0
        and     $val, $val, $t0
        srli    $val, $val, 2
        or      $val, $t1, $val

        ld      $t0, 16($brev8_const) # 0xF0F0F0F0F0F0F0F0
        slli    $t1, $val, 4
        and     $t1, $t1, $t0
        and     $val, $val, $t0
        srli    $val, $val, 4
        or      $val, $t1, $val
___
    return $seq;
}

sub sd_rev8_rv64i {
    # rev8 without `rev8` instruction (only in Zbb or Zbkb)
    # Stores the given value byte-reversed and needs one scratch register
    my $val = shift;
    my $addr = shift;
    my $off = shift;
    my $tmp = shift;
    my $off0 = ($off + 0);
    my $off1 = ($off + 1);
    my $off2 = ($off + 2);
    my $off3 = ($off + 3);
    my $off4 = ($off + 4);
    my $off5 = ($off + 5);
    my $off6 = ($off + 6);
    my $off7 = ($off + 7);
    my $seq = <<___;
        sb      $val, $off7($addr)
        srli    $tmp, $val, 8
        sb      $tmp, $off6($addr)
        srli    $tmp, $val, 16
        sb      $tmp, $off5($addr)
        srli    $tmp, $val, 24
        sb      $tmp, $off4($addr)
        srli    $tmp, $val, 32
        sb      $tmp, $off3($addr)
        srli    $tmp, $val, 40
        sb      $tmp, $off2($addr)
        srli    $tmp, $val, 48
        sb      $tmp, $off1($addr)
        srli    $tmp, $val, 56
        sb      $tmp, $off0($addr)
___
    return $seq;
}

# Scalar crypto instructions

sub aes64ds {
    # Encoding for aes64ds rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0011101_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub aes64dsm {
    # Encoding for aes64dsm rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0011111_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub aes64es {
    # Encoding for aes64es rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0011001_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub aes64esm {
    # Encoding for aes64esm rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0011011_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub aes64im {
    # Encoding for aes64im rd, rs1 instruction on RV64
    #                XXXXXXXXXXXX_ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b001100000000_00000_001_00000_0010011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    return ".word ".($template | ($rs1 << 15) | ($rd << 7));
}

sub aes64ks1i {
    # Encoding for aes64ks1i rd, rs1, rnum instruction on RV64
    #                XXXXXXXX_rnum_ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b00110001_0000_00000_001_00000_0010011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rnum = shift;
    return ".word ".($template | ($rnum << 20) | ($rs1 << 15) | ($rd << 7));
}

sub aes64ks2 {
    # Encoding for aes64ks2 rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0111111_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub brev8 {
    # brev8 rd, rs
    my $template = 0b011010000111_00000_101_00000_0010011;
    my $rd = read_reg shift;
    my $rs = read_reg shift;
    return ".word ".($template | ($rs << 15) | ($rd << 7));
}

sub clmul {
    # Encoding for clmul rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0000101_00000_00000_001_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub clmulh {
    # Encoding for clmulh rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0000101_00000_00000_011_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub rev8 {
    # Encoding for rev8 rd, rs instruction on RV64
    #               XXXXXXXXXXXXX_ rs  _XXX_ rd  _XXXXXXX
    my $template = 0b011010111000_00000_101_00000_0010011;
    my $rd = read_reg shift;
    my $rs = read_reg shift;
    return ".word ".($template | ($rs << 15) | ($rd << 7));
}

1;
