#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

my @regs = map("x$_",(0..31));
my %reglookup;
@reglookup{@regs} = @regs;

# Takes a register name, possibly an alias, and converts it to a register index
# from 0 to 31
sub read_reg {
    my $reg = lc shift;
    if (!exists($reglookup{$reg})) {
        die("Unknown register ".$reg);
    }
    my $regstr = $reglookup{$reg};
    if (!($regstr =~ /^x([0-9]+)$/)) {
        die("Could not process register ".$reg);
    }
    return $1;
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

1;
