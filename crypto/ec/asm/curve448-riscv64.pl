#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# RISC-V Vector (RVV) implementation of the Curve448 constant-time table
# lookup used by ossl_curve448_precomputed_scalarmult().
#
# Requires RV64I plus the 'V' extension with VLEN >= 128.  No Zvk* extension
# is used, so the code is guarded by RISCV_HAS_V() alone.
#
# Vector instructions are emitted as raw .word encodings (see riscv.pm): the
# assembler rejects vector mnemonics unless the build is configured with
# -march=<...>v, and linux64-riscv64 passes no -march at all.  Encoding them
# directly also keeps this file independent of the assembler version and of
# the VLEN of the machine that builds it.

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

################################################################################
# void ossl_curve448_lookup_rvv(void *out, const void *table, size_t rowsize,
#                               size_t numrows, size_t idx);
#
# Copies row number |idx| of |table| into |out|.  |rowsize| and |numrows| are
# not secret, |idx| is.  |out| and |table| must be 16 byte aligned; the only
# caller passes a niels_t local and a pointer into curve448_precomputed_s,
# both of which are (gf_s is declared __attribute__((aligned(16))) and
# sizeof(niels_s) is a multiple of 16).
#
# This is the vectorized form of constant_time_lookup().  The scalar version
# accumulates one byte at a time as
#
#     out[j] |= constant_time_select_8(mask, table[i * rowsize + j], 0)
#
# where mask = constant_time_is_zero_s(idx - i) is 0x00 or 0xff.  Since the
# false operand of the select is zero, the select reduces to a plain AND, so
# each row contributes (row & mask) and the rows are ORed together.  With
# e8/m8 the row is processed a full vector group at a time and the mask is
# applied as a scalar operand (vand.vx); the column loop is strip-mined with
# vsetvli so it is VLEN-agnostic and a partial final group is handled by a
# shorter vector.
#
# Every row is loaded unconditionally and the row mask only ever feeds data
# operands, so neither the control flow nor the set of addresses touched
# depends on |idx|: the constant-time property of the scalar code is kept.
{
my ($out,$table,$rowsize,$numrows,$idx) = ("a0","a1","a2","a3","a4");
my ($VL,$tmp,$tmp2,$mask,$i,$idxrun,$rowptr) = ("t0","t1","t2","t3","t4","t5","t6");
my ($j,$outptr,$tabptr) = ("a5","a6","a7");
my ($vout,$vrow) = ("v8","v16");

$code .= <<___;
.p2align 3
.globl ossl_curve448_lookup_rvv
.type ossl_curve448_lookup_rvv,\@function
ossl_curve448_lookup_rvv:
    beqz    $rowsize, .Llookup_done
    mv      $j, zero
    mv      $outptr, $out
    mv      $tabptr, $table

.Llookup_col:
    sub     $tmp, $rowsize, $j
    @{[vsetvli $VL, $tmp, "e8", "m8", "ta", "ma"]}
    @{[vmv_v_i $vout, 0]}
    beqz    $numrows, .Llookup_store
    mv      $i, zero
    mv      $idxrun, $idx
    mv      $rowptr, $tabptr

.Llookup_row:
    # mask = 0 - ((~idxrun & (idxrun - 1)) >> 63), i.e. constant_time_is_zero_s
    addi    $tmp, $idxrun, -1
    xori    $tmp2, $idxrun, -1
    and     $tmp, $tmp, $tmp2
    srli    $tmp, $tmp, 63
    neg     $mask, $tmp

    @{[vle8_v $vrow, $rowptr]}
    @{[vand_vx $vrow, $vrow, $mask]}
    @{[vor_vv $vout, $vout, $vrow]}

    add     $rowptr, $rowptr, $rowsize
    addi    $idxrun, $idxrun, -1
    addi    $i, $i, 1
    bltu    $i, $numrows, .Llookup_row

.Llookup_store:
    @{[vse8_v $vout, $outptr]}
    add     $j, $j, $VL
    add     $outptr, $outptr, $VL
    add     $tabptr, $tabptr, $VL
    bltu    $j, $rowsize, .Llookup_col

.Llookup_done:
    ret
.size ossl_curve448_lookup_rvv,.-ossl_curve448_lookup_rvv
___
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
