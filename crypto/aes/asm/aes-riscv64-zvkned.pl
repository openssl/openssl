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

# - RV64I
# - RISC-V vector ('V') with VLEN >= 128
# - RISC-V vector crypto AES extension ('Zvkned')

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
# int rv64i_zvkned_set_encrypt_key(const unsigned char *userKey, const int bits,
#                                  AES_KEY *key)
# int rv64i_zvkned_set_decrypt_key(const unsigned char *userKey, const int bits,
#                                  AES_KEY *key)
{
my ($UKEY,$BITS,$KEYP) = ("a0", "a1", "a2");
my ($T0,$T1,$T4) = ("t1", "t2", "t4");
my ($v0,  $v1,  $v2,  $v3,  $v4,  $v5,  $v6,
          $v7,  $v8,  $v9,  $v10, $v11, $v12,
          $v13, $v14, $v15, $v16, $v17, $v18,
          $v19, $v20, $v21, $v22, $v23, $v24,
) = map("v$_",(0..24));

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_set_encrypt_key
.type rv64i_zvkned_set_encrypt_key,\@function
rv64i_zvkned_set_encrypt_key:
    beqz $UKEY, L_fail_m1
    beqz $KEYP, L_fail_m1

    # Get proper routine for key size
    li $T0, 256
    beq $BITS, $T0, L_set_key_256
    li $T0, 128
    beq $BITS, $T0, L_set_key_128

    j L_fail_m2

.size rv64i_zvkned_set_encrypt_key,.-rv64i_zvkned_set_encrypt_key
___

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_set_decrypt_key
.type rv64i_zvkned_set_decrypt_key,\@function
rv64i_zvkned_set_decrypt_key:
    beqz $UKEY, L_fail_m1
    beqz $KEYP, L_fail_m1

    # Get proper routine for key size
    li $T0, 256
    beq $BITS, $T0, L_set_key_256
    li $T0, 128
    beq $BITS, $T0, L_set_key_128

    j L_fail_m2

.size rv64i_zvkned_set_decrypt_key,.-rv64i_zvkned_set_decrypt_key
___

$code .= <<___;
.p2align 3
L_set_key_128:
    # Store the number of rounds
    li $T1, 10
    sw $T1, 240($KEYP)

    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Load the key
    @{[vle32_v $v10, ($UKEY)]}

    # Generate keys for round 2-11 into registers v11-v20.
    @{[vaeskf1_vi $v11, $v10, 1]}   # v11 <- rk2  (w[ 4, 7])
    @{[vaeskf1_vi $v12, $v11, 2]}   # v12 <- rk3  (w[ 8,11])
    @{[vaeskf1_vi $v13, $v12, 3]}   # v13 <- rk4  (w[12,15])
    @{[vaeskf1_vi $v14, $v13, 4]}   # v14 <- rk5  (w[16,19])
    @{[vaeskf1_vi $v15, $v14, 5]}   # v15 <- rk6  (w[20,23])
    @{[vaeskf1_vi $v16, $v15, 6]}   # v16 <- rk7  (w[24,27])
    @{[vaeskf1_vi $v17, $v16, 7]}   # v17 <- rk8  (w[28,31])
    @{[vaeskf1_vi $v18, $v17, 8]}   # v18 <- rk9  (w[32,35])
    @{[vaeskf1_vi $v19, $v18, 9]}   # v19 <- rk10 (w[36,39])
    @{[vaeskf1_vi $v20, $v19, 10]}  # v20 <- rk11 (w[40,43])

    # Store the round keys
    @{[vse32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v20, ($KEYP)]}

    li a0, 1
    ret
.size L_set_key_128,.-L_set_key_128
___

$code .= <<___;
.p2align 3
L_set_key_256:
    # Store the number of rounds
    li $T1, 14
    sw $T1, 240($KEYP)

    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Load the key
    @{[vle32_v $v10, ($UKEY)]}
    addi $UKEY, $UKEY, 16
    @{[vle32_v $v11, ($UKEY)]}

    @{[vmv_v_v $v12, $v10]}
    @{[vaeskf2_vi $v12, $v11, 2]}
    @{[vmv_v_v $v13, $v11]}
    @{[vaeskf2_vi $v13, $v12, 3]}
    @{[vmv_v_v $v14, $v12]}
    @{[vaeskf2_vi $v14, $v13, 4]}
    @{[vmv_v_v $v15, $v13]}
    @{[vaeskf2_vi $v15, $v14, 5]}
    @{[vmv_v_v $v16, $v14]}
    @{[vaeskf2_vi $v16, $v15, 6]}
    @{[vmv_v_v $v17, $v15]}
    @{[vaeskf2_vi $v17, $v16, 7]}
    @{[vmv_v_v $v18, $v16]}
    @{[vaeskf2_vi $v18, $v17, 8]}
    @{[vmv_v_v $v19, $v17]}
    @{[vaeskf2_vi $v19, $v18, 9]}
    @{[vmv_v_v $v20, $v18]}
    @{[vaeskf2_vi $v20, $v19, 10]}
    @{[vmv_v_v $v21, $v19]}
    @{[vaeskf2_vi $v21, $v20, 11]}
    @{[vmv_v_v $v22, $v20]}
    @{[vaeskf2_vi $v22, $v21, 12]}
    @{[vmv_v_v $v23, $v21]}
    @{[vaeskf2_vi $v23, $v22, 13]}
    @{[vmv_v_v $v24, $v22]}
    @{[vaeskf2_vi $v24, $v23, 14]}

    @{[vse32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v20, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v21, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v22, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v23, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vse32_v $v24, ($KEYP)]}

    li a0, 1
    ret
.size L_set_key_256,.-L_set_key_256
___
}

################################################################################
# void rv64i_zvkned_encrypt(const unsigned char *in, unsigned char *out,
#                           const AES_KEY *key);
{
my ($INP,$OUTP,$KEYP) = ("a0", "a1", "a2");
my ($T0,$T1, $rounds, $T6) = ("a3", "a4", "t5", "t6");
my ($v0,  $v1,  $v2,  $v3,  $v4,  $v5,  $v6,
          $v7,  $v8,  $v9,  $v10, $v11, $v12,
          $v13, $v14, $v15, $v16, $v17, $v18,
          $v19, $v20, $v21, $v22, $v23, $v24,
) = map("v$_",(0..24));

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_encrypt
.type rv64i_zvkned_encrypt,\@function
rv64i_zvkned_encrypt:
    # Load number of rounds
    lwu     $rounds, 240($KEYP)

    # Get proper routine for key size
    li $T6, 14
    beq $rounds, $T6, L_enc_256
    li $T6, 10
    beq $rounds, $T6, L_enc_128

    j L_fail_m2
.size rv64i_zvkned_encrypt,.-rv64i_zvkned_encrypt
___

$code .= <<___;
.p2align 3
L_enc_128:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    @{[vle32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v20, ($KEYP)]}

    @{[vle32_v $v1, ($INP)]}

    @{[vaesz_vs $v1, $v10]}    # with round key w[ 0, 3]
    @{[vaesem_vs $v1, $v11]}   # with round key w[ 4, 7]
    @{[vaesem_vs $v1, $v12]}   # with round key w[ 8,11]
    @{[vaesem_vs $v1, $v13]}   # with round key w[12,15]
    @{[vaesem_vs $v1, $v14]}   # with round key w[16,19]
    @{[vaesem_vs $v1, $v15]}   # with round key w[20,23]
    @{[vaesem_vs $v1, $v16]}   # with round key w[24,27]
    @{[vaesem_vs $v1, $v17]}   # with round key w[28,31]
    @{[vaesem_vs $v1, $v18]}   # with round key w[32,35]
    @{[vaesem_vs $v1, $v19]}   # with round key w[36,39]
    @{[vaesef_vs $v1, $v20]}   # with round key w[40,43]

    @{[vse32_v $v1, ($OUTP)]}

    ret
.size L_enc_128,.-L_enc_128
___

$code .= <<___;
.p2align 3
L_enc_256:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    @{[vle32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v20, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v21, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v22, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v23, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v24, ($KEYP)]}

    @{[vle32_v $v1, ($INP)]}

    @{[vaesz_vs $v1, $v10]}     # with round key w[ 0, 3]
    @{[vaesem_vs $v1, $v11]}
    @{[vaesem_vs $v1, $v12]}
    @{[vaesem_vs $v1, $v13]}
    @{[vaesem_vs $v1, $v14]}
    @{[vaesem_vs $v1, $v15]}
    @{[vaesem_vs $v1, $v16]}
    @{[vaesem_vs $v1, $v17]}
    @{[vaesem_vs $v1, $v18]}
    @{[vaesem_vs $v1, $v19]}
    @{[vaesem_vs $v1, $v20]}
    @{[vaesem_vs $v1, $v21]}
    @{[vaesem_vs $v1, $v22]}
    @{[vaesem_vs $v1, $v23]}
    @{[vaesef_vs $v1, $v24]}

    @{[vse32_v $v1, ($OUTP)]}
    ret
.size L_enc_256,.-L_enc_256
___
}

################################################################################
# void rv64i_zvkned_decrypt(const unsigned char *in, unsigned char *out,
#                           const AES_KEY *key);
{
my ($INP,$OUTP,$KEYP) = ("a0", "a1", "a2");
my ($T0,$T1, $rounds, $T6) = ("a3", "a4", "t5", "t6");
my ($v0,  $v1,  $v2,  $v3,  $v4,  $v5,  $v6,
          $v7,  $v8,  $v9,  $v10, $v11, $v12,
          $v13, $v14, $v15, $v16, $v17, $v18,
          $v19, $v20, $v21, $v22, $v23, $v24,
) = map("v$_",(0..24));

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_decrypt
.type rv64i_zvkned_decrypt,\@function
rv64i_zvkned_decrypt:
    # Load number of rounds
    lwu     $rounds, 240($KEYP)

    # Get proper routine for key size
    li $T6, 14
    beq $rounds, $T6, L_dec_256
    li $T6, 10
    beq $rounds, $T6, L_dec_128

    j L_fail_m2
.size rv64i_zvkned_decrypt,.-rv64i_zvkned_decrypt
___

$code .= <<___;
.p2align 3
L_dec_128:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    @{[vle32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v20, ($KEYP)]}

    @{[vle32_v $v1, ($INP)]}

    @{[vaesz_vs $v1, $v20]}    # with round key w[43,47]
    @{[vaesdm_vs $v1, $v19]}   # with round key w[36,39]
    @{[vaesdm_vs $v1, $v18]}   # with round key w[32,35]
    @{[vaesdm_vs $v1, $v17]}   # with round key w[28,31]
    @{[vaesdm_vs $v1, $v16]}   # with round key w[24,27]
    @{[vaesdm_vs $v1, $v15]}   # with round key w[20,23]
    @{[vaesdm_vs $v1, $v14]}   # with round key w[16,19]
    @{[vaesdm_vs $v1, $v13]}   # with round key w[12,15]
    @{[vaesdm_vs $v1, $v12]}   # with round key w[ 8,11]
    @{[vaesdm_vs $v1, $v11]}   # with round key w[ 4, 7]
    @{[vaesdf_vs $v1, $v10]}   # with round key w[ 0, 3]

    @{[vse32_v $v1, ($OUTP)]}

    ret
.size L_dec_128,.-L_dec_128
___

$code .= <<___;
.p2align 3
L_dec_256:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    @{[vle32_v $v10, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v11, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v12, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v13, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v14, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v15, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v16, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v17, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v18, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v19, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v20, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v21, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v22, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v23, ($KEYP)]}
    addi $KEYP, $KEYP, 16
    @{[vle32_v $v24, ($KEYP)]}

    @{[vle32_v $v1, ($INP)]}

    @{[vaesz_vs $v1, $v24]}    # with round key w[56,59]
    @{[vaesdm_vs $v1, $v23]}   # with round key w[52,55]
    @{[vaesdm_vs $v1, $v22]}   # with round key w[48,51]
    @{[vaesdm_vs $v1, $v21]}   # with round key w[44,47]
    @{[vaesdm_vs $v1, $v20]}   # with round key w[40,43]
    @{[vaesdm_vs $v1, $v19]}   # with round key w[36,39]
    @{[vaesdm_vs $v1, $v18]}   # with round key w[32,35]
    @{[vaesdm_vs $v1, $v17]}   # with round key w[28,31]
    @{[vaesdm_vs $v1, $v16]}   # with round key w[24,27]
    @{[vaesdm_vs $v1, $v15]}   # with round key w[20,23]
    @{[vaesdm_vs $v1, $v14]}   # with round key w[16,19]
    @{[vaesdm_vs $v1, $v13]}   # with round key w[12,15]
    @{[vaesdm_vs $v1, $v12]}   # with round key w[ 8,11]
    @{[vaesdm_vs $v1, $v11]}   # with round key w[ 4, 7]
    @{[vaesdf_vs $v1, $v10]}   # with round key w[ 0, 3]

    @{[vse32_v $v1, ($OUTP)]}

    ret
.size L_dec_256,.-L_dec_256
___
}

$code .= <<___;
L_fail_m1:
    li a0, -1
    ret
.size L_fail_m1,.-L_fail_m1

L_fail_m2:
    li a0, -2
    ret
.size L_fail_m2,.-L_fail_m2
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
