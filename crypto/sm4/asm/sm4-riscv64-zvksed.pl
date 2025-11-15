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

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector Cryptography Bit-manipulation extension ('Zvkb')
# - RISC-V Vector SM4 Block Cipher extension ('Zvksed')

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

my ($V0, $V1, $V2, $V3, $V4, $V5, $V6, $V7,
    $V8, $V9, $V10, $V11, $V12, $V13, $V14, $V15,
    $V16, $V17, $V18, $V19, $V20, $V21, $V22, $V23,
    $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map("v$_",(0..31));

# Load 32 round keys to v1-v8 registers.
sub enc_load_key {
    my $keys = shift;

    my $code=<<___;
    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]} 
    @{[vle32_v $V16, $keys]} # rk[0:3]  
    addi $keys, $keys, 16
    @{[vle32_v $V17, $keys]} # rk[4:7]
    addi $keys, $keys, 16
    @{[vle32_v $V18, $keys]} # rk[8:11]
    addi $keys, $keys, 16
    @{[vle32_v $V19, $keys]} # rk[12:15]
    addi $keys, $keys, 16
    @{[vle32_v $V20, $keys]} # rk[16:19]
    addi $keys, $keys, 16
    @{[vle32_v $V21, $keys]} # rk[20:23]
    addi $keys, $keys, 16
    @{[vle32_v $V22, $keys]} # rk[24:27]
    addi $keys, $keys, 16
    @{[vle32_v $V23, $keys]} # rk[28:31]    
___

    return $code;
}

sub dec_load_key {
    my $keys = shift;

    my $code=<<___;
    @{[vle32_v $V23, $keys]} # rk[31:28]
    addi $keys, $keys, 16
    @{[vle32_v $V22, $keys]} # rk[27:24]
    addi $keys, $keys, 16
    @{[vle32_v $V21, $keys]} # rk[23:20]
    addi $keys, $keys, 16
    @{[vle32_v $V20, $keys]} # rk[19:16]
    addi $keys, $keys, 16
    @{[vle32_v $V19, $keys]} # rk[15:12]
    addi $keys, $keys, 16
    @{[vle32_v $V18, $keys]} # rk[11:8]
    addi $keys, $keys, 16
    @{[vle32_v $V17, $keys]} # rk[7:4]
    addi $keys, $keys, 16
    @{[vle32_v $V16, $keys]} # rk[3:0]   
___

    return $code;
}

# sm4 encryption with round keys v1-v8
sub enc_blk {
    my $data = shift;

    my $code=<<___;
    @{[vrev8_v $data, $data]}
    @{[vsm4r_vs $data, $V16]}
    @{[vsm4r_vs $data, $V17]}
    @{[vsm4r_vs $data, $V18]}
    @{[vsm4r_vs $data, $V19]}
    @{[vsm4r_vs $data, $V20]}
    @{[vsm4r_vs $data, $V21]}
    @{[vsm4r_vs $data, $V22]}
    @{[vsm4r_vs $data, $V23]}
    @{[vrev8_v $data, $data]}
___

    return $code;
}

# sm4 decryption with round keys v1-v8
sub dec_blk {
    my $data = shift;

    my $code=<<___;
    @{[vrev8_v $data, $data]}
    @{[vsm4r_vs $data, $V23]}
    @{[vsm4r_vs $data, $V22]}
    @{[vsm4r_vs $data, $V21]}
    @{[vsm4r_vs $data, $V20]}
    @{[vsm4r_vs $data, $V19]}
    @{[vsm4r_vs $data, $V18]}
    @{[vsm4r_vs $data, $V17]}
    @{[vsm4r_vs $data, $V16]}
    @{[vrev8_v $data, $data]}
___

    return $code;
}

sub dec_4blks {
    my $data0 = shift;
    my $data1 = shift;
    my $data2 = shift;
    my $data3 = shift;

    my $code=<<___;
    @{[vsm4r_vs $data0, $V23]}
    @{[vsm4r_vs $data1, $V23]}
    @{[vsm4r_vs $data2, $V23]}
    @{[vsm4r_vs $data3, $V23]}

    @{[vsm4r_vs $data0, $V22]}
    @{[vsm4r_vs $data1, $V22]}
    @{[vsm4r_vs $data2, $V22]}
    @{[vsm4r_vs $data3, $V22]}

    @{[vsm4r_vs $data0, $V21]}
    @{[vsm4r_vs $data1, $V21]}
    @{[vsm4r_vs $data2, $V21]}
    @{[vsm4r_vs $data3, $V21]}

    @{[vsm4r_vs $data0, $V20]}
    @{[vsm4r_vs $data1, $V20]}
    @{[vsm4r_vs $data2, $V20]}
    @{[vsm4r_vs $data3, $V20]}

    @{[vsm4r_vs $data0, $V19]}
    @{[vsm4r_vs $data1, $V19]}
    @{[vsm4r_vs $data2, $V19]}
    @{[vsm4r_vs $data3, $V19]}

    @{[vsm4r_vs $data0, $V18]}
    @{[vsm4r_vs $data1, $V18]}
    @{[vsm4r_vs $data2, $V18]}
    @{[vsm4r_vs $data3, $V18]}

    @{[vsm4r_vs $data0, $V17]}
    @{[vsm4r_vs $data1, $V17]}
    @{[vsm4r_vs $data2, $V17]}
    @{[vsm4r_vs $data3, $V17]}  

    @{[vsm4r_vs $data0, $V16]}
    @{[vsm4r_vs $data1, $V16]}
    @{[vsm4r_vs $data2, $V16]}
    @{[vsm4r_vs $data3, $V16]}  
___

    return $code;
}

####
# void rv64i_zvksed_sm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
#                                   size_t len, const SM4_KEY *key,
#                                   unsigned char *iv, const int enc);
#
{
my ($in,$out,$len,$keys,$ivp)=("a0","a1","a2","a3","a4");
my ($tmp,$stride,$base)=("t0","t1","t2");

$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_cbc_encrypt
.type rv64i_zvksed_sm4_cbc_encrypt,\@function
rv64i_zvksed_sm4_cbc_encrypt:
    # check whether the length is a multiple of 16 and >= 16
    li $tmp, 16
    bltu $len, $tmp, .Lcbc_enc_end  
    andi $tmp, $len, 15          
    bnez $tmp, .Lcbc_enc_end          

    # Load 32 round keys to v1-v8 registers.
    @{[enc_load_key $keys]}   

    # Load IV
    @{[vle32_v $V8, $ivp]}

.Lcbc_enc_loop:
    li $tmp, 64
    bltu $len, $tmp, .Lcbc_enc_single 
    # Load input data0-data3
    @{[vle32_v $V1, $in]}
    addi $in, $in, 16
    @{[vle32_v $V2, $in]}
    addi $in, $in, 16
    @{[vle32_v $V3, $in]}
    addi $in, $in, 16
    @{[vle32_v $V4, $in]}
    addi $in, $in, 16
    #XOR with IV                             
    @{[vxor_vv $V1, $V1, $V8]}  

    @{[enc_blk $V1]}

    li $stride, -4
    addi $base, $out, 12
    @{[vsse32_v $V1, $base, $stride]}
    #Update IV to ciphertext block 0
    @{[vle32_v $V8, $out]}  
    addi $out, $out, 16 

    @{[vxor_vv $V2, $V2, $V8]}

    @{[enc_blk $V2]}

    addi $base, $out, 12
    @{[vsse32_v $V2, $base, $stride]}
    #Update IV to ciphertext block 1
    @{[vle32_v $V8, $out]}  
    addi $out, $out, 16 

    @{[vxor_vv $V3, $V3, $V8]}

    @{[enc_blk $V3]}

    addi $base, $out, 12
    @{[vsse32_v $V3, $base, $stride]}
    #Update IV to ciphertext block 2
    @{[vle32_v $V8, $out]}   
    addi $out, $out, 16 

    @{[vxor_vv $V4, $V4, $V8]}

    @{[enc_blk $V4]}

    addi $base, $out, 12
    @{[vsse32_v $V4, $base, $stride]}
    #Update IV to ciphertext block 3
    @{[vle32_v $V8, $out]} 
    addi $out, $out, 16  

    addi $len, $len, -64
    bnez $len, .Lcbc_enc_loop
    #Save the final IV
    @{[vse32_v $V8, $ivp]}
    ret

.Lcbc_enc_single:
    # Load input data0
    @{[vle32_v $V1, $in]}  
    addi $in, $in, 16
    # XOR with IV                                                      
    @{[vxor_vv $V1, $V1, $V8]}  
    
    # Encrypt with all keys    
    @{[enc_blk $V1]}

    # Save the ciphertext (in reverse element order)
    li $stride, -4     
    addi $base, $out, 12
    @{[vsse32_v $V1, $base, $stride]}  

    # Update IV to ciphertext block 0
    @{[vle32_v $V8, $out]}  
    addi $out, $out, 16
    addi $len, $len, -16

    li $tmp, 16
    bgeu $len, $tmp, .Lcbc_enc_single  
    # Save the final IV
    @{[vse32_v $V8, $ivp]}
.Lcbc_enc_end:
    ret
.size rv64i_zvksed_sm4_cbc_encrypt,.-rv64i_zvksed_sm4_cbc_encrypt
___

####
# void rv64i_zvksed_sm4_cbc_decrypt(const unsigned char *in, unsigned char *out,
#                                   size_t len, const SM4_KEY *key,
#                                   unsigned char *iv, const int enc); 
#
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_cbc_decrypt
.type rv64i_zvksed_sm4_cbc_decrypt,\@function
rv64i_zvksed_sm4_cbc_decrypt:
    # check whether the length is a multiple of 16 and >= 16
    li $tmp, 16
    bltu $len, $tmp, .Lcbc_dec_end 
    andi $tmp, $len, 15          
    bnez $tmp, .Lcbc_dec_end          

    @{[vsetivli "zero", 4, "e32", "m1", "ta", "ma"]}
    # Load IV (in reverse element order)
    li $stride, -4   
    addi $base, $ivp, 12
    @{[vlse32_v $V8, $base, $stride]}  

    # Load 32 round keys 
    @{[dec_load_key $keys]}

.Lcbc_dec_loop:
    li $tmp, 128
    bltu $len, $tmp, .Lcbc_check_64 
    # Load input data0-data7
    @{[vle32_v $V1, $in]}
    addi $in, $in, 16
    @{[vle32_v $V2, $in]}
    addi $in, $in, 16
    @{[vle32_v $V3, $in]}
    addi $in, $in, 16
    @{[vle32_v $V4, $in]}
    addi $in, $in, 16
    @{[vle32_v $V5, $in]}
    addi $in, $in, 16
    @{[vle32_v $V6, $in]}
    addi $in, $in, 16
    @{[vle32_v $V7, $in]}
    addi $in, $in, 16
    @{[vle32_v $V24, $in]}
    addi $in, $in, 16

    @{[vrev8_v $V1, $V1]}
    @{[vrev8_v $V2, $V2]}
    @{[vrev8_v $V3, $V3]}
    @{[vrev8_v $V4, $V4]}
    @{[vrev8_v $V5, $V5]}
    @{[vrev8_v $V6, $V6]}
    @{[vrev8_v $V7, $V7]}
    @{[vrev8_v $V24, $V24]}

    # Decrypt 8 data blocks
    @{[dec_4blks $V1,$V2,$V3,$V4]}
    @{[dec_4blks $V5,$V6,$V7,$V24]}
   
    @{[vrev8_v $V1, $V1]}
    @{[vrev8_v $V2, $V2]}
    @{[vrev8_v $V3, $V3]}
    @{[vrev8_v $V4, $V4]}
    @{[vrev8_v $V5, $V5]}
    @{[vrev8_v $V6, $V6]}
    @{[vrev8_v $V7, $V7]}
    @{[vrev8_v $V24, $V24]}
    
    @{[vxor_vv $V1, $V1, $V8]}  

    # Update ciphertext to IV (in reverse element order)
    addi $base, $in, -128   
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}  
    # Save the plaintext (in reverse element order)  
    addi $base, $out, 12
    @{[vsse32_v $V1, $base, $stride]}    
    addi $out, $out, 16

    @{[vxor_vv $V2, $V2, $V8]} 

    addi $base, $in, -112  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V2, $base, $stride]}   
    addi $out, $out, 16    

    @{[vxor_vv $V3, $V3, $V8]} 

    addi $base, $in, -96  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V3, $base, $stride]}  
    addi $out, $out, 16    

    @{[vxor_vv $V4, $V4, $V8]} 

    addi $base, $in, -80 
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V4, $base, $stride]}   
    addi $out, $out, 16    

    @{[vxor_vv $V5, $V5, $V8]} 

    addi $base, $in, -64  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}    
    addi $base, $out, 12
    @{[vsse32_v $V5, $base, $stride]}   
    addi $out, $out, 16   

    @{[vxor_vv $V6, $V6, $V8]} 

    addi $base, $in, -48  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V6, $base, $stride]}  
    addi $out, $out, 16   

    @{[vxor_vv $V7, $V7, $V8]} 

    addi $base, $in, -32   
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}    
    addi $base, $out, 12
    @{[vsse32_v $V7, $base, $stride]}   
    addi $out, $out, 16   

    @{[vxor_vv $V24, $V24, $V8]} 

    addi $base, $in, -16   
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V24, $base, $stride]}  
    addi $out, $out, 16   

    addi $len, $len, -128
    bnez $len, .Lcbc_dec_loop
    #Save the final IV (in reverse element order)
    addi $base, $ivp, 12
    @{[vsse32_v $V8, $base, $stride]}
    ret

.Lcbc_check_64:
    li $tmp, 64
    bltu $len, $tmp, .Lcbc_dec_single  
    # Load input data0-data3
    @{[vle32_v $V1, $in]}
    addi $in, $in, 16
    @{[vle32_v $V2, $in]}
    addi $in, $in, 16
    @{[vle32_v $V3, $in]}
    addi $in, $in, 16
    @{[vle32_v $V4, $in]}
    addi $in, $in, 16

    @{[vrev8_v $V1, $V1]}
    @{[vrev8_v $V2, $V2]}
    @{[vrev8_v $V3, $V3]}
    @{[vrev8_v $V4, $V4]}

    # Decrypt 4 data blocks
    @{[dec_4blks $V1,$V2,$V3,$V4]}  
    
    @{[vrev8_v $V1, $V1]}
    @{[vrev8_v $V2, $V2]}
    @{[vrev8_v $V3, $V3]}
    @{[vrev8_v $V4, $V4]}

    @{[vxor_vv $V1, $V1, $V8]} 

    # Update ciphertext to IV (in reverse element order)
    addi $base, $in, -64  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}  
    # Save the plaintext (in reverse element order) 
    addi $base, $out, 12
    @{[vsse32_v $V1, $base, $stride]}   
    addi $out, $out, 16   

    @{[vxor_vv $V2, $V2, $V8]} 

    addi $base, $in, -48  
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}   
    addi $base, $out, 12
    @{[vsse32_v $V2, $base, $stride]}   
    addi $out, $out, 16   

    @{[vxor_vv $V3, $V3, $V8]} 

    addi $base, $in, -32   
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}      
    addi $base, $out, 12
    @{[vsse32_v $V3, $base, $stride]}   
    addi $out, $out, 16   

    @{[vxor_vv $V4, $V4, $V8]} 

    addi $base, $in, -16   
    addi $base, $base, 12  
    @{[vlse32_v $V8, $base, $stride]}     
    addi $base, $out, 12
    @{[vsse32_v $V4, $base, $stride]}   
    addi $out, $out, 16   

    addi $len, $len, -64
    bnez $len, .Lcbc_check_64
    #Save the final IV (in reverse element order)
    addi $base, $ivp, 12
    @{[vsse32_v $V8, $base, $stride]}
    ret

.Lcbc_dec_single:
    # Load input data0
    @{[vle32_v $V1, $in]}  
    addi $in, $in, 16

    # Decrypt with all keys   
    @{[dec_blk $V1]}

    #XOR with IV
    @{[vxor_vv $V1, $V1, $V8]}  

    # Update ciphertext to IV (in reverse element order)
    li $stride, -4
    addi $base, $in, -16   
    addi $base, $base, 12   
    @{[vlse32_v $V8, $base, $stride]} 

    # Save the plaintext (in reverse element order) 
    li $stride, -4
    addi $base, $out, 12
    @{[vsse32_v $V1, $base, $stride]}   
    addi $out, $out, 16
    addi $len, $len, -16

    li $tmp, 16
    bgeu $len, $tmp, .Lcbc_dec_single  
    #Save the final IV (in reverse element order)
    li $stride, -4
    addi $base, $ivp, 12
    @{[vsse32_v $V8, $base, $stride]}
.Lcbc_dec_end:
    ret
.size rv64i_zvksed_sm4_cbc_decrypt,.-rv64i_zvksed_sm4_cbc_decrypt
___
}

####
# int rv64i_zvksed_sm4_set_encrypt_key(const unsigned char *userKey,
#                                      SM4_KEY *key);
#
{
my ($ukey,$keys,$fk)=("a0","a1","t0");
my ($vukey,$vfk,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_set_encrypt_key
.type rv64i_zvksed_sm4_set_encrypt_key,\@function
rv64i_zvksed_sm4_set_encrypt_key:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Load the user key
    @{[vle32_v $vukey, $ukey]}
    @{[vrev8_v $vukey, $vukey]}

    # Load the FK.
    la $fk, FK
    @{[vle32_v $vfk, $fk]}

    # Generate round keys.
    @{[vxor_vv $vukey, $vukey, $vfk]}
    @{[vsm4k_vi $vk0, $vukey, 0]} # rk[0:3]
    @{[vsm4k_vi $vk1, $vk0, 1]} # rk[4:7]
    @{[vsm4k_vi $vk2, $vk1, 2]} # rk[8:11]
    @{[vsm4k_vi $vk3, $vk2, 3]} # rk[12:15]
    @{[vsm4k_vi $vk4, $vk3, 4]} # rk[16:19]
    @{[vsm4k_vi $vk5, $vk4, 5]} # rk[20:23]
    @{[vsm4k_vi $vk6, $vk5, 6]} # rk[24:27]
    @{[vsm4k_vi $vk7, $vk6, 7]} # rk[28:31]

    # Store round keys
    @{[vse32_v $vk0, $keys]} # rk[0:3]
    addi $keys, $keys, 16
    @{[vse32_v $vk1, $keys]} # rk[4:7]
    addi $keys, $keys, 16
    @{[vse32_v $vk2, $keys]} # rk[8:11]
    addi $keys, $keys, 16
    @{[vse32_v $vk3, $keys]} # rk[12:15]
    addi $keys, $keys, 16
    @{[vse32_v $vk4, $keys]} # rk[16:19]
    addi $keys, $keys, 16
    @{[vse32_v $vk5, $keys]} # rk[20:23]
    addi $keys, $keys, 16
    @{[vse32_v $vk6, $keys]} # rk[24:27]
    addi $keys, $keys, 16
    @{[vse32_v $vk7, $keys]} # rk[28:31]

    li a0, 1
    ret
.size rv64i_zvksed_sm4_set_encrypt_key,.-rv64i_zvksed_sm4_set_encrypt_key
___
}

####
# int rv64i_zvksed_sm4_set_decrypt_key(const unsigned char *userKey,
#                                      SM4_KEY *key);
#
{
my ($ukey,$keys,$fk,$stride)=("a0","a1","t0","t1");
my ($vukey,$vfk,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_set_decrypt_key
.type rv64i_zvksed_sm4_set_decrypt_key,\@function
rv64i_zvksed_sm4_set_decrypt_key:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Load the user key
    @{[vle32_v $vukey, $ukey]}
    @{[vrev8_v $vukey, $vukey]}

    # Load the FK.
    la $fk, FK
    @{[vle32_v $vfk, $fk]}

    # Generate round keys.
    @{[vxor_vv $vukey, $vukey, $vfk]}
    @{[vsm4k_vi $vk0, $vukey, 0]} # rk[0:3]
    @{[vsm4k_vi $vk1, $vk0, 1]} # rk[4:7]
    @{[vsm4k_vi $vk2, $vk1, 2]} # rk[8:11]
    @{[vsm4k_vi $vk3, $vk2, 3]} # rk[12:15]
    @{[vsm4k_vi $vk4, $vk3, 4]} # rk[16:19]
    @{[vsm4k_vi $vk5, $vk4, 5]} # rk[20:23]
    @{[vsm4k_vi $vk6, $vk5, 6]} # rk[24:27]
    @{[vsm4k_vi $vk7, $vk6, 7]} # rk[28:31]

    # Store round keys in reverse order
    addi $keys, $keys, 12
    li $stride, -4
    @{[vsse32_v $vk7, $keys, $stride]} # rk[31:28]
    addi $keys, $keys, 16
    @{[vsse32_v $vk6, $keys, $stride]} # rk[27:24]
    addi $keys, $keys, 16
    @{[vsse32_v $vk5, $keys, $stride]} # rk[23:20]
    addi $keys, $keys, 16
    @{[vsse32_v $vk4, $keys, $stride]} # rk[19:16]
    addi $keys, $keys, 16
    @{[vsse32_v $vk3, $keys, $stride]} # rk[15:12]
    addi $keys, $keys, 16
    @{[vsse32_v $vk2, $keys, $stride]} # rk[11:8]
    addi $keys, $keys, 16
    @{[vsse32_v $vk1, $keys, $stride]} # rk[7:4]
    addi $keys, $keys, 16
    @{[vsse32_v $vk0, $keys, $stride]} # rk[3:0]

    li a0, 1
    ret
.size rv64i_zvksed_sm4_set_decrypt_key,.-rv64i_zvksed_sm4_set_decrypt_key
___
}

####
# void rv64i_zvksed_sm4_encrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_encrypt
.type rv64i_zvksed_sm4_encrypt,\@function
rv64i_zvksed_sm4_encrypt:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Order of elements was adjusted in set_encrypt_key()
    @{[vle32_v $vk0, $keys]} # rk[0:3]
    addi $keys, $keys, 16
    @{[vle32_v $vk1, $keys]} # rk[4:7]
    addi $keys, $keys, 16
    @{[vle32_v $vk2, $keys]} # rk[8:11]
    addi $keys, $keys, 16
    @{[vle32_v $vk3, $keys]} # rk[12:15]
    addi $keys, $keys, 16
    @{[vle32_v $vk4, $keys]} # rk[16:19]
    addi $keys, $keys, 16
    @{[vle32_v $vk5, $keys]} # rk[20:23]
    addi $keys, $keys, 16
    @{[vle32_v $vk6, $keys]} # rk[24:27]
    addi $keys, $keys, 16
    @{[vle32_v $vk7, $keys]} # rk[28:31]

    # Load input data
    @{[vle32_v $vdata, $in]}
    @{[vrev8_v $vdata, $vdata]}

    # Encrypt with all keys
    @{[vsm4r_vs $vdata, $vk0]}
    @{[vsm4r_vs $vdata, $vk1]}
    @{[vsm4r_vs $vdata, $vk2]}
    @{[vsm4r_vs $vdata, $vk3]}
    @{[vsm4r_vs $vdata, $vk4]}
    @{[vsm4r_vs $vdata, $vk5]}
    @{[vsm4r_vs $vdata, $vk6]}
    @{[vsm4r_vs $vdata, $vk7]}

    # Save the ciphertext (in reverse element order)
    @{[vrev8_v $vdata, $vdata]}
    li $stride, -4
    addi $out, $out, 12
    @{[vsse32_v $vdata, $out, $stride]}

    ret
.size rv64i_zvksed_sm4_encrypt,.-rv64i_zvksed_sm4_encrypt
___
}

####
# void rv64i_zvksed_sm4_decrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_decrypt
.type rv64i_zvksed_sm4_decrypt,\@function
rv64i_zvksed_sm4_decrypt:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # Order of elements was adjusted in set_decrypt_key()
    @{[vle32_v $vk7, $keys]} # rk[31:28]
    addi $keys, $keys, 16
    @{[vle32_v $vk6, $keys]} # rk[27:24]
    addi $keys, $keys, 16
    @{[vle32_v $vk5, $keys]} # rk[23:20]
    addi $keys, $keys, 16
    @{[vle32_v $vk4, $keys]} # rk[19:16]
    addi $keys, $keys, 16
    @{[vle32_v $vk3, $keys]} # rk[15:11]
    addi $keys, $keys, 16
    @{[vle32_v $vk2, $keys]} # rk[11:8]
    addi $keys, $keys, 16
    @{[vle32_v $vk1, $keys]} # rk[7:4]
    addi $keys, $keys, 16
    @{[vle32_v $vk0, $keys]} # rk[3:0]

    # Load input data
    @{[vle32_v $vdata, $in]}
    @{[vrev8_v $vdata, $vdata]}

    # Encrypt with all keys
    @{[vsm4r_vs $vdata, $vk7]}
    @{[vsm4r_vs $vdata, $vk6]}
    @{[vsm4r_vs $vdata, $vk5]}
    @{[vsm4r_vs $vdata, $vk4]}
    @{[vsm4r_vs $vdata, $vk3]}
    @{[vsm4r_vs $vdata, $vk2]}
    @{[vsm4r_vs $vdata, $vk1]}
    @{[vsm4r_vs $vdata, $vk0]}

    # Save the ciphertext (in reverse element order)
    @{[vrev8_v $vdata, $vdata]}
    li $stride, -4
    addi $out, $out, 12
    @{[vsse32_v $vdata, $out, $stride]}

    ret
.size rv64i_zvksed_sm4_decrypt,.-rv64i_zvksed_sm4_decrypt
___
}

$code .= <<___;
# Family Key (little-endian 32-bit chunks)
.p2align 3
FK:
    .word 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
.size FK,.-FK
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
