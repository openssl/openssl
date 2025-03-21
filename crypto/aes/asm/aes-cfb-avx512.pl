#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2025, Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Implements AES-CFB128 encryption and decryption with Intel(R) VAES

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code=".text\n";

#################################################################
# Signature:
#
# void aes_cfb128_vaes_enc(
#     const unsigned char *in,
#     unsigned char *out,
#     size_t len,
#     const AES_KEY *ks,
#     const unsigned char ivec[16],
#     /*in-out*/ int *num);
#
# Preconditions:
# - all pointers are valid (not NULL...)
# - AES key schedule and rounds in `ks` are precomputed
#
# Invariants:
# - `*num` is between 0 and 15 (inclusive)
#################################################################

$code.=<<___;
.globl  aes_cfb128_vaes_enc
.type   aes_cfb128_vaes_enc,\@function,6
.align  16
aes_cfb128_vaes_enc:
.cfi_startproc
    endbranch
___

$inp="%rdi";          # arg0
$out="%rsi";          # arg1
$len="%rdx";          # arg2

$key_original="%rcx"; # arg3
$key_backup="%r10";
$key_crt="%r10";

$ivp="%r8";           # arg4
$nump="%r9";          # arg5

$num="%r11";
$left="%rcx";
$mask="%rax";

$rounds="%r11d";

$rnd0key="%xmm0";
$rndNkey="%xmm1";
$temp="%xmm2";
$plain="%xmm3";

sub vaes_encrypt_block_1x() {
    my ($aes_enc_loop_label)=@_;

$code.=<<___;
    vmovdqu ($key_crt),$rnd0key      # load round 0 key
    vmovdqu 16($key_crt),$rndNkey    # load round 1 key
    lea 32($key_crt),$key_crt        # $key_crt points to the 2nd round key
    vpxor $rnd0key,$temp,$temp       # AES pre-whitening

$aes_enc_loop_label:
    vaesenc $rndNkey,$temp,$temp     # AES encrypt with current round key
    dec $rounds
    vmovdqu ($key_crt),$rndNkey      # load next round key
    lea 16($key_crt),$key_crt        # $key_crt points to the next round key
    jnz $aes_enc_loop_label          # process all encryption rounds but the last

    vaesenclast $rndNkey,$temp,$temp # AES encrypt with the last round key
___
}

$code.=<<___;

    movsl ($nump),$num               # $num is the current byte index in the first partial block
                                     # $num belongs to 0..15; non-zero means a partial first block

    test $len,$len                   # return early if $len==0, unlikely to occur
    jz .Laes_cfb128_vaes_enc

    test $num,$num                   # check if the first block is partial
    jz .Laes_cfb128_enc_mid          # if not, jump to processing full blocks

###########################################################
# first partial block pre-processing
###########################################################

    mov $key_original,$key_backup    # make room for variable shl with cl

    mov \$0x10,$left                 # first block is partial
    sub $num,$left                   # calculate how many bytes $left to process in the block
    cmp $len,$left                   #
    cmova $len,$left                 # $left = min(16-$num,$len)

    mov \$1,$mask                    # build a mask with the least significant $left bits set
    shlq %cl,$mask                   # $left is left shift counter
    dec $mask                        # $mask is 2^$left-1
    kmovq $mask,%k1

    mov $num,%rax                    # keep in-out $num in %al
    add $left,%rax                   # advance $num
    and \$0x0F,%al                   # wrap-around $num in a 16-byte block

    leaq ($num,$ivp),%r11            # process $left iv bytes
    vmovdqu8 (%r11),%xmm0
    vmovdqu8 ($inp),%xmm1            # process $left input bytes
    vpxor %xmm0,%xmm1,%xmm2          # CipherFeedBack XOR
    vmovdqu8 %xmm2,($out){%k1}       # write $left output bytes
    vmovdqu8 %xmm2,(%r11){%k1}       # blend $left output bytes into iv

    add $left,$inp                   # advance pointers
    add $left,$out
    sub $left,$len
    jz .Laes_cfb128_enc_end          # return early if no AES encryption required

    mov $key_backup,$key_original    # restore "key_original" as arg3

.Laes_cfb128_enc_mid:

###########################################################
# inner full blocks processing
###########################################################

    vmovdqu ($ivp),$temp             # load iv

    cmp \$0x10,$len                  # is there a full plaintext block left (128 bits) ?
    jb .Laes_cfb128_enc_post

.Loop_aes_cfb128_enc_main:
    sub \$0x10,$len

    mov $key_original,$key_crt
    mov 240($key_original),$rounds   # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY

    vmovdqu ($inp),$plain            # load plaintext block
    lea 16($inp),$inp                # $inp points to next plaintext
___

    &vaes_encrypt_block_1x(".Loop_aes_cfb128_enc_main_inner");

$code.=<<___;
    vpxor $plain,$temp,$temp         # CipherFeedBack XOR
    cmp \$0x10,$len
    vmovdqu $temp,($out)             # write ciphertext
    lea 16($out),$out                # $out points to the next output block
    jge .Loop_aes_cfb128_enc_main

    xor %eax,%eax                    # reset num when processing full blocks

    vmovdqu $temp,($ivp)             # latest ciphertext block is next encryption input

.Laes_cfb128_enc_post:

###########################################################
# last partial block post-processing
###########################################################

    test $len,$len                   # check if the last block is partial
    jz .Laes_cfb128_enc_end

    mov $key_original,$key_crt
    mov 240($key_original),$rounds   # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY
___

    &vaes_encrypt_block_1x(".Loop_aes_cfb128_enc_post_inner");

$code.=<<___;
    mov $len,%rax                    # num=$len

    mov \$1,%r11                     # build a mask with the least significant $len bits set
    mov %dl,%cl                      # $len is left shift counter less than 16
    shlq %cl,%r11
    dec %r11                         # mask is 2^$len-1
    kmovq %r11,%k1

    vmovdqu8 ($inp),%xmm1{%k1}{z}    # read $len input bytes, zero the rest to not impact XOR
    vpxor $temp,%xmm1,%xmm0          # CipherFeedBack XOR
    vmovdqu8 %xmm0,($out){%k1}       # write $len output bytes
    vmovdqu8 %xmm0,($ivp)            # write chained/streaming iv

.Laes_cfb128_enc_end:

    mov %eax,($nump)                 # num is in/out, update for future/chained calls

    # zeroize
    vpxor $rnd0key,$rnd0key,$rnd0key
    vpxor $rndNkey,$rndNkey,$rndNkey
    vpxor $plain,$plain,$plain
    vpxor $temp,$temp,$temp

.Laes_cfb128_vaes_enc:
    ret
.cfi_endproc
.size aes_cfb128_vaes_enc,.-aes_cfb128_vaes_enc
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
