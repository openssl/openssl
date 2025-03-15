#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2025, Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Implements AES-CFB encryption and decryption using AES-NI and VAES

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
# void aesni_aescfb128_enc(
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
# - `*num` is between 0 and 15
#################################################################

$code.=<<___;
.globl  aesni_aescfb128_enc
.type   aesni_aescfb128_enc,\@function,6
.align  16
aesni_aescfb128_enc:
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

$idx="%r11";
$left="%rcx";
$mask="%rax";

$rounds="%r11d";

$rnd0key="%xmm0";
$rndNkey="%xmm1";
$temp="%xmm2";
$plain="%xmm3";

$code.=<<___;

    movsl ($nump),$idx               # nump points to the byte index in the first partial block
                                     # $idx belongs to 0..15; non-zero means a partial first block

    test $len,$len                   # return early if $len==0
    jz .Laesni_aescfb128_enc  

    test $idx,$idx                   # check if the first block is partial
    jz .Lcfb128_enc_mid  

    mov $key_original,$key_backup    # make room for variable shl with cl

    mov \$0x10,$left                 # first block is partial
    sub $idx,$left                   # calculate how many bytes $left to process in the block
    cmp $len,$left                   #
    cmova $len,$left                 # $left = min(16-$idx,$len)

    mov \$1,$mask                    # build a mask with the least significant $left bits set
    shlq %cl,$mask                   # $left is left shift counter
    dec $mask                        # $mask is 2^$left-1
    kmovq $mask,%k1  

    mov $idx,%rax                    # keep in-out num in %al
    add $left,%rax                   # advance num
    and \$0x0F,%al                   # wrap-around in a 16-byte block

    leaq ($idx,$ivp),%r11            # read $left iv bytes
    vmovdqu8 (%r11),%xmm0{%k1}  
    vmovdqu8 ($inp),%xmm1{%k1}       # read $left input bytes
    vpxorq %xmm0,%xmm1,%xmm2         # CipherFeedBack XOR
    vmovdqu8 %xmm2,($out){%k1}       # write $left output bytes
    vmovdqu8 %xmm2,(%r11){%k1}       # write $left chained/streaming input bytes

    add $left,$inp                   # advance pointers
    add $left,$out  
    sub $left,$len  
    jz .Lcfb128_enc_end              # return early if no AES encryption required

    mov $key_backup,$key_original    # restore "key_original" as arg3

.Lcfb128_enc_mid:  

    vmovups ($ivp),$temp             # load iv

    cmp \$0x10,$len                  # any full plaintext blocks left ?
    jb .Lcfb128_enc_post  

.Lcfb128_enc_main_loop:  
    sub \$0x10,$len  

    mov $key_original,$key_crt  
    mov 240($key_crt),$rounds        # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY

    vmovups ($inp),$plain            # load plaintext block
    lea 16($inp),$inp                # inp points to next plaintext

    vmovups ($key_crt),$rnd0key      # load round 0 key
    vmovups 16($key_crt),$rndNkey    # load round 1 key
    lea 32($key_crt),$key_crt        # key points to the 2nd round key
    xorps $rnd0key,$temp             # pre-whitening
.Loop_aesenc:  
    aesenc $rndNkey,$temp            # encrypt with current round key
    dec $rounds  
    vmovups ($key_crt),$rndNkey      # load next round key
    lea 16($key_crt),$key_crt        # key points to the next round key
    jnz .Loop_aesenc                 # process all encryption rounds but the last

    aesenclast $rndNkey,$temp        # encrypt with the last round key

    xorps $plain,$temp               # CipherFeedBack XOR
    cmp \$0x10,$len  
    vmovups $temp,($out)             # write ciphertext
    lea 16($out),$out                # out points to the next output block
    jge .Lcfb128_enc_main_loop  

    xor %eax,%eax                    # reset num when processing full blocks

    vmovups $temp,($ivp)             # latest ciphertext block is next encryption input

.Lcfb128_enc_post:  

    test $len,$len  
    jz .Lcfb128_enc_end  

    mov $key_original,$key_crt  
    mov 240($key_crt),$rounds        # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY

    vmovups ($key_crt),$rnd0key      # load round 0 key
    vmovups 16($key_crt),$rndNkey    # load round 1 key
    lea 32($key_crt),$key_crt        # key points to the 2nd round key
    xorps $rnd0key,$temp             # pre-whitening

.Loop_aesenc2:  
    aesenc $rndNkey,$temp            # encrypt with current round key
    dec $rounds  
    vmovups ($key_crt),$rndNkey      # load next round key
    lea 16($key_crt),$key_crt        # key points to the next round key
    jnz .Loop_aesenc2                # process all encryption rounds but the last

    aesenclast $rndNkey,$temp        # encrypt with the last round key

    mov $len,%rax                    # num=$len
    mov \$1,%r11                     # build a mask with the least significant $len bits set
    mov %dl,%cl                      # $len is left shift counter less than 16
    shlq %cl,%r11  
    dec %r11                         # mask is 2^$len-1
    kmovq %r11,%k1  

    vmovdqu8 ($inp),%xmm1{%k1}{z}    # read $len input bytes
    vpxorq $temp,%xmm1,%xmm0         # CipherFeedBack XOR
    vmovdqu8 %xmm0,($out){%k1}       # write $len output bytes
    vmovdqu8 %xmm0,($ivp)            # write $len chained/streaming input bytes

.Lcfb128_enc_end:  

    mov %eax,($nump)                 # num is in/out, update for future/chained calls

    vpxor $rnd0key,$rnd0key,$rnd0key # zeroize
    vpxor $rndNkey,$rndNkey,$rndNkey # zeroize
    vpxor $plain,$plain,$plain       # zeroize
    vpxor $temp,$temp,$temp          # zeroize

.Laesni_aescfb128_enc:
    ret
.cfi_endproc
.size aesni_aescfb128_enc,.-aesni_aescfb128_enc
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
