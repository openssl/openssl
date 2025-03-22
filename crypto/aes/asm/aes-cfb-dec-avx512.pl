#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2025, Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Implements AES-CFB128 decryption with Intel(R) VAES

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

$code="";

$code.=<<___;
.text
___

#################################################################
# Signature:
#
# void aes_cfb128_vaes_dec(
#     const unsigned char *in,
#     unsigned char *out,
#     size_t len,
#     const AES_KEY *ks,
#     const unsigned char ivec[16],
#     /*in-out*/ ossl_ssize_t *num);
#
# Preconditions:
# - all pointers are valid (not NULL...)
# - AES key schedule and rounds in `ks` are precomputed
#
# Invariants:
# - `*num` is between 0 and 15 (inclusive)
#################################################################

$code.=<<___;
.globl   aes_cfb128_vaes_dec
.type    aes_cfb128_vaes_dec,\@function,6
.balign  32
aes_cfb128_vaes_dec:
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
$rnd0key_4x="%zmm0";

$rndNkey="%xmm1";
$rndNkey_4x="%zmm1";

$temp="%xmm2";
$temp_4x="%zmm2";
$temp_8x="%zmm4";

$cipher="%xmm3";
$cipher_4x="%zmm3";
$cipher_8x="%zmm5";

sub vaes_encrypt_block_1x() {
    my ($aes_enc_loop_label)=@_;
$code.=<<___;
    vmovdqu ($key_crt),$rnd0key       # load round 0 key
    vmovdqu 16($key_crt),$rndNkey     # load round 1 key
    lea 32($key_crt),$key_crt         # $key_crt points to the 2nd round key
    vpxor $rnd0key,$temp,$temp        # AES pre-whitening

.balign 32
$aes_enc_loop_label:
    vaesenc $rndNkey,$temp,$temp      # AES encrypt with current round key
    dec $rounds
    vmovdqu ($key_crt),$rndNkey       # load next round key
    lea 16($key_crt),$key_crt         # $key_crt points to the next round key
    jnz $aes_enc_loop_label           # process all encryption rounds but the last
    vaesenclast $rndNkey,$temp,$temp  # AES encrypt with the last round key
___
}

$code.=<<___;

    mov ($nump),$num                  # $num is the current byte index in the first partial block
                                      # $num belongs to 0..15; non-zero means a partial first block

    test $len,$len                    # return early if $len==0, unlikely to occur
    jz .Laes_cfb128_vaes_dec

    test $num,$num                    # check if the first block is partial
    jz .Laes_cfb128_dec_mid           # if not, jump to processing full blocks

###########################################################
# first partial block pre-processing
###########################################################

    mov $key_original,$key_backup     # make room for variable shl with cl

    mov \$0x10,$left                  # first block is partial
    sub $num,$left                    # calculate how many bytes $left to process in the block
    cmp $len,$left                    #
    cmova $len,$left                  # $left = min(16-$num,$len)

    mov \$1,$mask                     # build a mask with the least significant $left bits set
    shlq %cl,$mask                    # $left is left shift counter
    dec $mask                         # $mask is 2^$left-1
    kmovq $mask,%k1

    mov $num,%rax                     # keep in-out num in %al
    add $left,%rax                    # advance $num
    and \$0x0F,%al                    # wrap-around $num in a 16-byte block

    leaq ($num,$ivp),%r11             # process $left iv bytes
    vmovdqu8 (%r11),%xmm0
    vmovdqu8 ($inp),%xmm1             # process $left input bytes
    vpxor %xmm0,%xmm1,%xmm2           # CipherFeedBack XOR
    vmovdqu8 %xmm2,($out){%k1}        # write $left output bytes
    vmovdqu8 %xmm1,(%r11){%k1}        # blend $left input bytes into iv

    add $left,$inp                    # advance pointers
    add $left,$out
    sub $left,$len
    jz .Laes_cfb128_dec_end           # return early if no AES encryption required

    mov $key_backup,$key_original     # restore "key_original" as arg3

.Laes_cfb128_dec_mid:

###########################################################
# inner full blocks processing
###########################################################

    # $temp_4x is "iv | iv | iv | iv"
    vbroadcasti32x4 ($ivp),$temp_4x           # load iv

    cmp \$0x80,$len                           # are there 8 ciphertext blocks left (1024 bits) ?
    jb .Laes_cfb128_dec_check_4x

###########################################################
# decrypt groups of 8 128-bit blocks in parallel
# behaves as 8x loop unroll
###########################################################

.balign 32
.Loop_aes_cfb128_dec_mid_8x:
    sub \$0x80,$len

    mov $key_original,$key_crt
    mov 240($key_original),$rounds            # load AES rounds
                                              # 240 is the byte-offset of the rounds field in AES_KEY

    # $cipher_4x is "ciphertext0 | ciphertext1 | ciphertext 2 | ciphertext 3"
    vmovdqu32 ($inp),$cipher_4x               # load 4 ciphertext blocks
    # $cipher_8x is "ciphertext4 | ciphertext5 | ciphertext 6 | ciphertext 7"
    vmovdqu32 64($inp),$cipher_8x             # load next 4 ciphertext blocks

    # $temp_4x is   "iv          | ciphertext0 | ciphertext 1 | ciphertext 2"
    valignq \$6,$temp_4x,$cipher_4x,$temp_4x
    # $temp_8x is   "ciphertext3 | ciphertext4 | ciphertext 5 | ciphertext 6"
    valignq \$6,$cipher_4x,$cipher_8x,$temp_8x

    lea 128($inp),$inp                        # $inp points to next ciphertext

    # $rnd0key_4x is "round-0-key | round-0-key | round-0-key | round-0-key"
    vbroadcasti32x4 ($key_crt),$rnd0key_4x    # load round 0 key
    # $rndNkey_4x is "round-1-key | round-1-key | round-1-key | round-1-key"
    vbroadcasti32x4 16($key_crt),$rndNkey_4x  # load round 1 key

    lea 32($key_crt),$key_crt                 # $key_crt points to the 2nd round key
    vpxord $rnd0key_4x,$temp_4x,$temp_4x      # parallel AES pre-whitening
    vpxord $rnd0key_4x,$temp_8x,$temp_8x      # parallel AES pre-whitening

.balign 32
.Loop_aes_cfb128_dec_mid_8x_inner:
    vaesenc $rndNkey_4x,$temp_4x,$temp_4x     # parallel AES encrypt with current round key
    vaesenc $rndNkey_4x,$temp_8x,$temp_8x     # parallel AES encrypt with current round key
    dec $rounds

    # $rndNkey_4x is "round-N-key | round-N-key | round-N-key | round-N-key"
    vbroadcasti32x4 ($key_crt),$rndNkey_4x    # load next round key

    lea 16($key_crt),$key_crt                 # $key_crt points to the next round key
    jnz .Loop_aes_cfb128_dec_mid_8x_inner     # process all encryption rounds but the last

    vaesenclast $rndNkey_4x,$temp_4x,$temp_4x # parallel AES encrypt with the last round key
    vaesenclast $rndNkey_4x,$temp_8x,$temp_8x # parallel AES encrypt with the last round key

    vpxord $cipher_4x,$temp_4x,$temp_4x       # CipherFeedBack XOR
    vpxord $cipher_8x,$temp_8x,$temp_8x       # CipherFeedBack XOR
    cmp \$0x80,$len
    vmovdqu32 $temp_4x,($out)                 # write 4 plaintext blocks
    vmovdqu32 $temp_8x,64($out)               # write 4 plaintext blocks
    vmovdqu8 $cipher_8x,$temp_4x
    lea 128($out),$out                        # $out points to the next output block

    jae .Loop_aes_cfb128_dec_mid_8x

    vextracti64x2 \$3,$cipher_8x,$temp        # latest ciphertext block is next decryption iv
    vinserti32x4 \$3,$temp,$temp_4x,$temp_4x  # move ciphertext3 to positions 0 and 3 in preparation for next shuffle

    xor %eax,%eax                             # reset num when processing full blocks

    vmovdqu $temp,($ivp)                      # latest plaintext block is next decryption iv

.Laes_cfb128_dec_check_4x:
    cmp \$0x40,$len                           # are there 4 ciphertext blocks left (512 bits) ?
    jb .Laes_cfb128_dec_check_1x

###########################################################
# decrypt groups of 4 128-bit blocks in parallel
# behaves as 4x loop unroll
###########################################################

# expects $temp_4x to contain "iv | iv | iv | iv"

.balign 32
.Loop_aes_cfb128_dec_mid_4x:
    sub \$0x40,$len

    mov $key_original,$key_crt
    mov 240($key_original),$rounds            # load AES rounds
                                              # 240 is the byte-offset of the rounds field in AES_KEY

    # $cipher_4x is "ciphertext0 | ciphertext1 | ciphertext 2 | ciphertext 3"
    vmovdqu32 ($inp),$cipher_4x               # load 4 ciphertext blocks

    # $temp_4x is   "iv          | ciphertext0 | ciphertext 1 | ciphertext 2"
    valignq \$6,$temp_4x,$cipher_4x,$temp_4x

    lea 64($inp),$inp                         # $inp points to next ciphertext

    # $rnd0key_4x is "round-0-key | round-0-key | round-0-key | round-0-key"
    vbroadcasti32x4 ($key_crt),$rnd0key_4x    # load round 0 key
    # $rndNkey_4x is "round-1-key | round-1-key | round-1-key | round-1-key"
    vbroadcasti32x4 16($key_crt),$rndNkey_4x  # load round 1 key

    lea 32($key_crt),$key_crt                 # $key_crt points to the 2nd round key
    vpxord $rnd0key_4x,$temp_4x,$temp_4x      # parallel AES pre-whitening
    
.balign 32
.Loop_aes_cfb128_dec_mid_4x_inner:
    vaesenc $rndNkey_4x,$temp_4x,$temp_4x     # parallel AES encrypt with current round key
    dec $rounds

    # $rndNkey_4x is "round-N-key | round-N-key | round-N-key | round-N-key"
    vbroadcasti32x4 ($key_crt),$rndNkey_4x    # load next round key

    lea 16($key_crt),$key_crt                 # $key_crt points to the next round key
    jnz .Loop_aes_cfb128_dec_mid_4x_inner     # process all encryption rounds but the last

    vaesenclast $rndNkey_4x,$temp_4x,$temp_4x # parallel AES encrypt with the last round key

    vpxord $cipher_4x,$temp_4x,$temp_4x       # CipherFeedBack XOR
    cmp \$0x40,$len
    vmovdqu32 $temp_4x,($out)                 # write 4 plaintext blocks
    vmovdqu8 $cipher_4x,$temp_4x
    lea 64($out),$out                         # $out points to the next output block

    jae .Loop_aes_cfb128_dec_mid_4x

    vextracti64x2 \$3,$temp_4x,$temp          # latest ciphertext block is next decryption iv
                                              # move ciphertext3 to position 0 in preparation for next step

    xor %eax,%eax                             # reset num when processing full blocks

    vmovdqu $temp,($ivp)                      # latest plaintext block is next decryption iv

.Laes_cfb128_dec_check_1x:
    cmp \$0x10,$len                           # are there full ciphertext blocks left (128 bits) ?
    jb .Laes_cfb128_dec_post

###########################################################
# decrypt the rest of full 128-bit blocks in series
###########################################################

# expects $temp to contain iv

.balign 32
.Loop_aes_cfb128_dec_mid_1x:
    sub \$0x10,$len

    mov $key_original,$key_crt
    mov 240($key_original),$rounds    # load AES rounds
                                      # 240 is the byte-offset of the rounds field in AES_KEY

    vmovdqu ($inp),$cipher            # load ciphertext block
    lea 16($inp),$inp                 # $inp points to next ciphertext
___

    &vaes_encrypt_block_1x(".Loop_aes_cfb128_dec_mid_1x_inner");

$code.=<<___;
    vpxor $cipher,$temp,$temp         # CipherFeedBack XOR
    cmp \$0x10,$len
    vmovdqu $temp,($out)              # write plaintext
    vmovdqu8 $cipher,$temp
    lea 16($out),$out                 # $out points to the next output block
    jae .Loop_aes_cfb128_dec_mid_1x

    xor %eax,%eax                     # reset $num when processing full blocks

    vmovdqu $temp,($ivp)              # latest plaintext block is next decryption input

.Laes_cfb128_dec_post:

###########################################################
# last partial block post-processing
###########################################################

    test $len,$len                    # check if the last block is partial
    jz .Laes_cfb128_dec_end

    mov $key_original,$key_crt
    mov 240($key_original),$rounds    # load AES rounds
                                      # 240 is the byte-offset of the rounds field in AES_KEY
___

    &vaes_encrypt_block_1x(".Loop_aes_cfb128_dec_post");

$code.=<<___;

    mov $len,%rax                     # num=$len
    mov \$1,%r11                      # build a mask with the least significant $len bits set
    mov %dl,%cl                       # $len is left shift counter less than 16
    shlq %cl,%r11
    dec %r11                          # mask is 2^$len-1
    kmovq %r11,%k1

    vmovdqu8 ($inp),%xmm1{%k1}{z}     # read $len input bytes, zero the rest to not impact XOR
    vpxor $temp,%xmm1,%xmm0           # CipherFeedBack XOR
    vmovdqu8 %xmm0,($out){%k1}        # write $len output bytes
    vpblendmb %xmm1,$temp,$temp {%k1} # blend $len input bytes into iv

    vmovdqu8 $temp,($ivp)             # write chained/streaming iv

.Laes_cfb128_dec_end:

    mov %rax,($nump)                  # num is in/out, update for future/chained calls

    # zeroize
    vpxord $rnd0key_4x,$rnd0key_4x,$rnd0key_4x
    vpxord $rndNkey_4x,$rndNkey_4x,$rndNkey_4x
    vpxord $cipher_4x,$cipher_4x,$cipher_4x
    vpxord $temp_4x,$temp_4x,$temp_4x
    vpxord $cipher_8x,$cipher_8x,$cipher_8x
    vpxord $temp_8x,$temp_8x,$temp_8x

.Laes_cfb128_vaes_dec:
    vzeroupper
    ret
.cfi_endproc
.size aes_cfb128_vaes_dec,.-aes_cfb128_vaes_dec
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
