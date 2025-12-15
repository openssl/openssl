# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

##############################################################################
#
# Copyright (c) 2025, Iakov Polyak <iakov.polyak@linaro.org>
#
# This file is an implementation of Camellia cipher algorithm.
# It includes both scalar 1-block and parallel byte-sliced (Neon/AES)
# 16-block implementations, both ported from x86_64 and intrinsics
# versions from Jussi Kivilinna's repos, as described in his masters thesis.
# It also contains CBC and CTR modes, benefiting from byte-sliced
# implementation.
#
##############################################################################
#
# Copyright 2020-2023 Jussi Kivilinna
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
##############################################################################
#
# camellia_asm.S ver 1.1
#
# Copyright © 2012-2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
##############################################################################
#
# November 2025
#
# Performance (and speedup wrt C-implementation) for CBC decryption and CTR.
# (`openssl speed -evp (-decrypt) camellia-128-xxx; 8192-byte message)
#
#                       ThX2            Graviton4
# CBC (decryption)  7.9 cpb (3.7x)      4 cpb (5x)
# CTR               8 cpb (4.25x)       4 cpb (4x)
#

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code=<<___;

.text

.arch   armv8-a+crypto

/*
    1-block (serial) implementation
*/
___

$xab = "x4"; # State Left Half
$xcd = "x5"; # State Right Half

$xt0 = "x6"; # Temp 1
$xt1 = "x7"; # Temp 2
$xt2 = "x8"; # Temp 3

# Inputs:
#  v_ab:            Input vector register name (e.g., v2 or v3)
#  v_x:             Output/Working vector register name (e.g., v1 to v5)
#  v_t0 - v_t4:     Temporary vector register names (v6-v10)
#  inv_shift_row:  v17
#  sbox4mask:      v18
#  _0f0f0f0fmask:  v19
#  pre_s1lo_mask:  v20
#  pre_s1hi_mask:  v21
#  post_s1lo_mask: v22
#  post_s1hi_mask: v23
#  sp0044:         v24
#  sp1110:         v25
#  sp0222:         v26
#  sp3033:         v27
#  key:            GPR name holding key (e.g., x1)
# Output:
#   Lower 64 bits of v_x contain the result.
#
sub f_aese(){
    my ($v_ab, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key) = @_;
$code.=<<___;

	/*
	 * S-function with AES subbytes
	 */

    /* Apply input rotation for sbox4 */
    and     $v_t0.16b,$v_ab.16b,$sbox4mask.16b
    bic     $v_x.16b,$v_ab.16b,$sbox4mask.16b
    add     $v_t1.16b,$v_t0.16b,$v_t0.16b
    ushr    $v_t0.16b,$v_t0.16b,#7
    orr     $v_t0.16b,$v_t0.16b,$v_t1.16b
    and     $v_t0.16b,$v_t0.16b,$sbox4mask.16b
    orr     $v_x.16b,$v_x.16b,$v_t0.16b

    /* Prefilter sboxes */
___
    &filter_8bit_neon($v_x, $pre_s1lo_mask, $pre_s1hi_mask, $_0f0f0f0fmask, $v_t2);
$code.=<<___;

    /* AES subbytes + AES shift rows */
    aese    $v_x.16b,$v_zero.16b

    /* Postfilter sboxes */
___
    &filter_8bit_neon($v_x, $post_s1lo_mask, $post_s1hi_mask, $_0f0f0f0fmask, $v_t2);
$code.=<<___;

    /* P-function */
    tbl     $v_t1.16b,{$v_x.16b},$inv_shift_row.16b
    tbl     $v_t4.16b,{$v_x.16b},$sp0044.16b
    tbl     $v_x.16b,{$v_x.16b},$sp1110.16b
    add     $v_t2.16b,$v_t1.16b,$v_t1.16b
    ushr    $v_t0.16b,$v_t1.16b,#7
    shl     $v_t3.16b,$v_t1.16b,#7
    orr     $v_t0.16b,$v_t0.16b,$v_t2.16b
    ushr    $v_t1.16b,$v_t1.16b,#1
    tbl     $v_t0.16b,{$v_t0.16b},$sp0222.16b
    orr     $v_t1.16b,$v_t1.16b,$v_t3.16b

    /* pre-load round subkey (the value already passed in a GPR) */
    fmov    d8,$key     // referring to v_t2 (v8)

    /* ...continue calculating P-function */
    eor     $v_t4.16b,$v_x.16b,$v_t4.16b
    tbl     $v_t1.16b,{$v_t1.16b},$sp3033.16b
    eor     $v_t0.16b,$v_t0.16b,$v_t4.16b
    eor     $v_t0.16b,$v_t0.16b,$v_t1.16b

    /* transform key... */
    rev64   $v_t2.2s,$v_t2.2s

    /* what is this "folding" doing? Need it here? */
    ext     $v_x.16b,$v_t0.16b,$v_zero.16b,#8
    eor     $v_x.16b,$v_t0.16b,$v_x.16b

    /* xor result with the round subkey */
    eor     $v_x.16b,$v_x.16b,$v_t2.16b    // xor result with subkey
___
}

# Port of xor2ror16. Assumes table base addresses are in GPRs.
# In: x_ab (data), x_dst (accum), x_tbl0, x_tbl1, x_tmp1, x_tmp2
# Out: x_ab (rotated), x_dst (updated)
sub xor2ror16 {
    my ($x_ab, $x_dst, $x_tbl0, $x_tbl1, $x_tmp1, $x_tmp2) = @_;
$code.=<<___;
    ubfx    $x_tmp2,$x_ab,#0,#8                 // tmp2 = ab & 0xff
    ubfx    $x_tmp1,$x_ab,#8,#8                 // tmp1 = (ab >> 8) & 0xff
    ror     $x_ab,$x_ab,#16
    ldr     $x_tmp2,[$x_tbl0,$x_tmp2,lsl #3]    // tmp2 = table0[tmp2]
    ldr     $x_tmp1,[$x_tbl1,$x_tmp1,lsl #3]    // tmp1 = table1[tmp1]
    eor     $x_dst,$x_dst,$x_tmp2
    eor     $x_dst,$x_dst,$x_tmp1
___
}

sub roundsm_aese(){
    my ($v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key) = @_;
    &f_aese($v_ab, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
$code.=<<___;
    eor     $v_cd.16b,$v_cd.16b,$v_x.16b
___
}

# Port of roundsm.
# In: x_ab, x_cd, x_rt2, x_rt0, x_rt1 (temps)
#     sp0044, sp0330, sp2200, sp1001, sp1110, sp4404, sp3033, sp0222 (table addrs)
# Out: x_ab, x_cd (updated)
sub roundsm_tbl{
    my ($x_ab, $x_cd, $x_rt2, $x_rt0, $x_rt1, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222) = @_;
    &xor2ror16($x_ab, $x_cd, $sp0044, $sp0330, $x_rt0, $x_rt1);
    &xor2ror16($x_ab, $x_rt2, $sp2200, $sp1001, $x_rt0, $x_rt1);
    &xor2ror16($x_ab, $x_cd, $sp1110, $sp4404, $x_rt0, $x_rt1);
    &xor2ror16($x_ab, $x_rt2, $sp3033, $sp0222, $x_rt0, $x_rt1);
$code.=<<___;
    eor     $x_cd,$x_cd,$x_rt2
___
}

# Port of fls. Operates on 32-bit halves of 64-bit GPRs.
# In: x_L (assumes x4, [lr|ll]), x_R (assumes x5, [rr|rl]), x_CTX, kl_idx, kr_idx
# Out: x_L, x_R (updated)
# Clobbers: x6-x9
sub fls{
    my ($x_L, $x_R, $x_CTX, $kl_idx, $kr_idx) = @_;
    my $kl_offset = $kl_idx * 8;
    my $kr_offset = $kr_idx * 8;
$code.=<<___;
    add     x8,$x_CTX,#$kl_offset  // assume key_table == 0
    add     x9,$x_CTX,#$kr_offset
    ldr     x6,[x8]             // [klr|kll]
    ldr     x7,[x9]             // [krr|krl]

    mov     w8,w6               // [ 0 | kll ]
    and     w8,w4,w8            // [ 0 | kll & ll ]
    ror     w8,w8,#31           // [ 0 | ROL1(kll & ll)]
    eor     x4,x4,x8,lsl #32    // [ lr^ROL1(kll & ll) | ll ]

    orr     x7,x5,x7            // [ rr v krr | rl v krl ]
    eor     x5,x5,x7,lsr #32    // [ rr | rl^(rr v krr)]

    ldr     w9,[x9]             // Re-load [0|krl] in advance

    orr     x6,x4,x6            // [ lr^ROL1(kll & ll) v klr | ll v kll ]
    eor     x4,x4,x6,lsr #32    // [ lr^ROL1(kll & ll) | ll^(lr^ROL1(kll & ll) v klr)]

    and     w9,w5,w9            // [ 0 | krl & (rl^(rr v krr)) ]
    ror     w9,w9,#31           // [ 0 | ROL1(krl & (rl^(rr v krr)))]
    eor     x5,x5,x9,lsl #32    // [ rr^ROL1(krl & (rl^(rr v krr)))| rl^(rr v krr) ]
___
}

# In: x2(src), x0(CTX). Out: x4, x5. Clobbers: x8, x9
sub enc_inpack(){
$code.=<<___;
    ldp     x4,x5,[x2]          // Load [lr|ll] and [rr|rl] big endian
    rev     x4,x4               // Swap bytes - now [ll|lr] little-endian
    rev     x5,x5               // Swap bytes - now [rl|rr] little-endian
    ror     x4,x4,#32           // Rotate - now [lr|ll] little-endian
    ror     x5,x5,#32           // Rotate - now [rr|rl] little-endian
    add     x9,x0,#0            // Assume key_table == 0
    ldr     x8,[x9]             // Load key[0] into x8
    eor     x4,x4,x8            // [lr|ll] ^= key[0]
___
}

# In: x2(src), x0(CTX). Out: x4, x5. Clobbers: x8, x9
sub dec_inpack(){
    my ($max) = @_;
$code.=<<___;
    ldp     x4,x5,[x2]          // Load [lr|ll] and [rr|rl] big endian
    rev     x4,x4               // Swap bytes - now [ll|lr] little-endian
    rev     x5,x5               // Swap bytes - now [rl|rr] little-endian
    ror     x4,x4,#32           // Rotate - now [lr|ll] little-endian
    ror     x5,x5,#32           // Rotate - now [rr|rl] little-endian
    lsl     w9,$max,#3          // max * 8
    add     x9,x0,x9            // &(CTX+max*8)
    ldr     x8,[x9,#0]          // assume key_table == 0
    eor     x4,x4,x8            // [lr|ll] ^= key[0]
___
}

sub load_key(){
    my ($subkey_idx, $key) = @_;
    my $subkey_offset = $subkey_idx * 8;
$code.=<<___;
    ldr     $key,[x0,#$subkey_offset]   // TODO: check this first
___
}

# In: x0, subkey_idx. Out: x8(key). Clobbers: x9
sub load_key_to_x8(){
    my ($subkey_idx) = @_;
    my $subkey_offset = $subkey_idx * 8;
$code.=<<___;
    add     x9,x0,#$subkey_offset   // Assume key_table == 0
    ldr     x8,[x9]
___
}

sub roundsm_aese_ab_to_cd(){
    my ($subkey_idx, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key) = @_;
    &load_key($subkey_idx, $key);
    &roundsm_aese($v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key)
}

sub roundsm_aese_cd_to_ab(){
    my ($subkey_idx, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key) = @_;
    &load_key($subkey_idx, $key);
    &roundsm_aese($v_cd, $v_ab, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key)
}

sub roundsm_ab_to_cd(){
    my ($subkey_idx, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222) = @_;
    &load_key_to_x8($subkey_idx);
    &roundsm_tbl($xab, $xcd, $xt2, $xt0, $xt1, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); # (ab=x4, cd=x5, rt2=x8, rt0=x6, rt1=x7)
}

sub roundsm_cd_to_ab(){
    my ($subkey_idx, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222) = @_;
    &load_key_to_x8($subkey_idx);
    &roundsm_tbl($xcd, $xab, $xt2, $xt0, $xt1, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); # (ab=x5, cd=x4, rt2=x8, rt0=x6, rt1=x7)
}

sub enc_rounds_aese(){
    my ($i, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key) = @_;
    &roundsm_aese_ab_to_cd($i+2, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
    &roundsm_aese_cd_to_ab($i+3, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
    &roundsm_aese_ab_to_cd($i+4, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
    &roundsm_aese_cd_to_ab($i+5, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
    &roundsm_aese_ab_to_cd($i+6, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
    &roundsm_aese_cd_to_ab($i+7, $v_ab, $v_cd, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key);
}

sub enc_rounds(){
    my ($i, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222) = @_;
    &roundsm_ab_to_cd($i+2, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); 
    &roundsm_cd_to_ab($i+3, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); 
    &roundsm_ab_to_cd($i+4, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); 
    &roundsm_cd_to_ab($i+5, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); 
    &roundsm_ab_to_cd($i+6, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222); 
    &roundsm_cd_to_ab($i+7, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
}

sub dec_rounds(){
    my ($i, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222) = @_;
    &roundsm_ab_to_cd($i+7, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
    &roundsm_cd_to_ab($i+6, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
    &roundsm_ab_to_cd($i+5, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
    &roundsm_cd_to_ab($i+4, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
    &roundsm_ab_to_cd($i+3, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
    &roundsm_cd_to_ab($i+2, $sp0044, $sp0330, $sp2200, $sp1001, $sp1110, $sp4404, $sp3033, $sp0222);
}

# In: x4, x5, x0, max(w30), x1(dst). Out: [x1]. Clobbers: x8, x9
sub enc_outunpack(){
    my ($max) = @_;
$code.=<<___;
    lsl     w9,$max,#3      // max * 8
    add     x9,x0,x9        // &(CTX+max*8)
    ldr     x8,[x9,#0]      // assume key_table == 0
    eor     x5,x5,x8        // CD^= key_table(CTX, max, 8)
    ror     x5,x5,#32       // Rotate CD state (swap rl and rr)
    rev     x5,x5           // Change endianness
    ror     x4,x4,#32       // Rotate  AB state (swap ll and lr)
    rev     x4,x4           // Change endianness
    stp     x5,x4,[x1]      // Store 128-bit result [RCD0 | RAB0]
___
}

# In: x4, x5, x0, x1(dst). Out: [x1]. Clobbers: x8, x9
sub dec_outunpack(){
$code.=<<___;
    add     x9,x0,#0        // Assume key_table == 0
    ldr     x8,[x9]         // Load key[0] into x8
    eor     x5,x5,x8        // CD^= key_table(CTX, max, 8)
    ror     x5,x5,#32       // Rotate CD state (swap rl and rr)
    rev     x5,x5           // Change endianness
    ror     x4,x4,#32       // Rotate  AB state (swap ll and lr)
    rev     x4,x4           // Change endianness
    stp     x5,x4,[x1]      // Store 128-bit result [RCD0 | RAB0]
___
}

$code.=<<___;
.global camellia_encrypt_1blk_aese
.type   camellia_encrypt_1blk_aese,%function
.align  5
camellia_encrypt_1blk_aese:
    stp     x29, x30, [sp, -144]!
    mov     x29, sp

    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === CONSTANT LOADING ===
    // Load constants needed for camellia_f into v17-v27 + v16(bswap)
    adrp    x10,camellia_neon_consts
    add     x10,x10,:lo12:camellia_neon_consts
    ldp     q20,q21,[x10],#64    // pre_tf_lo/hi_s1
    ldp     q22,q23,[x10],#112   // post_tf_lo/hi_s1
    ldr     q19,[x10],#48        //mask_0f
    ldr     q16,[x10],#16        //bswap128
    ldr     d18,[x10],#8         //sbox4_input_mask
    ldr     q17,[x10],#16        //inv_shift_row_and_unpcklbw
    ldp     q24,q25,[x10],#32    //sp0044/sp1110
    ldp     q26,q27,[x10],#32    //sp0222/sp3033
___
    &enc_inpack();

$code.=<<___;
    eor     v31.16b,v31.16b,v31.16b
    ror     x4,x4,#32
    ror     x5,x5,#32
    fmov    d0,x4
    fmov    d1,x5
___
    &enc_rounds_aese(0,"v0","v1","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x8");
$code.=<<___;
    mov     x4,v0.2d[0]
    mov     x5,v1.2d[0]
    ror     x4,x4,#32
    ror     x5,x5,#32
___
    &fls("x4", "x5", "x0", 8, 9);
$code.=<<___;
    ror     x4,x4,#32
    ror     x5,x5,#32
    fmov    d0,x4
    fmov    d1,x5
___
    &enc_rounds_aese(8,"v0","v1","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x8");
$code.=<<___;
    mov     x4,v0.2d[0]
    mov     x5,v1.2d[0]
    ror     x4,x4,#32
    ror     x5,x5,#32
___
    &fls("x4", "x5", "x0", 16, 17);
$code.=<<___;
    ror     x4,x4,#32
    ror     x5,x5,#32
    fmov    d0,x4
    fmov    d1,x5
___
    &enc_rounds_aese(16,"v0","v1","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x8");
$code.=<<___;
    mov     x4,v0.2d[0]
    mov     x5,v1.2d[0]
    ror     x4,x4,#32
    ror     x5,x5,#32
___

$code.=<<___;
    mov     w30,#24         // MAX = 24

    ldr     w9,[x0,#272]    // Assume key_length == 272
    cmp     w9,#16
    b.eq    __enc_done_aese
___
    &fls("x4", "x5", "x0", 24, 25);
$code.=<<___;
    ror     x4,x4,#32
    ror     x5,x5,#32
    fmov    d0,x4
    fmov    d1,x5
___
    &enc_rounds_aese(24,"v0","v1","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x8");
$code.=<<___;
    mov     x4,v0.2d[0]
    mov     x5,v1.2d[0]
    ror     x4,x4,#32
    ror     x5,x5,#32
___
$code.=<<___;
    mov     w30,#32         // MAX = 32

__enc_done_aese:
___
    &enc_outunpack("w30");
$code.=<<___;

    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]
    ldp     x29,x30,[sp],#144
    ret
.size   camellia_encrypt_1blk_aese,.-camellia_encrypt_1blk_aese

.global camellia_encrypt_1blk_armv8
.type   camellia_encrypt_1blk_armv8,%function
.align  5
camellia_encrypt_1blk_armv8:
    stp     x29, x30, [sp, -16]!
    mov     x29, sp

    /* Look-up table addresses */
    adrp    x10,.Lcamellia_sp10011110
    add     x10,x10,:lo12:.Lcamellia_sp10011110
    adrp    x11,.Lcamellia_sp22000222
    add     x11,x11,:lo12:.Lcamellia_sp22000222
    adrp    x12,.Lcamellia_sp03303033
    add     x12,x12,:lo12:.Lcamellia_sp03303033
    adrp    x13,.Lcamellia_sp00444404
    add     x13,x13,:lo12:.Lcamellia_sp00444404
    adrp    x14,.Lcamellia_sp02220222
    add     x14,x14,:lo12:.Lcamellia_sp02220222
    adrp    x15,.Lcamellia_sp30333033
    add     x15,x15,:lo12:.Lcamellia_sp30333033
    adrp    x16,.Lcamellia_sp44044404
    add     x16,x16,:lo12:.Lcamellia_sp44044404
    adrp    x17,.Lcamellia_sp11101110
    add     x17,x17,:lo12:.Lcamellia_sp11101110

___
    &enc_inpack();

    &enc_rounds(0, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
    &fls("x4", "x5", "x0", 8, 9);
    &enc_rounds(8, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
    &fls("x4", "x5", "x0", 16, 17);
    &enc_rounds(16, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");

$code.=<<___;
    mov     w30,#24         // MAX = 24

    ldr     w9,[x0,#272]    // Assume key_length == 272
    cmp     w9,#16
    b.eq    __enc_done_armv8
___
    &fls("x4", "x5", "x0", 24, 25);
    &enc_rounds(24, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
$code.=<<___;
    mov     w30,#32         // MAX = 32

__enc_done_armv8:
___
    &enc_outunpack("w30");
$code.=<<___;

    ldp     x29, x30, [sp], #16
    ret
.size   camellia_encrypt_1blk_armv8,.-camellia_encrypt_1blk_armv8

.global camellia_decrypt_1blk_armv8
.type   camellia_decrypt_1blk_armv8,%function
.align  5
camellia_decrypt_1blk_armv8:
    stp     x29, x30, [sp, -16]!
    mov     x29, sp

    ldr     w9,[x0,#272]    // Load key_length byte (assuming offset 272)
    mov     w30,#32         // w30 will hold the 'max' value
    mov     w8,#24
    cmp     w9,#16
    csel    w30,w8,w30,eq   // w30 == 24 if key_length == 16 else 32.

    /* Look-up table addresses */
    adrp    x10,.Lcamellia_sp10011110
    add     x10,x10,:lo12:.Lcamellia_sp10011110
    adrp    x11,.Lcamellia_sp22000222
    add     x11,x11,:lo12:.Lcamellia_sp22000222
    adrp    x12,.Lcamellia_sp03303033
    add     x12,x12,:lo12:.Lcamellia_sp03303033
    adrp    x13,.Lcamellia_sp00444404
    add     x13,x13,:lo12:.Lcamellia_sp00444404
    adrp    x14,.Lcamellia_sp02220222
    add     x14,x14,:lo12:.Lcamellia_sp02220222
    adrp    x15,.Lcamellia_sp30333033
    add     x15,x15,:lo12:.Lcamellia_sp30333033
    adrp    x16,.Lcamellia_sp44044404
    add     x16,x16,:lo12:.Lcamellia_sp44044404
    adrp    x17,.Lcamellia_sp11101110
    add     x17,x17,:lo12:.Lcamellia_sp11101110

___
    &dec_inpack("w30");
$code.=<<___;

    cmp     w30,#24
    b.eq    __dec_rounds16_armv8
___

    &dec_rounds(24, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
    &fls("x4", "x5", "x0", 25, 24);
$code.=<<___;

__dec_rounds16_armv8:
___

    &dec_rounds(16, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
    &fls("x4", "x5", "x0", 17, 16);
    &dec_rounds(8, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");
    &fls("x4", "x5", "x0", 9, 8);
    &dec_rounds(0, "x13", "x12", "x11", "x10", "x17", "x16", "x15", "x14");

    &dec_outunpack();
$code.=<<___;

    ldp     x29, x30, [sp], #16
    ret
.size   camellia_decrypt_1blk_armv8,.-camellia_decrypt_1blk_armv8

/*
    Camellia constants (for both 1- and 16-block routines).
*/

.rodata
.type   camellia_neon_consts,%object
.align  7
camellia_neon_consts:
// === Constants for Encryption rounds ===
.Lpre_tf_lo_s1:
    .byte 0x45, 0xe8, 0x40, 0xed, 0x2e, 0x83, 0x2b, 0x86
    .byte 0x4b, 0xe6, 0x4e, 0xe3, 0x20, 0x8d, 0x25, 0x88
.Lpre_tf_hi_s1:
    .byte 0x00, 0x51, 0xf1, 0xa0, 0x8a, 0xdb, 0x7b, 0x2a
    .byte 0x09, 0x58, 0xf8, 0xa9, 0x83, 0xd2, 0x72, 0x23
.Lpre_tf_lo_s4:
    .byte 0x45, 0x40, 0x2e, 0x2b, 0x4b, 0x4e, 0x20, 0x25
    .byte 0x14, 0x11, 0x7f, 0x7a, 0x1a, 0x1f, 0x71, 0x74
.Lpre_tf_hi_s4:
    .byte 0x00, 0xf1, 0x8a, 0x7b, 0x09, 0xf8, 0x83, 0x72
    .byte 0xad, 0x5c, 0x27, 0xd6, 0xa4, 0x55, 0x2e, 0xdf
.Lpost_tf_lo_s1:
    .byte 0x3c, 0xcc, 0xcf, 0x3f, 0x32, 0xc2, 0xc1, 0x31
    .byte 0xdc, 0x2c, 0x2f, 0xdf, 0xd2, 0x22, 0x21, 0xd1
.Lpost_tf_hi_s1:
    .byte 0x00, 0xf9, 0x86, 0x7f, 0xd7, 0x2e, 0x51, 0xa8
    .byte 0xa4, 0x5d, 0x22, 0xdb, 0x73, 0x8a, 0xf5, 0x0c
.Lpost_tf_lo_s2:
    .byte 0x78, 0x99, 0x9f, 0x7e, 0x64, 0x85, 0x83, 0x62
    .byte 0xb9, 0x58, 0x5e, 0xbf, 0xa5, 0x44, 0x42, 0xa3
.Lpost_tf_hi_s2:
    .byte 0x00, 0xf3, 0x0d, 0xfe, 0xaf, 0x5c, 0xa2, 0x51
    .byte 0x49, 0xba, 0x44, 0xb7, 0xe6, 0x15, 0xeb, 0x18
.Lpost_tf_lo_s3:
    .byte 0x1e, 0x66, 0xe7, 0x9f, 0x19, 0x61, 0xe0, 0x98
    .byte 0x6e, 0x16, 0x97, 0xef, 0x69, 0x11, 0x90, 0xe8
.Lpost_tf_hi_s3:
    .byte 0x00, 0xfc, 0x43, 0xbf, 0xeb, 0x17, 0xa8, 0x54
    .byte 0x52, 0xae, 0x11, 0xed, 0xb9, 0x45, 0xfa, 0x06
.Linv_shift_row:
    .byte 0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b
    .byte 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03
.Lmask_0f:
    .quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
.Lpack_bswap:
    .byte   3, 2, 1, 0, 7, 6, 5, 4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
.Lshufb_16x16b:
    .byte   0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
// === byteswap mask ===
.Lbswap128_mask:
	.byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
// === Constants for Key Schedule F-function ===
.Lsbox4_input_mask:
    // Selects bytes 1, 4 for input rotation (sbox4) within the 64-bit input
	.byte 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00;
.Linv_shift_row_and_unpcklbw:
    // Special shuffle mask used in key schedule's F-function (different from main rounds)
    .byte   0x00, 0xff, 0x0d, 0xff, 0x0a, 0xff, 0x07, 0xff
    .byte   0x04, 0xff, 0x01, 0xff, 0x0e, 0xff, 0x0b, 0xff
.Lsp0044440444044404mask:
    // Shuffle mask for combining results (part 1)
    .long   0xffff0404, 0x0404ff04
    .long   0x0d0dff0d, 0x0d0dff0d
.Lsp1110111010011110mask:
    // Shuffle mask for combining results (part 2)
    .long   0x000000ff, 0x000000ff
    .long   0x0bffff0b, 0x0b0b0bff
.Lsp0222022222000222mask:
    // Shuffle mask for combining results (part 3 - related to SBOX2 rotate)
    .long   0xff060606, 0xff060606
    .long   0x0c0cffff, 0xff0c0c0c
.Lsp3033303303303033mask:
    // Shuffle mask for combining results (part 4 - related to SBOX3 rotate)
    .long   0x04ff0404, 0x04ff0404
    .long   0xff0a0aff, 0x0aff0a0a
// === Sigmas for key setup ===
.Lsigma1:
	.long 0x3BCC908B, 0xA09E667F;
.Lsigma2:
	.long 0x4CAA73B2, 0xB67AE858;
.Lsigma3:
	.long 0xE94F82BE, 0xC6EF372F;
.Lsigma4:
	.long 0xF1D36F1C, 0x54FF53A5;
.Lsigma5:
	.long 0xDE682D1D, 0x10E527FA;
.Lsigma6:
	.long 0xB3E6C1FD, 0xB05688C2;
// === Precomputed SP-tables for 1-block implementation ===
.Lcamellia_sp10011110:
    .quad   0x7000007070707000, 0x8200008282828200, 0x2c00002c2c2c2c00
    .quad   0xec0000ecececec00, 0xb30000b3b3b3b300, 0x2700002727272700
    .quad   0xc00000c0c0c0c000, 0xe50000e5e5e5e500, 0xe40000e4e4e4e400
    .quad   0x8500008585858500, 0x5700005757575700, 0x3500003535353500
    .quad   0xea0000eaeaeaea00, 0x0c00000c0c0c0c00, 0xae0000aeaeaeae00
    .quad   0x4100004141414100, 0x2300002323232300, 0xef0000efefefef00
    .quad   0x6b00006b6b6b6b00, 0x9300009393939300, 0x4500004545454500
    .quad   0x1900001919191900, 0xa50000a5a5a5a500, 0x2100002121212100
    .quad   0xed0000edededed00, 0x0e00000e0e0e0e00, 0x4f00004f4f4f4f00
    .quad   0x4e00004e4e4e4e00, 0x1d00001d1d1d1d00, 0x6500006565656500
    .quad   0x9200009292929200, 0xbd0000bdbdbdbd00, 0x8600008686868600
    .quad   0xb80000b8b8b8b800, 0xaf0000afafafaf00, 0x8f00008f8f8f8f00
    .quad   0x7c00007c7c7c7c00, 0xeb0000ebebebeb00, 0x1f00001f1f1f1f00
    .quad   0xce0000cececece00, 0x3e00003e3e3e3e00, 0x3000003030303000
    .quad   0xdc0000dcdcdcdc00, 0x5f00005f5f5f5f00, 0x5e00005e5e5e5e00
    .quad   0xc50000c5c5c5c500, 0x0b00000b0b0b0b00, 0x1a00001a1a1a1a00
    .quad   0xa60000a6a6a6a600, 0xe10000e1e1e1e100, 0x3900003939393900
    .quad   0xca0000cacacaca00, 0xd50000d5d5d5d500, 0x4700004747474700
    .quad   0x5d00005d5d5d5d00, 0x3d00003d3d3d3d00, 0xd90000d9d9d9d900
    .quad   0x0100000101010100, 0x5a00005a5a5a5a00, 0xd60000d6d6d6d600
    .quad   0x5100005151515100, 0x5600005656565600, 0x6c00006c6c6c6c00
    .quad   0x4d00004d4d4d4d00, 0x8b00008b8b8b8b00, 0x0d00000d0d0d0d00
    .quad   0x9a00009a9a9a9a00, 0x6600006666666600, 0xfb0000fbfbfbfb00
    .quad   0xcc0000cccccccc00, 0xb00000b0b0b0b000, 0x2d00002d2d2d2d00
    .quad   0x7400007474747400, 0x1200001212121200, 0x2b00002b2b2b2b00
    .quad   0x2000002020202000, 0xf00000f0f0f0f000, 0xb10000b1b1b1b100
    .quad   0x8400008484848400, 0x9900009999999900, 0xdf0000dfdfdfdf00
    .quad   0x4c00004c4c4c4c00, 0xcb0000cbcbcbcb00, 0xc20000c2c2c2c200
    .quad   0x3400003434343400, 0x7e00007e7e7e7e00, 0x7600007676767600
    .quad   0x0500000505050500, 0x6d00006d6d6d6d00, 0xb70000b7b7b7b700
    .quad   0xa90000a9a9a9a900, 0x3100003131313100, 0xd10000d1d1d1d100
    .quad   0x1700001717171700, 0x0400000404040400, 0xd70000d7d7d7d700
    .quad   0x1400001414141400, 0x5800005858585800, 0x3a00003a3a3a3a00
    .quad   0x6100006161616100, 0xde0000dededede00, 0x1b00001b1b1b1b00
    .quad   0x1100001111111100, 0x1c00001c1c1c1c00, 0x3200003232323200
    .quad   0x0f00000f0f0f0f00, 0x9c00009c9c9c9c00, 0x1600001616161600
    .quad   0x5300005353535300, 0x1800001818181800, 0xf20000f2f2f2f200
    .quad   0x2200002222222200, 0xfe0000fefefefe00, 0x4400004444444400
    .quad   0xcf0000cfcfcfcf00, 0xb20000b2b2b2b200, 0xc30000c3c3c3c300
    .quad   0xb50000b5b5b5b500, 0x7a00007a7a7a7a00, 0x9100009191919100
    .quad   0x2400002424242400, 0x0800000808080800, 0xe80000e8e8e8e800
    .quad   0xa80000a8a8a8a800, 0x6000006060606000, 0xfc0000fcfcfcfc00
    .quad   0x6900006969696900, 0x5000005050505000, 0xaa0000aaaaaaaa00
    .quad   0xd00000d0d0d0d000, 0xa00000a0a0a0a000, 0x7d00007d7d7d7d00
    .quad   0xa10000a1a1a1a100, 0x8900008989898900, 0x6200006262626200
    .quad   0x9700009797979700, 0x5400005454545400, 0x5b00005b5b5b5b00
    .quad   0x1e00001e1e1e1e00, 0x9500009595959500, 0xe00000e0e0e0e000
    .quad   0xff0000ffffffff00, 0x6400006464646400, 0xd20000d2d2d2d200
    .quad   0x1000001010101000, 0xc40000c4c4c4c400, 0x0000000000000000
    .quad   0x4800004848484800, 0xa30000a3a3a3a300, 0xf70000f7f7f7f700
    .quad   0x7500007575757500, 0xdb0000dbdbdbdb00, 0x8a00008a8a8a8a00
    .quad   0x0300000303030300, 0xe60000e6e6e6e600, 0xda0000dadadada00
    .quad   0x0900000909090900, 0x3f00003f3f3f3f00, 0xdd0000dddddddd00
    .quad   0x9400009494949400, 0x8700008787878700, 0x5c00005c5c5c5c00
    .quad   0x8300008383838300, 0x0200000202020200, 0xcd0000cdcdcdcd00
    .quad   0x4a00004a4a4a4a00, 0x9000009090909000, 0x3300003333333300
    .quad   0x7300007373737300, 0x6700006767676700, 0xf60000f6f6f6f600
    .quad   0xf30000f3f3f3f300, 0x9d00009d9d9d9d00, 0x7f00007f7f7f7f00
    .quad   0xbf0000bfbfbfbf00, 0xe20000e2e2e2e200, 0x5200005252525200
    .quad   0x9b00009b9b9b9b00, 0xd80000d8d8d8d800, 0x2600002626262600
    .quad   0xc80000c8c8c8c800, 0x3700003737373700, 0xc60000c6c6c6c600
    .quad   0x3b00003b3b3b3b00, 0x8100008181818100, 0x9600009696969600
    .quad   0x6f00006f6f6f6f00, 0x4b00004b4b4b4b00, 0x1300001313131300
    .quad   0xbe0000bebebebe00, 0x6300006363636300, 0x2e00002e2e2e2e00
    .quad   0xe90000e9e9e9e900, 0x7900007979797900, 0xa70000a7a7a7a700
    .quad   0x8c00008c8c8c8c00, 0x9f00009f9f9f9f00, 0x6e00006e6e6e6e00
    .quad   0xbc0000bcbcbcbc00, 0x8e00008e8e8e8e00, 0x2900002929292900
    .quad   0xf50000f5f5f5f500, 0xf90000f9f9f9f900, 0xb60000b6b6b6b600
    .quad   0x2f00002f2f2f2f00, 0xfd0000fdfdfdfd00, 0xb40000b4b4b4b400
    .quad   0x5900005959595900, 0x7800007878787800, 0x9800009898989800
    .quad   0x0600000606060600, 0x6a00006a6a6a6a00, 0xe70000e7e7e7e700
    .quad   0x4600004646464600, 0x7100007171717100, 0xba0000babababa00
    .quad   0xd40000d4d4d4d400, 0x2500002525252500, 0xab0000abababab00
    .quad   0x4200004242424200, 0x8800008888888800, 0xa20000a2a2a2a200
    .quad   0x8d00008d8d8d8d00, 0xfa0000fafafafa00, 0x7200007272727200
    .quad   0x0700000707070700, 0xb90000b9b9b9b900, 0x5500005555555500
    .quad   0xf80000f8f8f8f800, 0xee0000eeeeeeee00, 0xac0000acacacac00
    .quad   0x0a00000a0a0a0a00, 0x3600003636363600, 0x4900004949494900
    .quad   0x2a00002a2a2a2a00, 0x6800006868686800, 0x3c00003c3c3c3c00
    .quad   0x3800003838383800, 0xf10000f1f1f1f100, 0xa40000a4a4a4a400
    .quad   0x4000004040404000, 0x2800002828282800, 0xd30000d3d3d3d300
    .quad   0x7b00007b7b7b7b00, 0xbb0000bbbbbbbb00, 0xc90000c9c9c9c900
    .quad   0x4300004343434300, 0xc10000c1c1c1c100, 0x1500001515151500
    .quad   0xe30000e3e3e3e300, 0xad0000adadadad00, 0xf40000f4f4f4f400
    .quad   0x7700007777777700, 0xc70000c7c7c7c700, 0x8000008080808000
    .quad   0x9e00009e9e9e9e00
.Lcamellia_sp22000222:
    .quad   0xe0e0000000e0e0e0, 0x0505000000050505, 0x5858000000585858
    .quad   0xd9d9000000d9d9d9, 0x6767000000676767, 0x4e4e0000004e4e4e
    .quad   0x8181000000818181, 0xcbcb000000cbcbcb, 0xc9c9000000c9c9c9
    .quad   0x0b0b0000000b0b0b, 0xaeae000000aeaeae, 0x6a6a0000006a6a6a
    .quad   0xd5d5000000d5d5d5, 0x1818000000181818, 0x5d5d0000005d5d5d
    .quad   0x8282000000828282, 0x4646000000464646, 0xdfdf000000dfdfdf
    .quad   0xd6d6000000d6d6d6, 0x2727000000272727, 0x8a8a0000008a8a8a
    .quad   0x3232000000323232, 0x4b4b0000004b4b4b, 0x4242000000424242
    .quad   0xdbdb000000dbdbdb, 0x1c1c0000001c1c1c, 0x9e9e0000009e9e9e
    .quad   0x9c9c0000009c9c9c, 0x3a3a0000003a3a3a, 0xcaca000000cacaca
    .quad   0x2525000000252525, 0x7b7b0000007b7b7b, 0x0d0d0000000d0d0d
    .quad   0x7171000000717171, 0x5f5f0000005f5f5f, 0x1f1f0000001f1f1f
    .quad   0xf8f8000000f8f8f8, 0xd7d7000000d7d7d7, 0x3e3e0000003e3e3e
    .quad   0x9d9d0000009d9d9d, 0x7c7c0000007c7c7c, 0x6060000000606060
    .quad   0xb9b9000000b9b9b9, 0xbebe000000bebebe, 0xbcbc000000bcbcbc
    .quad   0x8b8b0000008b8b8b, 0x1616000000161616, 0x3434000000343434
    .quad   0x4d4d0000004d4d4d, 0xc3c3000000c3c3c3, 0x7272000000727272
    .quad   0x9595000000959595, 0xabab000000ababab, 0x8e8e0000008e8e8e
    .quad   0xbaba000000bababa, 0x7a7a0000007a7a7a, 0xb3b3000000b3b3b3
    .quad   0x0202000000020202, 0xb4b4000000b4b4b4, 0xadad000000adadad
    .quad   0xa2a2000000a2a2a2, 0xacac000000acacac, 0xd8d8000000d8d8d8
    .quad   0x9a9a0000009a9a9a, 0x1717000000171717, 0x1a1a0000001a1a1a
    .quad   0x3535000000353535, 0xcccc000000cccccc, 0xf7f7000000f7f7f7
    .quad   0x9999000000999999, 0x6161000000616161, 0x5a5a0000005a5a5a
    .quad   0xe8e8000000e8e8e8, 0x2424000000242424, 0x5656000000565656
    .quad   0x4040000000404040, 0xe1e1000000e1e1e1, 0x6363000000636363
    .quad   0x0909000000090909, 0x3333000000333333, 0xbfbf000000bfbfbf
    .quad   0x9898000000989898, 0x9797000000979797, 0x8585000000858585
    .quad   0x6868000000686868, 0xfcfc000000fcfcfc, 0xecec000000ececec
    .quad   0x0a0a0000000a0a0a, 0xdada000000dadada, 0x6f6f0000006f6f6f
    .quad   0x5353000000535353, 0x6262000000626262, 0xa3a3000000a3a3a3
    .quad   0x2e2e0000002e2e2e, 0x0808000000080808, 0xafaf000000afafaf
    .quad   0x2828000000282828, 0xb0b0000000b0b0b0, 0x7474000000747474
    .quad   0xc2c2000000c2c2c2, 0xbdbd000000bdbdbd, 0x3636000000363636
    .quad   0x2222000000222222, 0x3838000000383838, 0x6464000000646464
    .quad   0x1e1e0000001e1e1e, 0x3939000000393939, 0x2c2c0000002c2c2c
    .quad   0xa6a6000000a6a6a6, 0x3030000000303030, 0xe5e5000000e5e5e5
    .quad   0x4444000000444444, 0xfdfd000000fdfdfd, 0x8888000000888888
    .quad   0x9f9f0000009f9f9f, 0x6565000000656565, 0x8787000000878787
    .quad   0x6b6b0000006b6b6b, 0xf4f4000000f4f4f4, 0x2323000000232323
    .quad   0x4848000000484848, 0x1010000000101010, 0xd1d1000000d1d1d1
    .quad   0x5151000000515151, 0xc0c0000000c0c0c0, 0xf9f9000000f9f9f9
    .quad   0xd2d2000000d2d2d2, 0xa0a0000000a0a0a0, 0x5555000000555555
    .quad   0xa1a1000000a1a1a1, 0x4141000000414141, 0xfafa000000fafafa
    .quad   0x4343000000434343, 0x1313000000131313, 0xc4c4000000c4c4c4
    .quad   0x2f2f0000002f2f2f, 0xa8a8000000a8a8a8, 0xb6b6000000b6b6b6
    .quad   0x3c3c0000003c3c3c, 0x2b2b0000002b2b2b, 0xc1c1000000c1c1c1
    .quad   0xffff000000ffffff, 0xc8c8000000c8c8c8, 0xa5a5000000a5a5a5
    .quad   0x2020000000202020, 0x8989000000898989, 0x0000000000000000
    .quad   0x9090000000909090, 0x4747000000474747, 0xefef000000efefef
    .quad   0xeaea000000eaeaea, 0xb7b7000000b7b7b7, 0x1515000000151515
    .quad   0x0606000000060606, 0xcdcd000000cdcdcd, 0xb5b5000000b5b5b5
    .quad   0x1212000000121212, 0x7e7e0000007e7e7e, 0xbbbb000000bbbbbb
    .quad   0x2929000000292929, 0x0f0f0000000f0f0f, 0xb8b8000000b8b8b8
    .quad   0x0707000000070707, 0x0404000000040404, 0x9b9b0000009b9b9b
    .quad   0x9494000000949494, 0x2121000000212121, 0x6666000000666666
    .quad   0xe6e6000000e6e6e6, 0xcece000000cecece, 0xeded000000ededed
    .quad   0xe7e7000000e7e7e7, 0x3b3b0000003b3b3b, 0xfefe000000fefefe
    .quad   0x7f7f0000007f7f7f, 0xc5c5000000c5c5c5, 0xa4a4000000a4a4a4
    .quad   0x3737000000373737, 0xb1b1000000b1b1b1, 0x4c4c0000004c4c4c
    .quad   0x9191000000919191, 0x6e6e0000006e6e6e, 0x8d8d0000008d8d8d
    .quad   0x7676000000767676, 0x0303000000030303, 0x2d2d0000002d2d2d
    .quad   0xdede000000dedede, 0x9696000000969696, 0x2626000000262626
    .quad   0x7d7d0000007d7d7d, 0xc6c6000000c6c6c6, 0x5c5c0000005c5c5c
    .quad   0xd3d3000000d3d3d3, 0xf2f2000000f2f2f2, 0x4f4f0000004f4f4f
    .quad   0x1919000000191919, 0x3f3f0000003f3f3f, 0xdcdc000000dcdcdc
    .quad   0x7979000000797979, 0x1d1d0000001d1d1d, 0x5252000000525252
    .quad   0xebeb000000ebebeb, 0xf3f3000000f3f3f3, 0x6d6d0000006d6d6d
    .quad   0x5e5e0000005e5e5e, 0xfbfb000000fbfbfb, 0x6969000000696969
    .quad   0xb2b2000000b2b2b2, 0xf0f0000000f0f0f0, 0x3131000000313131
    .quad   0x0c0c0000000c0c0c, 0xd4d4000000d4d4d4, 0xcfcf000000cfcfcf
    .quad   0x8c8c0000008c8c8c, 0xe2e2000000e2e2e2, 0x7575000000757575
    .quad   0xa9a9000000a9a9a9, 0x4a4a0000004a4a4a, 0x5757000000575757
    .quad   0x8484000000848484, 0x1111000000111111, 0x4545000000454545
    .quad   0x1b1b0000001b1b1b, 0xf5f5000000f5f5f5, 0xe4e4000000e4e4e4
    .quad   0x0e0e0000000e0e0e, 0x7373000000737373, 0xaaaa000000aaaaaa
    .quad   0xf1f1000000f1f1f1, 0xdddd000000dddddd, 0x5959000000595959
    .quad   0x1414000000141414, 0x6c6c0000006c6c6c, 0x9292000000929292
    .quad   0x5454000000545454, 0xd0d0000000d0d0d0, 0x7878000000787878
    .quad   0x7070000000707070, 0xe3e3000000e3e3e3, 0x4949000000494949
    .quad   0x8080000000808080, 0x5050000000505050, 0xa7a7000000a7a7a7
    .quad   0xf6f6000000f6f6f6, 0x7777000000777777, 0x9393000000939393
    .quad   0x8686000000868686, 0x8383000000838383, 0x2a2a0000002a2a2a
    .quad   0xc7c7000000c7c7c7, 0x5b5b0000005b5b5b, 0xe9e9000000e9e9e9
    .quad   0xeeee000000eeeeee, 0x8f8f0000008f8f8f, 0x0101000000010101
    .quad   0x3d3d0000003d3d3d
.Lcamellia_sp03303033:
    .quad   0x0038380038003838, 0x0041410041004141, 0x0016160016001616
    .quad   0x0076760076007676, 0x00d9d900d900d9d9, 0x0093930093009393
    .quad   0x0060600060006060, 0x00f2f200f200f2f2, 0x0072720072007272
    .quad   0x00c2c200c200c2c2, 0x00abab00ab00abab, 0x009a9a009a009a9a
    .quad   0x0075750075007575, 0x0006060006000606, 0x0057570057005757
    .quad   0x00a0a000a000a0a0, 0x0091910091009191, 0x00f7f700f700f7f7
    .quad   0x00b5b500b500b5b5, 0x00c9c900c900c9c9, 0x00a2a200a200a2a2
    .quad   0x008c8c008c008c8c, 0x00d2d200d200d2d2, 0x0090900090009090
    .quad   0x00f6f600f600f6f6, 0x0007070007000707, 0x00a7a700a700a7a7
    .quad   0x0027270027002727, 0x008e8e008e008e8e, 0x00b2b200b200b2b2
    .quad   0x0049490049004949, 0x00dede00de00dede, 0x0043430043004343
    .quad   0x005c5c005c005c5c, 0x00d7d700d700d7d7, 0x00c7c700c700c7c7
    .quad   0x003e3e003e003e3e, 0x00f5f500f500f5f5, 0x008f8f008f008f8f
    .quad   0x0067670067006767, 0x001f1f001f001f1f, 0x0018180018001818
    .quad   0x006e6e006e006e6e, 0x00afaf00af00afaf, 0x002f2f002f002f2f
    .quad   0x00e2e200e200e2e2, 0x0085850085008585, 0x000d0d000d000d0d
    .quad   0x0053530053005353, 0x00f0f000f000f0f0, 0x009c9c009c009c9c
    .quad   0x0065650065006565, 0x00eaea00ea00eaea, 0x00a3a300a300a3a3
    .quad   0x00aeae00ae00aeae, 0x009e9e009e009e9e, 0x00ecec00ec00ecec
    .quad   0x0080800080008080, 0x002d2d002d002d2d, 0x006b6b006b006b6b
    .quad   0x00a8a800a800a8a8, 0x002b2b002b002b2b, 0x0036360036003636
    .quad   0x00a6a600a600a6a6, 0x00c5c500c500c5c5, 0x0086860086008686
    .quad   0x004d4d004d004d4d, 0x0033330033003333, 0x00fdfd00fd00fdfd
    .quad   0x0066660066006666, 0x0058580058005858, 0x0096960096009696
    .quad   0x003a3a003a003a3a, 0x0009090009000909, 0x0095950095009595
    .quad   0x0010100010001010, 0x0078780078007878, 0x00d8d800d800d8d8
    .quad   0x0042420042004242, 0x00cccc00cc00cccc, 0x00efef00ef00efef
    .quad   0x0026260026002626, 0x00e5e500e500e5e5, 0x0061610061006161
    .quad   0x001a1a001a001a1a, 0x003f3f003f003f3f, 0x003b3b003b003b3b
    .quad   0x0082820082008282, 0x00b6b600b600b6b6, 0x00dbdb00db00dbdb
    .quad   0x00d4d400d400d4d4, 0x0098980098009898, 0x00e8e800e800e8e8
    .quad   0x008b8b008b008b8b, 0x0002020002000202, 0x00ebeb00eb00ebeb
    .quad   0x000a0a000a000a0a, 0x002c2c002c002c2c, 0x001d1d001d001d1d
    .quad   0x00b0b000b000b0b0, 0x006f6f006f006f6f, 0x008d8d008d008d8d
    .quad   0x0088880088008888, 0x000e0e000e000e0e, 0x0019190019001919
    .quad   0x0087870087008787, 0x004e4e004e004e4e, 0x000b0b000b000b0b
    .quad   0x00a9a900a900a9a9, 0x000c0c000c000c0c, 0x0079790079007979
    .quad   0x0011110011001111, 0x007f7f007f007f7f, 0x0022220022002222
    .quad   0x00e7e700e700e7e7, 0x0059590059005959, 0x00e1e100e100e1e1
    .quad   0x00dada00da00dada, 0x003d3d003d003d3d, 0x00c8c800c800c8c8
    .quad   0x0012120012001212, 0x0004040004000404, 0x0074740074007474
    .quad   0x0054540054005454, 0x0030300030003030, 0x007e7e007e007e7e
    .quad   0x00b4b400b400b4b4, 0x0028280028002828, 0x0055550055005555
    .quad   0x0068680068006868, 0x0050500050005050, 0x00bebe00be00bebe
    .quad   0x00d0d000d000d0d0, 0x00c4c400c400c4c4, 0x0031310031003131
    .quad   0x00cbcb00cb00cbcb, 0x002a2a002a002a2a, 0x00adad00ad00adad
    .quad   0x000f0f000f000f0f, 0x00caca00ca00caca, 0x0070700070007070
    .quad   0x00ffff00ff00ffff, 0x0032320032003232, 0x0069690069006969
    .quad   0x0008080008000808, 0x0062620062006262, 0x0000000000000000
    .quad   0x0024240024002424, 0x00d1d100d100d1d1, 0x00fbfb00fb00fbfb
    .quad   0x00baba00ba00baba, 0x00eded00ed00eded, 0x0045450045004545
    .quad   0x0081810081008181, 0x0073730073007373, 0x006d6d006d006d6d
    .quad   0x0084840084008484, 0x009f9f009f009f9f, 0x00eeee00ee00eeee
    .quad   0x004a4a004a004a4a, 0x00c3c300c300c3c3, 0x002e2e002e002e2e
    .quad   0x00c1c100c100c1c1, 0x0001010001000101, 0x00e6e600e600e6e6
    .quad   0x0025250025002525, 0x0048480048004848, 0x0099990099009999
    .quad   0x00b9b900b900b9b9, 0x00b3b300b300b3b3, 0x007b7b007b007b7b
    .quad   0x00f9f900f900f9f9, 0x00cece00ce00cece, 0x00bfbf00bf00bfbf
    .quad   0x00dfdf00df00dfdf, 0x0071710071007171, 0x0029290029002929
    .quad   0x00cdcd00cd00cdcd, 0x006c6c006c006c6c, 0x0013130013001313
    .quad   0x0064640064006464, 0x009b9b009b009b9b, 0x0063630063006363
    .quad   0x009d9d009d009d9d, 0x00c0c000c000c0c0, 0x004b4b004b004b4b
    .quad   0x00b7b700b700b7b7, 0x00a5a500a500a5a5, 0x0089890089008989
    .quad   0x005f5f005f005f5f, 0x00b1b100b100b1b1, 0x0017170017001717
    .quad   0x00f4f400f400f4f4, 0x00bcbc00bc00bcbc, 0x00d3d300d300d3d3
    .quad   0x0046460046004646, 0x00cfcf00cf00cfcf, 0x0037370037003737
    .quad   0x005e5e005e005e5e, 0x0047470047004747, 0x0094940094009494
    .quad   0x00fafa00fa00fafa, 0x00fcfc00fc00fcfc, 0x005b5b005b005b5b
    .quad   0x0097970097009797, 0x00fefe00fe00fefe, 0x005a5a005a005a5a
    .quad   0x00acac00ac00acac, 0x003c3c003c003c3c, 0x004c4c004c004c4c
    .quad   0x0003030003000303, 0x0035350035003535, 0x00f3f300f300f3f3
    .quad   0x0023230023002323, 0x00b8b800b800b8b8, 0x005d5d005d005d5d
    .quad   0x006a6a006a006a6a, 0x0092920092009292, 0x00d5d500d500d5d5
    .quad   0x0021210021002121, 0x0044440044004444, 0x0051510051005151
    .quad   0x00c6c600c600c6c6, 0x007d7d007d007d7d, 0x0039390039003939
    .quad   0x0083830083008383, 0x00dcdc00dc00dcdc, 0x00aaaa00aa00aaaa
    .quad   0x007c7c007c007c7c, 0x0077770077007777, 0x0056560056005656
    .quad   0x0005050005000505, 0x001b1b001b001b1b, 0x00a4a400a400a4a4
    .quad   0x0015150015001515, 0x0034340034003434, 0x001e1e001e001e1e
    .quad   0x001c1c001c001c1c, 0x00f8f800f800f8f8, 0x0052520052005252
    .quad   0x0020200020002020, 0x0014140014001414, 0x00e9e900e900e9e9
    .quad   0x00bdbd00bd00bdbd, 0x00dddd00dd00dddd, 0x00e4e400e400e4e4
    .quad   0x00a1a100a100a1a1, 0x00e0e000e000e0e0, 0x008a8a008a008a8a
    .quad   0x00f1f100f100f1f1, 0x00d6d600d600d6d6, 0x007a7a007a007a7a
    .quad   0x00bbbb00bb00bbbb, 0x00e3e300e300e3e3, 0x0040400040004040
    .quad   0x004f4f004f004f4f
.Lcamellia_sp00444404:
    .quad   0x0000707070700070, 0x00002c2c2c2c002c, 0x0000b3b3b3b300b3
    .quad   0x0000c0c0c0c000c0, 0x0000e4e4e4e400e4, 0x0000575757570057
    .quad   0x0000eaeaeaea00ea, 0x0000aeaeaeae00ae, 0x0000232323230023
    .quad   0x00006b6b6b6b006b, 0x0000454545450045, 0x0000a5a5a5a500a5
    .quad   0x0000edededed00ed, 0x00004f4f4f4f004f, 0x00001d1d1d1d001d
    .quad   0x0000929292920092, 0x0000868686860086, 0x0000afafafaf00af
    .quad   0x00007c7c7c7c007c, 0x00001f1f1f1f001f, 0x00003e3e3e3e003e
    .quad   0x0000dcdcdcdc00dc, 0x00005e5e5e5e005e, 0x00000b0b0b0b000b
    .quad   0x0000a6a6a6a600a6, 0x0000393939390039, 0x0000d5d5d5d500d5
    .quad   0x00005d5d5d5d005d, 0x0000d9d9d9d900d9, 0x00005a5a5a5a005a
    .quad   0x0000515151510051, 0x00006c6c6c6c006c, 0x00008b8b8b8b008b
    .quad   0x00009a9a9a9a009a, 0x0000fbfbfbfb00fb, 0x0000b0b0b0b000b0
    .quad   0x0000747474740074, 0x00002b2b2b2b002b, 0x0000f0f0f0f000f0
    .quad   0x0000848484840084, 0x0000dfdfdfdf00df, 0x0000cbcbcbcb00cb
    .quad   0x0000343434340034, 0x0000767676760076, 0x00006d6d6d6d006d
    .quad   0x0000a9a9a9a900a9, 0x0000d1d1d1d100d1, 0x0000040404040004
    .quad   0x0000141414140014, 0x00003a3a3a3a003a, 0x0000dededede00de
    .quad   0x0000111111110011, 0x0000323232320032, 0x00009c9c9c9c009c
    .quad   0x0000535353530053, 0x0000f2f2f2f200f2, 0x0000fefefefe00fe
    .quad   0x0000cfcfcfcf00cf, 0x0000c3c3c3c300c3, 0x00007a7a7a7a007a
    .quad   0x0000242424240024, 0x0000e8e8e8e800e8, 0x0000606060600060
    .quad   0x0000696969690069, 0x0000aaaaaaaa00aa, 0x0000a0a0a0a000a0
    .quad   0x0000a1a1a1a100a1, 0x0000626262620062, 0x0000545454540054
    .quad   0x00001e1e1e1e001e, 0x0000e0e0e0e000e0, 0x0000646464640064
    .quad   0x0000101010100010, 0x0000000000000000, 0x0000a3a3a3a300a3
    .quad   0x0000757575750075, 0x00008a8a8a8a008a, 0x0000e6e6e6e600e6
    .quad   0x0000090909090009, 0x0000dddddddd00dd, 0x0000878787870087
    .quad   0x0000838383830083, 0x0000cdcdcdcd00cd, 0x0000909090900090
    .quad   0x0000737373730073, 0x0000f6f6f6f600f6, 0x00009d9d9d9d009d
    .quad   0x0000bfbfbfbf00bf, 0x0000525252520052, 0x0000d8d8d8d800d8
    .quad   0x0000c8c8c8c800c8, 0x0000c6c6c6c600c6, 0x0000818181810081
    .quad   0x00006f6f6f6f006f, 0x0000131313130013, 0x0000636363630063
    .quad   0x0000e9e9e9e900e9, 0x0000a7a7a7a700a7, 0x00009f9f9f9f009f
    .quad   0x0000bcbcbcbc00bc, 0x0000292929290029, 0x0000f9f9f9f900f9
    .quad   0x00002f2f2f2f002f, 0x0000b4b4b4b400b4, 0x0000787878780078
    .quad   0x0000060606060006, 0x0000e7e7e7e700e7, 0x0000717171710071
    .quad   0x0000d4d4d4d400d4, 0x0000abababab00ab, 0x0000888888880088
    .quad   0x00008d8d8d8d008d, 0x0000727272720072, 0x0000b9b9b9b900b9
    .quad   0x0000f8f8f8f800f8, 0x0000acacacac00ac, 0x0000363636360036
    .quad   0x00002a2a2a2a002a, 0x00003c3c3c3c003c, 0x0000f1f1f1f100f1
    .quad   0x0000404040400040, 0x0000d3d3d3d300d3, 0x0000bbbbbbbb00bb
    .quad   0x0000434343430043, 0x0000151515150015, 0x0000adadadad00ad
    .quad   0x0000777777770077, 0x0000808080800080, 0x0000828282820082
    .quad   0x0000ecececec00ec, 0x0000272727270027, 0x0000e5e5e5e500e5
    .quad   0x0000858585850085, 0x0000353535350035, 0x00000c0c0c0c000c
    .quad   0x0000414141410041, 0x0000efefefef00ef, 0x0000939393930093
    .quad   0x0000191919190019, 0x0000212121210021, 0x00000e0e0e0e000e
    .quad   0x00004e4e4e4e004e, 0x0000656565650065, 0x0000bdbdbdbd00bd
    .quad   0x0000b8b8b8b800b8, 0x00008f8f8f8f008f, 0x0000ebebebeb00eb
    .quad   0x0000cececece00ce, 0x0000303030300030, 0x00005f5f5f5f005f
    .quad   0x0000c5c5c5c500c5, 0x00001a1a1a1a001a, 0x0000e1e1e1e100e1
    .quad   0x0000cacacaca00ca, 0x0000474747470047, 0x00003d3d3d3d003d
    .quad   0x0000010101010001, 0x0000d6d6d6d600d6, 0x0000565656560056
    .quad   0x00004d4d4d4d004d, 0x00000d0d0d0d000d, 0x0000666666660066
    .quad   0x0000cccccccc00cc, 0x00002d2d2d2d002d, 0x0000121212120012
    .quad   0x0000202020200020, 0x0000b1b1b1b100b1, 0x0000999999990099
    .quad   0x00004c4c4c4c004c, 0x0000c2c2c2c200c2, 0x00007e7e7e7e007e
    .quad   0x0000050505050005, 0x0000b7b7b7b700b7, 0x0000313131310031
    .quad   0x0000171717170017, 0x0000d7d7d7d700d7, 0x0000585858580058
    .quad   0x0000616161610061, 0x00001b1b1b1b001b, 0x00001c1c1c1c001c
    .quad   0x00000f0f0f0f000f, 0x0000161616160016, 0x0000181818180018
    .quad   0x0000222222220022, 0x0000444444440044, 0x0000b2b2b2b200b2
    .quad   0x0000b5b5b5b500b5, 0x0000919191910091, 0x0000080808080008
    .quad   0x0000a8a8a8a800a8, 0x0000fcfcfcfc00fc, 0x0000505050500050
    .quad   0x0000d0d0d0d000d0, 0x00007d7d7d7d007d, 0x0000898989890089
    .quad   0x0000979797970097, 0x00005b5b5b5b005b, 0x0000959595950095
    .quad   0x0000ffffffff00ff, 0x0000d2d2d2d200d2, 0x0000c4c4c4c400c4
    .quad   0x0000484848480048, 0x0000f7f7f7f700f7, 0x0000dbdbdbdb00db
    .quad   0x0000030303030003, 0x0000dadadada00da, 0x00003f3f3f3f003f
    .quad   0x0000949494940094, 0x00005c5c5c5c005c, 0x0000020202020002
    .quad   0x00004a4a4a4a004a, 0x0000333333330033, 0x0000676767670067
    .quad   0x0000f3f3f3f300f3, 0x00007f7f7f7f007f, 0x0000e2e2e2e200e2
    .quad   0x00009b9b9b9b009b, 0x0000262626260026, 0x0000373737370037
    .quad   0x00003b3b3b3b003b, 0x0000969696960096, 0x00004b4b4b4b004b
    .quad   0x0000bebebebe00be, 0x00002e2e2e2e002e, 0x0000797979790079
    .quad   0x00008c8c8c8c008c, 0x00006e6e6e6e006e, 0x00008e8e8e8e008e
    .quad   0x0000f5f5f5f500f5, 0x0000b6b6b6b600b6, 0x0000fdfdfdfd00fd
    .quad   0x0000595959590059, 0x0000989898980098, 0x00006a6a6a6a006a
    .quad   0x0000464646460046, 0x0000babababa00ba, 0x0000252525250025
    .quad   0x0000424242420042, 0x0000a2a2a2a200a2, 0x0000fafafafa00fa
    .quad   0x0000070707070007, 0x0000555555550055, 0x0000eeeeeeee00ee
    .quad   0x00000a0a0a0a000a, 0x0000494949490049, 0x0000686868680068
    .quad   0x0000383838380038, 0x0000a4a4a4a400a4, 0x0000282828280028
    .quad   0x00007b7b7b7b007b, 0x0000c9c9c9c900c9, 0x0000c1c1c1c100c1
    .quad   0x0000e3e3e3e300e3, 0x0000f4f4f4f400f4, 0x0000c7c7c7c700c7
    .quad   0x00009e9e9e9e009e
.Lcamellia_sp02220222:
    .quad   0x00e0e0e000e0e0e0, 0x0005050500050505, 0x0058585800585858
    .quad   0x00d9d9d900d9d9d9, 0x0067676700676767, 0x004e4e4e004e4e4e
    .quad   0x0081818100818181, 0x00cbcbcb00cbcbcb, 0x00c9c9c900c9c9c9
    .quad   0x000b0b0b000b0b0b, 0x00aeaeae00aeaeae, 0x006a6a6a006a6a6a
    .quad   0x00d5d5d500d5d5d5, 0x0018181800181818, 0x005d5d5d005d5d5d
    .quad   0x0082828200828282, 0x0046464600464646, 0x00dfdfdf00dfdfdf
    .quad   0x00d6d6d600d6d6d6, 0x0027272700272727, 0x008a8a8a008a8a8a
    .quad   0x0032323200323232, 0x004b4b4b004b4b4b, 0x0042424200424242
    .quad   0x00dbdbdb00dbdbdb, 0x001c1c1c001c1c1c, 0x009e9e9e009e9e9e
    .quad   0x009c9c9c009c9c9c, 0x003a3a3a003a3a3a, 0x00cacaca00cacaca
    .quad   0x0025252500252525, 0x007b7b7b007b7b7b, 0x000d0d0d000d0d0d
    .quad   0x0071717100717171, 0x005f5f5f005f5f5f, 0x001f1f1f001f1f1f
    .quad   0x00f8f8f800f8f8f8, 0x00d7d7d700d7d7d7, 0x003e3e3e003e3e3e
    .quad   0x009d9d9d009d9d9d, 0x007c7c7c007c7c7c, 0x0060606000606060
    .quad   0x00b9b9b900b9b9b9, 0x00bebebe00bebebe, 0x00bcbcbc00bcbcbc
    .quad   0x008b8b8b008b8b8b, 0x0016161600161616, 0x0034343400343434
    .quad   0x004d4d4d004d4d4d, 0x00c3c3c300c3c3c3, 0x0072727200727272
    .quad   0x0095959500959595, 0x00ababab00ababab, 0x008e8e8e008e8e8e
    .quad   0x00bababa00bababa, 0x007a7a7a007a7a7a, 0x00b3b3b300b3b3b3
    .quad   0x0002020200020202, 0x00b4b4b400b4b4b4, 0x00adadad00adadad
    .quad   0x00a2a2a200a2a2a2, 0x00acacac00acacac, 0x00d8d8d800d8d8d8
    .quad   0x009a9a9a009a9a9a, 0x0017171700171717, 0x001a1a1a001a1a1a
    .quad   0x0035353500353535, 0x00cccccc00cccccc, 0x00f7f7f700f7f7f7
    .quad   0x0099999900999999, 0x0061616100616161, 0x005a5a5a005a5a5a
    .quad   0x00e8e8e800e8e8e8, 0x0024242400242424, 0x0056565600565656
    .quad   0x0040404000404040, 0x00e1e1e100e1e1e1, 0x0063636300636363
    .quad   0x0009090900090909, 0x0033333300333333, 0x00bfbfbf00bfbfbf
    .quad   0x0098989800989898, 0x0097979700979797, 0x0085858500858585
    .quad   0x0068686800686868, 0x00fcfcfc00fcfcfc, 0x00ececec00ececec
    .quad   0x000a0a0a000a0a0a, 0x00dadada00dadada, 0x006f6f6f006f6f6f
    .quad   0x0053535300535353, 0x0062626200626262, 0x00a3a3a300a3a3a3
    .quad   0x002e2e2e002e2e2e, 0x0008080800080808, 0x00afafaf00afafaf
    .quad   0x0028282800282828, 0x00b0b0b000b0b0b0, 0x0074747400747474
    .quad   0x00c2c2c200c2c2c2, 0x00bdbdbd00bdbdbd, 0x0036363600363636
    .quad   0x0022222200222222, 0x0038383800383838, 0x0064646400646464
    .quad   0x001e1e1e001e1e1e, 0x0039393900393939, 0x002c2c2c002c2c2c
    .quad   0x00a6a6a600a6a6a6, 0x0030303000303030, 0x00e5e5e500e5e5e5
    .quad   0x0044444400444444, 0x00fdfdfd00fdfdfd, 0x0088888800888888
    .quad   0x009f9f9f009f9f9f, 0x0065656500656565, 0x0087878700878787
    .quad   0x006b6b6b006b6b6b, 0x00f4f4f400f4f4f4, 0x0023232300232323
    .quad   0x0048484800484848, 0x0010101000101010, 0x00d1d1d100d1d1d1
    .quad   0x0051515100515151, 0x00c0c0c000c0c0c0, 0x00f9f9f900f9f9f9
    .quad   0x00d2d2d200d2d2d2, 0x00a0a0a000a0a0a0, 0x0055555500555555
    .quad   0x00a1a1a100a1a1a1, 0x0041414100414141, 0x00fafafa00fafafa
    .quad   0x0043434300434343, 0x0013131300131313, 0x00c4c4c400c4c4c4
    .quad   0x002f2f2f002f2f2f, 0x00a8a8a800a8a8a8, 0x00b6b6b600b6b6b6
    .quad   0x003c3c3c003c3c3c, 0x002b2b2b002b2b2b, 0x00c1c1c100c1c1c1
    .quad   0x00ffffff00ffffff, 0x00c8c8c800c8c8c8, 0x00a5a5a500a5a5a5
    .quad   0x0020202000202020, 0x0089898900898989, 0x0000000000000000
    .quad   0x0090909000909090, 0x0047474700474747, 0x00efefef00efefef
    .quad   0x00eaeaea00eaeaea, 0x00b7b7b700b7b7b7, 0x0015151500151515
    .quad   0x0006060600060606, 0x00cdcdcd00cdcdcd, 0x00b5b5b500b5b5b5
    .quad   0x0012121200121212, 0x007e7e7e007e7e7e, 0x00bbbbbb00bbbbbb
    .quad   0x0029292900292929, 0x000f0f0f000f0f0f, 0x00b8b8b800b8b8b8
    .quad   0x0007070700070707, 0x0004040400040404, 0x009b9b9b009b9b9b
    .quad   0x0094949400949494, 0x0021212100212121, 0x0066666600666666
    .quad   0x00e6e6e600e6e6e6, 0x00cecece00cecece, 0x00ededed00ededed
    .quad   0x00e7e7e700e7e7e7, 0x003b3b3b003b3b3b, 0x00fefefe00fefefe
    .quad   0x007f7f7f007f7f7f, 0x00c5c5c500c5c5c5, 0x00a4a4a400a4a4a4
    .quad   0x0037373700373737, 0x00b1b1b100b1b1b1, 0x004c4c4c004c4c4c
    .quad   0x0091919100919191, 0x006e6e6e006e6e6e, 0x008d8d8d008d8d8d
    .quad   0x0076767600767676, 0x0003030300030303, 0x002d2d2d002d2d2d
    .quad   0x00dedede00dedede, 0x0096969600969696, 0x0026262600262626
    .quad   0x007d7d7d007d7d7d, 0x00c6c6c600c6c6c6, 0x005c5c5c005c5c5c
    .quad   0x00d3d3d300d3d3d3, 0x00f2f2f200f2f2f2, 0x004f4f4f004f4f4f
    .quad   0x0019191900191919, 0x003f3f3f003f3f3f, 0x00dcdcdc00dcdcdc
    .quad   0x0079797900797979, 0x001d1d1d001d1d1d, 0x0052525200525252
    .quad   0x00ebebeb00ebebeb, 0x00f3f3f300f3f3f3, 0x006d6d6d006d6d6d
    .quad   0x005e5e5e005e5e5e, 0x00fbfbfb00fbfbfb, 0x0069696900696969
    .quad   0x00b2b2b200b2b2b2, 0x00f0f0f000f0f0f0, 0x0031313100313131
    .quad   0x000c0c0c000c0c0c, 0x00d4d4d400d4d4d4, 0x00cfcfcf00cfcfcf
    .quad   0x008c8c8c008c8c8c, 0x00e2e2e200e2e2e2, 0x0075757500757575
    .quad   0x00a9a9a900a9a9a9, 0x004a4a4a004a4a4a, 0x0057575700575757
    .quad   0x0084848400848484, 0x0011111100111111, 0x0045454500454545
    .quad   0x001b1b1b001b1b1b, 0x00f5f5f500f5f5f5, 0x00e4e4e400e4e4e4
    .quad   0x000e0e0e000e0e0e, 0x0073737300737373, 0x00aaaaaa00aaaaaa
    .quad   0x00f1f1f100f1f1f1, 0x00dddddd00dddddd, 0x0059595900595959
    .quad   0x0014141400141414, 0x006c6c6c006c6c6c, 0x0092929200929292
    .quad   0x0054545400545454, 0x00d0d0d000d0d0d0, 0x0078787800787878
    .quad   0x0070707000707070, 0x00e3e3e300e3e3e3, 0x0049494900494949
    .quad   0x0080808000808080, 0x0050505000505050, 0x00a7a7a700a7a7a7
    .quad   0x00f6f6f600f6f6f6, 0x0077777700777777, 0x0093939300939393
    .quad   0x0086868600868686, 0x0083838300838383, 0x002a2a2a002a2a2a
    .quad   0x00c7c7c700c7c7c7, 0x005b5b5b005b5b5b, 0x00e9e9e900e9e9e9
    .quad   0x00eeeeee00eeeeee, 0x008f8f8f008f8f8f, 0x0001010100010101
    .quad   0x003d3d3d003d3d3d
.Lcamellia_sp30333033:
    .quad   0x3800383838003838, 0x4100414141004141, 0x1600161616001616
    .quad   0x7600767676007676, 0xd900d9d9d900d9d9, 0x9300939393009393
    .quad   0x6000606060006060, 0xf200f2f2f200f2f2, 0x7200727272007272
    .quad   0xc200c2c2c200c2c2, 0xab00ababab00abab, 0x9a009a9a9a009a9a
    .quad   0x7500757575007575, 0x0600060606000606, 0x5700575757005757
    .quad   0xa000a0a0a000a0a0, 0x9100919191009191, 0xf700f7f7f700f7f7
    .quad   0xb500b5b5b500b5b5, 0xc900c9c9c900c9c9, 0xa200a2a2a200a2a2
    .quad   0x8c008c8c8c008c8c, 0xd200d2d2d200d2d2, 0x9000909090009090
    .quad   0xf600f6f6f600f6f6, 0x0700070707000707, 0xa700a7a7a700a7a7
    .quad   0x2700272727002727, 0x8e008e8e8e008e8e, 0xb200b2b2b200b2b2
    .quad   0x4900494949004949, 0xde00dedede00dede, 0x4300434343004343
    .quad   0x5c005c5c5c005c5c, 0xd700d7d7d700d7d7, 0xc700c7c7c700c7c7
    .quad   0x3e003e3e3e003e3e, 0xf500f5f5f500f5f5, 0x8f008f8f8f008f8f
    .quad   0x6700676767006767, 0x1f001f1f1f001f1f, 0x1800181818001818
    .quad   0x6e006e6e6e006e6e, 0xaf00afafaf00afaf, 0x2f002f2f2f002f2f
    .quad   0xe200e2e2e200e2e2, 0x8500858585008585, 0x0d000d0d0d000d0d
    .quad   0x5300535353005353, 0xf000f0f0f000f0f0, 0x9c009c9c9c009c9c
    .quad   0x6500656565006565, 0xea00eaeaea00eaea, 0xa300a3a3a300a3a3
    .quad   0xae00aeaeae00aeae, 0x9e009e9e9e009e9e, 0xec00ececec00ecec
    .quad   0x8000808080008080, 0x2d002d2d2d002d2d, 0x6b006b6b6b006b6b
    .quad   0xa800a8a8a800a8a8, 0x2b002b2b2b002b2b, 0x3600363636003636
    .quad   0xa600a6a6a600a6a6, 0xc500c5c5c500c5c5, 0x8600868686008686
    .quad   0x4d004d4d4d004d4d, 0x3300333333003333, 0xfd00fdfdfd00fdfd
    .quad   0x6600666666006666, 0x5800585858005858, 0x9600969696009696
    .quad   0x3a003a3a3a003a3a, 0x0900090909000909, 0x9500959595009595
    .quad   0x1000101010001010, 0x7800787878007878, 0xd800d8d8d800d8d8
    .quad   0x4200424242004242, 0xcc00cccccc00cccc, 0xef00efefef00efef
    .quad   0x2600262626002626, 0xe500e5e5e500e5e5, 0x6100616161006161
    .quad   0x1a001a1a1a001a1a, 0x3f003f3f3f003f3f, 0x3b003b3b3b003b3b
    .quad   0x8200828282008282, 0xb600b6b6b600b6b6, 0xdb00dbdbdb00dbdb
    .quad   0xd400d4d4d400d4d4, 0x9800989898009898, 0xe800e8e8e800e8e8
    .quad   0x8b008b8b8b008b8b, 0x0200020202000202, 0xeb00ebebeb00ebeb
    .quad   0x0a000a0a0a000a0a, 0x2c002c2c2c002c2c, 0x1d001d1d1d001d1d
    .quad   0xb000b0b0b000b0b0, 0x6f006f6f6f006f6f, 0x8d008d8d8d008d8d
    .quad   0x8800888888008888, 0x0e000e0e0e000e0e, 0x1900191919001919
    .quad   0x8700878787008787, 0x4e004e4e4e004e4e, 0x0b000b0b0b000b0b
    .quad   0xa900a9a9a900a9a9, 0x0c000c0c0c000c0c, 0x7900797979007979
    .quad   0x1100111111001111, 0x7f007f7f7f007f7f, 0x2200222222002222
    .quad   0xe700e7e7e700e7e7, 0x5900595959005959, 0xe100e1e1e100e1e1
    .quad   0xda00dadada00dada, 0x3d003d3d3d003d3d, 0xc800c8c8c800c8c8
    .quad   0x1200121212001212, 0x0400040404000404, 0x7400747474007474
    .quad   0x5400545454005454, 0x3000303030003030, 0x7e007e7e7e007e7e
    .quad   0xb400b4b4b400b4b4, 0x2800282828002828, 0x5500555555005555
    .quad   0x6800686868006868, 0x5000505050005050, 0xbe00bebebe00bebe
    .quad   0xd000d0d0d000d0d0, 0xc400c4c4c400c4c4, 0x3100313131003131
    .quad   0xcb00cbcbcb00cbcb, 0x2a002a2a2a002a2a, 0xad00adadad00adad
    .quad   0x0f000f0f0f000f0f, 0xca00cacaca00caca, 0x7000707070007070
    .quad   0xff00ffffff00ffff, 0x3200323232003232, 0x6900696969006969
    .quad   0x0800080808000808, 0x6200626262006262, 0x0000000000000000
    .quad   0x2400242424002424, 0xd100d1d1d100d1d1, 0xfb00fbfbfb00fbfb
    .quad   0xba00bababa00baba, 0xed00ededed00eded, 0x4500454545004545
    .quad   0x8100818181008181, 0x7300737373007373, 0x6d006d6d6d006d6d
    .quad   0x8400848484008484, 0x9f009f9f9f009f9f, 0xee00eeeeee00eeee
    .quad   0x4a004a4a4a004a4a, 0xc300c3c3c300c3c3, 0x2e002e2e2e002e2e
    .quad   0xc100c1c1c100c1c1, 0x0100010101000101, 0xe600e6e6e600e6e6
    .quad   0x2500252525002525, 0x4800484848004848, 0x9900999999009999
    .quad   0xb900b9b9b900b9b9, 0xb300b3b3b300b3b3, 0x7b007b7b7b007b7b
    .quad   0xf900f9f9f900f9f9, 0xce00cecece00cece, 0xbf00bfbfbf00bfbf
    .quad   0xdf00dfdfdf00dfdf, 0x7100717171007171, 0x2900292929002929
    .quad   0xcd00cdcdcd00cdcd, 0x6c006c6c6c006c6c, 0x1300131313001313
    .quad   0x6400646464006464, 0x9b009b9b9b009b9b, 0x6300636363006363
    .quad   0x9d009d9d9d009d9d, 0xc000c0c0c000c0c0, 0x4b004b4b4b004b4b
    .quad   0xb700b7b7b700b7b7, 0xa500a5a5a500a5a5, 0x8900898989008989
    .quad   0x5f005f5f5f005f5f, 0xb100b1b1b100b1b1, 0x1700171717001717
    .quad   0xf400f4f4f400f4f4, 0xbc00bcbcbc00bcbc, 0xd300d3d3d300d3d3
    .quad   0x4600464646004646, 0xcf00cfcfcf00cfcf, 0x3700373737003737
    .quad   0x5e005e5e5e005e5e, 0x4700474747004747, 0x9400949494009494
    .quad   0xfa00fafafa00fafa, 0xfc00fcfcfc00fcfc, 0x5b005b5b5b005b5b
    .quad   0x9700979797009797, 0xfe00fefefe00fefe, 0x5a005a5a5a005a5a
    .quad   0xac00acacac00acac, 0x3c003c3c3c003c3c, 0x4c004c4c4c004c4c
    .quad   0x0300030303000303, 0x3500353535003535, 0xf300f3f3f300f3f3
    .quad   0x2300232323002323, 0xb800b8b8b800b8b8, 0x5d005d5d5d005d5d
    .quad   0x6a006a6a6a006a6a, 0x9200929292009292, 0xd500d5d5d500d5d5
    .quad   0x2100212121002121, 0x4400444444004444, 0x5100515151005151
    .quad   0xc600c6c6c600c6c6, 0x7d007d7d7d007d7d, 0x3900393939003939
    .quad   0x8300838383008383, 0xdc00dcdcdc00dcdc, 0xaa00aaaaaa00aaaa
    .quad   0x7c007c7c7c007c7c, 0x7700777777007777, 0x5600565656005656
    .quad   0x0500050505000505, 0x1b001b1b1b001b1b, 0xa400a4a4a400a4a4
    .quad   0x1500151515001515, 0x3400343434003434, 0x1e001e1e1e001e1e
    .quad   0x1c001c1c1c001c1c, 0xf800f8f8f800f8f8, 0x5200525252005252
    .quad   0x2000202020002020, 0x1400141414001414, 0xe900e9e9e900e9e9
    .quad   0xbd00bdbdbd00bdbd, 0xdd00dddddd00dddd, 0xe400e4e4e400e4e4
    .quad   0xa100a1a1a100a1a1, 0xe000e0e0e000e0e0, 0x8a008a8a8a008a8a
    .quad   0xf100f1f1f100f1f1, 0xd600d6d6d600d6d6, 0x7a007a7a7a007a7a
    .quad   0xbb00bbbbbb00bbbb, 0xe300e3e3e300e3e3, 0x4000404040004040
    .quad   0x4f004f4f4f004f4f
.Lcamellia_sp44044404:
    .quad   0x7070007070700070, 0x2c2c002c2c2c002c, 0xb3b300b3b3b300b3
    .quad   0xc0c000c0c0c000c0, 0xe4e400e4e4e400e4, 0x5757005757570057
    .quad   0xeaea00eaeaea00ea, 0xaeae00aeaeae00ae, 0x2323002323230023
    .quad   0x6b6b006b6b6b006b, 0x4545004545450045, 0xa5a500a5a5a500a5
    .quad   0xeded00ededed00ed, 0x4f4f004f4f4f004f, 0x1d1d001d1d1d001d
    .quad   0x9292009292920092, 0x8686008686860086, 0xafaf00afafaf00af
    .quad   0x7c7c007c7c7c007c, 0x1f1f001f1f1f001f, 0x3e3e003e3e3e003e
    .quad   0xdcdc00dcdcdc00dc, 0x5e5e005e5e5e005e, 0x0b0b000b0b0b000b
    .quad   0xa6a600a6a6a600a6, 0x3939003939390039, 0xd5d500d5d5d500d5
    .quad   0x5d5d005d5d5d005d, 0xd9d900d9d9d900d9, 0x5a5a005a5a5a005a
    .quad   0x5151005151510051, 0x6c6c006c6c6c006c, 0x8b8b008b8b8b008b
    .quad   0x9a9a009a9a9a009a, 0xfbfb00fbfbfb00fb, 0xb0b000b0b0b000b0
    .quad   0x7474007474740074, 0x2b2b002b2b2b002b, 0xf0f000f0f0f000f0
    .quad   0x8484008484840084, 0xdfdf00dfdfdf00df, 0xcbcb00cbcbcb00cb
    .quad   0x3434003434340034, 0x7676007676760076, 0x6d6d006d6d6d006d
    .quad   0xa9a900a9a9a900a9, 0xd1d100d1d1d100d1, 0x0404000404040004
    .quad   0x1414001414140014, 0x3a3a003a3a3a003a, 0xdede00dedede00de
    .quad   0x1111001111110011, 0x3232003232320032, 0x9c9c009c9c9c009c
    .quad   0x5353005353530053, 0xf2f200f2f2f200f2, 0xfefe00fefefe00fe
    .quad   0xcfcf00cfcfcf00cf, 0xc3c300c3c3c300c3, 0x7a7a007a7a7a007a
    .quad   0x2424002424240024, 0xe8e800e8e8e800e8, 0x6060006060600060
    .quad   0x6969006969690069, 0xaaaa00aaaaaa00aa, 0xa0a000a0a0a000a0
    .quad   0xa1a100a1a1a100a1, 0x6262006262620062, 0x5454005454540054
    .quad   0x1e1e001e1e1e001e, 0xe0e000e0e0e000e0, 0x6464006464640064
    .quad   0x1010001010100010, 0x0000000000000000, 0xa3a300a3a3a300a3
    .quad   0x7575007575750075, 0x8a8a008a8a8a008a, 0xe6e600e6e6e600e6
    .quad   0x0909000909090009, 0xdddd00dddddd00dd, 0x8787008787870087
    .quad   0x8383008383830083, 0xcdcd00cdcdcd00cd, 0x9090009090900090
    .quad   0x7373007373730073, 0xf6f600f6f6f600f6, 0x9d9d009d9d9d009d
    .quad   0xbfbf00bfbfbf00bf, 0x5252005252520052, 0xd8d800d8d8d800d8
    .quad   0xc8c800c8c8c800c8, 0xc6c600c6c6c600c6, 0x8181008181810081
    .quad   0x6f6f006f6f6f006f, 0x1313001313130013, 0x6363006363630063
    .quad   0xe9e900e9e9e900e9, 0xa7a700a7a7a700a7, 0x9f9f009f9f9f009f
    .quad   0xbcbc00bcbcbc00bc, 0x2929002929290029, 0xf9f900f9f9f900f9
    .quad   0x2f2f002f2f2f002f, 0xb4b400b4b4b400b4, 0x7878007878780078
    .quad   0x0606000606060006, 0xe7e700e7e7e700e7, 0x7171007171710071
    .quad   0xd4d400d4d4d400d4, 0xabab00ababab00ab, 0x8888008888880088
    .quad   0x8d8d008d8d8d008d, 0x7272007272720072, 0xb9b900b9b9b900b9
    .quad   0xf8f800f8f8f800f8, 0xacac00acacac00ac, 0x3636003636360036
    .quad   0x2a2a002a2a2a002a, 0x3c3c003c3c3c003c, 0xf1f100f1f1f100f1
    .quad   0x4040004040400040, 0xd3d300d3d3d300d3, 0xbbbb00bbbbbb00bb
    .quad   0x4343004343430043, 0x1515001515150015, 0xadad00adadad00ad
    .quad   0x7777007777770077, 0x8080008080800080, 0x8282008282820082
    .quad   0xecec00ececec00ec, 0x2727002727270027, 0xe5e500e5e5e500e5
    .quad   0x8585008585850085, 0x3535003535350035, 0x0c0c000c0c0c000c
    .quad   0x4141004141410041, 0xefef00efefef00ef, 0x9393009393930093
    .quad   0x1919001919190019, 0x2121002121210021, 0x0e0e000e0e0e000e
    .quad   0x4e4e004e4e4e004e, 0x6565006565650065, 0xbdbd00bdbdbd00bd
    .quad   0xb8b800b8b8b800b8, 0x8f8f008f8f8f008f, 0xebeb00ebebeb00eb
    .quad   0xcece00cecece00ce, 0x3030003030300030, 0x5f5f005f5f5f005f
    .quad   0xc5c500c5c5c500c5, 0x1a1a001a1a1a001a, 0xe1e100e1e1e100e1
    .quad   0xcaca00cacaca00ca, 0x4747004747470047, 0x3d3d003d3d3d003d
    .quad   0x0101000101010001, 0xd6d600d6d6d600d6, 0x5656005656560056
    .quad   0x4d4d004d4d4d004d, 0x0d0d000d0d0d000d, 0x6666006666660066
    .quad   0xcccc00cccccc00cc, 0x2d2d002d2d2d002d, 0x1212001212120012
    .quad   0x2020002020200020, 0xb1b100b1b1b100b1, 0x9999009999990099
    .quad   0x4c4c004c4c4c004c, 0xc2c200c2c2c200c2, 0x7e7e007e7e7e007e
    .quad   0x0505000505050005, 0xb7b700b7b7b700b7, 0x3131003131310031
    .quad   0x1717001717170017, 0xd7d700d7d7d700d7, 0x5858005858580058
    .quad   0x6161006161610061, 0x1b1b001b1b1b001b, 0x1c1c001c1c1c001c
    .quad   0x0f0f000f0f0f000f, 0x1616001616160016, 0x1818001818180018
    .quad   0x2222002222220022, 0x4444004444440044, 0xb2b200b2b2b200b2
    .quad   0xb5b500b5b5b500b5, 0x9191009191910091, 0x0808000808080008
    .quad   0xa8a800a8a8a800a8, 0xfcfc00fcfcfc00fc, 0x5050005050500050
    .quad   0xd0d000d0d0d000d0, 0x7d7d007d7d7d007d, 0x8989008989890089
    .quad   0x9797009797970097, 0x5b5b005b5b5b005b, 0x9595009595950095
    .quad   0xffff00ffffff00ff, 0xd2d200d2d2d200d2, 0xc4c400c4c4c400c4
    .quad   0x4848004848480048, 0xf7f700f7f7f700f7, 0xdbdb00dbdbdb00db
    .quad   0x0303000303030003, 0xdada00dadada00da, 0x3f3f003f3f3f003f
    .quad   0x9494009494940094, 0x5c5c005c5c5c005c, 0x0202000202020002
    .quad   0x4a4a004a4a4a004a, 0x3333003333330033, 0x6767006767670067
    .quad   0xf3f300f3f3f300f3, 0x7f7f007f7f7f007f, 0xe2e200e2e2e200e2
    .quad   0x9b9b009b9b9b009b, 0x2626002626260026, 0x3737003737370037
    .quad   0x3b3b003b3b3b003b, 0x9696009696960096, 0x4b4b004b4b4b004b
    .quad   0xbebe00bebebe00be, 0x2e2e002e2e2e002e, 0x7979007979790079
    .quad   0x8c8c008c8c8c008c, 0x6e6e006e6e6e006e, 0x8e8e008e8e8e008e
    .quad   0xf5f500f5f5f500f5, 0xb6b600b6b6b600b6, 0xfdfd00fdfdfd00fd
    .quad   0x5959005959590059, 0x9898009898980098, 0x6a6a006a6a6a006a
    .quad   0x4646004646460046, 0xbaba00bababa00ba, 0x2525002525250025
    .quad   0x4242004242420042, 0xa2a200a2a2a200a2, 0xfafa00fafafa00fa
    .quad   0x0707000707070007, 0x5555005555550055, 0xeeee00eeeeee00ee
    .quad   0x0a0a000a0a0a000a, 0x4949004949490049, 0x6868006868680068
    .quad   0x3838003838380038, 0xa4a400a4a4a400a4, 0x2828002828280028
    .quad   0x7b7b007b7b7b007b, 0xc9c900c9c9c900c9, 0xc1c100c1c1c100c1
    .quad   0xe3e300e3e3e300e3, 0xf4f400f4f4f400f4, 0xc7c700c7c7c700c7
    .quad   0x9e9e009e9e9e009e
.Lcamellia_sp11101110:
    .quad   0x7070700070707000, 0x8282820082828200, 0x2c2c2c002c2c2c00
    .quad   0xececec00ececec00, 0xb3b3b300b3b3b300, 0x2727270027272700
    .quad   0xc0c0c000c0c0c000, 0xe5e5e500e5e5e500, 0xe4e4e400e4e4e400
    .quad   0x8585850085858500, 0x5757570057575700, 0x3535350035353500
    .quad   0xeaeaea00eaeaea00, 0x0c0c0c000c0c0c00, 0xaeaeae00aeaeae00
    .quad   0x4141410041414100, 0x2323230023232300, 0xefefef00efefef00
    .quad   0x6b6b6b006b6b6b00, 0x9393930093939300, 0x4545450045454500
    .quad   0x1919190019191900, 0xa5a5a500a5a5a500, 0x2121210021212100
    .quad   0xededed00ededed00, 0x0e0e0e000e0e0e00, 0x4f4f4f004f4f4f00
    .quad   0x4e4e4e004e4e4e00, 0x1d1d1d001d1d1d00, 0x6565650065656500
    .quad   0x9292920092929200, 0xbdbdbd00bdbdbd00, 0x8686860086868600
    .quad   0xb8b8b800b8b8b800, 0xafafaf00afafaf00, 0x8f8f8f008f8f8f00
    .quad   0x7c7c7c007c7c7c00, 0xebebeb00ebebeb00, 0x1f1f1f001f1f1f00
    .quad   0xcecece00cecece00, 0x3e3e3e003e3e3e00, 0x3030300030303000
    .quad   0xdcdcdc00dcdcdc00, 0x5f5f5f005f5f5f00, 0x5e5e5e005e5e5e00
    .quad   0xc5c5c500c5c5c500, 0x0b0b0b000b0b0b00, 0x1a1a1a001a1a1a00
    .quad   0xa6a6a600a6a6a600, 0xe1e1e100e1e1e100, 0x3939390039393900
    .quad   0xcacaca00cacaca00, 0xd5d5d500d5d5d500, 0x4747470047474700
    .quad   0x5d5d5d005d5d5d00, 0x3d3d3d003d3d3d00, 0xd9d9d900d9d9d900
    .quad   0x0101010001010100, 0x5a5a5a005a5a5a00, 0xd6d6d600d6d6d600
    .quad   0x5151510051515100, 0x5656560056565600, 0x6c6c6c006c6c6c00
    .quad   0x4d4d4d004d4d4d00, 0x8b8b8b008b8b8b00, 0x0d0d0d000d0d0d00
    .quad   0x9a9a9a009a9a9a00, 0x6666660066666600, 0xfbfbfb00fbfbfb00
    .quad   0xcccccc00cccccc00, 0xb0b0b000b0b0b000, 0x2d2d2d002d2d2d00
    .quad   0x7474740074747400, 0x1212120012121200, 0x2b2b2b002b2b2b00
    .quad   0x2020200020202000, 0xf0f0f000f0f0f000, 0xb1b1b100b1b1b100
    .quad   0x8484840084848400, 0x9999990099999900, 0xdfdfdf00dfdfdf00
    .quad   0x4c4c4c004c4c4c00, 0xcbcbcb00cbcbcb00, 0xc2c2c200c2c2c200
    .quad   0x3434340034343400, 0x7e7e7e007e7e7e00, 0x7676760076767600
    .quad   0x0505050005050500, 0x6d6d6d006d6d6d00, 0xb7b7b700b7b7b700
    .quad   0xa9a9a900a9a9a900, 0x3131310031313100, 0xd1d1d100d1d1d100
    .quad   0x1717170017171700, 0x0404040004040400, 0xd7d7d700d7d7d700
    .quad   0x1414140014141400, 0x5858580058585800, 0x3a3a3a003a3a3a00
    .quad   0x6161610061616100, 0xdedede00dedede00, 0x1b1b1b001b1b1b00
    .quad   0x1111110011111100, 0x1c1c1c001c1c1c00, 0x3232320032323200
    .quad   0x0f0f0f000f0f0f00, 0x9c9c9c009c9c9c00, 0x1616160016161600
    .quad   0x5353530053535300, 0x1818180018181800, 0xf2f2f200f2f2f200
    .quad   0x2222220022222200, 0xfefefe00fefefe00, 0x4444440044444400
    .quad   0xcfcfcf00cfcfcf00, 0xb2b2b200b2b2b200, 0xc3c3c300c3c3c300
    .quad   0xb5b5b500b5b5b500, 0x7a7a7a007a7a7a00, 0x9191910091919100
    .quad   0x2424240024242400, 0x0808080008080800, 0xe8e8e800e8e8e800
    .quad   0xa8a8a800a8a8a800, 0x6060600060606000, 0xfcfcfc00fcfcfc00
    .quad   0x6969690069696900, 0x5050500050505000, 0xaaaaaa00aaaaaa00
    .quad   0xd0d0d000d0d0d000, 0xa0a0a000a0a0a000, 0x7d7d7d007d7d7d00
    .quad   0xa1a1a100a1a1a100, 0x8989890089898900, 0x6262620062626200
    .quad   0x9797970097979700, 0x5454540054545400, 0x5b5b5b005b5b5b00
    .quad   0x1e1e1e001e1e1e00, 0x9595950095959500, 0xe0e0e000e0e0e000
    .quad   0xffffff00ffffff00, 0x6464640064646400, 0xd2d2d200d2d2d200
    .quad   0x1010100010101000, 0xc4c4c400c4c4c400, 0x0000000000000000
    .quad   0x4848480048484800, 0xa3a3a300a3a3a300, 0xf7f7f700f7f7f700
    .quad   0x7575750075757500, 0xdbdbdb00dbdbdb00, 0x8a8a8a008a8a8a00
    .quad   0x0303030003030300, 0xe6e6e600e6e6e600, 0xdadada00dadada00
    .quad   0x0909090009090900, 0x3f3f3f003f3f3f00, 0xdddddd00dddddd00
    .quad   0x9494940094949400, 0x8787870087878700, 0x5c5c5c005c5c5c00
    .quad   0x8383830083838300, 0x0202020002020200, 0xcdcdcd00cdcdcd00
    .quad   0x4a4a4a004a4a4a00, 0x9090900090909000, 0x3333330033333300
    .quad   0x7373730073737300, 0x6767670067676700, 0xf6f6f600f6f6f600
    .quad   0xf3f3f300f3f3f300, 0x9d9d9d009d9d9d00, 0x7f7f7f007f7f7f00
    .quad   0xbfbfbf00bfbfbf00, 0xe2e2e200e2e2e200, 0x5252520052525200
    .quad   0x9b9b9b009b9b9b00, 0xd8d8d800d8d8d800, 0x2626260026262600
    .quad   0xc8c8c800c8c8c800, 0x3737370037373700, 0xc6c6c600c6c6c600
    .quad   0x3b3b3b003b3b3b00, 0x8181810081818100, 0x9696960096969600
    .quad   0x6f6f6f006f6f6f00, 0x4b4b4b004b4b4b00, 0x1313130013131300
    .quad   0xbebebe00bebebe00, 0x6363630063636300, 0x2e2e2e002e2e2e00
    .quad   0xe9e9e900e9e9e900, 0x7979790079797900, 0xa7a7a700a7a7a700
    .quad   0x8c8c8c008c8c8c00, 0x9f9f9f009f9f9f00, 0x6e6e6e006e6e6e00
    .quad   0xbcbcbc00bcbcbc00, 0x8e8e8e008e8e8e00, 0x2929290029292900
    .quad   0xf5f5f500f5f5f500, 0xf9f9f900f9f9f900, 0xb6b6b600b6b6b600
    .quad   0x2f2f2f002f2f2f00, 0xfdfdfd00fdfdfd00, 0xb4b4b400b4b4b400
    .quad   0x5959590059595900, 0x7878780078787800, 0x9898980098989800
    .quad   0x0606060006060600, 0x6a6a6a006a6a6a00, 0xe7e7e700e7e7e700
    .quad   0x4646460046464600, 0x7171710071717100, 0xbababa00bababa00
    .quad   0xd4d4d400d4d4d400, 0x2525250025252500, 0xababab00ababab00
    .quad   0x4242420042424200, 0x8888880088888800, 0xa2a2a200a2a2a200
    .quad   0x8d8d8d008d8d8d00, 0xfafafa00fafafa00, 0x7272720072727200
    .quad   0x0707070007070700, 0xb9b9b900b9b9b900, 0x5555550055555500
    .quad   0xf8f8f800f8f8f800, 0xeeeeee00eeeeee00, 0xacacac00acacac00
    .quad   0x0a0a0a000a0a0a00, 0x3636360036363600, 0x4949490049494900
    .quad   0x2a2a2a002a2a2a00, 0x6868680068686800, 0x3c3c3c003c3c3c00
    .quad   0x3838380038383800, 0xf1f1f100f1f1f100, 0xa4a4a400a4a4a400
    .quad   0x4040400040404000, 0x2828280028282800, 0xd3d3d300d3d3d300
    .quad   0x7b7b7b007b7b7b00, 0xbbbbbb00bbbbbb00, 0xc9c9c900c9c9c900
    .quad   0x4343430043434300, 0xc1c1c100c1c1c100, 0x1515150015151500
    .quad   0xe3e3e300e3e3e300, 0xadadad00adadad00, 0xf4f4f400f4f4f400
    .quad   0x7777770077777700, 0xc7c7c700c7c7c700, 0x8080800080808000
    .quad   0x9e9e9e009e9e9e00
.size   camellia_neon_consts,.-camellia_neon_consts
.previous
___
#
#    General macros
#

sub filter_8bit_neon(){
    my ($x,$lo_t,$hi_t,$mask,$tmp) = @_;
$code.=<<___;
    and     $tmp.16b,$x.16b,$mask.16b
    ushr    $x.16b,$x.16b,#4
    tbl     $tmp.16b,{$lo_t.16b},$tmp.16b
    tbl     $x.16b,{$hi_t.16b},$x.16b
    eor     $x.16b,$x.16b,$tmp.16b
___
}

#
#   16-block encryption/decryption macros
#

#
# IN:
#  v0..v7: byte-sliced AB state
#  mem_cd: register pointer storing CD state
#  key: index for key material
# OUT:
#  v0..v7: new byte-sliced CD state
# Clobbers:
#  x5 - key value
#  v8..v15: broadcasted key values
#  v16: mask_0f
#  v17: inv_shift_row
#  v18..v27: pre- and post-filters
#  v28-v31 - tmps
#
sub roundsm16(){
    my ($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $mem_cd, $key) = @_;
$code.=<<___;
    /* Load 64-bit round key */
    ldr     x5,[$key]

    /* S-FUNCTION (PRE-AES) */

    /* Inverse Shift Rows (pre-compensation) */
    tbl     $v0.16b,{$v0.16b},v17.16b
    tbl     $v7.16b,{$v7.16b},v17.16b
    tbl     $v1.16b,{$v1.16b},v17.16b
    tbl     $v4.16b,{$v4.16b},v17.16b
    tbl     $v2.16b,{$v2.16b},v17.16b
    tbl     $v5.16b,{$v5.16b},v17.16b
    tbl     $v3.16b,{$v3.16b},v17.16b
    tbl     $v6.16b,{$v6.16b},v17.16b

    /* Pre-Filter */
___
    &filter_8bit_neon($v0,"v18","v19","v16","v28");
    &filter_8bit_neon($v7,"v18","v19","v16","v28");
    &filter_8bit_neon($v1,"v18","v19","v16","v28");
    &filter_8bit_neon($v4,"v18","v19","v16","v28");
    &filter_8bit_neon($v2,"v18","v19","v16","v28");
    &filter_8bit_neon($v5,"v18","v19","v16","v28");
$code.=<<___;
    eor  v31.16b, v31.16b, v31.16b
___
    &filter_8bit_neon($v3,"v20","v21","v16","v28");
    &filter_8bit_neon($v6,"v20","v21","v16","v28");
$code.=<<___;

    /* AES CORE */
    aese $v0.16b,v31.16b
    aese $v7.16b,v31.16b
    aese $v1.16b,v31.16b
    aese $v4.16b,v31.16b
    aese $v2.16b,v31.16b
    aese $v5.16b,v31.16b
    aese $v3.16b,v31.16b
    aese $v6.16b,v31.16b

    /* Post-Filter */
___
    &filter_8bit_neon($v0,"v22","v23","v16","v28");
    &filter_8bit_neon($v7,"v22","v23","v16","v28");
    &filter_8bit_neon($v3,"v22","v23","v16","v28");
    &filter_8bit_neon($v6,"v22","v23","v16","v28");
    &filter_8bit_neon($v2,"v26","v27","v16","v28");
    &filter_8bit_neon($v5,"v26","v27","v16","v28");
    &filter_8bit_neon($v1,"v24","v25","v16","v28");
    &filter_8bit_neon($v4,"v24","v25","v16","v28");
$code.=<<___;

    /* Interleaved P-function and key broadcasting */
    fmov    d31,x5

    eor     $v0.16b,$v0.16b,$v5.16b
    movi    v29.16b,#3
    eor     $v1.16b,$v1.16b,$v6.16b
    movi    v30.16b,#2
    eor     $v2.16b,$v2.16b,$v7.16b
    eor     $v3.16b,$v3.16b,$v4.16b

    tbl     v11.16b,{v31.16b},v29.16b   // threes
    tbl     v10.16b,{v31.16b},v30.16b   // twos

    eor     $v4.16b,$v4.16b,$v2.16b
    movi    v29.16b,#1
    eor     $v5.16b,$v5.16b,$v3.16b
    movi    v30.16b,#7
    eor     $v6.16b,$v6.16b,$v0.16b
    eor     $v7.16b,$v7.16b,$v1.16b

    tbl     v9.16b,{v31.16b},v29.16b   // ones
    tbl     v15.16b,{v31.16b},v30.16b   // sevens

    eor     $v0.16b,$v0.16b,$v7.16b
    movi    v29.16b,#6
    eor     $v1.16b,$v1.16b,$v4.16b
    movi    v30.16b,#5
    eor     $v2.16b,$v2.16b,$v5.16b
    eor     $v3.16b,$v3.16b,$v6.16b

    tbl     v14.16b,{v31.16b},v29.16b   // sixs
    tbl     v13.16b,{v31.16b},v30.16b   // fives

    eor     $v4.16b,$v4.16b,$v3.16b
    movi    v29.16b,#4
    eor     $v5.16b,$v5.16b,$v0.16b
    eor     v30.16b,v30.16b,v30.16b
    eor     $v6.16b,$v6.16b,$v1.16b
    eor     $v7.16b,$v7.16b,$v2.16b     // Now the high snd low parts are swapped

    ldr     q28,[$mem_cd]

    tbl     v12.16b,{v31.16b},v29.16b   // fours
    tbl     v8.16b,{v31.16b},v30.16b    // zeros

    /* Final XOR's (w. broadcasted KEY & CD state) */
    ldr     q29,[$mem_cd,#16]
    ldr     q30,[$mem_cd,#32]
    ldr     q31,[$mem_cd,#48]

    eor     $v4.16b,$v4.16b,v11.16b
    eor     $v4.16b,$v4.16b,v28.16b

    eor     $v5.16b,$v5.16b,v10.16b
    eor     $v5.16b,$v5.16b,v29.16b

    ldr     q28,[$mem_cd,#64]

    eor     $v6.16b,$v6.16b,v9.16b
    eor     $v6.16b,$v6.16b,v30.16b

    ldr     q29,[$mem_cd,#80]

    eor     $v7.16b,$v7.16b,v8.16b
    eor     $v7.16b,$v7.16b,v31.16b

    ldr     q30,[$mem_cd,#96]

    eor     $v0.16b,$v0.16b,v15.16b
    eor     $v0.16b,$v0.16b,v28.16b

    ldr     q31,[$mem_cd,#112]

    eor     $v1.16b,$v1.16b,v14.16b
    eor     $v1.16b,$v1.16b,v29.16b

    eor     $v2.16b,$v2.16b,v13.16b
    eor     $v2.16b,$v2.16b,v30.16b

    eor     $v3.16b,$v3.16b,v12.16b
    eor     $v3.16b,$v3.16b,v31.16b
___
}

# does nothing
sub dummy_store(){}

sub store_ab_state(){
    my ($mem_ab) = @_;
$code.=<<___;
	/* Store new AB state */ \
    stp     q0,q1,[$mem_ab]
    stp     q2,q3,[$mem_ab,#32]
    stp     q4,q5,[$mem_ab,#64]
    stp     q6,q7,[$mem_ab,#96]
___
}

#
# IN/OUT:
#  v0..v7: byte-sliced AB state preloaded
#  mem_ab: byte-sliced AB state in memory
#  mem_cd: byte-sliced CD state in memory
#  first_key_ptr: ptr to access first key
#  store_ab: function to store state
# Clobbers:
#  x4 - second key pointer value
#
# Don't actually need to pass v0-v7!
sub two_roundsm16(){
    my ($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $mem_ab, $mem_cd, $first_key_ptr, $store_ab) = @_;

    &roundsm16($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $mem_cd, $first_key_ptr);
$code.=<<___;

    stp     q4,q5,[$mem_cd]
    stp     q6,q7,[$mem_cd,#32]
    stp     q0,q1,[$mem_cd,#64]
    stp     q2,q3,[$mem_cd,#96]

    add     x4,$first_key_ptr,#8
___
    &roundsm16($v4, $v5, $v6, $v7, $v0, $v1, $v2, $v3, $mem_ab, "x4");

    &$store_ab($mem_ab);
}

# Differs from above by decrementing instead of incrementing key ptr.
sub two_roundsm16_dec(){
    my ($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $mem_ab, $mem_cd, $first_key_ptr, $store_ab) = @_;

    &roundsm16($v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7, $mem_cd, $first_key_ptr);
$code.=<<___;

    stp     q4,q5,[$mem_cd]
    stp     q6,q7,[$mem_cd,#32]
    stp     q0,q1,[$mem_cd,#64]
    stp     q2,q3,[$mem_cd,#96]

    sub     x4,$first_key_ptr,#8
___
    &roundsm16($v4, $v5, $v6, $v7, $v0, $v1, $v2, $v3, $mem_ab, "x4");

    &$store_ab($mem_ab);
}

#
# IN:
#  v0..3: byte-sliced 32-bit integers
#  t0-t2: vector clobbers
# OUT:
#  v0..3: (IN <<< 1)
#
sub rol32_1_16(){
    my ($v0, $v1, $v2, $v3, $t0, $t1, $t2) = @_;
$code.=<<___;
    ushr    $t0.16b,$v0.16b,#7
    add     $v0.16b,$v0.16b,$v0.16b
    ushr    $t1.16b,$v1.16b,#7
    add     $v1.16b,$v1.16b,$v1.16b
    ushr    $t2.16b,$v2.16b,#7
    add     $v2.16b,$v2.16b,$v2.16b
    orr     $v1.16b,$t0.16b,$v1.16b
    ushr    $t0.16b,$v3.16b,#7
    add     $v3.16b,$v3.16b,$v3.16b
    orr     $v2.16b,$t1.16b,$v2.16b
    orr     $v3.16b,$t2.16b,$v3.16b
    orr     $v0.16b,$t0.16b,$v0.16b
___
}

#
# IN:
#   v0..v7: byte-sliced AB state in registers
#   mem_l: byte-sliced AB state in memory
#   mem_r: byte-sliced CD state in memory
#   key_a_ptr, key_b_ptr: pointer to keys
# OUT:
#   v0..v7: new byte-sliced AB state
#   Updated AB nd CD states written to memory
# Clobbers:
#  x5-x7: storage for keys
#  v8-v15,v16-19,v28-v31: temporary vectors
#
sub fls16(){
    my ($mem_l, $mem_r, $key_a_ptr, $key_b_ptr) = @_;
$code.=<<___;
    ldr     x5,[$key_a_ptr]         //x5={klr,kll}
    ldr     x6,[$key_b_ptr]         //x6={krr,krl}
	/*
	 * t0 = kll
	 * t0 &= ll
	 * lr ^= rol32(t0, 1)
	 */
    eor     v19.16b,v19.16b,v19.16b
    movi    v18.16b,#1
    fmov    s31, w5                 // v31 lower = kll
    movi    v17.16b,#2
    movi    v16.16b,#3
    tbl     v19.16b,{v31.16b},v19.16b
    tbl     v18.16b,{v31.16b},v18.16b
    tbl     v17.16b,{v31.16b},v17.16b
    tbl     v16.16b,{v31.16b},v16.16b

    ldp     q12,q13,[$mem_r,#64]    // pre-load right-hand state parts
    and     v16.16b,v0.16b,v16.16b
    and     v17.16b,v1.16b,v17.16b
    ldp     q14,q15,[$mem_r,#96]    // pre-load right-hand state parts
    and     v18.16b,v2.16b,v18.16b
    and     v19.16b,v3.16b,v19.16b

___
    &rol32_1_16("v19","v18","v17","v16","v28","v29","v30");
$code.=<<___;

    eor     v4.16b,v16.16b,v4.16b
    eor     v5.16b,v17.16b,v5.16b
    eor     v6.16b,v18.16b,v6.16b
    eor     v7.16b,v19.16b,v7.16b
    stp     q4,q5,[$mem_l,#64]
    stp     q6,q7,[$mem_l,#96]

	/*
	 * t2 = krr
	 * t2 |= rr
	 * rl ^= t2
	 */

    lsr     x7,x6,#32
    eor     v19.16b,v19.16b,v19.16b
    ldp     q8,q9,[$mem_r]               // pre-load right-hand state parts
    movi    v18.16b,#1
    fmov    s31,w7
    movi    v17.16b,#2
    movi    v16.16b,#3
    ldp     q10,q11,[$mem_r,#32]        // pre-load right-hand state parts
    tbl     v19.16b,{v31.16b},v19.16b
    tbl     v18.16b,{v31.16b},v18.16b
    tbl     v17.16b,{v31.16b},v17.16b
    tbl     v16.16b,{v31.16b},v16.16b

    orr     v16.16b,v12.16b,v16.16b
    orr     v17.16b,v13.16b,v17.16b
    orr     v18.16b,v14.16b,v18.16b
    orr     v19.16b,v15.16b,v19.16b

    eor     v8.16b,v8.16b,v16.16b
    eor     v9.16b,v9.16b,v17.16b
    eor     v10.16b,v10.16b,v18.16b
    eor     v11.16b,v11.16b,v19.16b

    stp     q8,q9,[$mem_r]               // Note, updated values stay in v8-v11
    stp     q10,q11,[$mem_r,#32]

	/*
	 * t2 = krl
	 * t2 &= rl
	 * rr ^= rol32(t2, 1)
	 */

    eor     v19.16b,v19.16b,v19.16b
    movi    v18.16b,#1
    fmov    s31,w6
    movi    v17.16b,#2
    movi    v16.16b,#3
    tbl     v19.16b,{v31.16b},v19.16b
    tbl     v18.16b,{v31.16b},v18.16b
    tbl     v17.16b,{v31.16b},v17.16b
    tbl     v16.16b,{v31.16b},v16.16b

    and     v16.16b,v8.16b,v16.16b      // Re-use updated right state values
    and     v17.16b,v9.16b,v17.16b
    and     v18.16b,v10.16b,v18.16b
    and     v19.16b,v11.16b,v19.16b

___
    &rol32_1_16("v19","v18","v17","v16","v28","v29","v30");
$code.=<<___;

    eor     v12.16b,v16.16b,v12.16b
    eor     v13.16b,v17.16b,v13.16b
    eor     v14.16b,v18.16b,v14.16b
    eor     v15.16b,v19.16b,v15.16b
    stp     q12,q13,[$mem_r,#64]
    stp     q14,q15,[$mem_r,#96]

	/*
	 * t0 = klr
	 * t0 |= lr
	 * ll ^= t0
	 */

    lsr     x7,x5,#32
    eor     v19.16b,v19.16b,v19.16b
    movi    v18.16b,#1
    fmov    s31,w7
    movi    v17.16b,#2
    movi    v16.16b,#3
    tbl     v19.16b,{v31.16b},v19.16b
    tbl     v18.16b,{v31.16b},v18.16b
    tbl     v17.16b,{v31.16b},v17.16b
    tbl     v16.16b,{v31.16b},v16.16b

    orr     v16.16b,v4.16b,v16.16b
    orr     v17.16b,v5.16b,v17.16b
    orr     v18.16b,v6.16b,v18.16b
    orr     v19.16b,v7.16b,v19.16b

    eor     v0.16b,v0.16b,v16.16b
    eor     v1.16b,v1.16b,v17.16b
    eor     v2.16b,v2.16b,v18.16b
    eor     v3.16b,v3.16b,v19.16b

    stp     q0,q1,[$mem_l]
    stp     q2,q3,[$mem_l,#32]
___
}

sub transpose_4x4(){
    my ($v0, $v1, $v2, $v3, $t1, $t2) = @_;
$code.=<<___;
    zip2    $t2.4s,$v0.4s,$v1.4s
    zip1    $v0.4s,$v0.4s,$v1.4s

    zip1    $t1.4s,$v2.4s,$v3.4s
    zip2    $v2.4s,$v2.4s,$v3.4s
    
    zip2    $v1.2d,$v0.2d,$t1.2d
    zip1    $v0.2d,$v0.2d,$t1.2d
    
    zip2    $v3.2d,$t2.2d,$v2.2d
    zip1    $v2.2d,$t2.2d,$v2.2d
___
}

# 
# IN: 
#  a0-a3, b0-b3, c0-c3, d0-d3 (vector registers)
# OUT:
#  a0-a3, b0-b3, c0-c3, d0-d3 (transposed, in registers)
# Clobbers:
#  t0 (v16), t1 (v17) (vector registers), tmp (GPR for constant address)
#
sub byteslice_16x16b_fast(){
    my ($a0, $b0, $c0, $d0, $a1, $b1, $c1, $d1, $a2, $b2, $c2, $d2, $a3, $b3, $c3, $d3, $t0, $t1, $tmp) = @_;

    &transpose_4x4($a0, $a1, $a2, $a3, $t0, $t1);
    &transpose_4x4($b0, $b1, $b2, $b3, $t0, $t1);

    &transpose_4x4($c0, $c1, $c2, $c3, $t0, $t1);
    &transpose_4x4($d0, $d1, $d2, $d3, $t0, $t1);
$code.=<<___;

    adrp    $tmp,.Lshufb_16x16b
    add     $tmp,$tmp,:lo12:.Lshufb_16x16b
    ldr     q16,[$tmp]

    tbl     $a0.16b,{$a0.16b},$t0.16b
    tbl     $a1.16b,{$a1.16b},$t0.16b
    tbl     $a2.16b,{$a2.16b},$t0.16b
    tbl     $a3.16b,{$a3.16b},$t0.16b
    tbl     $b0.16b,{$b0.16b},$t0.16b
    tbl     $b1.16b,{$b1.16b},$t0.16b
    tbl     $b2.16b,{$b2.16b},$t0.16b
    tbl     $b3.16b,{$b3.16b},$t0.16b
    tbl     $c0.16b,{$c0.16b},$t0.16b
    tbl     $c1.16b,{$c1.16b},$t0.16b
    tbl     $c2.16b,{$c2.16b},$t0.16b
    tbl     $c3.16b,{$c3.16b},$t0.16b
    tbl     $d0.16b,{$d0.16b},$t0.16b
    tbl     $d1.16b,{$d1.16b},$t0.16b
    tbl     $d2.16b,{$d2.16b},$t0.16b
    tbl     $d3.16b,{$d3.16b},$t0.16b
___

    &transpose_4x4($a0, $b0, $c0, $d0, $t0, $t1);
    &transpose_4x4($a1, $b1, $c1, $d1, $t0, $t1);

    &transpose_4x4($a2, $b2, $c2, $d2, $t0, $t1);
    &transpose_4x4($a3, $b3, $c3, $d3, $t0, $t1);
}

#
# IN:
#  key_ptr (GPR), rio_ptr (GPR)
# OUT:
#  v0-v15 (whitened plaintext)
# Clobbers:
#  tmp_key (v16, vector), tmp_gpr (GPR for addr), v17-v31
#
sub inpack16_pre(){
    my ($rio_ptr, $key_ptr, $tmp_key, $tmp_gpr) = @_;
$code.=<<___;
    /* Load and prepare key */
    ldr     $tmp_gpr,[$key_ptr]
    fmov    d16,$tmp_gpr
    ldp     q18,q19,[$rio_ptr]                      // Pre-load some input
    adrp    $tmp_gpr,.Lpack_bswap
    add     $tmp_gpr,$tmp_gpr,:lo12:.Lpack_bswap
    ldr     q17,[$tmp_gpr]                          // Load constant into a temporary
    ldp     q20,q21,[$rio_ptr,#32]                  // Pre-load some more input
    tbl     $tmp_key.16b,{$tmp_key.16b},v17.16b
 
    /* Load plaintext blocks and XOR with key */
    ldp     q22,q23,[$rio_ptr,#64]
    eor     v15.16b,v18.16b,$tmp_key.16b
    eor     v14.16b,v19.16b,$tmp_key.16b
    ldp     q24,q25,[$rio_ptr,#96]
    eor     v13.16b,v20.16b,$tmp_key.16b
    eor     v12.16b,v21.16b,$tmp_key.16b
    ldp     q26,q27,[$rio_ptr,#128]
    eor     v11.16b,v22.16b,$tmp_key.16b
    eor     v10.16b,v23.16b,$tmp_key.16b
    ldp     q28,q29,[$rio_ptr,#160]
    eor     v9.16b,v24.16b,$tmp_key.16b
    eor     v8.16b,v25.16b,$tmp_key.16b
    ldp     q30,q31,[$rio_ptr,#192]
    eor     v7.16b,v26.16b,$tmp_key.16b
    eor     v6.16b,v27.16b,$tmp_key.16b
    ldp     q18,q19,[$rio_ptr,#224]
    eor     v5.16b,v28.16b,$tmp_key.16b
    eor     v4.16b,v29.16b,$tmp_key.16b
    eor     v3.16b,v30.16b,$tmp_key.16b
    eor     v2.16b,v31.16b,$tmp_key.16b
    eor     v1.16b,v18.16b,$tmp_key.16b
    eor     v0.16b,v19.16b,$tmp_key.16b
___
}

#
# IN:
#  v0-v15 (whitened plaintext)
#  mem_ab, mem_cd (GPRs)
# OUT:
#  Writes byte-sliced state to memory buffers.
# Clobbers:
#  v0-v15 (become byte-sliced), st0, st1 (vector temps - v16,v17), tmp (GPR temp)
#
sub inpack16_post(){
    my ($mem_ab, $mem_cd, $st0, $st1, $tmp) = @_;
$code.=<<___;
    /* Perform the byte-slice transpose in-place on v0-v15 */
___
    &byteslice_16x16b_fast("v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", $st0, $st1, $tmp);

$code.=<<___;
    /* Store the results */
    stp     q0,q1,[$mem_ab]
    stp     q2,q3,[$mem_ab,#32]
    stp     q4,q5,[$mem_ab,#64]
    stp     q6,q7,[$mem_ab,#96]
    stp     q8,q9,[$mem_cd]
    stp     q10,q11,[$mem_cd,#32]
    stp     q12,q13,[$mem_cd,#64]
    stp     q14,q15,[$mem_cd,#96]
___
}

# 
# IN:
#  v0-v15 (byte-sliced ciphertext, implicit), key_ptr (GPR)
# OUT:
#  v0-v15 (block-oriented, whitened ciphertext)
# Clobbers:
#  tmp_v0, tmp_v1, tmp_key (vector temps - v16:v18),
#  tmp_gpr (GPR temp)
#
sub outunpack16(){
    my ($key_ptr, $tmp_v0, $tmp_v1, $tmp_key, $tmp_gpr) = @_;
$code.=<<___;
    /* Perform inverse byte-slice (transpose) in-place */
___
    &byteslice_16x16b_fast("v8", "v12", "v0", "v4", "v9", "v13", "v1", "v5", "v10", "v14", "v2", "v6", "v11", "v15", "v3", "v7", $tmp_v0, $tmp_v1, $tmp_gpr);
$code.=<<___;

    /* Load and prepare final key */
    ldr     $tmp_gpr,[$key_ptr]
    fmov    d18,$tmp_gpr
    adrp    $tmp_gpr,.Lpack_bswap
    add     $tmp_gpr,$tmp_gpr,:lo12:.Lpack_bswap
    ldr     q16,[$tmp_gpr]                              // Load constant into a temporary
    tbl     $tmp_key.16b,{$tmp_key.16b},$tmp_v0.16b

    /* XOR with final key */
    eor     v0.16b,v0.16b,$tmp_key.16b
    eor     v1.16b,v1.16b,$tmp_key.16b
    eor     v2.16b,v2.16b,$tmp_key.16b
    eor     v3.16b,v3.16b,$tmp_key.16b
    eor     v4.16b,v4.16b,$tmp_key.16b
    eor     v5.16b,v5.16b,$tmp_key.16b
    eor     v6.16b,v6.16b,$tmp_key.16b
    eor     v7.16b,v7.16b,$tmp_key.16b
    eor     v8.16b,v8.16b,$tmp_key.16b
    eor     v9.16b,v9.16b,$tmp_key.16b
    eor     v10.16b,v10.16b,$tmp_key.16b
    eor     v11.16b,v11.16b,$tmp_key.16b
    eor     v12.16b,v12.16b,$tmp_key.16b
    eor     v13.16b,v13.16b,$tmp_key.16b
    eor     v14.16b,v14.16b,$tmp_key.16b
    eor     v15.16b,v15.16b,$tmp_key.16b
___
}

#
# Inputs:
#  v0-v15 (final block-oriented ciphertext), rio_ptr (GPR)
#
sub write_output(){
    my ($rio_ptr) = @_;
$code.=<<___;
    stp     q7,q6,[$rio_ptr]
    stp     q5,q4,[$rio_ptr,#32]
    stp     q3,q2,[$rio_ptr,#64]
    stp     q1,q0,[$rio_ptr,#96]
    stp     q15,q14,[$rio_ptr,#128]
    stp     q13,q12,[$rio_ptr,#160]
    stp     q11,q10,[$rio_ptr,#192]
    stp     q9,q8,[$rio_ptr,#224]
___
}

$code.=<<___;
/*
    16-block byte-sliced encryption/decryption
*/

.align 5
.L16_enc_core:
    // Core encryption algorithm (factored out of the main routine for the sake of CTR mode).

    // Set up temp buffer pointers using vout_ptr (x1)
    mov     x10,x1          // x10 -> vout
    add     x11,x1,#128     // x11 -> vout + 128

    // Call inpack16_post: byte-slices v0-v15, stores to mem_ab(x10), mem_cd(x11)
    // Clobbers: v16, v17 and x4
___
    &inpack16_post("x10", "x11", "v16", "v17", "x4");
$code.=<<___;

    // Load Constants into v16-v27
    adrp    x15,camellia_neon_consts
    add     x15,x15,:lo12:camellia_neon_consts
    ldp     q18,q19,[x15],#32    // pre_tf_lo/hi_s1
    ldp     q20,q21,[x15],#32    // pre_tf_lo/hi_s4
    ldp     q22,q23,[x15],#32    // post_tf_lo/hi_s1
    ldp     q24,q25,[x15],#32    // post_tf_lo/hi_s2
    ldp     q26,q27,[x15],#32    // post_tf_lo/hi_s3
    ldr     q17,[x15],#16        // inv_shift_row
    ldr     q16,[x15],#-176        // mask_0f

    // === MAIN ROUND LOOP ===
    mov     x12,#0      // x12 -> k = 0
    sub     x14,x8,#8   // x14 -> lastk - 8
.Lenc_loop:
    // Calculate base key pointer for this block: &key_table[k]
    lsl     x13,x12,#3  // x13 -> key_base_idx = k * 8
    add     x13,x0,x13  // x13 = &key_table[k] - assuming here key_table_base = ctx[0] -> x0

    // Round 1 (keys k+2, k+3)
    add     x4,x13,#16  // &key_table[k+2]
___
    &two_roundsm16("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","store_ab_state");
$code.=<<___;

    // Round 2 (keys k+4, k+5)
    add     x4,x13,#32  // &key_table[k+4]
___
    &two_roundsm16("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","store_ab_state");
$code.=<<___;

    // Round 3 (keys k+6, k+7)
    add     x4,x13,#48  // &key_table[k+6]
___
    &two_roundsm16("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","dummy_store");
$code.=<<___;

    // Check loop condition
    cmp     x12,x14
    b.eq    .Lenc_done

    // x4 -> key pointer: &key_table[k+8]
    add     x4,x13,#64
    add     x3,x13,#72
___
    &fls16("x10", "x11", "x4", "x3"); # uses x5-x7 and v16-v19 as clobbers, writes to v0-v7
$code.=<<___;

    // Increment k
    add     x12,x12,#8

    ldp     q18,q19,[x15],#160    // pre_tf_lo/hi_s1
    ldr     q17,[x15],#16           // inv_shift_row
    ldr     q16,[x15],#-176        // mask_0f
    b       .Lenc_loop

.Lenc_done:
    // Load final CD state from mem_cd(x11) into v8-v15
    ldp     q8,q9,[x11]
    ldp     q10,q11,[x11,#32]
    ldp     q12,q13,[x11,#64]
    ldp     q14,q15,[x11,#96]

    // Calculate final key pointer: &key_table[lastk] (lastk is in x8)
    lsl     x4,x8,#3    // lastk * 8
    add     x4,x0,x4    // &key_table[lastk]

    // Call outunpack16: Operates in-place on v0-v15
___
    &outunpack16("x4", "v16", "v17", "v18", "x5");
$code.=<<___;

    ret

.globl  camellia_encrypt_16blks_neon
.type   camellia_encrypt_16blks_neon,%function
.align  5
camellia_encrypt_16blks_neon:
    // === PROLOGUE ===
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === SETUP ===
    // Determine lastk
    ldr     w9,[x0,#272]
    mov     w8,#32
    mov     w10,#24
    cmp     w9,#16
    csel    w8,w10,w8,le         // x8 -> lastk: if key_length <= 16 then 24, else - 32 

    // === INPUT PROCESSING ===
    // Call inpack16_pre: reads vin(x2), key[0](=ctx_ptr: x0), writes v0-v15
    // clobbers: v16-v31 and x4
___
    &inpack16_pre("x2", "x0", "v16", "x4");
$code.=<<___;

    bl      .L16_enc_core
___

    &write_output("x1");
$code.=<<___;

    // === EPILOGUE ===
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144
    ret
.size   camellia_encrypt_16blks_neon,.-camellia_encrypt_16blks_neon

.align 5
.L16_dec_core:
    // Core decryption algorithm (factored out of the main routine for the sake of CBC and CTR modes).

    // Set up temp buffer pointers using vout_ptr (x1)
    mov     x10,x1          // x10 -> vout
    add     x11,x1,#128     // x11 -> vout + 128

    // Call inpack16_post: byte-slices v0-v15, stores to mem_ab(x10), mem_cd(x11)
    // Clobbers: v16, v17 and x4
___
    &inpack16_post("x10", "x11", "v16", "v17", "x4");
$code.=<<___;

    // Load Constants into v16-v27
    adrp    x15,camellia_neon_consts
    add     x15,x15,:lo12:camellia_neon_consts
    ldp     q18,q19,[x15],#32    // pre_tf_lo/hi_s1
    ldp     q20,q21,[x15],#32    // pre_tf_lo/hi_s4
    ldp     q22,q23,[x15],#32    // post_tf_lo/hi_s1
    ldp     q24,q25,[x15],#32    // post_tf_lo/hi_s2
    ldp     q26,q27,[x15],#32    // post_tf_lo/hi_s3
    ldr     q17,[x15],#16        // inv_shift_row
    ldr     q16,[x15],#-176        // mask_0f

    // === MAIN ROUND LOOP ===
    sub     x12,x8,#8   // x14 -> lastk - 8
.Ldec_loop:
    // Calculate base key pointer for this block: &key_table[k]
    lsl     x13,x12,#3  // x13 -> key_base_idx = k * 8
    add     x13,x0,x13  // x13 = &key_table[k] - assuming here key_table_base = ctx[0] -> x0

    // Round 1 (keys k+6, k+7)
    add     x4,x13,#56  // &key_table[k+7]
___
    &two_roundsm16_dec("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","store_ab_state");
$code.=<<___;

    // Round 2 (keys k+4, k+5)
    add     x4,x13,#40  // &key_table[k+5]
___
    &two_roundsm16_dec("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","store_ab_state");
$code.=<<___;

    // Round 3 (keys k+2, k+3)
    add     x4,x13,#24  // &key_table[k+3]
___
    &two_roundsm16_dec("v0","v1","v2","v3","v4","v5","v6","v7","x10","x11","x4","dummy_store");
$code.=<<___;

    // Check loop condition
    cbz     x12,.Ldec_done

    // x4 -> key pointer: &key_table[k+8]
    add     x3,x13,#0
    add     x4,x13,#8
___
    &fls16("x10", "x11", "x4", "x3"); # uses x5-x7 and v16-v19 as clobbers, writes to v0-v7
$code.=<<___;

    // Decrement k
    sub     x12,x12,#8

    ldp     q18,q19,[x15],#160    // pre_tf_lo/hi_s1
    ldr     q17,[x15],#16           // inv_shift_row
    ldr     q16,[x15],#-176        // mask_0f
    b       .Ldec_loop

.Ldec_done:
    // Load final CD state from mem_cd(x11) into v8-v15
    ldp     q8,q9,[x11]
    ldp     q10,q11,[x11,#32]
    ldp     q12,q13,[x11,#64]
    ldp     q14,q15,[x11,#96]

    // Call outunpack16: Operates in-place on v0-v15
___
    &outunpack16("x0", "v16", "v17", "v18", "x5");
$code.=<<___;

    ret

.globl  camellia_decrypt_16blks_neon
.type   camellia_decrypt_16blks_neon,%function
.align  5
camellia_decrypt_16blks_neon:
    // === PROLOGUE ===
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === SETUP ===
    // Determine lastk
    ldr     w9,[x0,#272]
    mov     w8,#32
    mov     w10,#24
    cmp     w9,#16
    csel    w8,w10,w8,le         // x8 -> lastk: if key_length <= 16 then 24, else - 32 

    // === INPUT PROCESSING ===
    // Call inpack16_pre: reads vin(x2), key[0](=ctx_ptr: x0), writes v0-v15
    // clobbers: v16-v31 and x5
    lsl     x4,x8,#3
    add     x4,x0,x4
___
    &inpack16_pre("x2", "x4", "v16", "x5");
$code.=<<___;

    bl      .L16_dec_core
___

    &write_output("x1");
$code.=<<___;

    // === EPILOGUE ===
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144
    ret
.size   camellia_decrypt_16blks_neon,.-camellia_decrypt_16blks_neon

/*
    Encryption modes
*/

.text
# ====================================================================
# CBC ENCRYPTION
#
# void camellia_cbc_encrypt_neon(const unsigned char *in, 
#                                unsigned char *out, 
#                                size_t len, 
#                                const void *key, 
#                                unsigned char *ivec)
# ====================================================================
.global camellia_cbc_encrypt_neon
.type   camellia_cbc_encrypt_neon, %function
.align  5
camellia_cbc_encrypt_neon:
    // Arguments (AAPCS64): x0=in, x1=out, x2=len, x3=key, x4=ivec

    // Prologue
    stp     x29,x30,[sp,#-64]!
    mov     x29,sp
    stp     x19,x20,[sp,#16]
    stp     x21,x22,[sp,#32]
    str     x23,[sp,#48]
    
    // Check length (must be >= 16 for at least one loop)
    cmp     x2, #16
    b.lo    .Lcbc_abort_exit    // !Assume there are no half-empty blocks!
    
    and     x19,x2,#-16         // x19 = len & ~15 (Full block length in bytes)
    add     x19,x0,x19          // x19 = ENDP = INP + full_len

    // Back up some reg-s
    mov     x20,x0              // Input
    mov     x21,x1              // Output
    mov     x22,x3              // Key (CTX)
    mov     x23,x4              // IV
    
    ldp     x6,x7,[x23]         // Load the 128-bit IV into v6 and v7 (C_0)

.Lcbc_enc_loop:
    ldp     x0,x1,[x20],#16         // Load P_i into v0

    // P_i ^ IV
    eor     x0,x0,x6
    eor     x1,x1,x7

    stp     x0,x1,[x21]             // Store in OUTP!

    mov     x0,x22                  // CTX
    mov     x1,x21                  // OUTP
    mov     x2,x21                  // INP is OUTP!
    
    //bl      camellia_encrypt_1blk_armv8     // Factor out write_output?
    bl      camellia_encrypt_1blk_aese     // Factor out write_output?
    
    ldp     x6,x7,[x21]             // Load output

    add     x21,x21,#16         // OUTP++

    cmp     x20,x19
    b.lo    .Lcbc_enc_loop

    stp     x6,x7,[x23]

.Lcbc_abort_exit:
    // Epilogue
    ldp     x19,x20,[sp,#16]
    ldp     x21,x22,[sp,#32]
    ldr     x23,[sp,#48]
    ldp     x29,x30,[sp],#64
    ret
.size camellia_cbc_encrypt_neon,.-camellia_cbc_encrypt_neon

# ====================================================================
# CBC DECRYPTION ROUTINE (Full implementation: Bulk + Tail)
#
# void camellia_cbc_decrypt_neon(const unsigned char *in, 
#                                unsigned char *out, 
#                                size_t len, 
#                                const void *key, 
#                                unsigned char *ivec)
# ====================================================================
.globl  camellia_cbc_decrypt_neon
.type   camellia_cbc_decrypt_neon,%function
.align  5
camellia_cbc_decrypt_neon:
    // Arguments: x0=in, x1=out, x2=len, x3=key, x4=iv

    // === PROLOGUE ===
    // Stack alloc: 144 (for vector saves as per core requirement) + 64 (for GPR saves, aligned) + 256 "scratch space" = 464
    stp     x29,x30,[sp,#-464]!
    mov     x29,sp

    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    stp     x19,x20,[sp,#144]
    stp     x21,x22,[sp,#160]
    stp     x23,x24,[sp,#176]
    str     x25,[sp,#192]

    // Move Arguments to preserved registers
    mov     x19,x0      // In
    mov     x20,x1      // Out
    mov     x21,x2      // Len
    mov     x22,x3      // Key
    mov     x23,x4      // IV Ptr

    // === KEY SETUP ===
    // Determine lastk (x8) required by Core
    ldr     w9,[x22,#272]
    mov     w8,#32
    mov     w10,#24
    cmp     w9,#16
    csel    w8,w10,w8,le    // x8 = lastk

    lsl     x24,x8,#3
    add     x24,x22,x24     // x24 = &key_table[lastk]

.Lcbc_dec_bulk_loop:
    cmp     x21,#256
    b.lt    .Lcbc_dec_tail

    // === PREPARE CORE CALL ===
    // .L16_dec_core expects:
    //   x0 = Context (Key)
    //   x1 = Output/Scratch
    //   x2 = Input Pointer
    //   x8 = lastk
    mov     x0,x22
    add     x1,sp,#208  // let core routine use stack as scratch
    mov     x2,x19

    // inpack16_pre: reads vin(x2), key[0](=ctx_ptr: x0), writes v0-v15
    // clobbers: v16-v31 and x5
___
    &inpack16_pre("x19", "x24", "v16", "x5");
$code.=<<___;
    
    // Call the factored-out core
    // Returns decrypted blocks in v0-v15
    bl      .L16_dec_core

    // === CBC XOR LOGIC ===
    // Mapping: v7=Block0 ... v0=Block7 ... v15=Block8 ... v8=Block15
    // P_0  = Dec(C_0) ^ IV
    // P_i  = Dec(C_i) ^ C_{i-1}
    
    // Load IV (Current IV state) into v31, start pre-loading Input Ciphertext
    ldr     q31,[x23]
    ld1     {v16.16b-v19.16b},[x19],#64   // Load C0-C3
    
    // XOR Block 0 (v7) with IV
    eor     v7.16b,v7.16b,v31.16b

    // XOR remaining blocks with Input Ciphertext
    eor     v6.16b,v6.16b,v16.16b 
    eor     v5.16b,v5.16b,v17.16b 
    ld1     {v20.16b-v23.16b},[x19],#64   // Load C4-C7
    eor     v4.16b,v4.16b,v18.16b
    eor     v3.16b,v3.16b,v19.16b
    ld1     {v24.16b-v27.16b},[x19],#64   // Load C8-C11
    eor     v2.16b,v2.16b,v20.16b
    eor     v1.16b,v1.16b,v21.16b
    ld1     {v28.16b-v31.16b}, [x19], #64   // Load C12-C15
    eor     v0.16b,v0.16b,v22.16b
    eor     v15.16b,v15.16b,v23.16b
    eor     v14.16b,v14.16b,v24.16b
    eor     v13.16b,v13.16b,v25.16b
    eor     v12.16b,v12.16b,v26.16b
    eor     v11.16b,v11.16b,v27.16b
    eor     v10.16b,v10.16b,v28.16b
    eor     v9.16b,v9.16b,v29.16b
    eor     v8.16b,v8.16b,v30.16b

    // === WRITE OUTPUT ===
___
    &write_output("x20");
$code.=<<___;

    // === UPDATE IV ===
    str     q31,[x23]

    // === ADVANCE POINTERS ===
    add     x20,x20,#256
    sub     x21,x21,#256
    b       .Lcbc_dec_bulk_loop

.Lcbc_dec_tail:
    cbz     x21,.Lcbc_dec_done

    ldp     x24,x25,[x23]        // IV (Low/High)
    
.Lcbc_tail_loop:
    // Load Ciphertext (C_i)
    ldp     x6,x7,[x19]         // x6/x7 = C_i
    
    // Save C_i (It becomes IV for i+1)
    stp     x6,x7,[sp,#208]     // use "scratch space"

    // Call Decrypt 1-Block
    mov     x0, x22
    mov     x1, x20
    mov     x2, x19
    
    bl      camellia_decrypt_1blk_armv8     // Factor write_out out?
    
    // XOR Result with Previous IV
    ldp     x0,x1,[x20]     // Load Dec(C_i)
    
    eor     x0,x0,x24
    eor     x1,x1,x25
    
    stp     x0,x1,[x20]     // Store P_i

    // Update IV
    ldp     x24,x25,[sp,#208]

    // Advance
    add     x19,x19,#16
    add     x20,x20,#16
    subs    x21,x21,#16
    b.gt    .Lcbc_tail_loop

    // Store Final IV back to memory
    stp     x24,x25,[x23]

.Lcbc_dec_done:
    // === EPILOGUE ===
    ldr     x25,[sp,#192]
    ldp     x23,x24,[sp,#176]
    ldp     x21,x22,[sp,#160]
    ldp     x19,x20,[sp,#144]

    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#464
    ret
.size   camellia_cbc_decrypt_neon,.-camellia_cbc_decrypt_neon

# ====================================================================
# CTR MODE (32-bit Counter)
# ====================================================================
.globl  camellia_ctr32_encrypt_blocks_neon
.type   camellia_ctr32_encrypt_blocks_neon,%function
.align  5
camellia_ctr32_encrypt_blocks_neon:
    // Arguments: x0=in, x1=out, x2=nblocks, x3=key, x4=iv

    // === PROLOGUE ===
    // Stack: 
    //   208 (Regs) 
    // + 256 (Scratch for Core: mem_ab/mem_cd)
    // + 32  (Storage for Generator State: v28/v29)
    // = 496 bytes
    stp     x29,x30,[sp,#-496]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    stp     x19,x20,[sp,#144]
    stp     x21,x22,[sp,#160]
    stp     x23,x24,[sp,#176]
    str     x25,[sp,#192]

    mov     x19,x0      // In
    mov     x20,x1      // Out
    mov     x21,x2      // Blocks
    mov     x22,x3      // Key
    mov     x23,x4      // IV Ptr

    // === KEY SETUP ===
    ldr     w9,[x22,#272]
    mov     w8,#32
    mov     w10,#24
    cmp     w9,#16
    csel    w8,w10,w8,le    // x8 = lastk

    // Prepare Whitening Key (as done in inpack16_pre)
    ldr     x5,[x22]
    fmov    d29,x5
    adrp    x6,.Lpack_bswap
    add     x6,x6,:lo12:.Lpack_bswap
    ldr     q17,[x6]
    tbl     v29.16b,{v29.16b},v17.16b 

    // 2. Prepare Counter (v28, w24)
    ldr     q28,[x23]
    rev32   v28.16b,v28.16b        // To LE
    mov     w24,v28.s[3]           // Extract Counter

    stp     q28,q29,[sp,#464]       // Backup generator state

.Lctr_bulk_loop:
    cmp     x21,#16
    b.lt    .Lctr_tail

    ldp     q28,q29,[sp,#464]       // Restore generator state

    // === COUNTER GENERATION ===
    // Generate 16 counters in v0-v15
___
    for($i=15; $i>=0; $i--) {
$code.=<<___;
        mov     v$i.16b,v28.16b         // Copy Base
        mov     v$i.s[3],w24            // Insert Counter
        add     w24,w24,#1              // Increment
        rev32   v$i.16b,v$i.16b         // To BE
        eor     v$i.16b,v$i.16b,v29.16b // Whiten
___
    }
$code.=<<___;

    // === ENCRYPT ===
    mov     x0,x22         // Key
    add     x1,sp,#208    // Scratch Space
    bl      .L16_enc_core

    // === XOR WITH INPUT ===
    ld1     {v16.16b-v19.16b},[x19],#64   // Load In[0-3]
    eor     v7.16b,v7.16b,v16.16b         // Out[0] = KeyStream(v7) ^ In[0]
    eor     v6.16b,v6.16b,v17.16b         // Out[1] = KeyStream(v6) ^ In[1]
    ld1     {v20.16b-v23.16b},[x19],#64
    eor     v5.16b,v5.16b,v18.16b
    eor     v4.16b,v4.16b,v19.16b
    ld1     {v24.16b-v27.16b},[x19],#64
    eor     v3.16b,v3.16b,v20.16b
    eor     v2.16b,v2.16b,v21.16b
    eor     v1.16b,v1.16b,v22.16b
    eor     v0.16b,v0.16b,v23.16b
    ld1     {v16.16b-v19.16b},[x19],#64
    eor     v15.16b,v15.16b,v24.16b
    eor     v14.16b,v14.16b,v25.16b
    eor     v13.16b,v13.16b,v26.16b
    eor     v12.16b,v12.16b,v27.16b
    eor     v11.16b,v11.16b,v16.16b
    eor     v10.16b,v10.16b,v17.16b
    eor     v9.16b,v9.16b,v18.16b
    eor     v8.16b,v8.16b,v19.16b

    // === STORE OUTPUT ===
___
    &write_output("x20");
$code.=<<___;

    // Advance Output Pointer
    add     x20,x20,#256
    sub     x21,x21,#16
    b       .Lctr_bulk_loop

.Lctr_tail:
    cbz     x21,.Lctr_done

    ldr     q28,[sp,#464]       // Load base IV

.Lctr_tail_loop:
    mov     v28.s[3],w24        // Update counter in vector

    rev32   v30.16b,v28.16b     // Use v30 as temp to keep v28 LE
    str     q30,[sp,#208]       // Store to stack to use as Inp

    mov     x0,x22              // Key
    add     x1,sp,#224          // Output Scratch
    add     x2,sp,#208          // Input (Counter)
    
    bl      camellia_encrypt_1blk_aese
    //bl      camellia_encrypt_1blk_armv8
    
    // XOR & Store
    ldp     x6,x7,[sp,#224]     // Keystream
    ldp     x4,x5,[x19]       // Input
    eor     x4,x4,x6
    eor     x5,x5,x7
    stp     x4,x5,[x20]       // Output
    
    // Increment counter
    add     w24,w24,#1
    
    add     x19,x19,#16
    add     x20,x20,#16
    subs    x21,x21,#1
    b.gt    .Lctr_tail_loop

.Lctr_done:
    // Save IV
    ldr     q28,[sp,#464]
    mov     v28.s[3],w24       
    rev32   v28.16b,v28.16b    
    str     q28,[x23]    

    // Epilogue
    ldr     x25,[sp,#192]
    ldp     x23,x24,[sp,#176]
    ldp     x21,x22,[sp,#160]
    ldp     x19,x20,[sp,#144]

    ldp     q14,q15,[sp,#112]
    ldp     q12,q13,[sp,#80]
    ldp     q10,q11,[sp,#48]
    ldp     q8,q9,[sp,#16]

    ldp     x29,x30,[sp],#496
    ret
.size   camellia_ctr32_encrypt_blocks_neon,.-camellia_ctr32_encrypt_blocks_neon

/*
   "Optimised" key setup 
*/
___
# Neon macro for Camellia F-function (key schedule variant)
# Inputs:
#  v_ab:            Input vector register name (e.g., v2 or v3)
#  v_x:             Output/Working vector register name (e.g., v1 to v5)
#  v_t0 - v_t4:     Temporary vector register names (v6-v10)
#  inv_shift_row:  v17
#  sbox4mask:      v18
#  _0f0f0f0fmask:  v19
#  pre_s1lo_mask:  v20
#  pre_s1hi_mask:  v21
#  post_s1lo_mask: v22
#  post_s1hi_mask: v23
#  sp0044:         v24
#  sp1110:         v25
#  sp0222:         v26
#  sp3033:         v27
#  key:       GPR name holding key address (e.g., x1)
#  x_tmp:  Temporary GPR (e.g., x5)
# Output:
#   Lower 64 bits of v_x contain the result.
#
sub camellia_f(){
    my ($v_ab, $v_x, $v_t0, $v_t1, $v_t2, $v_t3, $v_t4, $v_zero, $inv_shift_row, $sbox4mask, $_0f0f0f0fmask, $pre_s1lo_mask, $pre_s1hi_mask, $post_s1lo_mask, $post_s1hi_mask, $sp0044, $sp1110, $sp0222, $sp3033, $key, $x_tmp) = @_;
$code.=<<___;
    ldr     $x_tmp,[$key]
    fmov    d6,$x_tmp   // referring to v_t0 (v6) as d6

    
    eor     $v_x.16b,$v_ab.16b,$v_t0.16b   // x = ab ^ key

	/*
	 * S-function with AES subbytes
	 */

    /* Apply input rotation for sbox4 */
    and     $v_t0.16b,$v_x.16b,$sbox4mask.16b
    bic     $v_x.16b,$v_x.16b,$sbox4mask.16b
    add     $v_t1.16b,$v_t0.16b,$v_t0.16b
    ushr    $v_t0.16b,$v_t0.16b,#7
    orr     $v_t0.16b,$v_t0.16b,$v_t1.16b
    and     $v_t0.16b,$v_t0.16b,$sbox4mask.16b
    orr     $v_x.16b,$v_x.16b,$v_t0.16b

    /* Prefilter sboxes */
___
    &filter_8bit_neon($v_x, $pre_s1lo_mask, $pre_s1hi_mask, $_0f0f0f0fmask, $v_t2);
$code.=<<___;

    /* AES subbytes + AES shift rows */
    aese    $v_x.16b,$v_zero.16b

    /* Postfilter sboxes */
___
    &filter_8bit_neon($v_x, $post_s1lo_mask, $post_s1hi_mask, $_0f0f0f0fmask, $v_t2);
$code.=<<___;

    tbl     $v_t1.16b,{$v_x.16b},$inv_shift_row.16b
    tbl     $v_t4.16b,{$v_x.16b},$sp0044.16b
    tbl     $v_x.16b,{$v_x.16b},$sp1110.16b
    add     $v_t2.16b,$v_t1.16b,$v_t1.16b
    ushr    $v_t0.16b,$v_t1.16b,#7
    shl     $v_t3.16b,$v_t1.16b,#7
    orr     $v_t0.16b,$v_t0.16b,$v_t2.16b
    ushr    $v_t1.16b,$v_t1.16b,#1
    tbl     $v_t0.16b,{$v_t0.16b},$sp0222.16b
    orr     $v_t1.16b,$v_t1.16b,$v_t3.16b

    eor     $v_t4.16b,$v_x.16b,$v_t4.16b
    tbl     $v_t1.16b,{$v_t1.16b},$sp3033.16b
    eor     $v_t0.16b,$v_t0.16b,$v_t4.16b
    eor     $v_t0.16b,$v_t0.16b,$v_t1.16b

    ext     $v_x.16b,$v_t0.16b,$v_zero.16b,#8
    eor     $v_x.16b,$v_t0.16b,$v_x.16b
___
}

sub vec_rol128(){
    my ($in, $out, $nrol, $t0) = @_;
    my $rem_nrol = 64 - $nrol;
$code.=<<___;
    ext     $out.16b,$in.16b,$in.16b,#8
    shl     $t0.2d,$in.2d,#$nrol
    ushr    $out.2d,$out.2d,#$rem_nrol
    add     $out.16b,$out.16b,$t0.16b
___
}

sub vec_ror128(){
    my ($in, $out, $nror, $t0) = @_;
    my $rem_nror = 64 - $nror;
$code.=<<___;
    ext     $out.16b,$in.16b,$in.16b,#8
    ushr    $t0.2d,$in.2d,#$nror
    shl     $out.2d,$out.2d,#$rem_nror
    add     $out.16b,$out.16b,$t0.16b;
___
}

# 128-bit key setup global variables
$CTX = "x0";             # Context pointer passed in x0
$KL128 = "v0";           # Input key in v0
$KA128 = "v2";           # Intermediate key KA generated in v2

$code.=<<___;
.text
.globl  __camellia_setup128_neon
.type   __camellia_setup128_neon,%function
.align  5
__camellia_setup128_neon:
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === CONSTANT LOADING ===
    // Load constants needed for camellia_f into v17-v27 + v16(bswap)
    adrp    x1,camellia_neon_consts
    add     x1,x1,:lo12:camellia_neon_consts
    ldp     q20,q21,[x1],#64    // pre_tf_lo/hi_s1
    ldp     q22,q23,[x1],#112   // post_tf_lo/hi_s1
    ldr     q19,[x1],#48        //mask_0f
    ldr     q16,[x1],#16        //bswap128
    ldr     d18,[x1],#8         //sbox4_input_mask
    ldr     q17,[x1],#16        //inv_shift_row_and_unpcklbw
    ldp     q24,q25,[x1],#32    //sp0044/sp1110
    ldp     q26,q27,[x1],#32    //sp0222/sp3033

    // Prepare zero vector
    eor     v31.16b,v31.16b,v31.16b
    
    // === INITIAL KEY HANDLING ===
    // Byte swap input key KL128 (v0) using v16
    tbl     $KL128.16b,{$KL128.16b},v16.16b
    
    // === GENERATE KA (into v2) ===
    // Split KL128 into halves (KL_R in v2 lower, KL_L in v3 lower)
    ext     v2.16b,$KL128.16b,v31.16b,#8
    mov     v3.d[0],$KL128.d[0]
    mov     v3.d[1],xzr

    // Get addresses of sigma constants
    adrp    x1,.Lsigma1
    add     x1,x1,:lo12:.Lsigma1 // x1 -> sigma1
    add     x2,x1,#8             // x2 -> sigma2
    add     x3,x1,#16            // x3 -> sigma3
    add     x4,x1,#24            // x4 -> sigma4

    // F(KL_R, sigma1) -> v4
___
    &camellia_f("v2","v4","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x1","x5");
$code.=<<___;
    eor     v3.16b,v3.16b,v4.16b       // KL_L ^= F(...)
    // F(KL_L, sigma2) -> v2
___
    &camellia_f("v3","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x2","x5");
$code.=<<___;
    // v2 now holds KA_R' (in lower 64 bits)
    // F(KA_R', sigma3) -> v3
___
    &camellia_f("v2","v3","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x3","x5");
$code.=<<___;
    // v3 now holds KA_L' (in lower 64 bits)
    eor     v3.16b,v3.16b,v4.16b       // intermediate needed for next step
    // F(KA_L', sigma4) -> v4
___
    &camellia_f("v3","v4","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x4","x5");
$code.=<<___;

    // Combine KA_L'(v3) and KA_R'(v2 ^ v4) into KA128 (v2)
    eor     v1.16b,v2.16b,v4.16b        // KA_R' ^= T4
    mov     $KA128.d[0],v3.d[0]        // v2 lower lane = v3 lower lane (KA_L')
    mov     $KA128.d[1],v1.d[0]        // v2 upper lane = v1 lower lane (KA_R'^T4)

    // === GENERATE ROTATED SUBKEYS ===
    add     x1,$CTX,#192                // Get address for subkey 24
    str     q2,[x1]                     // Store KA128 early

___
    &vec_rol128($KL128, "v3", 15, "v15");     # v3 = KL <<< 15
    &vec_rol128($KA128, "v4", 15, "v15");     # v4 = KA <<< 15
    &vec_rol128($KA128, "v5", 30, "v15");     # v5 = KA <<< 30
    &vec_rol128($KL128, "v6", 45, "v15");     # v6 = KL <<< 45
    &vec_rol128($KA128, "v7", 45, "v15");     # v7 = KA <<< 45
    &vec_rol128($KL128, "v8", 60, "v15");     # v8 = KL <<< 60
    &vec_rol128($KA128, "v9", 60, "v15");     # v9 = KA <<< 60
    &vec_ror128($KL128, "v10", 51, "v15");    # v10 = KL >>> 51 (ror 128-77=51)
$code.=<<___;

    // === ABSORB KW2 ===
    // Calculate kw2 (upper 64 of KL128) into v15
    mov     v15.d[0],$KL128.d[0]
    mov     v15.d[1],xzr
    // XOR kw2 into intermediates
    eor     $KA128.16b,$KA128.16b,v15.16b    // KA128 ^= kw2
    eor     v3.16b,v3.16b,v15.16b          // v3 ^= kw2
    eor     v4.16b,v4.16b,v15.16b          // v4 ^= kw2

    // subl(1) ^= subr(1) & ~subr(9)
    bic     v13.16b,v15.16b,v5.16b
    ext     v11.16b,v31.16b,v13.16b,#4
    ext     v13.16b,v11.16b,v11.16b,#8  // because all other elements are zero anyway
    eor     v15.16b,v15.16b,v13.16b
    // dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    and     v14.16b,v15.16b,v5.16b   // v14 = v15 & v5 (dw = subl(1) & subl(9))
    shl     v11.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v11.16b,v14.16b
    ext     v14.16b,v31.16b,v14.16b,#8
    ext     v14.16b,v14.16b,v31.16b,#12
    eor     v15.16b,v14.16b,v15.16b

    // XOR final absorb value (v15) into subkeys
    eor     v6.16b,v6.16b,v15.16b
    eor     v8.16b,v8.16b,v15.16b
    eor     v9.16b,v9.16b,v15.16b

    // subl(1) ^= subr(1) & ~subr(17) (v10 = KL>>>51)
    bic     v13.16b,v15.16b,v10.16b  // v13 = v10 & ~v15
    ext     v11.16b,v31.16b,v13.16b,#4
    ext     v13.16b,v11.16b,v11.16b,#8
    eor     v15.16b,v15.16b,v13.16b
    // dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    and     v14.16b,v15.16b,v10.16b
    shl     v11.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v11.16b,v14.16b
    ext     v14.16b,v31.16b,v14.16b,#8
    ext     v14.16b,v14.16b,v31.16b,#12
    eor     v15.16b,v14.16b,v15.16b

    // Group ext's together?
    ext     v11.16b,$KL128.16b,$KL128.16b,#8
    rev64   $KL128.4s,v11.4s
    ext     v12.16b,$KA128.16b,$KA128.16b,#8
    rev64   $KA128.4s,v12.4s
    ext     v13.16b,v3.16b,v3.16b,#8
    rev64   v3.4s,v13.4s
    ext     v14.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v14.4s
    ext     v11.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v11.4s
    ext     v12.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v12.4s
    ext     v13.16b,v7.16b,v7.16b,#8
    rev64   v7.4s,v13.4s
    ext     v14.16b,v8.16b,v8.16b,#8
    rev64   v8.4s,v14.4s
    ext     v11.16b,v9.16b,v9.16b,#8
    rev64   v9.4s,v11.4s
    ext     v12.16b,v10.16b,v10.16b,#8
    rev64   v10.4s, v12.4s

    // Store intermediates (adjusting for 64-bit stores where needed)
    add     x1,$CTX,#0
    str     q0,[x1]   //KL128
    ext     v13.16b,$KL128.16b,$KL128.16b,#8
    rev64   $KL128.4s,v13.4s // Reverse back KL for later use

    add     x1,$CTX,#16
    str     q2,[x1]    //KA128
    add     x2,$CTX,#32
    str     q3,[x2]
    add     x3,$CTX,#48
    str     q4,[x3]
    add     x4,$CTX,#64
    str     q5,[x4]
    add     x5,$CTX,#80
    str     q6,[x5]

    ext     v8.16b,v8.16b,v31.16b,#8
    add     x1,$CTX,#96
    str     d7,[x1]  // Store lower half of v7
    add     x2,$CTX,#104
    str     d8,[x2]
    add     x3,$CTX,#112
    str     q9,[x3]
    add     x4,$CTX,#128
    str     q10,[x4]

    // === ABSORB KW4 ===
    // Reload KA128 (now shuffled)
    add     x1,$CTX,#192
    ldr     q2,[x1]

    // Calculate rotated keys needed (note: KL128 and KA128 were reversed back above)
___
    &vec_ror128($KL128, "v3", 34, "v7");    # v3 = KL >>> 34 (ror 128-94)
    &vec_ror128($KA128, "v4", 34, "v7");    # v4 = KA >>> 34
    &vec_ror128($KL128, "v5", 17, "v7");    # v5 = KL >>> 17 (ror 128-111)
    &vec_ror128($KA128, "v6", 17, "v7");    # v6 = KA >>> 17
$code.=<<___;

    eor     v3.16b,v3.16b,v15.16b
    eor     v4.16b,v4.16b,v15.16b
    eor     v5.16b,v5.16b,v15.16b
    ext     v15.16b,v31.16b,v15.16b,#8
    eor     v6.16b,v6.16b,v15.16b

    // Absorb kw4 into other subkeys
    ext     v15.16b,v31.16b,v6.16b,#8
    eor     v5.16b,v5.16b,v15.16b
    eor     v4.16b,v4.16b,v15.16b
    eor     v3.16b,v3.16b,v15.16b

    // subl(25) ^= subr(25) & ~subr(16)
    add     x1,$CTX,#128;
    ldr     q10,[x1]
    ext     v11.16b,v10.16b,v10.16b,#8
    rev64   v10.4s,v11.4s

    bic     v13.16b,v15.16b,v10.16b
    ext     v13.16b,v31.16b,v13.16b, #12
    eor     v15.16b,v15.16b,v13.16b

    // dw = subl(25) & subl(16), subr(25) ^= CAMELLIA_RL1(dw);
    and     v14.16b,v15.16b,v10.16b // v14 = v15 & v10 (dw)
    shl     v11.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v11.16b,v14.16b
    ext     v14.16b,v14.16b, v31.16b, #12
    ext     v14.16b,v31.16b, v14.16b, #8;
    eor     v15.16b,v14.16b, v15.16b; // v15 ^= rotated RL1(dw)
    // v15 holds final absorb value for kw4 stage

    ext     v11.16b,v3.16b,v3.16b,#8
    rev64   v3.4s,v11.4s
    ext     v12.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v12.4s
    ext     v13.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v13.4s
    ext     v14.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v14.4s

    add     x1,$CTX,#144
    str     q3,[x1]
    add     x2,$CTX,#160
    str     q4,[x2]
    add     x3,$CTX,#176
    str     q5,[x3]
    add     x4,$CTX,#192
    str     q6,[x4]

    add     x1,$CTX,#112
    ldr     q3,[x1]
    ext     v11.16b,v3.16b,v3.16b,#8
    rev64   v3.4s,v11.4s
    add     x2,$CTX,#96
    ldr     q4,[x2]
    ext     v12.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v12.4s
    add     x3,$CTX,#80
    ldr     q5,[x3]
    ext     v13.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v13.4s
    add     x4,$CTX,#64
    ldr     q6,[x4]
    ext     v14.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v14.4s

    eor     v3.16b,v3.16b,v15.16b
    eor     v4.16b,v4.16b,v15.16b
    eor     v5.16b,v5.16b,v15.16b

    // subl(25) ^= subr(25) & ~subr(8)
    bic     v13.16b,v15.16b,v6.16b // v13 = v6 & ~v15
    ext     v13.16b,v31.16b,v13.16b,#12
    eor     v15.16b,v13.16b,v15.16b
    // dw = subl(25) & subl(8), subr(25) ^= CAMELLIA_RL1(dw);
    and     v14.16b,v15.16b,v6.16b; // v14 = v15 & v6 (dw)
    shl     v11.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v11.16b,v14.16b
    ext     v14.16b,v14.16b,v31.16b,#12
    ext     v14.16b,v31.16b,v14.16b,#8;
    eor     v15.16b,v14.16b,v15.16b; // v15 ^= rotated RL1(dw)

    ext     v11.16b,v3.16b,v3.16b,#8
    rev64   v3.4s,v11.4s
    ext     v12.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v12.4s
    ext     v13.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v13.4s

    add     x1,$CTX,#112
    str     q3,[x1]
    add     x2,$CTX,#96
    str     q4,[x2]
    add     x3,$CTX,#80
    str     q5,[x3]

    add     x1,$CTX,#48
    ldr     q6,[x1]
    ext     v11.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v11.4s
    add     x2,$CTX,#32
    ldr     q4,[x2]
    ext     v12.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v12.4s
    add     x3,$CTX,#16
    ldr     q2,[x3]
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    add     x4,$CTX,#0
    ldr     q0,[x4]
    ext     v14.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v14.4s

    eor     v6.16b,v6.16b,v15.16b
    eor     v4.16b,v4.16b,v15.16b
    eor     v2.16b,v2.16b,v15.16b
    eor     v0.16b,v0.16b,v15.16b

    ext     v11.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v11.4s
    ext     v12.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v12.4s
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    ext     v13.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v13.4s

    ext     v3.16b,v2.16b,v31.16b,#8
    ext     v5.16b,v4.16b,v31.16b,#8
    ext     v7.16b,v6.16b,v31.16b,#8

    eor     v0.16b,v2.16b,v0.16b
    eor     v2.16b,v4.16b,v2.16b

    add     x1,$CTX,#0
    str     d0,[x1]
    add     x2,$CTX,#16
    str     d3,[x2]
    eor     v3.16b,v5.16b,v3.16b
    eor     v4.16b,v6.16b,v4.16b
    eor     v5.16b,v7.16b,v5.16b
    add     x1,$CTX,#24
    str     d2,[x1]
    add     x2,$CTX,#32
    str     d3,[x2];
    add     x3,$CTX,#40
    str     d4,[x3];
    add     x4,$CTX,#48
    str     d5,[x4];

    add     x1,$CTX,#56
    ldr     d7,[x1]
    add     x2,$CTX,#64
    ldr     d8,[x2]
    add     x3,$CTX,#72
    ldr     d9,[x3]
    add     x4,$CTX,#80
    ldr     d10,[x4]
	/* tl = subl(10) ^ (subr(10) & ~subr(8)); */
    bic     v15.16b,v10.16b,v8.16b
    ext     v15.16b,v15.16b,v31.16b,#4
    eor     v0.16b,v15.16b,v10.16b
	/* dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw); */
    and     v15.16b,v0.16b,v8.16b
    shl     v14.4s,v15.4s,#1
    ushr    v15.4s,v15.4s,#31
    add     v15.16b,v14.16b,v15.16b
    ext     v15.16b,v31.16b,v15.16b,#4
    ext     v15.16b,v15.16b,v31.16b,#8
    eor     v0.16b,v0.16b,v15.16b

    eor     v6.16b,v0.16b,v6.16b
    str     d6,[x1]

    add     x1,$CTX,#88
    ldr     d11,[x1]
    add     x2,$CTX,#96
    ldr     d12,[x2]
    add     x3,$CTX,#104
    ldr     d13,[x3]
    add     x4,$CTX,#112
    ldr     d14,[x4]
    add     x5,$CTX,#120
    ldr     d15,[x5]
	/* tl = subl(7) ^ (subr(7) & ~subr(9)); */
    bic     v1.16b,v7.16b,v9.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v1.16b,v7.16b
	/* dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v0.16b,v9.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    eor     v0.16b,v11.16b,v0.16b
    eor     v10.16b,v12.16b,v10.16b
    eor     v11.16b,v13.16b,v11.16b
    eor     v12.16b,v14.16b,v12.16b
    eor     v13.16b,v15.16b,v13.16b
    add     x1,$CTX,#80
    str     d0,[x1]
    add     x2,$CTX,#88
    str     d10,[x2]
    add     x3,$CTX,#96
    str     d11,[x3]
    add     x4,$CTX,#104
    str     d12,[x4]
    add     x5,$CTX,#112
    str     d13,[x5]

    add     x1,$CTX,#128
    ldr     d6,[x1]
    add     x2,$CTX,#136
    ldr     d7,[x2]
    add     x3,$CTX,#144
    ldr     d8,[x3]
    add     x4,$CTX,#152
    ldr     d9,[x4]
    add     x5,$CTX,#160
    ldr     d10,[x5]

	/* tl = subl(18) ^ (subr(18) & ~subr(16)); */
    bic     v1.16b,v8.16b,v6.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v1.16b,v8.16b
	/* dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v0.16b,v6.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    eor     v0.16b,v14.16b,v0.16b
    add     x1,$CTX,#120
    str     d0,[x1]

	/* tl = subl(15) ^ (subr(15) & ~subr(17)); */
    bic     v1.16b,v15.16b,v7.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v15.16b,v1.16b
	/* dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v0.16b,v7.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    add     x1,$CTX,#168
    ldr     d1,[x1]
    add     x2,$CTX,#176
    ldr     d2,[x2]
    add     x3,$CTX,#184
    ldr     d3,[x3]
    add     x4,$CTX,#192
    ldr     d4,[x4]

    eor     v0.16b,v9.16b,v0.16b
    eor     v8.16b,v10.16b,v8.16b
    eor     v9.16b,v1.16b,v9.16b
    eor     v10.16b,v2.16b,v10.16b
    eor     v1.16b,v3.16b,v1.16b
    eor     v3.16b,v4.16b,v3.16b
    
    add     x1,$CTX,#144
    str     d0,[x1]
    add     x2,$CTX,#152
    str     d8,[x2]
    add     x3,$CTX,#160
    str     d9,[x3]
    add     x4,$CTX,#168
    str     d10,[x4]
    add     x5,$CTX,#176
    str     d1,[x5]
    add     x1,$CTX,#184  // could continue with x6?
    str     d2,[x1]
    add     x2,$CTX,#192
    str     d3,[x2]

    // === ZERO UNUSED KEYS ===
    mov     x1, #0
    add     x3,$CTX,#8
    str     x1,[x3]
    add     x4,$CTX,#200
    str     x1,[x4]

    // === EPILOGUE ===
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]
    ldp     x29,x30,[sp],#144
    ret
.size __camellia_setup128_neon, .-__camellia_setup128_neon
___

$KR128 = "v1";
$KB128 = "v3";

$code.=<<___;
.text
.globl  __camellia_setup256_neon
.type   __camellia_setup256_neon,%function
.align  5
__camellia_setup256_neon:
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === CONSTANT LOADING ===
    // Load constants needed for camellia_f into v17-v27 + v16(bswap)
    adrp    x1,camellia_neon_consts
    add     x1,x1,:lo12:camellia_neon_consts
    ldp     q20,q21,[x1],#64    // pre_tf_lo/hi_s1
    ldp     q22,q23,[x1],#112   // post_tf_lo/hi_s1
    ldr     q19,[x1],#48        //mask_0f
    ldr     q16,[x1],#16        //bswap128
    ldr     d18,[x1],#8         //sbox4_input_mask
    ldr     q17,[x1],#16        //inv_shift_row_and_unpcklbw
    ldp     q24,q25,[x1],#32    //sp0044/sp1110
    ldp     q26,q27,[x1],#32    //sp0222/sp3033

    // Prepare zero vector
    eor     v31.16b,v31.16b,v31.16b
    
    // === INITIAL KEY HANDLING ===
    // Byte swap input keys KL128 & KR128 (v0 & v1) using v16
    tbl     $KL128.16b,{$KL128.16b},v16.16b
    tbl     $KR128.16b,{$KR128.16b},v16.16b
    
    // === GENERATE KA & KB(into v2 & v3) ===
    eor     v3.16b,$KL128.16b,$KR128.16b
    ext     v5.16b,$KR128.16b,v31.16b,#8     // here using v5 instead of ref. v6
    ext     v2.16b,v3.16b,v31.16b,#8
    ext     v3.16b,v31.16b,v3.16b,#8
    ext     v3.16b,v3.16b,v31.16b,#8

    // Get addresses of sigma constants
    adrp    x1,.Lsigma1
    add     x1,x1,:lo12:.Lsigma1 // x1 -> sigma1
    add     x2,x1,#8             // x2 -> sigma2
    add     x3,x1,#16            // x3 -> sigma3
    add     x4,x1,#24            // x4 -> sigma4
    add     x5,x1,#32            // x5 -> sigma5
    add     x6,x1,#40            // x6 -> sigma6

___
    &camellia_f("v2","v4","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x1","x7");
$code.=<<___;
    eor     v3.16b,v4.16b,v3.16b
___
    &camellia_f("v3","v2","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x2","x7");
$code.=<<___;
    eor     v2.16b,v5.16b,v2.16b
___
    &camellia_f("v2","v3","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x3","x7");
$code.=<<___;
    eor     v3.16b,v4.16b,v3.16b
    eor     v3.16b,$KR128.16b,v3.16b
___
    &camellia_f("v3","v4","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x4","x7");
$code.=<<___;

    eor     v6.16b,v4.16b,v2.16b
    mov     $KA128.d[0],v3.d[0]
    mov     $KA128.d[1],v6.d[0]

	/*
	 * Generate KB
	 */
    eor     v3.16b,$KA128.16b,$KR128.16b
    ext     v4.16b,v3.16b,v31.16b,#8
    ext     v3.16b,v31.16b,v3.16b,#8
    ext     v3.16b,v3.16b,v31.16b,#8

___
    &camellia_f("v4","v5","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x5","x7");
$code.=<<___;
    eor     v3.16b,v5.16b,v3.16b

___
    &camellia_f("v3","v5","v6","v7","v8","v9","v10","v31","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","x6","x7");
$code.=<<___;
    eor     v4.16b,v5.16b,v4.16b
    mov     $KB128.d[1],v4.d[0]

    /*
     * Generate subkeys
     */
    add     x1,$CTX,#256
    str     q3,[x1]     // KB128

___
    &vec_rol128($KR128, "v4", 15, "v15");
    &vec_rol128($KA128, "v5", 15, "v15");
    &vec_rol128($KR128, "v6", 30, "v15");
    &vec_rol128($KB128, "v7", 30, "v15");
    &vec_rol128($KL128, "v8", 45, "v15");
    &vec_rol128($KA128, "v9", 45, "v15");
    &vec_rol128($KL128, "v10", 60, "v15");
    &vec_rol128($KR128, "v11", 60, "v15");
    &vec_rol128($KB128, "v12", 60, "v15");
$code.=<<___;

	/* absorb kw2 to other subkeys */
    mov     v15.d[0],$KL128.d[0]
    mov     v15.d[1],xzr
    eor     $KB128.16b,$KB128.16b,v15.16b
    eor     v4.16b,v15.16b,v4.16b
    eor     v5.16b,v15.16b,v5.16b

	/* subl(1) ^= subr(1) & ~subr(9); */
    bic     v13.16b,v15.16b,v6.16b
    ext     v13.16b,v31.16b,v13.16b,#4
    ext     v13.16b,v13.16b,v31.16b,#8
    eor     v15.16b,v13.16b,v15.16b
	/* dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v6.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v31.16b,v14.16b,#8
    ext     v14.16b,v14.16b,v31.16b,#12
    eor     v15.16b,v14.16b,v15.16b

    eor     v7.16b,v15.16b,v7.16b
    eor     v8.16b,v15.16b,v8.16b
    eor     v9.16b,v15.16b,v9.16b

    ext     v13.16b,$KL128.16b,$KL128.16b,#8
    rev64   $KL128.4s,v13.4s
    ext     v14.16b,$KB128.16b,$KB128.16b,#8
    rev64   $KB128.4s,v14.4s
    ext     v13.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v13.4s
    ext     v14.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v14.4s
    ext     v13.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v13.4s
    ext     v14.16b,v7.16b,v7.16b,#8
    rev64   v7.4s,v14.4s
    ext     v13.16b,v8.16b,v8.16b,#8
    rev64   v8.4s,v13.4s
    ext     v14.16b,v9.16b,v9.16b,#8
    rev64   v9.4s,v14.4s

    add     x1,$CTX,#0
    str     q0,[x1]     // KL128
    ext     v13.16b,$KL128.16b,$KL128.16b,#8
    rev64   $KL128.4s,v13.4s
    add     x2,$CTX,#16
    str     q3,[x2]     // KB128
    add     x3,$CTX,#32
    str     q4,[x3]
    add     x4,$CTX,#48
    str     q5,[x4]
    add     x5,$CTX,#64
    str     q6,[x5]
    add     x6,$CTX,#80
    str     q7,[x6]
    add     x7,$CTX,#96
    str     q8,[x7]
    add     x1,$CTX,#112
    str     q9,[x1]

    add     x2,$CTX,#256
    ldr     q3,[x2]     // KB128

	/* subl(1) ^= subr(1) & ~subr(17); */
    bic     v13.16b,v15.16b,v10.16b
    ext     v13.16b,v31.16b,v13.16b,#4
    ext     v13.16b,v13.16b,v31.16b,#8
    eor     v15.16b,v13.16b,v15.16b
	/* dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v10.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v31.16b,v14.16b,#8
    ext     v14.16b,v14.16b,v31.16b,#12
    eor     v15.16b,v14.16b,v15.16b

    eor     v11.16b,v15.16b,v11.16b
    eor     v12.16b,v15.16b,v12.16b

___
    &vec_ror128($KL128, "v4", 128-77, "v14");
    &vec_ror128($KA128, "v5", 128-77, "v14");
    &vec_ror128($KR128, "v6", 128-94, "v14");
    &vec_ror128($KA128, "v7", 128-94, "v14");
    &vec_ror128($KL128, "v8", 128-111, "v14");
    &vec_ror128($KB128, "v9", 128-111, "v14");
$code.=<<___;

    eor     v4.16b,v15.16b,v4.16b

    ext     v13.16b,v10.16b,v10.16b,#8
    rev64   v10.4s,v13.4s
    ext     v14.16b,v11.16b,v11.16b,#8
    rev64   v11.4s,v14.4s
    ext     v13.16b,v12.16b,v12.16b,#8
    rev64   v12.4s,v13.4s
    ext     v14.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v14.4s

    add     x1,$CTX,#128
    str     q10,[x1]
    add     x2,$CTX,#144
    str     q11,[x2]
    add     x3,$CTX,#160
    str     q12,[x3]
    add     x4,$CTX,#176
    str     q4,[x4]

	/* subl(1) ^= subr(1) & ~subr(25); */
    bic     v13.16b,v15.16b,v5.16b
    ext     v13.16b,v31.16b,v13.16b,#4
    ext     v13.16b,v13.16b,v31.16b,#8
    eor     v15.16b,v13.16b,v15.16b
	/* dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v5.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v31.16b,v14.16b,#8
    ext     v14.16b,v14.16b,v31.16b,#12
    eor     v15.16b,v14.16b,v15.16b

    eor     v6.16b,v15.16b,v6.16b
    eor     v7.16b,v15.16b,v7.16b
    eor     v8.16b,v15.16b,v8.16b
    ext     v15.16b,v31.16b,v15.16b,#8
    eor     v9.16b,v15.16b,v9.16b

	/* absorb kw4 to other subkeys */
    ext     v15.16b,v31.16b,v9.16b,#8
    eor     v8.16b,v15.16b,v8.16b
    eor     v7.16b,v15.16b,v7.16b
    eor     v6.16b,v15.16b,v6.16b

	/* subl(33) ^= subr(33) & ~subr(24); */
    bic     v14.16b,v15.16b,v5.16b
    ext     v14.16b,v31.16b,v14.16b,#12
    eor     v15.16b,v14.16b,v15.16b
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v5.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v14.16b,v31.16b,#12
    ext     v14.16b,v31.16b,v14.16b,#8
    eor     v15.16b,v14.16b,v15.16b

    ext     v13.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v13.4s
    ext     v14.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v14.4s
    ext     v13.16b,v7.16b,v7.16b,#8
    rev64   v7.4s,v13.4s
    ext     v14.16b,v8.16b,v8.16b,#8
    rev64   v8.4s,v14.4s
    ext     v13.16b,v9.16b,v9.16b,#8
    rev64   v9.4s,v13.4s

    add     x1,$CTX,#192
    str     q5,[x1]
    add     x2,$CTX,#208
    str     q6,[x2]
    add     x3,$CTX,#224
    str     q7,[x3]
    add     x4,$CTX,#240
    str     q8,[x4]
    add     x5,$CTX,#256
    str     q9,[x5]

    add     x1,$CTX,#176
    ldr     q0,[x1]
    ext     v13.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v13.4s
    add     x2,$CTX,#160
    ldr     q1,[x2]
    ext     v14.16b,v1.16b,v1.16b,#8
    rev64   v1.4s,v14.4s
    add     x3,$CTX,#144
    ldr     q2,[x3]
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    add     x4,$CTX,#128
    ldr     q3,[x4]
    ext     v14.16b,v3.16b,v3.16b,#8
    rev64   v3.4s,v14.4s
    add     x5,$CTX,#112
    ldr     q4,[x5]
    ext     v13.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v13.4s
    add     x6,$CTX,#96
    ldr     q5,[x6]
    ext     v14.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v14.4s
    add     x7,$CTX,#80
    ldr     q6,[x7]
    ext     v13.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v13.4s
    add     x1,$CTX,#64
    ldr     q7,[x1]
    ext     v14.16b,v7.16b,v7.16b,#8
    rev64   v7.4s,v14.4s

    eor     v0.16b,v15.16b,v0.16b
    eor     v1.16b,v15.16b,v1.16b
    eor     v2.16b,v15.16b,v2.16b

	/* subl(33) ^= subr(33) & ~subr(24); */
    bic     v14.16b,v15.16b,v3.16b
    ext     v14.16b,v31.16b,v14.16b,#12
    eor     v15.16b,v14.16b,v15.16b
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v3.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v14.16b,v31.16b,#12
    ext     v14.16b,v31.16b,v14.16b,#8
    eor     v15.16b,v14.16b,v15.16b

    eor     v4.16b,v15.16b,v4.16b
    eor     v5.16b,v15.16b,v5.16b
    eor     v6.16b,v15.16b,v6.16b

    ext     v13.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v13.4s
    ext     v14.16b,v1.16b,v1.16b,#8
    rev64   v1.4s,v14.4s
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    ext     v14.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v14.4s
    ext     v13.16b,v5.16b,v5.16b,#8
    rev64   v5.4s,v13.4s
    ext     v14.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v14.4s

    add     x1,$CTX,#176
    str     q0,[x1]
    add     x2,$CTX,#160
    str     q1,[x2]
    add     x3,$CTX,#144
    str     q2,[x3]
    add     x4,$CTX,#112
    str     q4,[x4]
    add     x5,$CTX,#96
    str     q5,[x5]
    add     x6,$CTX,#80
    str     q6,[x6]

    add     x1,$CTX,#48
    ldr     q6,[x1]
    ext     v13.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v13.4s
    add     x2,$CTX,#32
    ldr     q4,[x2]
    ext     v14.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v14.4s
    add     x3,$CTX,#16
    ldr     q2,[x3]
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    add     x4,$CTX,#0
    ldr     q0,[x4]
    ext     v14.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v14.4s

	/* subl(33) ^= subr(33) & ~subr(24); */
    bic     v14.16b,v15.16b,v7.16b
    ext     v14.16b,v31.16b,v14.16b,#12
    eor     v15.16b,v14.16b,v15.16b
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
    and     v14.16b,v15.16b,v7.16b
    shl     v13.4s,v14.4s,#1
    ushr    v14.4s,v14.4s,#31
    add     v14.16b,v13.16b,v14.16b
    ext     v14.16b,v14.16b,v31.16b,#12
    ext     v14.16b,v31.16b,v14.16b,#8
    eor     v15.16b,v14.16b,v15.16b

    eor     v6.16b,v15.16b,v6.16b
    eor     v4.16b,v15.16b,v4.16b
    eor     v2.16b,v15.16b,v2.16b
    eor     v0.16b,v15.16b,v0.16b

    ext     v13.16b,v6.16b,v6.16b,#8
    rev64   v6.4s,v13.4s
    ext     v14.16b,v4.16b,v4.16b,#8
    rev64   v4.4s,v14.4s
    ext     v13.16b,v2.16b,v2.16b,#8
    rev64   v2.4s,v13.4s
    ext     v14.16b,v0.16b,v0.16b,#8
    rev64   v0.4s,v14.4s

    ext     v3.16b,v2.16b,v31.16b,#8
    ext     v5.16b,v4.16b,v31.16b,#8
    ext     v7.16b,v6.16b,v31.16b,#8

    /*
	 * key XOR is end of F-function.
	 */
    eor     v0.16b,v2.16b,v0.16b
    eor     v2.16b,v4.16b,v2.16b

    add     x1,$CTX,#0
    str     d0,[x1]
    add     x2,$CTX,#16
    str     d3,[x2]
    eor     v3.16b,v5.16b,v3.16b
    eor     v4.16b,v6.16b,v4.16b
    eor     v5.16b,v7.16b,v5.16b
    add     x3,$CTX,#24
    str     d2,[x3]
    add     x4,$CTX,#32
    str     d3,[x4]
    add     x5,$CTX,#40
    str     d4,[x5]
    add     x6,$CTX,#48
    str     d5,[x6]

    add     x1,$CTX,#56
    ldr     d7,[x1]
    add     x2,$CTX,#64
    ldr     d8,[x2]
    add     x3,$CTX,#72
    ldr     d9,[x3]
    add     x4,$CTX,#80
    ldr     d10,[x4]
	/* tl = subl(10) ^ (subr(10) & ~subr(8)); */
    bic     v15.16b,v10.16b,v8.16b
    ext     v15.16b,v15.16b,v31.16b,#4
    eor     v0.16b,v15.16b,v10.16b
	/* dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw); */
    and     v15.16b,v8.16b,v0.16b
    shl     v14.4s,v15.4s,#1
    ushr    v15.4s,v15.4s,#31
    add     v15.16b,v14.16b,v15.16b
    ext     v15.16b,v31.16b,v15.16b,#4
    ext     v15.16b,v15.16b,v31.16b,#8
    eor     v0.16b,v15.16b,v0.16b

    eor     v6.16b,v0.16b,v6.16b
    add     x1,$CTX,#56
    str     d6,[x1]

    add     x2,$CTX,#88
    ldr     d11,[x2]
    add     x3,$CTX,#96
    ldr     d12,[x3]
    add     x4,$CTX,#104
    ldr     d13,[x4]
    add     x5,$CTX,#112
    ldr     d14,[x5]
    add     x6,$CTX,#120
    ldr     d15,[x6]
	/* tl = subl(7) ^ (subr(7) & ~subr(9)); */
    bic     v1.16b,v7.16b,v9.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v1.16b,v7.16b
	/* dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v9.16b,v0.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    eor     v0.16b,v11.16b,v0.16b
    eor     v10.16b,v12.16b,v10.16b
    eor     v11.16b,v13.16b,v11.16b
    eor     v12.16b,v14.16b,v12.16b
    eor     v13.16b,v15.16b,v13.16b
    add     x1,$CTX,#80
    str     d0,[x1]
    add     x2,$CTX,#88
    str     d10,[x2]
    add     x3,$CTX,#96
    str     d11,[x3]
    add     x4,$CTX,#104
    str     d12,[x4]
    add     x5,$CTX,#112
    str     d13,[x5]

    add     x1,$CTX,#128
    ldr     d6,[x1]
    add     x2,$CTX,#136
    ldr     d7,[x2]
    add     x3,$CTX,#144
    ldr     d8,[x3]
    add     x4,$CTX,#152
    ldr     d9,[x4]
    add     x5,$CTX,#160
    ldr     d10,[x5]
	/* tl = subl(18) ^ (subr(18) & ~subr(16)); */
    bic     v1.16b,v8.16b,v6.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v1.16b,v8.16b
	/* dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v6.16b,v0.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    eor     v0.16b,v14.16b,v0.16b
    add     x1,$CTX,#120
    str     d0,[x1]

	/* tl = subl(15) ^ (subr(15) & ~subr(17)); */
    bic     v1.16b,v15.16b,v7.16b
    ext     v1.16b,v1.16b,v31.16b,#4
    eor     v0.16b,v1.16b,v15.16b
	/* dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw); */
    and     v1.16b,v7.16b,v0.16b
    shl     v2.4s,v1.4s,#1
    ushr    v1.4s,v1.4s,#31
    add     v1.16b,v2.16b,v1.16b
    ext     v1.16b,v31.16b,v1.16b,#4
    ext     v1.16b,v1.16b,v31.16b,#8
    eor     v0.16b,v1.16b,v0.16b

    add     x1,$CTX,#168
    ldr     d1,[x1]
    add     x2,$CTX,#176
    ldr     d2,[x2]
    add     x3,$CTX,#184
    ldr     d3,[x3]
    add     x4,$CTX,#192
    ldr     d4,[x4]

    eor     v0.16b,v9.16b,v0.16b
    eor     v8.16b,v10.16b,v8.16b
    eor     v9.16b,v1.16b,v9.16b
    eor     v10.16b,v2.16b,v10.16b
    eor     v1.16b,v3.16b,v1.16b

    add     x1,$CTX,#144
    str     d0,[x1]
    add     x2,$CTX,#152
    str     d8,[x2]
    add     x3,$CTX,#160
    str     d9,[x3]
    add     x4,$CTX,#168
    str     d10,[x4]
    add     x5,$CTX,#176
    str     d1,[x5]

    add     x1,$CTX,#200
    ldr     d5,[x1]
    add     x2,$CTX,#208
    ldr     d6,[x2]
    add     x3,$CTX,#216
    ldr     d7,[x3]
    add     x4,$CTX,#224
    ldr     d8,[x4]
    add     x5,$CTX,#232
    ldr     d9,[x5]
    add     x6,$CTX,#240
    ldr     d10,[x6]
    add     x7,$CTX,#248
    ldr     d11,[x7]
    add     x1,$CTX,#256
    ldr     d12,[x1]

	/* tl = subl(26) ^ (subr(26) & ~subr(24)); */
    bic     v15.16b,v6.16b,v4.16b
    ext     v15.16b,v15.16b,v31.16b,#4
    eor     v0.16b,v15.16b,v6.16b
	/* dw = tl & subl(26), tr = subr(24) ^ CAMELLIA_RL1(dw); */
    and     v15.16b,v4.16b,v0.16b
    shl     v14.4s,v15.4s,#1
    ushr    v15.4s,v15.4s,#31
    add     v15.16b,v14.16b,v15.16b
    ext     v15.16b,v31.16b,v15.16b,#4
    ext     v15.16b,v15.16b,v31.16b,#8
    eor     v0.16b,v15.16b,v0.16b

    eor     v2.16b,v0.16b,v2.16b
    add     x1,$CTX,#184
    str     d2,[x1]

	/* tl = subl(23) ^ (subr(23) &  ~subr(25)); */
    bic     v15.16b,v3.16b,v5.16b
    ext     v15.16b,v15.16b,v31.16b,#4
    eor     v0.16b,v15.16b,v3.16b
	/* dw = tl & subl(26), tr = subr(24) ^ CAMELLIA_RL1(dw); */
    and     v15.16b,v5.16b,v0.16b
    shl     v14.4s,v15.4s,#1
    ushr    v15.4s,v15.4s,#31
    add     v15.16b,v14.16b,v15.16b
    ext     v15.16b,v31.16b,v15.16b,#4
    ext     v15.16b,v15.16b,v31.16b,#8
    eor     v0.16b,v15.16b,v0.16b

    eor     v0.16b,v7.16b,v0.16b
    eor     v6.16b,v8.16b,v6.16b
    eor     v7.16b,v9.16b,v7.16b
    eor     v8.16b,v10.16b,v8.16b
    eor     v9.16b,v11.16b,v9.16b
    eor     v11.16b,v12.16b,v11.16b

    add     x1,$CTX,#208
    str     d0,[x1]
    add     x2,$CTX,#216
    str     d6,[x2]
    add     x3,$CTX,#224
    str     d7,[x3]
    add     x4,$CTX,#232
    str     d8,[x4]
    add     x5,$CTX,#240
    str     d9,[x5]
    add     x6,$CTX,#248
    str     d10,[x6]
    add     x7,$CTX,#256
    str     d11,[x7]

    mov     x1, #0
    add     x2,$CTX,#8
    str     x1,[x2]
    add     x3,$CTX,#264
    str     x1,[x3]

    // === EPILOGUE ===
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]
    ldp     x29,x30,[sp],#144

    ret

.size __camellia_setup256_neon,.-__camellia_setup256_neon

.global camellia_keysetup_neon
.type   camellia_keysetup_neon, %function
.align  4
camellia_keysetup_neon:
    // Input:
    //   x0: ctx (struct camellia_simd_ctx *)
    //   x1: key (const unsigned char *)
    //   x2: keylen (int) - 16, 24, or 32

    // Store key_length into ctx->key_length
    // Offset is 272 (68 * 4 bytes for key_table)
    str     w2,[x0,#272]

    // Load the first 128 bits of the key into v0
    ldr     q0,[x1]

    // Check key length
    cmp     w2,#24
    b.lt    .Lsetup_128    // keylen < 24 (i.e., 16)
    b.eq    .Lsetup_192    // keylen == 24

    // === 256-bit Case ===
    // Load the second 128 bits into v1
    ldr     q1,[x1,#16]
    // Tail call to setup256
    b       __camellia_setup256_neon

.Lsetup_192:
    // === 192-bit Case ===
    // Camellia 192 treats the second half as: [ K[16..23] | ~K[16..23] ]
    // Load the 64 bits of K_R into a GPR
    ldr     x3,[x1,#16]
    // Create the complement (~K_R)
    mvn     x4,x3
    // Assemble v1: Lower 64 = K_R, Upper 64 = ~K_R
    mov     v1.d[0],x3
    mov     v1.d[1],x4
    // Tail call to setup256
    b       __camellia_setup256_neon

.Lsetup_128:
    // === 128-bit Case ===
    // Tail call to setup128
    b       __camellia_setup128_neon

.size   camellia_keysetup_neon, .-camellia_keysetup_neon
___
$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
