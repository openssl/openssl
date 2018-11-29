#!/usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is dual licensed under OpenSSL and CRYPTOGAMS
# licenses depending on where you obtain it. For further details see
# https://github.com/dot-asm/cryptogams/.
# ====================================================================

$flavour = shift;
if ($flavour=~/\w[\w\-]*\.\w+$/) { $output=$flavour; undef $flavour; }
else { while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {} }

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

$code.=<<___;
#if defined(__thumb2__)
.syntax	unified
.thumb
#else
.code	32
#endif

.text

.globl	bn_div_3_words
.type	bn_div_3_words,%function
.align	5
bn_div_3_words:
	stmdb	sp!,{r4-r7}
	ldr	r4,[r0,#-4]	@ load R.lo
	ldr	r5,[r0]		@ load R.hi
	eor	r0,r0,r0	@ Q = 0
	mov	r3,#32		@ loop counter

.Loop:
	subs	r6,r4,r1	@ R - D
	add	r0,r0,r0	@ Q <<= 1
	sbcs	r7,r5,r2
	add	r0,r0,#1	@ + speculative bit
#ifdef	__thumb2__
	it	hs
#endif
	movhs	r4,r6		@ select between R and R - D
	 lsr	r1,r1,#1
#ifdef	__thumb2__
	it	hs
#endif
	movhs	r5,r7
	 orr	r1,r1,r2,lsl#31
	sbc	r0,r0,#0	@ subtract speculative bit
	 lsr	r2,r2,#1	@ D >>= 1
	subs	r3,r3,#1
	bne	.Loop

	asr	r3,r0,#31	@ top bit -> mask
	add	r0,r0,r0	@ Q <<= 1
	subs	r6,r4,r1	@ R - D
	add	r0,r0,#1	@ + specilative bit
	sbcs	r7,r5,r2
	sbc	r0,r0,#0	@ subtract speculative bit

	orr	r0,r0,r3	@ all ones if overflow

	ldmia	sp!,{r4-r7}
	bx	lr
.size	bn_div_3_words,.-bn_div_3_words
___

print $code;
close STDOUT;
