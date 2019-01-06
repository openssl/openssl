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

$output = pop;
open STDOUT,">$output" if $output;

$code.=<<___;
.section	".text",#alloc,#execinstr

.globl	bn_div_3_words
.align	32
bn_div_3_words:
	lduw		[%o0-4], %o3		! load R.lo
	clruw		%o1, %o1
	lduw		[%o0+0], %o4		! load R.hi
	sllx		%o2,  32, %o2
	clr		%o0			! Q = 0
	sllx		%o4,  32, %o4
	or		%o2, %o1, %o1		! D
	or		%o4, %o3, %o2		! R
	mov		31,  %o5 		! loop counter

.Loop:
	subcc		%o2, %o1, %o3		! R - D
	add		%o0, %o0, %o0		! Q <<= 1
	clr		%o4
	movcc		%xcc,%o3, %o2
	movcc		%xcc,  1, %o4
	srlx		%o1,   1, %o1		! D >>= 1
	add		%o4, %o0, %o0
	brnz,a,pt	%o5, .Loop 
	sub		%o5,   1, %o5

	subcc		%o2, %o1, %o3		! R - D
	clr		%o4
	sra		%o0,  31, %o5		! top bit -> mask
	add		%o0, %o0, %o0		! Q <<= 1
	movcc		%xcc,  1, %o4
	add		%o4, %o0, %o0

	retl
	or		%o5, %o0, %o0		! all ones if overflow
.size	bn_div_3_words,.-bn_div_3_words
___

print $code;
close STDOIT;
