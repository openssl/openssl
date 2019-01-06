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
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open STDOUT,"| \"$^X\" $xlate $flavour $output";

$code.=<<___;
.text

.globl	bn_div_3_words
.type	bn_div_3_words,%function
.align	5
bn_div_3_words:
	ldp	x4,x5,[x0,#-8]	// load R
	eor	x0,x0,x0	// Q = 0
	mov	x3,#64		// loop counter
	nop

.Loop:
	subs	x6,x4,x1	// R - D
	add	x0,x0,x0	// Q <<= 1
	sbcs	x7,x5,x2
	add	x0,x0,#1	// + speculative bit
	csel	x4,x4,x6,lo	// select between R and R - D
	 lsr	x1,x1,#1
	csel	x5,x5,x7,lo
	 orr	x1,x1,x2,lsl#63
	sbc	x0,x0,xzr	// subtract speculative bit
	 lsr	x2,x2,#1	// D >>= 1
	sub	x3,x3,#1
	cbnz	x3,.Loop

	asr	x3,x0,#63	// top bit -> mask
	add	x0,x0,x0	// Q <<= 1
	subs	x6,x4,x1	// R - D
	add	x0,x0,#1	// + specilative bit
	sbcs	x7,x5,x2
	sbc	x0,x0,xzr	// subtract speculative bit

	orr	x0,x0,x3	// all ones if overflow

	ret
.size	bn_div_3_words,.-bn_div_3_words
___

print $code;
close STDOUT;
