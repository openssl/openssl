#!/usr/bin/evn perl
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

if ($flavour =~ /32/) {
	$BITS=	32;
	$BNSZ=	$BITS/8;
	$SIZE_T=4;

	$LD=	"lwz";		# load
	$SARI=	"srawi";	# signed shift right by immediate
	$SHRI=	"srwi";		# unsigned shift right by immediate
	$SHLI=	"slwi";		# unsigned shift left by immediate
} elsif ($flavour =~ /64/) {
	$BITS=	64;
	$BNSZ=	$BITS/8;
	$SIZE_T=8;

	# same as above, but 64-bit mnemonics...
	$LD=	"ld";		# load
	$SARI=	"sradi";	# signed shift right by immediate
	$SHRI=	"srdi";		# unsigned shift right by immediate
	$SHLI=	"sldi";		# unsigned shift left by immediate
} else { die "nonsense $flavour"; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour ".shift || die "can't call $xlate: $!";

$code=<<___;
.text

.globl	.bn_div_3_words
.align	5
.bn_div_3_words:
	$LD	r6,-$BNSZ(r3)		# load R.lo
	$LD	r7,0(r3)		# load R.hi
	li	r11,$BITS		# loop counter
	xor	r3,r3,r3		# Q = 0
	xor	r0,r0,r0		# zero
	mtctr	r11
	b	Loop
	nop

Loop:
	add	r3,r3,r3		# Q <<= 1
	subfc	r8,r4,r6		# R - D
	addi	r3,r3,1			# + speculative bit
	subfe	r9,r5,r7
	 $SHLI	r10,r5,$BITS-1
	subfe	r3,r0,r3		# subtract speculative bit
	 $SHRI	r4,r4,1
	andi.	r11,r3,1
	 $SHRI	r5,r5,1
	neg	r11,r11
	xor	r8,r8,r6		# select between R and R - D
	xor	r9,r9,r7
	and	r8,r8,r11
	and	r9,r9,r11
	 or	r4,r4,r10		# D >>= 1
	xor	r6,r6,r8
	xor	r7,r7,r9
	bdnz	Loop

	$SARI	r11,r3,$BITS-1		# top bit -> mask
	add	r3,r3,r3		# Q <<=1
	subfc	r8,r4,r6		# R - D
	addi	r3,r3,1			# + speculative bit
	subfe	r9,r5,r7
	subfe	r3,r0,r3		# subtract speculative bit

	or	r3,r3,r11		# all ones if overflow

	blr
	.long	0
	.byte	0,12,0x14,0,0,0,3,0
	.long	0
.size	.bn_div_3_words,.-.bn_div_3_words
___

print $code;
close STDOUT;
