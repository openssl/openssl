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

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$code.=<<___;
.text

.globl	bn_div_3_words
.type	bn_div_3_words,\@function
.align	32
bn_div_3_words:
___
if ($flavour =~ /3[12]/) {	#### 32-bit version
$code.=<<___;
	ahi	%r2,-4
	st	%r6,24(%r15)
	xgr	%r0,%r0		# just zero
	lghi	%r1,32		# loop counter
	lg	%r5,0(%r2)	# load R	
	xgr	%r2,%r2		# Q = 0
	llgfr	%r3,%r3		# clear upper half
	sllg	%r4,%r4,32
	rllg	%r5,%r5,32	# compose R
	ogr	%r3,%r4		# compose D

.Loop:
	alr	%r2,%r2		# Q <<= 1
	ahi	%r2,1		# + speculative bit
	lgr	%r6,%r5		# put aside R
	slgr	%r5,%r3		# R -= D
	lghi	%r4,1
	slbr	%r2,%r0		# subtract speculative bit
	nr	%r4,%r2
	lcgr	%r4,%r4		# 0 - least significant bit
	xgr	%r5,%r6		# select between R and R - D
	ngr	%r5,%r4
	srlg	%r3,%r3,1	# D >>= 1
	xgr	%r5,%r6
	brct	%r1,.Loop

	lr	%r1,%r2
	alr	%r2,%r2		# Q <<= 1
	sra	%r1,31		# top bit -> mask
	ahi	%r2,1		# + speculative bit

	slgr	%r5,%r3
	slbr	%r2,%r0		# subtract speculative bit

	or	%r2,%r1		# all ones if overflow

	l	%r6,24(%r15)
	br	%r14
___
} else {			#### 64-bit version
$code.=<<___;
	aghi	%r2,-8
	stmg	%r6,%r9,48(%r15)
	xgr	%r0,%r0		# just zero
	lghi	%r1,64		# loop counter
	lmg	%r5,%r6,0(%r2)	# load R	
	xgr	%r2,%r2		# Q = 0

.Loop:
	la	%r2,1(%r2,%r2)	# Q <<= 1 + speculative bit
	lgr	%r7,%r5		# put aside R
	slgr	%r5,%r3		# R -= D
	lgr	%r8,%r6
	slbgr	%r6,%r4
	lghi	%r9,1
	slbgr	%r2,%r0		# subtract speculative bit
	ngr	%r9,%r2
	lcgr	%r9,%r9		# 0 - least significant bit
	xgr	%r5,%r7		# select between R and R - D
	xgr	%r6,%r8
	 srlg	%r3,%r3,1
	ngr	%r5,%r9
	ngr	%r6,%r9
	 sllg	%r9,%r4,63
	xgr	%r5,%r7
	xgr	%r6,%r8
	 srlg	%r4,%r4,1
	 ogr	%r3,%r9		# D >>= 1
	brct	%r1,.Loop

	srag	%r1,%r2,63	# top bit -> mask
	la	%r2,1(%r2,%r2)	# Q <<= 1 + speculative bit

	slgr	%r5,%r3
	slbgr	%r6,%r4
	slbgr	%r2,%r0		# subtract speculative bit

	ogr	%r2,%r1		# all ones if overflow

	lmg	%r6,%r9,48(%r15)
	br	%r14
___
}
$code.=<<___;
.size	bn_div_3_words,.-bn_div_3_words
___

print $code;
close STDOUT;
