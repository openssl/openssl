#!/usr/bin/env perl
# Copyright 2017-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see https://github.com/dot-asm/cryptogams/.
# ====================================================================
#
# Keccak-1600 for ARMv8.
#
# June 2017.
#
# This is straightforward KECCAK_1X_ALT implementation. It makes no
# sense to attempt SIMD/NEON implementation for following reason.
# 64-bit lanes of vector registers can't be addressed as easily as in
# 32-bit mode. This means that 64-bit NEON is bound to be slower than
# 32-bit NEON, and this implementation is faster than 32-bit NEON on
# same processor. Even though it takes more scalar xor's and andn's,
# it gets compensated by availability of rotate. Not to forget that
# most processors achieve higher issue rate with scalar instructions.
#
# February 2018.
#
# Add hardware-assisted ARMv8.2 implementation. It's KECCAK_1X_ALT
# variant with register permutation/rotation twist that allows to
# eliminate copies to temporary registers. If you look closely you'll
# notice that it uses only one lane of vector registers. The new
# instructions effectively facilitate parallel hashing, which we don't
# support [yet?]. But lowest-level core procedure is prepared for it.
# The inner round is 67 [vector] instructions, so it's not actually
# obvious that it will provide performance improvement [in serial
# hash] as long as vector instructions issue rate is limited to 1 per
# cycle...
#
######################################################################
# Numbers are cycles per processed byte.
#
#		r=1088(*)
#
# Cortex-A53	13
# Cortex-A57	12
# X-Gene	14
# Mongoose	10
# Kryo		12
# Denver	7.8
# Apple A7	7.2
# ThunderX2	9.7
#
# (*)	Corresponds to SHA3-256. No improvement coefficients are listed
#	because they vary too much from compiler to compiler. Newer
#	compiler does much better and improvement varies from 5% on
#	Cortex-A57 to 25% on Cortex-A53. While in comparison to older
#	compiler this code is at least 2x faster...

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

$code.=<<___;
#include "arch/arm_arch.h"

.rodata

.align 8	// strategic alignment and padding that allows to use
		// address value as loop termination condition...
	.quad	0,0,0,0,0,0,0,0
.type	iotas,%object
iotas:
	.quad	0x0000000000000001
	.quad	0x0000000000008082
	.quad	0x800000000000808a
	.quad	0x8000000080008000
	.quad	0x000000000000808b
	.quad	0x0000000080000001
	.quad	0x8000000080008081
	.quad	0x8000000000008009
	.quad	0x000000000000008a
	.quad	0x0000000000000088
	.quad	0x0000000080008009
	.quad	0x000000008000000a
	.quad	0x000000008000808b
	.quad	0x800000000000008b
	.quad	0x8000000000008089
	.quad	0x8000000000008003
	.quad	0x8000000000008002
	.quad	0x8000000000000080
	.quad	0x000000000000800a
	.quad	0x800000008000000a
	.quad	0x8000000080008081
	.quad	0x8000000000008080
	.quad	0x0000000080000001
	.quad	0x8000000080008008
.size	iotas,.-iotas
___
								{{{
my @A = map([ "x$_", "x".($_+1), "x".($_+2), "x".($_+3), "x".($_+4) ],
            (0, 5, 10, 15, 20));
   $A[3][3] = "x25"; # x18 is reserved

my @C = map("x$_", (26,27,28,30));

$code.=<<___;
.text

.type	KeccakF1600_int,%function
.align	5
KeccakF1600_int:
	AARCH64_SIGN_LINK_REGISTER
	adrp	$C[2],iotas
	add	$C[2],$C[2],:lo12:iotas
	stp	$C[2],x30,[sp,#16]		// 32 bytes on top are mine
	b	.Loop
.align	4
.Loop:
	////////////////////////////////////////// Theta
	eor	$C[0],$A[0][0],$A[1][0]
	stp	$A[0][4],$A[1][4],[sp,#0]	// offload pair...
	eor	$C[1],$A[0][1],$A[1][1]
	eor	$C[2],$A[0][2],$A[1][2]
	eor	$C[3],$A[0][3],$A[1][3]
___
	$C[4]=$A[0][4];
	$C[5]=$A[1][4];
$code.=<<___;
	eor	$C[4],$A[0][4],$A[1][4]
	eor	$C[0],$C[0],$A[2][0]
	eor	$C[1],$C[1],$A[2][1]
	eor	$C[2],$C[2],$A[2][2]
	eor	$C[3],$C[3],$A[2][3]
	eor	$C[4],$C[4],$A[2][4]
	eor	$C[0],$C[0],$A[3][0]
	eor	$C[1],$C[1],$A[3][1]
	eor	$C[2],$C[2],$A[3][2]
	eor	$C[3],$C[3],$A[3][3]
	eor	$C[4],$C[4],$A[3][4]
	eor	$C[0],$C[0],$A[4][0]
	eor	$C[2],$C[2],$A[4][2]
	eor	$C[1],$C[1],$A[4][1]
	eor	$C[3],$C[3],$A[4][3]
	eor	$C[4],$C[4],$A[4][4]

	eor	$C[5],$C[0],$C[2],ror#63

	eor	$A[0][1],$A[0][1],$C[5]
	eor	$A[1][1],$A[1][1],$C[5]
	eor	$A[2][1],$A[2][1],$C[5]
	eor	$A[3][1],$A[3][1],$C[5]
	eor	$A[4][1],$A[4][1],$C[5]

	eor	$C[5],$C[1],$C[3],ror#63
	eor	$C[2],$C[2],$C[4],ror#63
	eor	$C[3],$C[3],$C[0],ror#63
	eor	$C[4],$C[4],$C[1],ror#63

	eor	$C[1],   $A[0][2],$C[5]		// mov	$C[1],$A[0][2]
	eor	$A[1][2],$A[1][2],$C[5]
	eor	$A[2][2],$A[2][2],$C[5]
	eor	$A[3][2],$A[3][2],$C[5]
	eor	$A[4][2],$A[4][2],$C[5]

	eor	$A[0][0],$A[0][0],$C[4]
	eor	$A[1][0],$A[1][0],$C[4]
	eor	$A[2][0],$A[2][0],$C[4]
	eor	$A[3][0],$A[3][0],$C[4]
	eor	$A[4][0],$A[4][0],$C[4]
___
	$C[4]=undef;
	$C[5]=undef;
$code.=<<___;
	ldp	$A[0][4],$A[1][4],[sp,#0]	// re-load offloaded data
	eor	$C[0],   $A[0][3],$C[2]		// mov	$C[0],$A[0][3]
	eor	$A[1][3],$A[1][3],$C[2]
	eor	$A[2][3],$A[2][3],$C[2]
	eor	$A[3][3],$A[3][3],$C[2]
	eor	$A[4][3],$A[4][3],$C[2]

	eor	$C[2],   $A[0][4],$C[3]		// mov	$C[2],$A[0][4]
	eor	$A[1][4],$A[1][4],$C[3]
	eor	$A[2][4],$A[2][4],$C[3]
	eor	$A[3][4],$A[3][4],$C[3]
	eor	$A[4][4],$A[4][4],$C[3]

	////////////////////////////////////////// Rho+Pi
	mov	$C[3],$A[0][1]
	ror	$A[0][1],$A[1][1],#64-$rhotates[1][1]
	//mov	$C[1],$A[0][2]
	ror	$A[0][2],$A[2][2],#64-$rhotates[2][2]
	//mov	$C[0],$A[0][3]
	ror	$A[0][3],$A[3][3],#64-$rhotates[3][3]
	//mov	$C[2],$A[0][4]
	ror	$A[0][4],$A[4][4],#64-$rhotates[4][4]

	ror	$A[1][1],$A[1][4],#64-$rhotates[1][4]
	ror	$A[2][2],$A[2][3],#64-$rhotates[2][3]
	ror	$A[3][3],$A[3][2],#64-$rhotates[3][2]
	ror	$A[4][4],$A[4][1],#64-$rhotates[4][1]

	ror	$A[1][4],$A[4][2],#64-$rhotates[4][2]
	ror	$A[2][3],$A[3][4],#64-$rhotates[3][4]
	ror	$A[3][2],$A[2][1],#64-$rhotates[2][1]
	ror	$A[4][1],$A[1][3],#64-$rhotates[1][3]

	ror	$A[4][2],$A[2][4],#64-$rhotates[2][4]
	ror	$A[3][4],$A[4][3],#64-$rhotates[4][3]
	ror	$A[2][1],$A[1][2],#64-$rhotates[1][2]
	ror	$A[1][3],$A[3][1],#64-$rhotates[3][1]

	ror	$A[2][4],$A[4][0],#64-$rhotates[4][0]
	ror	$A[4][3],$A[3][0],#64-$rhotates[3][0]
	ror	$A[1][2],$A[2][0],#64-$rhotates[2][0]
	ror	$A[3][1],$A[1][0],#64-$rhotates[1][0]

	ror	$A[1][0],$C[0],#64-$rhotates[0][3]
	ror	$A[2][0],$C[3],#64-$rhotates[0][1]
	ror	$A[3][0],$C[2],#64-$rhotates[0][4]
	ror	$A[4][0],$C[1],#64-$rhotates[0][2]

	////////////////////////////////////////// Chi+Iota
	bic	$C[0],$A[0][2],$A[0][1]
	bic	$C[1],$A[0][3],$A[0][2]
	bic	$C[2],$A[0][0],$A[0][4]
	bic	$C[3],$A[0][1],$A[0][0]
	eor	$A[0][0],$A[0][0],$C[0]
	bic	$C[0],$A[0][4],$A[0][3]
	eor	$A[0][1],$A[0][1],$C[1]
	 ldr	$C[1],[sp,#16]
	eor	$A[0][3],$A[0][3],$C[2]
	eor	$A[0][4],$A[0][4],$C[3]
	eor	$A[0][2],$A[0][2],$C[0]
	 ldr	$C[3],[$C[1]],#8		// Iota[i++]

	bic	$C[0],$A[1][2],$A[1][1]
	 tst	$C[1],#255			// are we done?
	 str	$C[1],[sp,#16]
	bic	$C[1],$A[1][3],$A[1][2]
	bic	$C[2],$A[1][0],$A[1][4]
	 eor	$A[0][0],$A[0][0],$C[3]		// A[0][0] ^= Iota
	bic	$C[3],$A[1][1],$A[1][0]
	eor	$A[1][0],$A[1][0],$C[0]
	bic	$C[0],$A[1][4],$A[1][3]
	eor	$A[1][1],$A[1][1],$C[1]
	eor	$A[1][3],$A[1][3],$C[2]
	eor	$A[1][4],$A[1][4],$C[3]
	eor	$A[1][2],$A[1][2],$C[0]

	bic	$C[0],$A[2][2],$A[2][1]
	bic	$C[1],$A[2][3],$A[2][2]
	bic	$C[2],$A[2][0],$A[2][4]
	bic	$C[3],$A[2][1],$A[2][0]
	eor	$A[2][0],$A[2][0],$C[0]
	bic	$C[0],$A[2][4],$A[2][3]
	eor	$A[2][1],$A[2][1],$C[1]
	eor	$A[2][3],$A[2][3],$C[2]
	eor	$A[2][4],$A[2][4],$C[3]
	eor	$A[2][2],$A[2][2],$C[0]

	bic	$C[0],$A[3][2],$A[3][1]
	bic	$C[1],$A[3][3],$A[3][2]
	bic	$C[2],$A[3][0],$A[3][4]
	bic	$C[3],$A[3][1],$A[3][0]
	eor	$A[3][0],$A[3][0],$C[0]
	bic	$C[0],$A[3][4],$A[3][3]
	eor	$A[3][1],$A[3][1],$C[1]
	eor	$A[3][3],$A[3][3],$C[2]
	eor	$A[3][4],$A[3][4],$C[3]
	eor	$A[3][2],$A[3][2],$C[0]

	bic	$C[0],$A[4][2],$A[4][1]
	bic	$C[1],$A[4][3],$A[4][2]
	bic	$C[2],$A[4][0],$A[4][4]
	bic	$C[3],$A[4][1],$A[4][0]
	eor	$A[4][0],$A[4][0],$C[0]
	bic	$C[0],$A[4][4],$A[4][3]
	eor	$A[4][1],$A[4][1],$C[1]
	eor	$A[4][3],$A[4][3],$C[2]
	eor	$A[4][4],$A[4][4],$C[3]
	eor	$A[4][2],$A[4][2],$C[0]

	bne	.Loop

	ldr	x30,[sp,#24]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600_int,.-KeccakF1600_int

.type	KeccakF1600,%function
.align	5
KeccakF1600:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-128]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]
	stp	x25,x26,[sp,#64]
	stp	x27,x28,[sp,#80]
	sub	sp,sp,#48

	str	x0,[sp,#32]			// offload argument
	mov	$C[0],x0
	ldp	$A[0][0],$A[0][1],[x0,#16*0]
	ldp	$A[0][2],$A[0][3],[$C[0],#16*1]
	ldp	$A[0][4],$A[1][0],[$C[0],#16*2]
	ldp	$A[1][1],$A[1][2],[$C[0],#16*3]
	ldp	$A[1][3],$A[1][4],[$C[0],#16*4]
	ldp	$A[2][0],$A[2][1],[$C[0],#16*5]
	ldp	$A[2][2],$A[2][3],[$C[0],#16*6]
	ldp	$A[2][4],$A[3][0],[$C[0],#16*7]
	ldp	$A[3][1],$A[3][2],[$C[0],#16*8]
	ldp	$A[3][3],$A[3][4],[$C[0],#16*9]
	ldp	$A[4][0],$A[4][1],[$C[0],#16*10]
	ldp	$A[4][2],$A[4][3],[$C[0],#16*11]
	ldr	$A[4][4],[$C[0],#16*12]

	bl	KeccakF1600_int

	ldr	$C[0],[sp,#32]
	stp	$A[0][0],$A[0][1],[$C[0],#16*0]
	stp	$A[0][2],$A[0][3],[$C[0],#16*1]
	stp	$A[0][4],$A[1][0],[$C[0],#16*2]
	stp	$A[1][1],$A[1][2],[$C[0],#16*3]
	stp	$A[1][3],$A[1][4],[$C[0],#16*4]
	stp	$A[2][0],$A[2][1],[$C[0],#16*5]
	stp	$A[2][2],$A[2][3],[$C[0],#16*6]
	stp	$A[2][4],$A[3][0],[$C[0],#16*7]
	stp	$A[3][1],$A[3][2],[$C[0],#16*8]
	stp	$A[3][3],$A[3][4],[$C[0],#16*9]
	stp	$A[4][0],$A[4][1],[$C[0],#16*10]
	stp	$A[4][2],$A[4][3],[$C[0],#16*11]
	str	$A[4][4],[$C[0],#16*12]

	ldp	x19,x20,[x29,#16]
	add	sp,sp,#48
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x25,x26,[x29,#64]
	ldp	x27,x28,[x29,#80]
	ldp	x29,x30,[sp],#128
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600,.-KeccakF1600

.globl	SHA3_absorb
.type	SHA3_absorb,%function
.align	5
SHA3_absorb:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-128]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]
	stp	x25,x26,[sp,#64]
	stp	x27,x28,[sp,#80]
	sub	sp,sp,#64

	stp	x0,x1,[sp,#32]			// offload arguments
	stp	x2,x3,[sp,#48]

	mov	$C[0],x0			// uint64_t A[5][5]
	mov	$C[1],x1			// const void *inp
	mov	$C[2],x2			// size_t len
	mov	$C[3],x3			// size_t bsz
	ldp	$A[0][0],$A[0][1],[$C[0],#16*0]
	ldp	$A[0][2],$A[0][3],[$C[0],#16*1]
	ldp	$A[0][4],$A[1][0],[$C[0],#16*2]
	ldp	$A[1][1],$A[1][2],[$C[0],#16*3]
	ldp	$A[1][3],$A[1][4],[$C[0],#16*4]
	ldp	$A[2][0],$A[2][1],[$C[0],#16*5]
	ldp	$A[2][2],$A[2][3],[$C[0],#16*6]
	ldp	$A[2][4],$A[3][0],[$C[0],#16*7]
	ldp	$A[3][1],$A[3][2],[$C[0],#16*8]
	ldp	$A[3][3],$A[3][4],[$C[0],#16*9]
	ldp	$A[4][0],$A[4][1],[$C[0],#16*10]
	ldp	$A[4][2],$A[4][3],[$C[0],#16*11]
	ldr	$A[4][4],[$C[0],#16*12]
	b	.Loop_absorb

.align	4
.Loop_absorb:
	subs	$C[0],$C[2],$C[3]		// len - bsz
	blo	.Labsorbed

	str	$C[0],[sp,#48]			// save len - bsz
___
for (my $i=0; $i<24; $i+=2) {
my $j = $i+1;
$code.=<<___;
	ldr	$C[0],[$C[1]],#8		// *inp++
#ifdef	__AARCH64EB__
	rev	$C[0],$C[0]
#endif
	eor	$A[$i/5][$i%5],$A[$i/5][$i%5],$C[0]
	cmp	$C[3],#8*($i+2)
	blo	.Lprocess_block
	ldr	$C[0],[$C[1]],#8		// *inp++
#ifdef	__AARCH64EB__
	rev	$C[0],$C[0]
#endif
	eor	$A[$j/5][$j%5],$A[$j/5][$j%5],$C[0]
	beq	.Lprocess_block
___
}
$code.=<<___;
	ldr	$C[0],[$C[1]],#8		// *inp++
#ifdef	__AARCH64EB__
	rev	$C[0],$C[0]
#endif
	eor	$A[4][4],$A[4][4],$C[0]

.Lprocess_block:
	str	$C[1],[sp,#40]			// save inp

	bl	KeccakF1600_int

	ldr	$C[1],[sp,#40]			// restore arguments
	ldp	$C[2],$C[3],[sp,#48]
	b	.Loop_absorb

.align	4
.Labsorbed:
	ldr	$C[1],[sp,#32]
	stp	$A[0][0],$A[0][1],[$C[1],#16*0]
	stp	$A[0][2],$A[0][3],[$C[1],#16*1]
	stp	$A[0][4],$A[1][0],[$C[1],#16*2]
	stp	$A[1][1],$A[1][2],[$C[1],#16*3]
	stp	$A[1][3],$A[1][4],[$C[1],#16*4]
	stp	$A[2][0],$A[2][1],[$C[1],#16*5]
	stp	$A[2][2],$A[2][3],[$C[1],#16*6]
	stp	$A[2][4],$A[3][0],[$C[1],#16*7]
	stp	$A[3][1],$A[3][2],[$C[1],#16*8]
	stp	$A[3][3],$A[3][4],[$C[1],#16*9]
	stp	$A[4][0],$A[4][1],[$C[1],#16*10]
	stp	$A[4][2],$A[4][3],[$C[1],#16*11]
	str	$A[4][4],[$C[1],#16*12]

	mov	x0,$C[2]			// return value
	ldp	x19,x20,[x29,#16]
	add	sp,sp,#64
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x25,x26,[x29,#64]
	ldp	x27,x28,[x29,#80]
	ldp	x29,x30,[sp],#128
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_absorb,.-SHA3_absorb
___
{
my ($A_flat,$out,$len,$bsz) = map("x$_",(19..22));
$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze,%function
.align	5
SHA3_squeeze:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-48]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]

	mov	$A_flat,x0			// put aside arguments
	mov	$out,x1
	mov	$len,x2
	mov	$bsz,x3
	cmp	w4, #0				// w4 = 'next' argument
	bne	.Lnext_block

.Loop_squeeze:
	ldr	x4,[x0],#8
#ifdef	__AARCH64EB__
	rev	x4,x4
#endif
	cmp	$len,#8
	blo	.Lsqueeze_tail
	str	x4,[$out],#8
	subs	$len,$len,#8
	beq	.Lsqueeze_done

	subs	x3,x3,#8
	bhi	.Loop_squeeze
.Lnext_block:
	mov	x0,$A_flat
	bl	KeccakF1600
	mov	x0,$A_flat
	mov	x3,$bsz
	b	.Loop_squeeze

.align	4
.Lsqueeze_tail:
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1

.Lsqueeze_done:
	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x29,x30,[sp],#48
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_squeeze,.-SHA3_squeeze
___
}								}}}

								{{{
#
# A 5*5 matrix of double words
# Each double word represents data for 2 separate Streams.
# Registers q0..q24 hold the state.
# A word is 64 bits so .2d = double word
# Note that XAR and RAX1 instructions actually use .2d not .16b
# (since they operate on lanes - not 16 bytes)
# This is fixed up in the foreach(split("\n",$code)) at the end of the file.
my @A = map([ "v".$_.".16b", "v".($_+1).".16b", "v".($_+2).".16b",
                             "v".($_+3).".16b", "v".($_+4).".16b" ],
            (0, 5, 10, 15, 20));

my @C = map("v$_.16b", (25..31));
my @D = @C[4,5,6,2,3];

#
# @brief Internal KeccakF1600 function to process 2 lanes in parallel.
# @details It does not save or restore any registers.
#    As there are only 32 vector register to play with and 25 of them are used
#    for just for the state, trying to interleave the permute steps nicely is
#    tricky.
# @param q0..q24 the input/output state of double words
# @comment uses registers X9, X10, and q25..q31
# @assumptions The SHA3 features eor3, rax1, xar, bcax are available
#
# The algorithm does 24 rounds of the following steps:
# 1) Theta
#    C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
#    D[x] = C[(x-1)%5] ^ ROTL1(C[(x+1)%5])
#    A`[x][y] = A[x][y] ^ D[x]
#  EOR3 can be used twice to form C[x].
#  RAX1 is used by D[x] (rotate and XOR)
#
# 2) Rho and Pi
#    B[y][(2x + 3y)%5] = ROL(A[x][y], r[x][y])
# XAR (XOR and rotate right, to do ROL we rotate 64-x)
# 3) Chi
#    A`[x][y] = B[x][y] ^ (~B[(x+1)%5][y] AND B[(x+2)%5][y])
# BCAX ((Bitwise clear = NOT) AND XOR)
# 4) Iota
#    A`[0][0] = A[0][0] ^ IotaRoundConstant
$code.=<<___;
.type	KeccakF1600_ce,%function
.align	5
KeccakF1600_ce:
	mov	x9,#24
	adrp	x10,iotas
	add	x10,x10,:lo12:iotas
	b	.Loop_ce
.align	4
.Loop_ce:
	////////////////////////////////////////////////// Theta
	eor3	$C[0],$A[4][0],$A[3][0],$A[2][0]
	eor3	$C[1],$A[4][1],$A[3][1],$A[2][1]
	eor3	$C[2],$A[4][2],$A[3][2],$A[2][2]
	eor3	$C[3],$A[4][3],$A[3][3],$A[2][3]
	eor3	$C[4],$A[4][4],$A[3][4],$A[2][4]
	eor3	$C[0],$C[0],   $A[1][0],$A[0][0]
	eor3	$C[1],$C[1],   $A[1][1],$A[0][1]
	eor3	$C[2],$C[2],   $A[1][2],$A[0][2]
	eor3	$C[3],$C[3],   $A[1][3],$A[0][3]
	eor3	$C[4],$C[4],   $A[1][4],$A[0][4]

	rax1	$C[5],$C[0],$C[2]			// D[1]
	rax1	$C[6],$C[1],$C[3]			// D[2]
	rax1	$C[2],$C[2],$C[4]			// D[3]
	rax1	$C[3],$C[3],$C[0]			// D[4]
	rax1	$C[4],$C[4],$C[1]			// D[0]

	////////////////////////////////////////////////// Theta+Rho+Pi
	xar	$C[0],   $A[0][1],$D[1],#64-$rhotates[0][1] // C[0]=A[2][0]

	xar	$A[0][1],$A[1][1],$D[1],#64-$rhotates[1][1]
	xar	$A[1][1],$A[1][4],$D[4],#64-$rhotates[1][4]
	xar	$A[1][4],$A[4][2],$D[2],#64-$rhotates[4][2]
	xar	$A[4][2],$A[2][4],$D[4],#64-$rhotates[2][4]
	xar	$A[2][4],$A[4][0],$D[0],#64-$rhotates[4][0]

	xar	$C[1],   $A[0][2],$D[2],#64-$rhotates[0][2] // C[1]=A[4][0]

	xar	$A[0][2],$A[2][2],$D[2],#64-$rhotates[2][2]
	xar	$A[2][2],$A[2][3],$D[3],#64-$rhotates[2][3]
	xar	$A[2][3],$A[3][4],$D[4],#64-$rhotates[3][4]
	xar	$A[3][4],$A[4][3],$D[3],#64-$rhotates[4][3]
	xar	$A[4][3],$A[3][0],$D[0],#64-$rhotates[3][0]

	xar	$A[3][0],$A[0][4],$D[4],#64-$rhotates[0][4]

	xar	$D[4],   $A[4][4],$D[4],#64-$rhotates[4][4] // D[4]=A[0][4]
	xar	$A[4][4],$A[4][1],$D[1],#64-$rhotates[4][1]
	xar	$A[1][3],$A[1][3],$D[3],#64-$rhotates[1][3] // A[1][3]=A[4][1]
	xar	$A[0][4],$A[3][1],$D[1],#64-$rhotates[3][1] // A[0][4]=A[1][3]
	xar	$A[3][1],$A[1][0],$D[0],#64-$rhotates[1][0]

	xar	$A[1][0],$A[0][3],$D[3],#64-$rhotates[0][3]

	eor	$A[0][0],$A[0][0],$D[0]

	xar	$D[3],   $A[3][3],$D[3],#64-$rhotates[3][3] // D[3]=A[0][3]
	xar	$A[0][3],$A[3][2],$D[2],#64-$rhotates[3][2] // A[0][3]=A[3][3]
	xar	$D[1],   $A[2][1],$D[1],#64-$rhotates[2][1] // D[1]=A[3][2]
	xar	$D[2],   $A[1][2],$D[2],#64-$rhotates[1][2] // D[2]=A[2][1]
	xar	$D[0],   $A[2][0],$D[0],#64-$rhotates[2][0] // D[0]=A[1][2]

	////////////////////////////////////////////////// Chi+Iota
	bcax	$A[4][0],$C[1],   $A[4][2],$A[1][3]	// A[1][3]=A[4][1]
	bcax	$A[4][1],$A[1][3],$A[4][3],$A[4][2]	// A[1][3]=A[4][1]
	bcax	$A[4][2],$A[4][2],$A[4][4],$A[4][3]
	bcax	$A[4][3],$A[4][3],$C[1],   $A[4][4]
	bcax	$A[4][4],$A[4][4],$A[1][3],$C[1]	// A[1][3]=A[4][1]

	ld1r	{$C[1]},[x10],#8

	bcax	$A[3][2],$D[1],   $A[3][4],$A[0][3]	// A[0][3]=A[3][3]
	bcax	$A[3][3],$A[0][3],$A[3][0],$A[3][4]	// A[0][3]=A[3][3]
	bcax	$A[3][4],$A[3][4],$A[3][1],$A[3][0]
	bcax	$A[3][0],$A[3][0],$D[1],   $A[3][1]
	bcax	$A[3][1],$A[3][1],$A[0][3],$D[1]	// A[0][3]=A[3][3]

	bcax	$A[2][0],$C[0],   $A[2][2],$D[2]
	bcax	$A[2][1],$D[2],   $A[2][3],$A[2][2]
	bcax	$A[2][2],$A[2][2],$A[2][4],$A[2][3]
	bcax	$A[2][3],$A[2][3],$C[0],   $A[2][4]
	bcax	$A[2][4],$A[2][4],$D[2],   $C[0]

	bcax	$A[1][2],$D[0],   $A[1][4],$A[0][4]	// A[0][4]=A[1][3]
	bcax	$A[1][3],$A[0][4],$A[1][0],$A[1][4]	// A[0][4]=A[1][3]
	bcax	$A[1][4],$A[1][4],$A[1][1],$A[1][0]
	bcax	$A[1][0],$A[1][0],$D[0],   $A[1][1]
	bcax	$A[1][1],$A[1][1],$A[0][4],$D[0]	// A[0][4]=A[1][3]

	bcax	$A[0][3],$D[3],   $A[0][0],$D[4]
	bcax	$A[0][4],$D[4],   $A[0][1],$A[0][0]
	bcax	$A[0][0],$A[0][0],$A[0][2],$A[0][1]
	bcax	$A[0][1],$A[0][1],$D[3],   $A[0][2]
	bcax	$A[0][2],$A[0][2],$D[4],   $D[3]

	eor	$A[0][0],$A[0][0],$C[1]

	subs	x9,x9,#1
	bne	.Loop_ce

	ret
.size	KeccakF1600_ce,.-KeccakF1600_ce

.type	KeccakF1600_cext,%function
.align	5
KeccakF1600_cext:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0
	stp	d8,d9,[sp,#16]		// per ABI requirement
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]
___
for($i=0; $i<24; $i+=2) {		# load A[5][5]
my $j=$i+1;
$code.=<<___;
	ldp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	ldr	d24,[x0,#8*$i]
	bl	KeccakF1600_ce
	ldr	x30,[sp,#8]
___
for($i=0; $i<24; $i+=2) {		# store A[5][5]
my $j=$i+1;
$code.=<<___;
	stp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	str	d24,[x0,#8*$i]

	ldp	d8,d9,[sp,#16]
	ldp	d10,d11,[sp,#32]
	ldp	d12,d13,[sp,#48]
	ldp	d14,d15,[sp,#64]
	ldr	x29,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600_cext,.-KeccakF1600_cext
___

{
my ($ctx,$inp,$len,$bsz) = map("x$_",(0..3));
$code.=<<___;
.globl	SHA3_absorb_cext
.type	SHA3_absorb_cext,%function
.align	5
SHA3_absorb_cext:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0
	stp	d8,d9,[sp,#16]		// per ABI requirement
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]
___
for($i=0; $i<24; $i+=2) {		# load A[5][5]
my $j=$i+1;
$code.=<<___;
	ldp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	ldr	d24,[x0,#8*$i]
	b	.Loop_absorb_ce

.align	4
.Loop_absorb_ce:
	subs	$len,$len,$bsz		// len - bsz
	blo	.Labsorbed_ce
___
for (my $i=0; $i<24; $i+=2) {
my $j = $i+1;
$code.=<<___;
	ldr	d31,[$inp],#8		// *inp++
#ifdef	__AARCH64EB__
	rev64	v31.16b,v31.16b
#endif
	eor	$A[$i/5][$i%5],$A[$i/5][$i%5],v31.16b
	cmp	$bsz,#8*($i+2)
	blo	.Lprocess_block_ce
	ldr	d31,[$inp],#8		// *inp++
#ifdef	__AARCH64EB__
	rev64	v31.16b,v31.16b
#endif
	eor	$A[$j/5][$j%5],$A[$j/5][$j%5],v31.16b
	beq	.Lprocess_block_ce
___
}
$code.=<<___;
	ldr	d31,[$inp],#8		// *inp++
#ifdef	__AARCH64EB__
	rev64	v31.16b,v31.16b
#endif
	eor	$A[4][4],$A[4][4],v31.16b

.Lprocess_block_ce:
	bl	KeccakF1600_ce
	b	.Loop_absorb_ce
.align	4
.Labsorbed_ce:
___
for($i=0; $i<24; $i+=2) {		# store A[5][5]
my $j=$i+1;
$code.=<<___;
	stp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	str	d24,[x0,#8*$i]
	add	x0,$len,$bsz		// return value

	ldp	d8,d9,[sp,#16]
	ldp	d10,d11,[sp,#32]
	ldp	d12,d13,[sp,#48]
	ldp	d14,d15,[sp,#64]
	ldp	x29,x30,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_absorb_cext,.-SHA3_absorb_cext
___
}
{
my ($ctx,$out,$len,$bsz) = map("x$_",(0..3));
$code.=<<___;
.globl	SHA3_squeeze_cext
.type	SHA3_squeeze_cext,%function
.align	5
SHA3_squeeze_cext:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0
	mov	x9,$ctx
	mov	x10,$bsz

.Loop_squeeze_ce:
	ldr	x4,[x9],#8
#ifdef	__AARCH64EB__
	rev	x4,x4
#endif
	cmp	$len,#8
	blo	.Lsqueeze_tail_ce
	str	x4,[$out],#8
	beq	.Lsqueeze_done_ce

	sub	$len,$len,#8
	subs	x10,x10,#8
	bhi	.Loop_squeeze_ce

	bl	KeccakF1600_cext
	ldr	x30,[sp,#8]
	mov	x9,$ctx
	mov	x10,$bsz
	b	.Loop_squeeze_ce

.align	4
.Lsqueeze_tail_ce:
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1

.Lsqueeze_done_ce:
	ldr	x29,[sp],#16
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_squeeze_cext,.-SHA3_squeeze_cext
___
}								}}}

{{{
my $shake128_rate = 168; # 21 words
my $shake256_rate = 136; # 17 words

# @brief Call this at the start of a function, it saves the Frame Pointer,
#        Return Address (LR), and the vector registers q8..q15
#        Although the requirement is only to save the low part v8..v15,
#        we need to save the hi part also, so that we can zeroize nicely
#        when we are finished.
# @param $name name of function, function_end() should have a matching name
# @param $is_global set to 1 to indicate this function can be called externally.
sub function_start {
    my ($name, $is_global) = @_;
    if ($is_global == 1) {
$code.=<<___;
.globl  $name
___
    }
$code.=<<___;
.type   $name,%function
.align  5
$name:
    AARCH64_SIGN_LINK_REGISTER
    stp x29,x30,[sp,#-144]!
    add x29,sp,#0
    stp q8,q9,[sp,#16]      // per ABI requirement
    stp q10,q11,[sp,#48]
    stp q12,q13,[sp,#80]
    stp q14,q15,[sp,#112]
___
}

# @brief Call this at the end of a function, it restores the Frame Pointer,
#        Return Address (LR), and the vector registers q8..q15
#        The q8..15 registers are also cleared from the stack.
#        We restore q8..15 instead of v8..v15 because we need to clean up
#.       q vectors when the squeeze has finished.
# @param $name name of function, function_start() should have a matching name
sub function_end {
    my ($name) = @_;
$code.=<<___;
    eor v0.16b, v0.16b, v0.16b
    ldp q8,q9,[sp,#16]
    ldp q10,q11,[sp,#48]
    ldp q12,q13,[sp,#80]
    ldp q14,q15,[sp,#112]
    stp q0, q0, [sp, #16]
    stp q0, q0, [sp, #48]
    stp q0, q0, [sp, #80]
    stp q0, q0, [sp, #112]
    ldp x29, x30, [sp], #144
    AARCH64_VALIDATE_LINK_REGISTER
    ret
.size   $name,.-$name
___
}

## @brief Copy aligned input to 4 vector registers representing the double word state
##        You only can move directly into the state on the first absorb call. Subsequent
##        absorbs require XORing into the state.
## @param $inp Input buffer containing 2 lane Double Words. It Must be aligned to a 16 byte boundary.
##             It is post incremented by 64 (4 double words)
## @param $i The state double word index (Normally a multiple of 4).. Maps to q$i
## @param $j The state double word index (Normally a (multiple of 4) + 1)
## @param $k The state double word index (Normally a (multiple of 4) + 2)
## @param $l The state double word index (Normally a (multiple of 4) + 3)
sub copy_4x2_input_align16_to_qvectors {
    my ($inp, $i, $j, $k, $l) = @_;
$code.=<<___;
    ldp q$i,q$j,[$inp],#32
    ldp q$k,q$l,[$inp],#32
___
}

## @brief Copy aligned input to 1 vector register representing the double word state
## @param $inp Input buffer (Must be aligned to 16 byte boundary)
##             It is not post incremented
## @param $i The state double word index. Maps to q$i
sub copy_1x2_input_align16_to_qvectors {
    my ($inp, $i) = @_;
$code.=<<___;
    ldr q$i,[$inp]
___
}

## @brief Copy aligned input to 21 vector register representing the double word state
##        and clear the remaining 4 vector registers.
## @param $inp Input buffer (Must be aligned to 16 byte boundary),
##             It is not post incremented
sub shake128_2x_copy_input_block_to_qvectors {
    my ($inp) = @_;
    copy_4x2_input_align16_to_qvectors($inp,0,1,2,3);
    copy_4x2_input_align16_to_qvectors($inp,4,5,6,7);
    copy_4x2_input_align16_to_qvectors($inp,8,9,10,11);
    copy_4x2_input_align16_to_qvectors($inp,12,13,14,15);
    copy_4x2_input_align16_to_qvectors($inp,16,17,18,19);
    copy_1x2_input_align16_to_qvectors($inp,20);
    zero_4_qvectors(21,22,23,24);
}
## @brief Copy aligned input to 17 vector register representing the double word state
##        and clear the remaining 8 vector registers.
## @param $inp Input buffer (Must be aligned to 16 byte boundary)
##             It is not post incremented
sub shake256_2x_copy_input_block_to_qvectors {
    my ($inp) = @_;
    copy_4x2_input_align16_to_qvectors($inp,0,1,2,3);
    copy_4x2_input_align16_to_qvectors($inp,4,5,6,7);
    copy_4x2_input_align16_to_qvectors($inp,8,9,10,11);
    copy_4x2_input_align16_to_qvectors($inp,12,13,14,15);
    copy_1x2_input_align16_to_qvectors($inp,16);
    zero_4_qvectors(17,18,19,20);
    zero_4_qvectors(21,22,23,24);
}

## @brief Copy $state into 25 double words in q0..q24.
## @param $state A 5*5 state of double words (Must be aligned to 16 byte boundary).
##               It is not post incremented.
sub load_qvectors_from_aligned16_state {
    my ($state) = @_;
    for($i=0; $i<24; $i+=2) {
        my $j=$i+1;
        my $offs=16*$i;
$code.=<<___;
    ldp q$i,q$j,[$state,#$offs]
___
    }
    my $offs=16*$i;
$code.=<<___;
    ldr q$i,[$state,#$offs]
___
}

## @brief Save 4 Double word q vectors to $state
## @param $state Output 5x5 double word state array (aligned to 16 byte boundary).
##               It is not post incremented.
## @param $i Saves to 4 vectors starting at q$i
sub save_4_qvectors_to_aligned16_state {
    my ($state, $i) = @_;
    my $j = $i+1;
    my $k = $i+2;
    my $l = $i+3;
$code.=<<___;
    stp q$i,q$j,[$state,#16*$i]
    stp q$k,q$l,[$state,#16*($i+2)]
___
}

## @brief Save All 25 Double word q vectors to $state
## @param $state A 5 by 5 double word state array (aligned to 16 byte boundary).
##               It is not post incremented.
## @param $i Saves to 4 vectors starting at q$i
sub save_qvectors_to_aligned16_state {
    my ($state) = @_;
    for ($i=0; $i<24; $i+=4) {
        save_4_qvectors_to_aligned16_state($state,$i);
    }
$code.=<<___;
    str q$i,[$state,#16*$i]
___
}

## @brief Set 4 double words in q$i, q$j, q$k, q$l to zero.
##        This is used to zero the state 'capacity' data after the rate words.
sub zero_4_qvectors {
    my ($i, $j, $k, $l) = @_;
$code.=<<___;
    eor v$i.16b,v$i.16b,v$i.16b
    eor v$j.16b,v$j.16b,v$j.16b
    eor v$k.16b,v$k.16b,v$k.16b
    eor v$l.16b,v$l.16b,v$l.16b
___
}

## @brief Move 4 double words from q$i..q($i+3) to 2 output buffers.
##        Each double word copies the first lane to $out1 and the second lane to $out2
## @param out1 An output buffer for lane1 that can hold 4 words,
##        It is post incremented by 4 words. It must be 8 byte aligned.
## @param out2 An Output buffer for lane2 that can hold 4 words.
##        It is post incremented by 4 words. It must be 8 byte aligned.
sub copy_4x2_qvectors_to_out2 {
    my ($out1, $out2, $i) = @_;
    my $j = $i+1;
    my $k = $i+2;
    my $l = $i+3;
$code.=<<___;
    st1 {v$i.d}[0], [$out1], #8
    st1 {v$i.d}[1], [$out2], #8
    st1 {v$j.d}[0], [$out1], #8
    st1 {v$j.d}[1], [$out2], #8
    st1 {v$k.d}[0], [$out1], #8
    st1 {v$k.d}[1], [$out2], #8
    st1 {v$l.d}[0], [$out1], #8
    st1 {v$l.d}[1], [$out2], #8
___
}
## @brief Move 1 double word from q$i to 2 output buffers.
##        Each double word copies the first lane to $out1 and the second lane to $out2
## @param out1 An output buffer for lane0 that can hold 1 word,
##             It is post incremented by 1 word. It must be 8 byte aligned.
## @param out2 An Output buffer for lane1 that can hold 1 word,
##             It is post incremented by 1 word. It must be 8 byte aligned.
sub copy_1x2_qvectors_to_out2 {
    my ($out1, $out2, $i) = @_;
$code.=<<___;
    st1 {v$i.d}[0], [$out1], #8
    st1 {v$i.d}[1], [$out2], #8
___
}

## @brief Copy 21 double words from q0..q20 to 2 output streams
## @param out1 is post incremented by 21 words
## @param out2 is post incremented by 21 words
sub shake128_2x_copy_qvectors_to_out_block{
    my ($out1, $out2) = @_;
    for($i=0; $i<20; $i+=4) {
        copy_4x2_qvectors_to_out2($out1, $out2, $i);
    }
    copy_1x2_qvectors_to_out2($out1, $out2, 20);
}

## @brief Copy 17 double words from q0..q16 to 2 output streams
## @param out1 is post incremented by 17 words
## @param out2 is post incremented by 17 words
sub shake256_2x_copy_qvectors_to_out_block{
    my ($out1, $out2) = @_;
    for($i=0; $i<16; $i+=4) {
        copy_4x2_qvectors_to_out2($out1, $out2, $i);
    }
    copy_1x2_qvectors_to_out2($out1, $out2, 16);
}

{
# These functions are intended for a one shot absorb and squeeze of a single block

## @param $inp 16 byte aligned interleaved message (21 double words)
## @param $state_out Output state of 5x5 double words.
## @param $out1 Output Stream1 of 168 bytes (Must be Aligned to an 8 byte boundary)
## @param $out2 Output Stream2 of 168 bytes (Must be Aligned to an 8 byte boundary)
my ($state_out,$inp,$out1,$out2) = map("x$_",(0..3));
function_start('ossl_shake128_2x_oneshot_singleblock_absorb_interleaved_squeeze', 1);
    shake128_2x_copy_input_block_to_qvectors($inp);
$code.=<<___;
    bl  KeccakF1600_ce
___
    shake128_2x_copy_qvectors_to_out_block($out1, $out2);
    save_qvectors_to_aligned16_state($state_out);
function_end('ossl_shake128_2x_oneshot_singleblock_absorb_interleaved_squeeze');

## @param $inp 16 byte aligned interleaved message (17 double words)
## @param $state_out Output state of 5x5 double words.
## @param $out1 Output Stream1 of 136 bytes (Must be Aligned to an 8 byte boundary)
## @param $out2 Output Stream2 of 136 bytes (Must be Aligned to an 8 byte boundary)
my ($state_out,$inp,$out1,$out2) = map("x$_",(0..3));
function_start('ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze', 1);
    shake256_2x_copy_input_block_to_qvectors($inp);
$code.=<<___;
    bl  KeccakF1600_ce
___
    shake256_2x_copy_qvectors_to_out_block($out1, $out2);
    save_qvectors_to_aligned16_state($state_out);
function_end('ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze');

# These functions are intended for multiple squeeze(s) of a single block
# May be called multiple times after ossl_shake???_2x_oneshot_singleblock_absorb_interleaved_squeeze

## @brief A 2 way SHAKE128 squeeze of a single block
## @param $state The Input/Output state of 5x5 double words
## @param $out1 Output Stream1 of 168 bytes (Must be Aligned to an 8 byte boundary)
## @param $out2 Output Stream2 of 168 bytes (Must be Aligned to an 8 byte boundary)
my ($state,$out1,$out2) = map("x$_",(0..2));
function_start('ossl_shake128_2x_squeeze_singleblock', 1);
    load_qvectors_from_aligned16_state($state);
$code.=<<___;
    bl  KeccakF1600_ce
___
    shake128_2x_copy_qvectors_to_out_block($out1, $out2);
    save_qvectors_to_aligned16_state($state);
function_end('ossl_shake128_2x_squeeze_singleblock');

## @brief A 2 way SHAKE256 squeeze of a single block
## @param $state The Input/Output state of 5x5 double words
## @param $out1 Output Stream1 of 136 bytes (Must be Aligned to an 8 byte boundary)
## @param $out2 Output Stream2 of 136 bytes (Must be Aligned to an 8 byte boundary)
my ($state,$out1,$out2) = map("x$_",(0..2));
function_start('ossl_shake256_2x_squeeze_singleblock', 1);
    load_qvectors_from_aligned16_state($state);
$code.=<<___;
    bl  KeccakF1600_ce
___
    shake256_2x_copy_qvectors_to_out_block($out1, $out2);
    save_qvectors_to_aligned16_state($state);
function_end('ossl_shake256_2x_squeeze_singleblock');

## @brief A 2 way SHAKE256 one shot function that does not use external state.
##        it absorbs a single block, and assumes that 1 or more blocks will be squeezed at once
## @param $inp 16 byte aligned interleaved message (17 double words)
## @param $out1 Output Stream1 of outlen bytes (Must be Aligned to an 8 byte boundary)
## @param $out2 Output Stream2 of outlen bytes (Must be Aligned to an 8 byte boundary)
## @param $outlen Must be a non zero multiple of the rate (136)
my ($inp,$out1,$out2,$outlen) = map("x$_",(0..4));
function_start('ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze', 1);
    shake256_2x_copy_input_block_to_qvectors($inp);
$code.=<<___;
.Loop_shake256_2x_squeeze:
    bl  KeccakF1600_ce
    subs $outlen,$outlen,#$shake256_rate
___
    shake256_2x_copy_qvectors_to_out_block($out1, $out2);
$code.=<<___;
    b.ne .Loop_shake256_2x_squeeze
___
function_end('ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze');
}                               }}}

$code.=<<___;
## @brief To be called on completion if the values stored in the state are secret.
##        This clears the temporary vectors q0..q7, q16..q31. It does not clear q8..q15 as they
##        are saved and restored on each call.
.globl SHA3_secure_vector_clear_armv8
.type   SHA3_secure_vector_clear_armv8,%function
.align  5
SHA3_secure_vector_clear_armv8:
___
    zero_4_qvectors(0,1,2,3);
    zero_4_qvectors(4,5,6,7);

    zero_4_qvectors(16,17,18,19);
    zero_4_qvectors(20,21,22,23);

    zero_4_qvectors(24,25,26,27);
    zero_4_qvectors(28,29,30,31);
$code.=<<___;
    ret
.size  SHA3_secure_vector_clear_armv8,.-SHA3_secure_vector_clear_armv8
___

$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by <https://github.com/dot-asm>"
___

{   my  %opcode = (
	"rax1"	=> 0xce608c00,	"eor3"	=> 0xce000000,
	"bcax"	=> 0xce200000,	"xar"	=> 0xce800000	);

    sub unsha3 {
	my ($mnemonic,$arg)=@_;

	$arg =~ m/[qv]([0-9]+)[^,]*,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv#]([0-9\-]+))?)?/
	&&
	sprintf ".inst\t0x%08x\t//%s %s",
			$opcode{$mnemonic}|$1|($2<<5)|($3<<16)|(eval($4)<<10),
			$mnemonic,$arg;
    }
}

foreach(split("\n",$code)) {

	s/\`([^\`]*)\`/eval($1)/ge;
	m/\bld1r\b/ and s/\.16b/.2d/g	or
	s/\b(eor3|rax1|xar|bcax)\s+(v.*)/unsha3($1,$2)/ge;

	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
