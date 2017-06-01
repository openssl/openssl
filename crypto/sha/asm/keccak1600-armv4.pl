#!/usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# Keccak-1600 for ARMv4.
#
# June 2017.
#
# This is KECCAK_1X variant (see keccak1600.c) with bit interleaving.
# How does it compare to Keccak Code Package? It's as fast, but several
# times smaller, and is endian- and ISA-neutral. ISA neutrality means
# that minimum ISA requirement is ARMv4, yet it can be assembled even
# as ARMv7 Thumb-2.
#
########################################################################
# Numbers are cycles per processed byte accounting even for input bit
# interleaving.
#
#		r=1600(*)	r=1024
#
# Cortex-A7	71/+180%	103
# Cortex-A8	48/+290%	69
# Cortex-A15	34/+210%	49
#
# (*)	Not used in real life, meaningful as estimate for single sponge
#	operation performance. Numbers after slash are improvement over
#	compiler-generated KECCAK_1X reference code.

my @C = map("r$_",(0..9));
my @E = map("r$_",(10..12,14));

########################################################################
# Stack layout
# ----->+-----------------------+
#       | uint64_t A[5][5]      |
#       | ...                   |
# +200->+-----------------------+
#       | uint64_t D[5]         |
#       | ...                   |
# +240->+-----------------------+
#       | uint64_t T[2][5]      |
#       | ...                   |
# +320->+-----------------------+
#       | saved lr              |
# +324->+-----------------------+
#       | loop counter          |
# +328->+-----------------------+
#       | ...

my @A = map([ 8*$_, 8*($_+1), 8*($_+2), 8*($_+3), 8*($_+4) ], (0,5,10,15,20));
my @D = map(8*$_, (25..29));
my @T = map([ 8*$_, 8*($_+1), 8*($_+2), 8*($_+3), 8*($_+4) ], (30,35));

$code.=<<___;
.text

#if defined(__thumb2__)
.syntax	unified
.thumb
#else
.code	32
#endif

.type	iotas,%object
.align	5
iotas:
	.long	0x00000001, 0x00000000
	.long	0x00000000, 0x00000089
	.long	0x00000000, 0x8000008b
	.long	0x00000000, 0x80008080
	.long	0x00000001, 0x0000008b
	.long	0x00000001, 0x00008000
	.long	0x00000001, 0x80008088
	.long	0x00000001, 0x80000082
	.long	0x00000000, 0x0000000b
	.long	0x00000000, 0x0000000a
	.long	0x00000001, 0x00008082
	.long	0x00000000, 0x00008003
	.long	0x00000001, 0x0000808b
	.long	0x00000001, 0x8000000b
	.long	0x00000001, 0x8000008a
	.long	0x00000001, 0x80000081
	.long	0x00000000, 0x80000081
	.long	0x00000000, 0x80000008
	.long	0x00000000, 0x00000083
	.long	0x00000000, 0x80008003
	.long	0x00000001, 0x80008088
	.long	0x00000000, 0x80000088
	.long	0x00000001, 0x00008000
	.long	0x00000000, 0x80008082
.size	iotas,.-iotas

.type	KeccakF1600_int, %function
.align	5
KeccakF1600_int:
	ldmia	sp,{@C[0]-@C[9]}		@ A[0][0..4]
	add	@E[0],sp,#$A[1][0]
KeccakF1600_enter:
	str	lr,[sp,#320]
	eor	@E[1],@E[1],@E[1]
	str	@E[1],[sp,#324]
	b	.Lround_enter

.align	4
.Lround:
	ldmia	sp,{@C[0]-@C[9]}		@ A[0][0..4]
.Lround_enter:
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[1][0..1]
	eor	@C[0],@C[0],@E[0]
	 add	@E[0],sp,#$A[1][2]
	eor	@C[1],@C[1],@E[1]
	eor	@C[2],@C[2],@E[2]
	eor	@C[3],@C[3],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[1][2..3]
	eor	@C[4],@C[4],@E[0]
	 add	@E[0],sp,#$A[1][4]
	eor	@C[5],@C[5],@E[1]
	eor	@C[6],@C[6],@E[2]
	eor	@C[7],@C[7],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[1][4]..A[2][0]
	eor	@C[8],@C[8],@E[0]
	 add	@E[0],sp,#$A[2][1]
	eor	@C[9],@C[9],@E[1]
	eor	@C[0],@C[0],@E[2]
	eor	@C[1],@C[1],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[2][1..2]
	eor	@C[2],@C[2],@E[0]
	 add	@E[0],sp,#$A[2][3]
	eor	@C[3],@C[3],@E[1]
	eor	@C[4],@C[4],@E[2]
	eor	@C[5],@C[5],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[2][3..4]
	eor	@C[6],@C[6],@E[0]
	 add	@E[0],sp,#$A[3][0]
	eor	@C[7],@C[7],@E[1]
	eor	@C[8],@C[8],@E[2]
	eor	@C[9],@C[9],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[3][0..1]
	eor	@C[0],@C[0],@E[0]
	 add	@E[0],sp,#$A[3][2]
	eor	@C[1],@C[1],@E[1]
	eor	@C[2],@C[2],@E[2]
	eor	@C[3],@C[3],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[3][2..3]
	eor	@C[4],@C[4],@E[0]
	 add	@E[0],sp,#$A[3][4]
	eor	@C[5],@C[5],@E[1]
	eor	@C[6],@C[6],@E[2]
	eor	@C[7],@C[7],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[3][4]..A[4][0]
	eor	@C[8],@C[8],@E[0]
	 add	@E[0],sp,#$A[4][1]
	eor	@C[9],@C[9],@E[1]
	eor	@C[0],@C[0],@E[2]
	eor	@C[1],@C[1],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[4][1..2]
	eor	@C[2],@C[2],@E[0]
	 add	@E[0],sp,#$A[4][3]
	eor	@C[3],@C[3],@E[1]
	eor	@C[4],@C[4],@E[2]
	eor	@C[5],@C[5],@E[3]
	ldmia	@E[0],{@E[0]-@E[2],@E[3]}	@ A[4][3..4]
	eor	@C[6],@C[6],@E[0]
	eor	@C[7],@C[7],@E[1]
	eor	@C[8],@C[8],@E[2]
	eor	@C[9],@C[9],@E[3]

	eor	@E[0],@C[0],@C[5],ror#32-1	@ E[0] = ROL64(C[2], 1) ^ C[0];
	eor	@E[1],@C[1],@C[4]
	str	@E[0],[sp,#$D[1]]		@ D[1] = E[0]
	eor	@E[2],@C[6],@C[1],ror#32-1	@ E[1] = ROL64(C[0], 1) ^ C[3];
	str	@E[1],[sp,#$D[1]+4]
	eor	@E[3],@C[7],@C[0]
	str	@E[2],[sp,#$D[4]]		@ D[4] = E[1]
	eor	@C[0],@C[8],@C[3],ror#32-1	@ C[0] = ROL64(C[1], 1) ^ C[4];
	str	@E[3],[sp,#$D[4]+4]
	eor	@C[1],@C[9],@C[2]
	str	@C[0],[sp,#$D[0]]		@ D[0] = C[0]
	eor	@C[2],@C[2],@C[7],ror#32-1	@ C[1] = ROL64(C[3], 1) ^ C[1];
	str	@C[1],[sp,#$D[0]+4]
	eor	@C[3],@C[3],@C[6]
	str	@C[2],[sp,#$D[2]]		@ D[2] = C[1]
	eor	@C[4],@C[4],@C[9],ror#32-1	@ C[2] = ROL64(C[4], 1) ^ C[2];
	str	@C[3],[sp,#$D[2]+4]
	eor	@C[5],@C[5],@C[8]
	 ldr	@C[8],[sp,#$A[3][0]]
	 ldr	@C[9],[sp,#$A[3][0]+4]
	str	@C[4],[sp,#$D[3]]		@ D[3] = C[2]
	str	@C[5],[sp,#$D[3]+4]

	ldr	@C[6],[sp,#$A[0][1]]
	eor	@C[8],@C[8],@C[0]
	ldr	@C[7],[sp,#$A[0][1]+4]
	eor	@C[9],@C[9],@C[1]
	str	@C[8],[sp,#$T[0][0]]		@ T[0][0] = A[3][0] ^ C[0]; /* borrow T[0][0] */
	ldr	@C[8],[sp,#$A[0][2]]
	str	@C[9],[sp,#$T[0][0]+4]
	ldr	@C[9],[sp,#$A[0][2]+4]
	eor	@C[6],@C[6],@E[0]
	eor	@C[7],@C[7],@E[1]
	str	@C[6],[sp,#$T[0][1]]		@ T[0][1] = A[0][1] ^ E[0]; /* D[1] */
	ldr	@C[6],[sp,#$A[0][3]]
	str	@C[7],[sp,#$T[0][1]+4]
	ldr	@C[7],[sp,#$A[0][3]+4]
	eor	@C[8],@C[8],@C[2]
	eor	@C[9],@C[9],@C[3]
	str	@C[8],[sp,#$T[0][2]]		@ T[0][2] = A[0][2] ^ C[1]; /* D[2] */
	ldr	@C[8],[sp,#$A[0][4]]
	str	@C[9],[sp,#$T[0][2]+4]
	ldr	@C[9],[sp,#$A[0][4]+4]
	eor	@C[6],@C[6],@C[4]
	eor	@C[7],@C[7],@C[5]
	str	@C[6],[sp,#$T[0][3]]		@ T[0][3] = A[0][3] ^ C[2]; /* D[3] */
	eor	@C[8],@C[8],@E[2]
	str	@C[7],[sp,#$T[0][3]+4]
	eor	@C[9],@C[9],@E[3]
	 ldr	@C[6],[sp,#$A[3][3]]
	 ldr	@C[7],[sp,#$A[3][3]+4]
	str	@C[8],[sp,#$T[0][4]]		@ T[0][4] = A[0][4] ^ E[1]; /* D[4] */
	str	@C[9],[sp,#$T[0][4]+4]

	ldr	@C[8],[sp,#$A[4][4]]
	eor	@C[4],@C[4],@C[6]
	ldr	@C[9],[sp,#$A[4][4]+4]
	eor	@C[5],@C[5],@C[7]
	ror	@C[7],@C[4],#32-10		@ C[3] = ROL64(A[3][3] ^ C[2], rhotates[3][3]);   /* D[3] */
	ldr	@C[4],[sp,#$A[0][0]]
	ror	@C[6],@C[5],#32-11
	ldr	@C[5],[sp,#$A[0][0]+4]
	eor	@C[8],@C[8],@E[2]
	eor	@C[9],@C[9],@E[3]
	ror	@C[8],@C[8],#32-7		@ C[4] = ROL64(A[4][4] ^ E[1], rhotates[4][4]);   /* D[4] */
	ldr	@E[2],[sp,#$A[2][2]]
	ror	@C[9],@C[9],#32-7
	ldr	@E[3],[sp,#$A[2][2]+4]
	eor	@C[0],@C[0],@C[4]
	eor	@C[1],@C[1],@C[5]		@ C[0] =       A[0][0] ^ C[0]; /* rotate by 0 */  /* D[0] */
	eor	@E[2],@E[2],@C[2]
	ldr	@C[2],[sp,#$A[1][1]]
	eor	@E[3],@E[3],@C[3]
	ldr	@C[3],[sp,#$A[1][1]+4]
	ror	@C[5],@E[2],#32-21		@ C[2] = ROL64(A[2][2] ^ C[1], rhotates[2][2]);   /* D[2] */
	 ldr	@E[2],[sp,#324]			@ load counter
	eor	@C[2],@C[2],@E[0]
	ror	@C[4],@E[3],#32-22
	 adr	@E[3],iotas
	eor	@C[3],@C[3],@E[1]
	ror	@C[2],@C[2],#32-22		@ C[1] = ROL64(A[1][1] ^ E[0], rhotates[1][1]);   /* D[1] */
	 add	@E[3],@E[3],@E[2]
	ror	@C[3],@C[3],#32-22

	ldr	@E[0],[@E[3],#0]		@ iotas[i].lo
	add	@E[2],@E[2],#8
	ldr	@E[1],[@E[3],#4]		@ iotas[i].hi
	cmp	@E[2],#192
	str	@E[2],[sp,#324]			@ store counter

	bic	@E[2],@C[4],@C[2]
	bic	@E[3],@C[5],@C[3]
	eor	@E[2],@E[2],@C[0]
	eor	@E[3],@E[3],@C[1]
	eor	@E[0],@E[0],@E[2]
	eor	@E[1],@E[1],@E[3]
	str	@E[0],[sp,#$A[0][0]]		@ A[0][0] = C[0] ^ (~C[1] & C[2]) ^ iotas[i];
	bic	@E[2],@C[6],@C[4]
	str	@E[1],[sp,#$A[0][0]+4]
	bic	@E[3],@C[7],@C[5]
	eor	@E[2],@E[2],@C[2]
	eor	@E[3],@E[3],@C[3]
	str	@E[2],[sp,#$A[0][1]]		@ A[0][1] = C[1] ^ (~C[2] & C[3]);
	bic	@E[0],@C[8],@C[6]
	str	@E[3],[sp,#$A[0][1]+4]
	bic	@E[1],@C[9],@C[7]
	eor	@E[0],@E[0],@C[4]
	eor	@E[1],@E[1],@C[5]
	str	@E[0],[sp,#$A[0][2]]		@ A[0][2] = C[2] ^ (~C[3] & C[4]);
	bic	@E[2],@C[0],@C[8]
	str	@E[1],[sp,#$A[0][2]+4]
	bic	@E[3],@C[1],@C[9]
	eor	@E[2],@E[2],@C[6]
	eor	@E[3],@E[3],@C[7]
	str	@E[2],[sp,#$A[0][3]]		@ A[0][3] = C[3] ^ (~C[4] & C[0]);
	bic	@E[0],@C[2],@C[0]
	str	@E[3],[sp,#$A[0][3]+4]
	 add	@E[3],sp,#$D[0]
	bic	@E[1],@C[3],@C[1]
	eor	@E[0],@E[0],@C[8]
	eor	@E[1],@E[1],@C[9]
	str	@E[0],[sp,#$A[0][4]]		@ A[0][4] = C[4] ^ (~C[0] & C[1]);
	str	@E[1],[sp,#$A[0][4]+4]

	ldmia	@E[3],{@C[6]-@C[9],@E[0],@E[1],@E[2],@E[3]}	@ D[0..3]
	ldr	@C[0],[sp,#$A[1][0]]
	ldr	@C[1],[sp,#$A[1][0]+4]
	ldr	@C[2],[sp,#$A[2][1]]
	ldr	@C[3],[sp,#$A[2][1]+4]
	ldr	@C[4],[sp,#$D[4]]
	eor	@C[0],@C[0],@C[6]
	ldr	@C[5],[sp,#$D[4]+4]
	eor	@C[1],@C[1],@C[7]
	str	@C[0],[sp,#$T[1][0]]		@ T[1][0] = A[1][0] ^ (C[3] = D[0]);
	add	@C[0],sp,#$A[1][2]
	str	@C[1],[sp,#$T[1][0]+4]
	eor	@C[2],@C[2],@C[8]
	eor	@C[3],@C[3],@C[9]
	str	@C[2],[sp,#$T[1][1]]		@ T[1][1] = A[2][1] ^ (C[4] = D[1]); /* borrow T[1][1] */
	str	@C[3],[sp,#$T[1][1]+4]
	ldmia	@C[0],{@C[0]-@C[3]}		@ A[1][2..3]
	eor	@C[0],@C[0],@E[0]
	eor	@C[1],@C[1],@E[1]
	str	@C[0],[sp,#$T[1][2]]		@ T[1][2] = A[1][2] ^ (E[0] = D[2]);
	ldr	@C[0],[sp,#$A[2][4]]
	str	@C[1],[sp,#$T[1][2]+4]
	ldr	@C[1],[sp,#$A[2][4]+4]
	eor	@C[2],@C[2],@E[2]
	eor	@C[3],@C[3],@E[3]
	str	@C[2],[sp,#$T[1][3]]		@ T[1][3] = A[1][3] ^ (E[1] = D[3]);
	 ldr	@C[2],[sp,#$T[0][3]]
	str	@C[3],[sp,#$T[1][3]+4]
	 ldr	@C[3],[sp,#$T[0][3]+4]
	eor	@C[0],@C[0],@C[4]
	 ldr	@E[2],[sp,#$A[1][4]]
	eor	@C[1],@C[1],@C[5]
	 ldr	@E[3],[sp,#$A[1][4]+4]
	str	@C[0],[sp,#$T[1][4]]		@ T[1][4] = A[2][4] ^ (C[2] = D[4]); /* borrow T[1][4] */

	ror	@C[0],@C[2],#32-14		@ C[0] = ROL64(T[0][3],        rhotates[0][3]);
	 str	@C[1],[sp,#$T[1][4]+4]
	ror	@C[1],@C[3],#32-14
	eor	@C[2],@E[2],@C[4]
	ldr	@C[4],[sp,#$A[2][0]]
	eor	@C[3],@E[3],@C[5]
	ldr	@C[5],[sp,#$A[2][0]+4]
	ror	@C[2],@C[2],#32-10		@ C[1] = ROL64(A[1][4] ^ C[2], rhotates[1][4]);   /* D[4] */
	ldr	@E[2],[sp,#$A[3][1]]
	ror	@C[3],@C[3],#32-10
	ldr	@E[3],[sp,#$A[3][1]+4]
	eor	@C[6],@C[6],@C[4]
	eor	@C[7],@C[7],@C[5]
	ror	@C[5],@C[6],#32-1		@ C[2] = ROL64(A[2][0] ^ C[3], rhotates[2][0]);   /* D[0] */
	eor	@E[2],@E[2],@C[8]
	ror	@C[4],@C[7],#32-2
	ldr	@C[8],[sp,#$A[4][2]]
	eor	@E[3],@E[3],@C[9]
	ldr	@C[9],[sp,#$A[4][2]+4]
	ror	@C[7],@E[2],#32-22		@ C[3] = ROL64(A[3][1] ^ C[4], rhotates[3][1]);   /* D[1] */
	eor	@E[0],@E[0],@C[8]
	ror	@C[6],@E[3],#32-23
	eor	@E[1],@E[1],@C[9]
	ror	@C[9],@E[0],#32-30		@ C[4] = ROL64(A[4][2] ^ E[0], rhotates[4][2]);   /* D[2] */

	bic	@E[0],@C[4],@C[2]
	 ror	@C[8],@E[1],#32-31
	bic	@E[1],@C[5],@C[3]
	eor	@E[0],@E[0],@C[0]
	eor	@E[1],@E[1],@C[1]
	str	@E[0],[sp,#$A[1][0]]		@ A[1][0] = C[0] ^ (~C[1] & C[2])
	bic	@E[2],@C[6],@C[4]
	str	@E[1],[sp,#$A[1][0]+4]
	bic	@E[3],@C[7],@C[5]
	eor	@E[2],@E[2],@C[2]
	eor	@E[3],@E[3],@C[3]
	str	@E[2],[sp,#$A[1][1]]		@ A[1][1] = C[1] ^ (~C[2] & C[3]);
	bic	@E[0],@C[8],@C[6]
	str	@E[3],[sp,#$A[1][1]+4]
	bic	@E[1],@C[9],@C[7]
	eor	@E[0],@E[0],@C[4]
	eor	@E[1],@E[1],@C[5]
	str	@E[0],[sp,#$A[1][2]]		@ A[1][2] = C[2] ^ (~C[3] & C[4]);
	bic	@E[2],@C[0],@C[8]
	str	@E[1],[sp,#$A[1][2]+4]
	bic	@E[3],@C[1],@C[9]
	eor	@E[2],@E[2],@C[6]
	eor	@E[3],@E[3],@C[7]
	str	@E[2],[sp,#$A[1][3]]		@ A[1][3] = C[3] ^ (~C[4] & C[0]);
	bic	@E[0],@C[2],@C[0]
	str	@E[3],[sp,#$A[1][3]+4]
	 add	@E[3],sp,#$D[3]
	bic	@E[1],@C[3],@C[1]
	 ldr	@C[1],[sp,#$T[0][1]]
	eor	@E[0],@E[0],@C[8]
	 ldr	@C[0],[sp,#$T[0][1]+4]
	eor	@E[1],@E[1],@C[9]
	str	@E[0],[sp,#$A[1][4]]		@ A[1][4] = C[4] ^ (~C[0] & C[1]);
	str	@E[1],[sp,#$A[1][4]+4]

	ldr	@C[2],[sp,#$T[1][2]]
	ldr	@C[3],[sp,#$T[1][2]+4]
	ldmia	@E[3],{@E[0]-@E[2],@E[3]}	@ D[3..4]
	ldr	@C[4],[sp,#$A[2][3]]
	ror	@C[0],@C[0],#32-1		@ C[0] = ROL64(T[0][1],        rhotates[0][1]);
	ldr	@C[5],[sp,#$A[2][3]+4]
	ror	@C[2],@C[2],#32-3		@ C[1] = ROL64(T[1][2],        rhotates[1][2]);
	ldr	@C[6],[sp,#$A[3][4]]
	ror	@C[3],@C[3],#32-3
	ldr	@C[7],[sp,#$A[3][4]+4]
	eor	@E[0],@E[0],@C[4]
	ldr	@C[8],[sp,#$A[4][0]]
	eor	@E[1],@E[1],@C[5]
	ldr	@C[9],[sp,#$A[4][0]+4]
	ror	@C[5],@E[0],#32-12		@ C[2] = ROL64(A[2][3] ^ D[3], rhotates[2][3]);
	ldr	@E[0],[sp,#$D[0]]
	ror	@C[4],@E[1],#32-13
	ldr	@E[1],[sp,#$D[0]+4]
	eor	@C[6],@C[6],@E[2]
	eor	@C[7],@C[7],@E[3]
	ror	@C[6],@C[6],#32-4		@ C[3] = ROL64(A[3][4] ^ D[4], rhotates[3][4]);
	eor	@C[8],@C[8],@E[0]
	ror	@C[7],@C[7],#32-4
	eor	@C[9],@C[9],@E[1]
	ror	@C[8],@C[8],#32-9		@ C[4] = ROL64(A[4][0] ^ D[0], rhotates[4][0]);

	bic	@E[0],@C[4],@C[2]
	 ror	@C[9],@C[9],#32-9
	bic	@E[1],@C[5],@C[3]
	eor	@E[0],@E[0],@C[0]
	eor	@E[1],@E[1],@C[1]
	str	@E[0],[sp,#$A[2][0]]		@ A[2][0] = C[0] ^ (~C[1] & C[2])
	bic	@E[2],@C[6],@C[4]
	str	@E[1],[sp,#$A[2][0]+4]
	bic	@E[3],@C[7],@C[5]
	eor	@E[2],@E[2],@C[2]
	eor	@E[3],@E[3],@C[3]
	str	@E[2],[sp,#$A[2][1]]		@ A[2][1] = C[1] ^ (~C[2] & C[3]);
	bic	@E[0],@C[8],@C[6]
	str	@E[3],[sp,#$A[2][1]+4]
	bic	@E[1],@C[9],@C[7]
	eor	@E[0],@E[0],@C[4]
	eor	@E[1],@E[1],@C[5]
	str	@E[0],[sp,#$A[2][2]]		@ A[2][2] = C[2] ^ (~C[3] & C[4]);
	bic	@E[2],@C[0],@C[8]
	str	@E[1],[sp,#$A[2][2]+4]
	bic	@E[3],@C[1],@C[9]
	eor	@E[2],@E[2],@C[6]
	eor	@E[3],@E[3],@C[7]
	str	@E[2],[sp,#$A[2][3]]		@ A[2][3] = C[3] ^ (~C[4] & C[0]);
	bic	@E[0],@C[2],@C[0]
	str	@E[3],[sp,#$A[2][3]+4]
	bic	@E[1],@C[3],@C[1]
	eor	@E[0],@E[0],@C[8]
	eor	@E[1],@E[1],@C[9]
	str	@E[0],[sp,#$A[2][4]]		@ A[2][4] = C[4] ^ (~C[0] & C[1]);
	 add	@C[2],sp,#$T[1][0]
	str	@E[1],[sp,#$A[2][4]+4]

	add	@E[3],sp,#$D[2]
	ldr	@C[1],[sp,#$T[0][4]]
	ldr	@C[0],[sp,#$T[0][4]+4]
	ldmia	@C[2],{@C[2]-@C[5]}		@ T[1][0..1]
	ldmia	@E[3],{@E[0]-@E[2],@E[3]}	@ D[2..3]
	ror	@C[1],@C[1],#32-13		@ C[0] = ROL64(T[0][4],        rhotates[0][4]);
	ldr	@C[6],[sp,#$A[3][2]]
	ror	@C[0],@C[0],#32-14
	ldr	@C[7],[sp,#$A[3][2]+4]
	ror	@C[2],@C[2],#32-18		@ C[1] = ROL64(T[1][0],        rhotates[1][0]);
	ldr	@C[8],[sp,#$A[4][3]]
	ror	@C[3],@C[3],#32-18
	ldr	@C[9],[sp,#$A[4][3]+4]
	ror	@C[4],@C[4],#32-5		@ C[2] = ROL64(T[1][1],        rhotates[2][1]); /* originally A[2][1] */
	eor	@E[0],@E[0],@C[6]
	ror	@C[5],@C[5],#32-5
	eor	@E[1],@E[1],@C[7]
	ror	@C[7],@E[0],#32-7		@ C[3] = ROL64(A[3][2] ^ D[2], rhotates[3][2]);
	eor	@C[8],@C[8],@E[2]
	ror	@C[6],@E[1],#32-8
	eor	@C[9],@C[9],@E[3]
	ror	@C[8],@C[8],#32-28		@ C[4] = ROL64(A[4][3] ^ D[3], rhotates[4][3]);

	bic	@E[0],@C[4],@C[2]
	 ror	@C[9],@C[9],#32-28
	bic	@E[1],@C[5],@C[3]
	eor	@E[0],@E[0],@C[0]
	eor	@E[1],@E[1],@C[1]
	str	@E[0],[sp,#$A[3][0]]		@ A[3][0] = C[0] ^ (~C[1] & C[2])
	bic	@E[2],@C[6],@C[4]
	str	@E[1],[sp,#$A[3][0]+4]
	bic	@E[3],@C[7],@C[5]
	eor	@E[2],@E[2],@C[2]
	eor	@E[3],@E[3],@C[3]
	str	@E[2],[sp,#$A[3][1]]		@ A[3][1] = C[1] ^ (~C[2] & C[3]);
	bic	@E[0],@C[8],@C[6]
	str	@E[3],[sp,#$A[3][1]+4]
	bic	@E[1],@C[9],@C[7]
	eor	@E[0],@E[0],@C[4]
	eor	@E[1],@E[1],@C[5]
	str	@E[0],[sp,#$A[3][2]]		@ A[3][2] = C[2] ^ (~C[3] & C[4]);
	bic	@E[2],@C[0],@C[8]
	str	@E[1],[sp,#$A[3][2]+4]
	bic	@E[3],@C[1],@C[9]
	eor	@E[2],@E[2],@C[6]
	eor	@E[3],@E[3],@C[7]
	str	@E[2],[sp,#$A[3][3]]		@ A[3][3] = C[3] ^ (~C[4] & C[0]);
	bic	@E[0],@C[2],@C[0]
	str	@E[3],[sp,#$A[3][3]+4]
	bic	@E[1],@C[3],@C[1]
	eor	@E[0],@E[0],@C[8]
	eor	@E[1],@E[1],@C[9]
	str	@E[0],[sp,#$A[3][4]]		@ A[3][4] = C[4] ^ (~C[0] & C[1]);
	 add	@E[3],sp,#$T[1][3]
	str	@E[1],[sp,#$A[3][4]+4]

	ldr	@C[0],[sp,#$T[0][2]]
	ldr	@C[1],[sp,#$T[0][2]+4]
	ldmia	@E[3],{@E[0]-@E[2],@E[3]}	@ T[1][3..4]
	ldr	@C[7],[sp,#$T[0][0]]
	ror	@C[0],@C[0],#32-31		@ C[0] = ROL64(T[0][2],        rhotates[0][2]);
	ldr	@C[6],[sp,#$T[0][0]+4]
	ror	@C[1],@C[1],#32-31
	ldr	@C[8],[sp,#$A[4][1]]
	ror	@C[3],@E[0],#32-27		@ C[1] = ROL64(T[1][3],        rhotates[1][3]);
	ldr	@E[0],[sp,#$D[1]]
	ror	@C[2],@E[1],#32-28
	ldr	@C[9],[sp,#$A[4][1]+4]
	ror	@C[5],@E[2],#32-19		@ C[2] = ROL64(T[1][4],        rhotates[2][4]); /* originally A[2][4] */
	ldr	@E[1],[sp,#$D[1]+4]
	ror	@C[4],@E[3],#32-20
	eor	@C[8],@C[8],@E[0]
	ror	@C[7],@C[7],#32-20		@ C[3] = ROL64(T[0][0],        rhotates[3][0]); /* originally A[3][0] */
	eor	@C[9],@C[9],@E[1]
	ror	@C[6],@C[6],#32-21

	bic	@E[0],@C[4],@C[2]
	 ror	@C[8],@C[8],#32-1		@ C[4] = ROL64(A[4][1] ^ D[1], rhotates[4][1]);
	bic	@E[1],@C[5],@C[3]
	 ror	@C[9],@C[9],#32-1
	eor	@E[0],@E[0],@C[0]
	eor	@E[1],@E[1],@C[1]
	str	@E[0],[sp,#$A[4][0]]		@ A[4][0] = C[0] ^ (~C[1] & C[2])
	bic	@E[2],@C[6],@C[4]
	str	@E[1],[sp,#$A[4][0]+4]
	bic	@E[3],@C[7],@C[5]
	eor	@E[2],@E[2],@C[2]
	eor	@E[3],@E[3],@C[3]
	str	@E[2],[sp,#$A[4][1]]		@ A[4][1] = C[1] ^ (~C[2] & C[3]);
	bic	@E[0],@C[8],@C[6]
	str	@E[3],[sp,#$A[4][1]+4]
	bic	@E[1],@C[9],@C[7]
	eor	@E[0],@E[0],@C[4]
	eor	@E[1],@E[1],@C[5]
	str	@E[0],[sp,#$A[4][2]]		@ A[4][2] = C[2] ^ (~C[3] & C[4]);
	bic	@E[2],@C[0],@C[8]
	str	@E[1],[sp,#$A[4][2]+4]
	bic	@E[3],@C[1],@C[9]
	eor	@E[2],@E[2],@C[6]
	eor	@E[3],@E[3],@C[7]
	str	@E[2],[sp,#$A[4][3]]		@ A[4][3] = C[3] ^ (~C[4] & C[0]);
	bic	@E[0],@C[2],@C[0]
	str	@E[3],[sp,#$A[4][3]+4]
	bic	@E[1],@C[3],@C[1]
	eor	@E[2],@E[0],@C[8]
	eor	@E[3],@E[1],@C[9]
	str	@E[2],[sp,#$A[4][4]]		@ A[4][4] = C[4] ^ (~C[0] & C[1]);
	 add	@E[0],sp,#$A[1][0]
	str	@E[3],[sp,#$A[4][4]+4]

	blo	.Lround

	ldr	pc,[sp,#320]
.size	KeccakF1600_int,.-KeccakF1600_int

.type	KeccakF1600, %function
.align	5
KeccakF1600:
	stmdb	sp!,{r0,r4-r11,lr}
	sub	sp,sp,#320+16			@ space for A[5][5],D[5],T[2][5],...

	add	@E[0],r0,#$A[1][0]
	add	@E[1],sp,#$A[1][0]
	mov	@E[2],r0
	ldmia	@E[0]!,{@C[0]-@C[9]}		@ copy A[5][5] to stack
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0]!,{@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0]!,{@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0], {@C[0]-@C[9]}
	stmia	@E[1], {@C[0]-@C[9]}
	ldmia	@E[2], {@C[0]-@C[9]}		@ A[0][0..4]
	add	@E[0],sp,#$A[1][0]
	stmia	sp,    {@C[0]-@C[9]}

	bl	KeccakF1600_enter

	ldr	@E[1], [sp,#320+16]		@ restore pointer to A
	ldmia	sp,    {@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}		@ return A[5][5]
	ldmia	@E[0]!,{@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0]!,{@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0]!,{@C[0]-@C[9]}
	stmia	@E[1]!,{@C[0]-@C[9]}
	ldmia	@E[0], {@C[0]-@C[9]}
	stmia	@E[1], {@C[0]-@C[9]}

	add	sp,sp,#320+20
	ldmia	sp!,{r4-r11,pc}
.size	KeccakF1600,.-KeccakF1600
___
{ my ($hi,$lo,$i,$A_flat, $len,$bsz,$inp) = map("r$_",(5..8, 10..12));

########################################################################
# Stack layout
# ----->+-----------------------+
#       | uint64_t A[5][5]      |
#       | ...                   |
#       | ...                   |
# +336->+-----------------------+
#       | uint64_t *A           |
# +340->+-----------------------+
#       | const void *inp       |
# +344->+-----------------------+
#       | size_t len            |
# +348->+-----------------------+
#       | size_t bs             |
# +352->+-----------------------+
#       | ....

$code.=<<___;
.global	SHA3_absorb
.type	SHA3_absorb,%function
.align	5
SHA3_absorb:
	stmdb	sp!,{r0-r12,lr}
	sub	sp,sp,#320+16

	mov	r12,r0
	add	r14,sp,#0
	mov	$len,r2
	mov	$bsz,r3

	ldmia	r12!,{@C[0]-@C[9]}	@ copy A[5][5] to stack
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12, {@C[0]-@C[9]}
	stmia	r14, {@C[0]-@C[9]}

	ldr	$inp,[sp,#340]

.Loop_absorb:
	subs	r0,$len,$bsz
	blo	.Labsorbed
	add	$A_flat,sp,#0
	str	r0,[sp,#344]		@ save len - bsz

.Loop_block:
	ldmia	$A_flat,{r2-r3}		@ A_flat[i]
	ldrb	r0,[$inp,#7]!		@ inp[7]
	mov	$i,#8

.Lane_loop:
	subs	$i,$i,#1
	lsl	r1,r0,#24
	blo	.Lane_done
#ifdef	__thumb2__
	it	ne
	ldrbne	r0,[$inp,#-1]!
#else
	ldrneb	r0,[$inp,#-1]!
#endif
	adds	r1,r1,r1		@ sip through carry flag
	adc	$hi,$hi,$hi
	adds	r1,r1,r1
	adc	$lo,$lo,$lo
	adds	r1,r1,r1
	adc	$hi,$hi,$hi
	adds	r1,r1,r1
	adc	$lo,$lo,$lo
	adds	r1,r1,r1
	adc	$hi,$hi,$hi
	adds	r1,r1,r1
	adc	$lo,$lo,$lo
	adds	r1,r1,r1
	adc	$hi,$hi,$hi
	adds	r1,r1,r1
	adc	$lo,$lo,$lo
	b	.Lane_loop

.Lane_done:
	eor	r2,r2,$lo
	eor	r3,r3,$hi
	add	$inp,$inp,#8
	stmia	$A_flat!,{r2-r3}	@ A_flat[i++] ^= BitInterleave(inp[0..7])
	subs	$bsz,$bsz,#8
	bhi	.Loop_block

	str	$inp,[sp,#340]

	bl	KeccakF1600_int

	ldr	$inp,[sp,#340]
	ldr	$len,[sp,#344]
	ldr	$bsz,[sp,#348]
	b	.Loop_absorb

.align	4
.Labsorbed:
	add	r12,sp,#$A[1][0]
	ldr	r14, [sp,#336]		@ pull pointer to A[5][5]
	ldmia	sp,  {@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}	@ return A[5][5]
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12!,{@C[0]-@C[9]}
	stmia	r14!,{@C[0]-@C[9]}
	ldmia	r12, {@C[0]-@C[9]}
	stmia	r14, {@C[0]-@C[9]}

	add	sp,sp,#320+32
	mov	r0,$len			@ return value
	ldmia	sp!,{r4-r12,pc}
.size	SHA3_absorb,.-SHA3_absorb
___
}
{ my ($A_flat,$out,$len,$bsz, $byte,$shl) = map("r$_", (4..9));

$code.=<<___;
.global	SHA3_squeeze
.type	SHA3_squeeze,%function
.align	5
SHA3_squeeze:
	stmdb	sp!,{r4-r10,lr}
	mov	r12,r0
	mov	$A_flat,r0
	mov	$out,r1
	mov	$len,r2
	mov	$bsz,r3
	mov	r14,r3
	b	.Loop_squeeze

.align	4
.Loop_squeeze:
	ldmia	r12!,{r0,r1}		@ A_flat[i++]
	mov	$shl,#28

.Lane_squeeze:
	lsl	r2,r0,$shl
	lsl	r3,r1,$shl
	eor	$byte,$byte,$byte
	adds	r3,r3,r3		@ sip through carry flag
	adc	$byte,$byte,$byte
	adds	r2,r2,r2
	adc	$byte,$byte,$byte
	adds	r3,r3,r3
	adc	$byte,$byte,$byte
	adds	r2,r2,r2
	adc	$byte,$byte,$byte
	adds	r3,r3,r3
	adc	$byte,$byte,$byte
	adds	r2,r2,r2
	adc	$byte,$byte,$byte
	adds	r3,r3,r3
	adc	$byte,$byte,$byte
	adds	r2,r2,r2
	adc	$byte,$byte,$byte
	subs	$len,$len,#1		@ len -= 1
	str	$byte,[$out],#1
	beq	.Lsqueeze_done
	subs	$shl,$shl,#4
	bhs	.Lane_squeeze

	subs	r14,r14,#8		@ bsz -= 8
	bhi	.Loop_squeeze

	mov	r0,$A_flat

	bl	KeccakF1600

	mov	r12,$A_flat
	mov	r14,$bsz
	b	.Loop_squeeze

.Lsqueeze_done:
	ldmia	sp!,{r4-r10,pc}
.size	SHA3_squeeze,.-SHA3_squeeze
.asciz	"Keccak-1600 absorb and squeeze for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
.align	2
___
}

print $code;

close STDOUT; # enforce flush
