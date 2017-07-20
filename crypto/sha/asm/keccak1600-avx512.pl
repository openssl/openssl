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
# Keccak-1600 for AVX-512F.
#
# July 2017.
#
# Below code is KECCAK_1X_ALT implementation (see sha/keccak1600.c).
# Pretty straightforward, the only "magic" is data layout in registers.
# It's impossible to have one that is optimal for every step, hence
# it's changing as algorithm progresses. Data is saved in order that
# benefits Chi, but at the same time is easily convertible to order
# that benefits Theta. Conversion from Chi layout to Theta is
# explicit and reverse one is kind of fused with Pi...
#
########################################################################
# Numbers are cycles per processed byte out of large message.
#
#			r=1088(*)
#
# Knights Landing	8.9
# Skylake-X		6.7
#
# (*)	Corresponds to SHA3-256.

########################################################################
# Coordinates below correspond to those in sha/keccak1600.c. Layout
# suitable for Chi is one with y coordinates aligned column-wise. Trick
# is to add regular shift to x coordinate, so that Chi can still be
# performed with as little as 7 instructions, yet be converted to layout
# suitable for Theta with intra-register permutations alone. Here is
# "magic" layout for Chi (with pre-Theta shuffle):
#
# [4][4] [3][3] [2][2] [1][1] [0][0]>4.3.2.1.0>[4][4] [3][3] [2][2] [1][1] [0][0]
# [4][0] [3][4] [2][3] [1][2] [0][1]>3.2.1.0.4>[3][4] [2][3] [1][2] [0][1] [4][0]
# [4][1] [3][0] [2][4] [1][3] [0][2]>2.1.0.4.3>[2][4] [1][3] [0][2] [4][1] [3][0]
# [4][2] [3][1] [2][0] [1][4] [0][3]>1.0.4.3.2>[1][4] [0][3] [4][2] [3][1] [2][0]
# [4][3] [3][2] [2][1] [1][0] [0][4]>0.4.3.2.1>[0][4] [4][3] [3][2] [2][1] [1][0]
#
# Layout suitable to Theta has x coordinates aligned column-wise
# [it's interleaved with Pi indices transformation for reference]:
#
# [4][4] [3][3] [2][2] [1][1] [0][0]	$A00
##[0][4] [0][3] [0][2] [0][1] [0][0]
# [3][4] [2][3] [1][2] [0][1] [4][0]	$A01
##[2][3] [2][2] [2][1] [2][0] [2][4]
# [2][4] [1][3] [0][2] [4][1] [3][0]	$A02
##[4][2] [4][1] [4][0] [4][4] [4][3]
# [1][4] [0][3] [4][2] [3][1] [2][0]	$A03
##[1][1] [1][0] [1][4] [1][3] [1][2]
# [0][4] [4][3] [3][2] [2][1] [1][0]	$A04
##[3][0] [3][4] [3][3] [3][2] [3][1]
#
# Pi itself is performed by blending above data and finally shuffling it
# to original Chi layout:
#
# [1][1] [2][2] [3][3] [4][4] [0][0]>1.2.3.4.0>[4][4] [3][3] [2][2] [1][1] [0][0]
# [2][3] [3][4] [4][0] [0][1] [1][2]>2.3.4.0.1>[4][0] [3][4] [2][3] [1][2] [0][1]
# [3][0] [4][1] [0][2] [1][3] [2][4]>3.4.0.1.2>[4][1] [3][0] [2][4] [1][3] [0][2]
# [4][2] [0][3] [1][4] [2][0] [3][1]>4.0.1.2.3>[4][2] [3][1] [2][0] [1][4] [0][3]
# [0][4] [1][0] [2][1] [3][2] [4][3]>0.1.2.3.4>[4][3] [3][2] [2][1] [1][0] [0][4]
#
# As implied, data is loaded in Chi layout. Digits in variables' names
# represent right most coordinates of loaded data chunk:

my ($A00,	# [4][4] [3][3] [2][2] [1][1] [0][0]
    $A01,	# [4][0] [3][4] [2][3] [1][2] [0][1]
    $A02,	# [4][1] [3][0] [2][4] [1][3] [0][2]
    $A03,	# [4][2] [3][1] [2][0] [1][4] [0][3]
    $A04) =	# [4][3] [3][2] [2][1] [1][0] [0][4]
    map("%zmm$_",(0..4));

# We also need to map the magic order into offsets within structure:

my @A_jagged = ([0,0], [1,0], [2,0], [3,0], [4,0],
		[4,1], [0,1], [1,1], [2,1], [3,1],
		[3,2], [4,2], [0,2], [1,2], [2,2],
		[2,3], [3,3], [4,3], [0,3], [1,3],
		[1,4], [2,4], [3,4], [4,4], [0,4]);
   @A_jagged_in  = map(8*($$_[0]*8+$$_[1]), @A_jagged);	# ... and now linear
   @A_jagged_out = map(8*($$_[0]*5+$$_[1]), @A_jagged);	# ... and now linear

my @T       = map("%zmm$_",(5..7,16..17));
my @Chi     = map("%zmm$_",(18..22));
my @Theta   = map("%zmm$_",(33,23..26));	# invalid @Theta[0] is not typo
my @Rhotate = map("%zmm$_",(27..31));

my ($C00,$D00) = @T[0..1];
my ($k00001,$k00010,$k00100,$k01000,$k10000,$k11111) = map("%k$_",(1..6));

$code.=<<___;
.text

.type	__KeccakF1600,\@function
.align	32
__KeccakF1600:
	lea		iotas(%rip),%r10
	mov		\$24,%eax
	jmp		.Loop_avx512

.align	32
.Loop_avx512:
	######################################### Theta
	#vpermq		$A00,@Theta[0],$A00	# doesn't actually change order
	vpermq		$A01,@Theta[1],$A01
	vpermq		$A02,@Theta[2],$A02
	vpermq		$A03,@Theta[3],$A03
	vpermq		$A04,@Theta[4],$A04

	vmovdqa64	$A00,@T[0]		# put aside original A00
	vpternlogq	\$0x96,$A02,$A01,$A00	# and use it as "C00"
	vpternlogq	\$0x96,$A04,$A03,$A00

	vprolq		\$1,$A00,$D00
	vpermq		$A00,@Theta[1],$A00
	vpermq		$D00,@Theta[4],$D00

	vpternlogq	\$0x96,$A00,$D00,@T[0]	# T[0] is original A00
	vpternlogq	\$0x96,$A00,$D00,$A01
	vpternlogq	\$0x96,$A00,$D00,$A02
	vpternlogq	\$0x96,$A00,$D00,$A03
	vpternlogq	\$0x96,$A00,$D00,$A04

	######################################### Rho
	vprolvq		@Rhotate[0],@T[0],$A00	# T[0] is original A00
	vprolvq		@Rhotate[1],$A01,$A01
	vprolvq		@Rhotate[2],$A02,$A02
	vprolvq		@Rhotate[3],$A03,$A03
	vprolvq		@Rhotate[4],$A04,$A04

	######################################### Pi
	vpblendmq	$A02,$A00,@{T[0]}{$k00010}
	vpblendmq	$A00,$A03,@{T[1]}{$k00010}
	vpblendmq	$A03,$A01,@{T[2]}{$k00010}
	vpblendmq	$A01,$A04,@{T[3]}{$k00010}
	vpblendmq	$A04,$A02,@{T[4]}{$k00010}

	vpblendmq	$A04,@T[0],@{T[0]}{$k00100}
	vpblendmq	$A02,@T[1],@{T[1]}{$k00100}
	vpblendmq	$A00,@T[2],@{T[2]}{$k00100}
	vpblendmq	$A03,@T[3],@{T[3]}{$k00100}
	vpblendmq	$A01,@T[4],@{T[4]}{$k00100}

	vpblendmq	$A01,@T[0],@{T[0]}{$k01000}
	vpblendmq	$A04,@T[1],@{T[1]}{$k01000}
	vpblendmq	$A02,@T[2],@{T[2]}{$k01000}
	vpblendmq	$A00,@T[3],@{T[3]}{$k01000}
	vpblendmq	$A03,@T[4],@{T[4]}{$k01000}

	vpblendmq	$A03,@T[0],@{T[0]}{$k10000}
	vpblendmq	$A01,@T[1],@{T[1]}{$k10000}
	vpblendmq	$A04,@T[2],@{T[2]}{$k10000}
	vpblendmq	$A02,@T[3],@{T[3]}{$k10000}
	vpblendmq	$A00,@T[4],@{T[4]}{$k10000}

	vpermq		@T[0],@Chi[0],$A00
	vpermq		@T[1],@Chi[1],$A01
	vpermq		@T[2],@Chi[2],$A02
	vpermq		@T[3],@Chi[3],$A03
	vpermq		@T[4],@Chi[4],$A04

	######################################### Chi
	vmovdqa64	$A00,@T[0]
	vpternlogq	\$0xD2,$A02,$A01,$A00
	vmovdqa64	$A01,@T[1]
	vpternlogq	\$0xD2,$A03,$A02,$A01
	vpternlogq	\$0xD2,$A04,$A03,$A02
	vpternlogq	\$0xD2,@T[0],$A04,$A03
	vpternlogq	\$0xD2,@T[1],@T[0],$A04

	######################################### Iota
	vpxorq		(%r10),$A00,${A00}{$k00001}
	lea		8(%r10),%r10

	dec		%eax
	jnz		.Loop_avx512

	ret
.size	__KeccakF1600,.-__KeccakF1600
___

my ($A_flat,$inp,$len,$bsz) = ("%rdi","%rsi","%rdx","%rcx");
my  $out = $inp;	# in squeeze

$code.=<<___;
.globl	SHA3_absorb
.type	SHA3_absorb,\@function
.align	32
SHA3_absorb:
	mov	%rsp,%r11

	lea	-320(%rsp),%rsp
	and	\$-64,%rsp

	lea	96($A_flat),$A_flat
	lea	96($inp),$inp
	lea	128(%rsp),%r9

	vzeroupper

	lea		theta_perm(%rip),%r8

	kxnorw		$k11111,$k11111,$k11111
	kshiftrw	\$15,$k11111,$k00001
	kshiftrw	\$11,$k11111,$k11111
	kshiftlw	\$1,$k00001,$k00010
	kshiftlw	\$2,$k00001,$k00100
	kshiftlw	\$3,$k00001,$k01000
	kshiftlw	\$4,$k00001,$k10000

	#vmovdqa64	64*0(%r8),@Theta[0]
	vmovdqa64	64*1(%r8),@Theta[1]
	vmovdqa64	64*2(%r8),@Theta[2]
	vmovdqa64	64*3(%r8),@Theta[3]
	vmovdqa64	64*4(%r8),@Theta[4]

	vmovdqa64	64*5(%r8),@Rhotate[0]
	vmovdqa64	64*6(%r8),@Rhotate[1]
	vmovdqa64	64*7(%r8),@Rhotate[2]
	vmovdqa64	64*8(%r8),@Rhotate[3]
	vmovdqa64	64*9(%r8),@Rhotate[4]

	vmovdqa64	64*10(%r8),@Chi[0]
	vmovdqa64	64*11(%r8),@Chi[1]
	vmovdqa64	64*12(%r8),@Chi[2]
	vmovdqa64	64*13(%r8),@Chi[3]
	vmovdqa64	64*14(%r8),@Chi[4]

	vmovdqu64	40*0-96($A_flat),${A00}{$k11111}{z}
	vpxorq		@T[0],@T[0],@T[0]
	vmovdqu64	40*1-96($A_flat),${A01}{$k11111}{z}
	vmovdqu64	40*2-96($A_flat),${A02}{$k11111}{z}
	vmovdqu64	40*3-96($A_flat),${A03}{$k11111}{z}
	vmovdqu64	40*4-96($A_flat),${A04}{$k11111}{z}

	vmovdqa64	@T[0],0*64-128(%r9)	# zero transfer area on stack
	vmovdqa64	@T[0],1*64-128(%r9)
	vmovdqa64	@T[0],2*64-128(%r9)
	vmovdqa64	@T[0],3*64-128(%r9)
	vmovdqa64	@T[0],4*64-128(%r9)
	jmp		.Loop_absorb_avx512

.align	32
.Loop_absorb_avx512:
	mov		$bsz,%rax
	sub		$bsz,$len
	jc		.Ldone_absorb_avx512

	shr		\$3,%eax
___
for(my $i=0; $i<25; $i++) {
$code.=<<___
	mov	8*$i-96($inp),%r8
	mov	%r8,$A_jagged_in[$i]-128(%r9)
	dec	%eax
	jz	.Labsorved_avx512
___
}
$code.=<<___;
.Labsorved_avx512:
	lea	($inp,$bsz),$inp

	vpxorq	64*0-128(%r9),$A00,$A00
	vpxorq	64*1-128(%r9),$A01,$A01
	vpxorq	64*2-128(%r9),$A02,$A02
	vpxorq	64*3-128(%r9),$A03,$A03
	vpxorq	64*4-128(%r9),$A04,$A04

	call	__KeccakF1600

	jmp	.Loop_absorb_avx512

.align	32
.Ldone_absorb_avx512:
	vmovdqu64	$A00,40*0-96($A_flat){$k11111}
	vmovdqu64	$A01,40*1-96($A_flat){$k11111}
	vmovdqu64	$A02,40*2-96($A_flat){$k11111}
	vmovdqu64	$A03,40*3-96($A_flat){$k11111}
	vmovdqu64	$A04,40*4-96($A_flat){$k11111}

	vzeroupper

	lea	(%r11),%rsp
	lea	($len,$bsz),%rax		# return value
	ret
.size	SHA3_absorb,.-SHA3_absorb

.globl	SHA3_squeeze
.type	SHA3_squeeze,\@function
.align	32
SHA3_squeeze:
	mov	%rsp,%r11

	lea	96($A_flat),$A_flat
	cmp	$bsz,$len
	jbe	.Lno_output_extension_avx512

	vzeroupper

	lea		theta_perm(%rip),%r8

	kxnorw		$k11111,$k11111,$k11111
	kshiftrw	\$15,$k11111,$k00001
	kshiftrw	\$11,$k11111,$k11111
	kshiftlw	\$1,$k00001,$k00010
	kshiftlw	\$2,$k00001,$k00100
	kshiftlw	\$3,$k00001,$k01000
	kshiftlw	\$4,$k00001,$k10000

	#vmovdqa64	64*0(%r8),@Theta[0]
	vmovdqa64	64*1(%r8),@Theta[1]
	vmovdqa64	64*2(%r8),@Theta[2]
	vmovdqa64	64*3(%r8),@Theta[3]
	vmovdqa64	64*4(%r8),@Theta[4]

	vmovdqa64	64*5(%r8),@Rhotate[0]
	vmovdqa64	64*6(%r8),@Rhotate[1]
	vmovdqa64	64*7(%r8),@Rhotate[2]
	vmovdqa64	64*8(%r8),@Rhotate[3]
	vmovdqa64	64*9(%r8),@Rhotate[4]

	vmovdqa64	64*10(%r8),@Chi[0]
	vmovdqa64	64*11(%r8),@Chi[1]
	vmovdqa64	64*12(%r8),@Chi[2]
	vmovdqa64	64*13(%r8),@Chi[3]
	vmovdqa64	64*14(%r8),@Chi[4]

	vmovdqu64	40*0-96($A_flat),${A00}{$k11111}{z}
	vmovdqu64	40*1-96($A_flat),${A01}{$k11111}{z}
	vmovdqu64	40*2-96($A_flat),${A02}{$k11111}{z}
	vmovdqu64	40*3-96($A_flat),${A03}{$k11111}{z}
	vmovdqu64	40*4-96($A_flat),${A04}{$k11111}{z}

.Lno_output_extension_avx512:
	shr	\$3,$bsz
	mov	$bsz,%rax

.Loop_squeeze_avx512:
	mov	@A_jagged_out[$i]-96($A_flat),%r8
___
for (my $i=0; $i<25; $i++) {
$code.=<<___;
	sub	\$8,$len
	jc	.Ltail_squeeze_avx512
	mov	%r8,($out)
	lea	8($out),$out
	je	.Ldone_squeeze_avx512
	dec	%eax
	je	.Lextend_output_avx512
	mov	@A_jagged_out[$i+1]-96($A_flat),%r8
___
}
$code.=<<___;
.Lextend_output_avx512:
	call	__KeccakF1600

	vmovdqu64	$A00,40*0-96($A_flat){$k11111}
	vmovdqu64	$A01,40*1-96($A_flat){$k11111}
	vmovdqu64	$A02,40*2-96($A_flat){$k11111}
	vmovdqu64	$A03,40*3-96($A_flat){$k11111}
	vmovdqu64	$A04,40*4-96($A_flat){$k11111}

	mov	$bsz,%rax
	jmp	.Loop_squeeze_avx512


.Ltail_squeeze_avx512:
	add	\$8,$len
.Loop_tail_avx512:
	mov	%r8b,($out)
	lea	1($out),$out
	shr	\$8,%r8
	dec	$len
	jnz	.Loop_tail_avx512

.Ldone_squeeze_avx512:
	vzeroupper

	lea	(%r11),%rsp
	ret
.size	SHA3_squeeze,.-SHA3_squeeze

.align	64
theta_perm:
	.quad	0, 1, 2, 3, 4, 5, 6, 7		# [not used]
	.quad	4, 0, 1, 2, 3, 5, 6, 7
	.quad	3, 4, 0, 1, 2, 5, 6, 7
	.quad	2, 3, 4, 0, 1, 5, 6, 7
	.quad	1, 2, 3, 4, 0, 5, 6, 7

rhotates:
	.quad	0,  44, 43, 21, 14, 0, 0, 0	# [0][0] [1][1] [2][2] [3][3] [4][4]
	.quad	18, 1,  6,  25, 8,  0, 0, 0	# [4][0] [0][1] [1][2] [2][3] [3][4]
	.quad	41, 2,	62, 55, 39, 0, 0, 0	# [3][0] [4][1] [0][2] [1][3] [2][4]
	.quad	3,  45, 61, 28, 20, 0, 0, 0	# [2][0] [3][1] [4][2] [0][3] [1][4]
	.quad	36, 10, 15, 56, 27, 0, 0, 0	# [1][0] [2][1] [3][2] [4][3] [0][4]

chi_perm:
	.quad	0, 4, 3, 2, 1, 5, 6, 7
	.quad	1, 0, 4, 3, 2, 5, 6, 7
	.quad	2, 1, 0, 4, 3, 5, 6, 7
	.quad	3, 2, 1, 0, 4, 5, 6, 7
	.quad	4, 3, 2, 1, 0, 5, 6, 7

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

.asciz	"Keccak-1600 absorb and squeeze for AVX-512F, CRYPTOGAMS by <appro\@openssl.org>"
___

print $code;
close STDOUT;
