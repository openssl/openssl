#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
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
# November 2014
#
# ChaCha20 for x86_64.
#
# Performance in cycles per byte out of large buffer.
#
#		IALU/gcc 4.8(i)	1xSSSE3/SSE2	4xSSSE3	    8xAVX2
#
# P4		9.48/+99%	-/22.7(ii)	-
# Core2		7.83/+55%	7.90/8.08	4.35
# Westmere	7.19/+50%	5.60/6.70	3.00
# Sandy Bridge	8.31/+42%	5.45/6.76	2.72
# Ivy Bridge	6.71/+46%	5.40/6.49	2.41
# Haswell	5.92/+43%	5.20/6.45	2.42	    1.23
# Silvermont	12.0/+33%	7.75/7.40	7.03(iii)
# Sledgehammer	7.28/+52%	-/14.2(ii)	-
# Bulldozer	9.66/+28%	9.85/11.1	3.06(iv)
# VIA Nano	10.5/+46%	6.72/8.60	6.05
#
# (i)	compared to older gcc 3.x one can observe >2x improvement on
#	most platforms;
# (ii)	as it can be seen, SSE2 performance is too low on legacy
#	processors; NxSSE2 results are naturally better, but not
#	impressively better than IALU ones, which is why you won't
#	find SSE2 code below;
# (iii)	this is not optimal result for Atom because of MSROM
#	limitations, SSE2 can do better, but gain is considered too
#	low to justify the [maintenance] effort;
# (iv)	Bulldozer actually executes 4xXOP code path that delivers 2.20;

use strict;

my $flavour = shift;
my $output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

my $win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; my $dir=$1;
my $xlate;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

my $avx = 0;
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.19) + ($1>=2.22);
}

if (!$avx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	   `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.09) + ($1>=2.10);
}

if (!$avx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
	   `ml64 2>&1` =~ /Version ([0-9]+)\./) {
	$avx = ($1>=10) + ($1>=11);
}

if (!$avx && `$ENV{CC} -v 2>&1` =~ /((?:^clang|LLVM) version|.*based on LLVM) ([3-9]\.[0-9]+)/) {
	$avx = ($2>=3.0) + ($2>3.0);
}

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

# input parameter block
my ($out,$inp,$len,$key,$counter)=("%rdi","%rsi","%rdx","%rcx","%r8");

my $code="";
$code.=<<___;
.text

.extern OPENSSL_ia32cap_P

.align	64
.Lzero:
.long	0,0,0,0
.Lone:
.long	1,0,0,0
.Linc:
.long	0,1,2,3
.Lfour:
.long	4,4,4,4
.Lincy:
.long	0,2,4,6,1,3,5,7
.Leight:
.long	8,8,8,8,8,8,8,8
.Lrot16:
.byte	0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
.Lrot24:
.byte	0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
.Lsigma:
.asciz	"expand 32-byte k"
.asciz	"ChaCha20 for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
___

my @x=("%eax","%ebx","%ecx","%edx",map("%r${_}d",(8..11)),
       "%nox","%nox","%nox","%nox",map("%r${_}d",(12..15)));
my @t=("%esi","%edi");

sub ROUND {			# critical path is 24 cycles per round
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_)=@t;

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

	# Normally instructions would be interleaved to favour in-order
	# execution. Generally out-of-order cores manage it gracefully,
	# but not this time for some reason. As in-order execution
	# cores are dying breed, old Atom is the only one around,
	# instructions are left uninterleaved. Besides, Atom is better
	# off executing 1xSSSE3 code anyway...

<<___;
	add	@x[$b0],@x[$a0]		# Q1
	xor	@x[$a0],@x[$d0]
	rol	\$16,@x[$d0]
	 add	@x[$b1],@x[$a1]		# Q2
	 xor	@x[$a1],@x[$d1]
	 rol	\$16,@x[$d1]

	add	@x[$d0],$xc
	xor	$xc,@x[$b0]
	rol	\$12,@x[$b0]
	 add	@x[$d1],$xc_
	 xor	$xc_,@x[$b1]
	 rol	\$12,@x[$b1]

	add	@x[$b0],@x[$a0]
	xor	@x[$a0],@x[$d0]
	rol	\$8,@x[$d0]
	 add	@x[$b1],@x[$a1]
	 xor	@x[$a1],@x[$d1]
	 rol	\$8,@x[$d1]

	add	@x[$d0],$xc
	xor	$xc,@x[$b0]
	rol	\$7,@x[$b0]
	 add	@x[$d1],$xc_
	 xor	$xc_,@x[$b1]
	 rol	\$7,@x[$b1]

	mov	$xc,4*$c0(%rsp)		# reload pair of 'c's
	 mov	$xc_,4*$c1(%rsp)
	mov	4*$c2(%rsp),$xc
	 mov	4*$c3(%rsp),$xc_

	add	@x[$b2],@x[$a2]		# Q3
	xor	@x[$a2],@x[$d2]
	rol	\$16,@x[$d2]
	 add	@x[$b3],@x[$a3]		# Q4
	 xor	@x[$a3],@x[$d3]
	 rol	\$16,@x[$d3]

	add	@x[$d2],$xc
	xor	$xc,@x[$b2]
	rol	\$12,@x[$b2]
	 add	@x[$d3],$xc_
	 xor	$xc_,@x[$b3]
	 rol	\$12,@x[$b3]

	add	@x[$b2],@x[$a2]
	xor	@x[$a2],@x[$d2]
	rol	\$8,@x[$d2]
	 add	@x[$b3],@x[$a3]
	 xor	@x[$a3],@x[$d3]
	 rol	\$8,@x[$d3]

	add	@x[$d2],$xc
	xor	$xc,@x[$b2]
	rol	\$7,@x[$b2]
	 add	@x[$d3],$xc_
	 xor	$xc_,@x[$b3]
	 rol	\$7,@x[$b3]
___
}

########################################################################
# Generic code path that handles all lengths on pre-SSSE3 processors.
$code.=<<___;
.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,\@function,5
.align	64
ChaCha20_ctr32:
	cmp	\$0,$len
	je	.Lno_data
	mov	OPENSSL_ia32cap_P+4(%rip),%r10
	test	\$`1<<(41-32)`,%r10d
	jnz	.LChaCha20_ssse3

	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	sub	\$64+24,%rsp

	#movdqa	.Lsigma(%rip),%xmm0
	movdqu	($key),%xmm1
	movdqu	16($key),%xmm2
	movdqu	($counter),%xmm3
	movdqa	.Lone(%rip),%xmm4

	#movdqa	%xmm0,4*0(%rsp)		# key[0]
	movdqa	%xmm1,4*4(%rsp)		# key[1]
	movdqa	%xmm2,4*8(%rsp)		# key[2]
	movdqa	%xmm3,4*12(%rsp)	# key[3]
	mov	$len,%rbp		# reassign $len
	jmp	.Loop_outer

.align	32
.Loop_outer:
	mov	\$0x61707865,@x[0]      # 'expa'
	mov	\$0x3320646e,@x[1]      # 'nd 3'
	mov	\$0x79622d32,@x[2]      # '2-by'
	mov	\$0x6b206574,@x[3]      # 'te k'
	mov	4*4(%rsp),@x[4]
	mov	4*5(%rsp),@x[5]
	mov	4*6(%rsp),@x[6]
	mov	4*7(%rsp),@x[7]
	movd	%xmm3,@x[12]
	mov	4*13(%rsp),@x[13]
	mov	4*14(%rsp),@x[14]
	mov	4*15(%rsp),@x[15]

	mov	%rbp,64+0(%rsp)		# save len
	mov	\$10,%ebp
	mov	$inp,64+8(%rsp)		# save inp
	movq	%xmm2,%rsi		# "@x[8]"
	mov	$out,64+16(%rsp)	# save out
	mov	%rsi,%rdi
	shr	\$32,%rdi		# "@x[9]"
	jmp	.Loop

.align	32
.Loop:
	${\ROUND(0, 4, 8,12)}
	${\ROUND(0, 5,10,15)}
	dec	%ebp
	jnz	.Loop

	mov	@t[1],4*9(%rsp)		# modulo-scheduled
	mov	@t[0],4*8(%rsp)
	mov	64(%rsp),%rbp		# load len
	movdqa	%xmm2,%xmm1
	mov	64+8(%rsp),$inp		# load inp
	paddd	%xmm4,%xmm3		# increment counter
	mov	64+16(%rsp),$out	# load out

	add	\$0x61707865,@x[0]      # 'expa'
	add	\$0x3320646e,@x[1]      # 'nd 3'
	add	\$0x79622d32,@x[2]      # '2-by'
	add	\$0x6b206574,@x[3]      # 'te k'
	add	4*4(%rsp),@x[4]
	add	4*5(%rsp),@x[5]
	add	4*6(%rsp),@x[6]
	add	4*7(%rsp),@x[7]
	add	4*12(%rsp),@x[12]
	add	4*13(%rsp),@x[13]
	add	4*14(%rsp),@x[14]
	add	4*15(%rsp),@x[15]
	paddd	4*8(%rsp),%xmm1

	cmp	\$64,%rbp
	jb	.Ltail

	xor	4*0($inp),@x[0]		# xor with input
	xor	4*1($inp),@x[1]
	xor	4*2($inp),@x[2]
	xor	4*3($inp),@x[3]
	xor	4*4($inp),@x[4]
	xor	4*5($inp),@x[5]
	xor	4*6($inp),@x[6]
	xor	4*7($inp),@x[7]
	movdqu	4*8($inp),%xmm0
	xor	4*12($inp),@x[12]
	xor	4*13($inp),@x[13]
	xor	4*14($inp),@x[14]
	xor	4*15($inp),@x[15]
	lea	4*16($inp),$inp		# inp+=64
	pxor	%xmm1,%xmm0

	movdqa	%xmm2,4*8(%rsp)
	movd	%xmm3,4*12(%rsp)

	mov	@x[0],4*0($out)		# write output
	mov	@x[1],4*1($out)
	mov	@x[2],4*2($out)
	mov	@x[3],4*3($out)
	mov	@x[4],4*4($out)
	mov	@x[5],4*5($out)
	mov	@x[6],4*6($out)
	mov	@x[7],4*7($out)
	movdqu	%xmm0,4*8($out)
	mov	@x[12],4*12($out)
	mov	@x[13],4*13($out)
	mov	@x[14],4*14($out)
	mov	@x[15],4*15($out)
	lea	4*16($out),$out		# out+=64

	sub	\$64,%rbp
	jnz	.Loop_outer

	jmp	.Ldone

.align	16
.Ltail:
	mov	@x[0],4*0(%rsp)
	mov	@x[1],4*1(%rsp)
	xor	%rbx,%rbx
	mov	@x[2],4*2(%rsp)
	mov	@x[3],4*3(%rsp)
	mov	@x[4],4*4(%rsp)
	mov	@x[5],4*5(%rsp)
	mov	@x[6],4*6(%rsp)
	mov	@x[7],4*7(%rsp)
	movdqa	%xmm1,4*8(%rsp)
	mov	@x[12],4*12(%rsp)
	mov	@x[13],4*13(%rsp)
	mov	@x[14],4*14(%rsp)
	mov	@x[15],4*15(%rsp)

.Loop_tail:
	movzb	($inp,%rbx),%eax
	movzb	(%rsp,%rbx),%edx
	lea	1(%rbx),%rbx
	xor	%edx,%eax
	mov	%al,-1($out,%rbx)
	dec	%rbp
	jnz	.Loop_tail

.Ldone:
	add	\$64+24,%rsp
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
.Lno_data:
	ret
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
___

########################################################################
# SSSE3 code path that handles shorter lengths
{
my ($a,$b,$c,$d,$t,$t1,$rot16,$rot24)=map("%xmm$_",(0..7));

sub SSSE3ROUND {	# critical path is 20 "SIMD ticks" per round
<<___;
	paddd	$b,$a
	pxor	$a,$d
	pshufb	$rot16,$d

	paddd	$d,$c
	pxor	$c,$b
	movdqa	$b,$t
	psrld	\$20,$b
	pslld	\$12,$t
	por	$t,$b

	paddd	$b,$a
	pxor	$a,$d
	pshufb	$rot24,$d

	paddd	$d,$c
	pxor	$c,$b
	movdqa	$b,$t
	psrld	\$25,$b
	pslld	\$7,$t
	por	$t,$b
___
}

my $xframe = $win64 ? 32+32+8 : 24;

$code.=<<___;
.type	ChaCha20_ssse3,\@function,5
.align	32
ChaCha20_ssse3:
.LChaCha20_ssse3:
___
$code.=<<___	if ($avx);
	test	\$`1<<(43-32)`,%r10d
	jnz	.LChaCha20_4xop		# XOP is fastest even if we use 1/4
___
$code.=<<___;
	cmp	\$128,$len		# we might throw away some data,
	ja	.LChaCha20_4x		# but overall it won't be slower

.Ldo_sse3_after_all:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	sub	\$64+$xframe,%rsp
___
$code.=<<___	if ($win64);
	movaps	%xmm6,64+32(%rsp)
	movaps	%xmm7,64+48(%rsp)
___
$code.=<<___;
	movdqa	.Lsigma(%rip),$a
	movdqu	($key),$b
	movdqu	16($key),$c
	movdqu	($counter),$d
	movdqa	.Lrot16(%rip),$rot16
	movdqa	.Lrot24(%rip),$rot24

	movdqa	$a,0x00(%rsp)
	movdqa	$b,0x10(%rsp)
	movdqa	$c,0x20(%rsp)
	movdqa	$d,0x30(%rsp)
	mov	\$10,%ebp
	jmp	.Loop_ssse3

.align	32
.Loop_outer_ssse3:
	movdqa	.Lone(%rip),$d
	movdqa	0x00(%rsp),$a
	movdqa	0x10(%rsp),$b
	movdqa	0x20(%rsp),$c
	paddd	0x30(%rsp),$d
	mov	\$10,%ebp
	movdqa	$d,0x30(%rsp)
	jmp	.Loop_ssse3

.align	32
.Loop_ssse3:
	${\SSSE3ROUND()}
	pshufd	\$0b01001110,$c,$c
	pshufd	\$0b00111001,$b,$b
	pshufd	\$0b10010011,$d,$d
	nop

	${\SSSE3ROUND()}
	pshufd	\$0b01001110,$c,$c
	pshufd	\$0b10010011,$b,$b
	pshufd	\$0b00111001,$d,$d

	dec	%ebp
	jnz	.Loop_ssse3

	paddd	0x00(%rsp),$a
	paddd	0x10(%rsp),$b
	paddd	0x20(%rsp),$c
	paddd	0x30(%rsp),$d

	cmp	\$64,$len
	jb	.Ltail_ssse3

	movdqu	0x00($inp),$t
	movdqu	0x10($inp),$t1
	pxor	$t,$a			# xor with input
	movdqu	0x20($inp),$t
	pxor	$t1,$b
	movdqu	0x30($inp),$t1
	lea	0x40($inp),$inp		# inp+=64
	pxor	$t,$c
	pxor	$t1,$d

	movdqu	$a,0x00($out)		# write output
	movdqu	$b,0x10($out)
	movdqu	$c,0x20($out)
	movdqu	$d,0x30($out)
	lea	0x40($out),$out		# out+=64

	sub	\$64,$len
	jnz	.Loop_outer_ssse3

	jmp	.Ldone_ssse3

.align	16
.Ltail_ssse3:
	movdqa	$a,0x00(%rsp)
	movdqa	$b,0x10(%rsp)
	movdqa	$c,0x20(%rsp)
	movdqa	$d,0x30(%rsp)
	xor	%rbx,%rbx

.Loop_tail_ssse3:
	movzb	($inp,%rbx),%eax
	movzb	(%rsp,%rbx),%ecx
	lea	1(%rbx),%rbx
	xor	%ecx,%eax
	mov	%al,-1($out,%rbx)
	dec	$len
	jnz	.Loop_tail_ssse3

.Ldone_ssse3:
___
$code.=<<___	if ($win64);
	movaps	64+32(%rsp),%xmm6
	movaps	64+48(%rsp),%xmm7
___
$code.=<<___;
	add	\$64+$xframe,%rsp
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret
.size	ChaCha20_ssse3,.-ChaCha20_ssse3
___
}

########################################################################
# SSSE3 code path that handles longer messages.
{
# assign variables to favor Atom front-end
my ($xd0,$xd1,$xd2,$xd3, $xt0,$xt1,$xt2,$xt3,
    $xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3)=map("%xmm$_",(0..15));
my  @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	"%nox","%nox","%nox","%nox", $xd0,$xd1,$xd2,$xd3);

sub SSSE3_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_,$t0,$t1)=($xt0,$xt1,$xt2,$xt3);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @xx[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

<<___;
	paddd		@xx[$b0],@xx[$a0]	# Q1
	 paddd		@xx[$b1],@xx[$a1]	# Q2
	pxor		@xx[$a0],@xx[$d0]
	 pxor		@xx[$a1],@xx[$d1]
	pshufb		$t1,@xx[$d0]
	 pshufb		$t1,@xx[$d1]

	paddd		@xx[$d0],$xc
	 paddd		@xx[$d1],$xc_
	pxor		$xc,@xx[$b0]
	 pxor		$xc_,@xx[$b1]
	movdqa		@xx[$b0],$t0
	pslld		\$12,@xx[$b0]
	psrld		\$20,$t0
	 movdqa		@xx[$b1],$t1
	 pslld		\$12,@xx[$b1]
	por		$t0,@xx[$b0]
	 psrld		\$20,$t1
	movdqa		(%r11),$t0		# .Lrot24(%rip)
	 por		$t1,@xx[$b1]

	paddd		@xx[$b0],@xx[$a0]
	 paddd		@xx[$b1],@xx[$a1]
	pxor		@xx[$a0],@xx[$d0]
	 pxor		@xx[$a1],@xx[$d1]
	pshufb		$t0,@xx[$d0]
	 pshufb		$t0,@xx[$d1]

	paddd		@xx[$d0],$xc
	 paddd		@xx[$d1],$xc_
	pxor		$xc,@xx[$b0]
	 pxor		$xc_,@xx[$b1]
	movdqa		@xx[$b0],$t1
	pslld		\$7,@xx[$b0]
	psrld		\$25,$t1
	 movdqa		@xx[$b1],$t0
	 pslld		\$7,@xx[$b1]
	por		$t1,@xx[$b0]
	 psrld		\$25,$t0
	movdqa		(%r10),$t1		# .Lrot16(%rip)
	 por		$t0,@xx[$b1]

	movdqa		$xc,`16*($c0-8)`(%rsp)	# reload pair of 'c's
	 movdqa		$xc_,`16*($c1-8)`(%rsp)
	movdqa		`16*($c2-8)`(%rsp),$xc
	 movdqa		`16*($c3-8)`(%rsp),$xc_

	paddd		@xx[$b2],@xx[$a2]	# Q3
	 paddd		@xx[$b3],@xx[$a3]	# Q4
	pxor		@xx[$a2],@xx[$d2]
	 pxor		@xx[$a3],@xx[$d3]
	pshufb		$t1,@xx[$d2]
	 pshufb		$t1,@xx[$d3]

	paddd		@xx[$d2],$xc
	 paddd		@xx[$d3],$xc_
	pxor		$xc,@xx[$b2]
	 pxor		$xc_,@xx[$b3]
	movdqa		@xx[$b2],$t0
	pslld		\$12,@xx[$b2]
	psrld		\$20,$t0
	 movdqa		@xx[$b3],$t1
	 pslld		\$12,@xx[$b3]
	por		$t0,@xx[$b2]
	 psrld		\$20,$t1
	movdqa		(%r11),$t0		# .Lrot24(%rip)
	 por		$t1,@xx[$b3]

	paddd		@xx[$b2],@xx[$a2]
	 paddd		@xx[$b3],@xx[$a3]
	pxor		@xx[$a2],@xx[$d2]
	 pxor		@xx[$a3],@xx[$d3]
	pshufb		$t0,@xx[$d2]
	 pshufb		$t0,@xx[$d3]

	paddd		@xx[$d2],$xc
	 paddd		@xx[$d3],$xc_
	pxor		$xc,@xx[$b2]
	 pxor		$xc_,@xx[$b3]
	movdqa		@xx[$b2],$t1
	pslld		\$7,@xx[$b2]
	psrld		\$25,$t1
	 movdqa		@xx[$b3],$t0
	 pslld		\$7,@xx[$b3]
	por		$t1,@xx[$b2]
	 psrld		\$25,$t0
	movdqa		(%r10),$t1		# .Lrot16(%rip)
	 por		$t0,@xx[$b3]
___
}

my $xframe = $win64 ? 0xa0 : 0;

$code.=<<___;
.type	ChaCha20_4x,\@function,5
.align	32
ChaCha20_4x:
.LChaCha20_4x:
	mov		%r10,%r11
___
$code.=<<___	if ($avx>1);
	shr		\$32,%r10		# OPENSSL_ia32cap_P+8
	test		\$`1<<5`,%r10		# test AVX2
	jnz		.LChaCha20_8x
___
$code.=<<___;
	cmp		\$192,$len
	ja		.Lproceed4x

	and		\$`1<<26|1<<22`,%r11	# isolate XSAVE+MOVBE
	cmp		\$`1<<22`,%r11		# check for MOVBE without XSAVE
	je		.Ldo_sse3_after_all	# to detect Atom

.Lproceed4x:
	lea		-0x78(%rsp),%r11
	sub		\$0x148+$xframe,%rsp
___
	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x40		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x100	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x140
$code.=<<___	if ($win64);
	movaps		%xmm6,-0x30(%r11)
	movaps		%xmm7,-0x20(%r11)
	movaps		%xmm8,-0x10(%r11)
	movaps		%xmm9,0x00(%r11)
	movaps		%xmm10,0x10(%r11)
	movaps		%xmm11,0x20(%r11)
	movaps		%xmm12,0x30(%r11)
	movaps		%xmm13,0x40(%r11)
	movaps		%xmm14,0x50(%r11)
	movaps		%xmm15,0x60(%r11)
___
$code.=<<___;
	movdqa		.Lsigma(%rip),$xa3	# key[0]
	movdqu		($key),$xb3		# key[1]
	movdqu		16($key),$xt3		# key[2]
	movdqu		($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization
	lea		.Lrot16(%rip),%r10
	lea		.Lrot24(%rip),%r11

	pshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	pshufd		\$0x55,$xa3,$xa1
	movdqa		$xa0,0x40(%rsp)		# ... and offload
	pshufd		\$0xaa,$xa3,$xa2
	movdqa		$xa1,0x50(%rsp)
	pshufd		\$0xff,$xa3,$xa3
	movdqa		$xa2,0x60(%rsp)
	movdqa		$xa3,0x70(%rsp)

	pshufd		\$0x00,$xb3,$xb0
	pshufd		\$0x55,$xb3,$xb1
	movdqa		$xb0,0x80-0x100(%rcx)
	pshufd		\$0xaa,$xb3,$xb2
	movdqa		$xb1,0x90-0x100(%rcx)
	pshufd		\$0xff,$xb3,$xb3
	movdqa		$xb2,0xa0-0x100(%rcx)
	movdqa		$xb3,0xb0-0x100(%rcx)

	pshufd		\$0x00,$xt3,$xt0	# "\$xc0"
	pshufd		\$0x55,$xt3,$xt1	# "\$xc1"
	movdqa		$xt0,0xc0-0x100(%rcx)
	pshufd		\$0xaa,$xt3,$xt2	# "\$xc2"
	movdqa		$xt1,0xd0-0x100(%rcx)
	pshufd		\$0xff,$xt3,$xt3	# "\$xc3"
	movdqa		$xt2,0xe0-0x100(%rcx)
	movdqa		$xt3,0xf0-0x100(%rcx)

	pshufd		\$0x00,$xd3,$xd0
	pshufd		\$0x55,$xd3,$xd1
	paddd		.Linc(%rip),$xd0	# don't save counters yet
	pshufd		\$0xaa,$xd3,$xd2
	movdqa		$xd1,0x110-0x100(%rcx)
	pshufd		\$0xff,$xd3,$xd3
	movdqa		$xd2,0x120-0x100(%rcx)
	movdqa		$xd3,0x130-0x100(%rcx)

	jmp		.Loop_enter4x

.align	32
.Loop_outer4x:
	movdqa		0x40(%rsp),$xa0		# re-load smashed key
	movdqa		0x50(%rsp),$xa1
	movdqa		0x60(%rsp),$xa2
	movdqa		0x70(%rsp),$xa3
	movdqa		0x80-0x100(%rcx),$xb0
	movdqa		0x90-0x100(%rcx),$xb1
	movdqa		0xa0-0x100(%rcx),$xb2
	movdqa		0xb0-0x100(%rcx),$xb3
	movdqa		0xc0-0x100(%rcx),$xt0	# "\$xc0"
	movdqa		0xd0-0x100(%rcx),$xt1	# "\$xc1"
	movdqa		0xe0-0x100(%rcx),$xt2	# "\$xc2"
	movdqa		0xf0-0x100(%rcx),$xt3	# "\$xc3"
	movdqa		0x100-0x100(%rcx),$xd0
	movdqa		0x110-0x100(%rcx),$xd1
	movdqa		0x120-0x100(%rcx),$xd2
	movdqa		0x130-0x100(%rcx),$xd3
	paddd		.Lfour(%rip),$xd0	# next SIMD counters

.Loop_enter4x:
	movdqa		$xt2,0x20(%rsp)		# SIMD equivalent of "@x[10]"
	movdqa		$xt3,0x30(%rsp)		# SIMD equivalent of "@x[11]"
	movdqa		(%r10),$xt3		# .Lrot16(%rip)
	mov		\$10,%eax
	movdqa		$xd0,0x100-0x100(%rcx)	# save SIMD counters
	jmp		.Loop4x

.align	32
.Loop4x:
	${\SSSE3_lane_ROUND(0, 4, 8,12)}
	${\SSSE3_lane_ROUND(0, 5,10,15)}
	dec		%eax
	jnz		.Loop4x

	paddd		0x40(%rsp),$xa0		# accumulate key material
	paddd		0x50(%rsp),$xa1
	paddd		0x60(%rsp),$xa2
	paddd		0x70(%rsp),$xa3

	movdqa		$xa0,$xt2		# "de-interlace" data
	punpckldq	$xa1,$xa0
	movdqa		$xa2,$xt3
	punpckldq	$xa3,$xa2
	punpckhdq	$xa1,$xt2
	punpckhdq	$xa3,$xt3
	movdqa		$xa0,$xa1
	punpcklqdq	$xa2,$xa0		# "a0"
	movdqa		$xt2,$xa3
	punpcklqdq	$xt3,$xt2		# "a2"
	punpckhqdq	$xa2,$xa1		# "a1"
	punpckhqdq	$xt3,$xa3		# "a3"
___
	($xa2,$xt2)=($xt2,$xa2);
$code.=<<___;
	paddd		0x80-0x100(%rcx),$xb0
	paddd		0x90-0x100(%rcx),$xb1
	paddd		0xa0-0x100(%rcx),$xb2
	paddd		0xb0-0x100(%rcx),$xb3

	movdqa		$xa0,0x00(%rsp)		# offload \$xaN
	movdqa		$xa1,0x10(%rsp)
	movdqa		0x20(%rsp),$xa0		# "xc2"
	movdqa		0x30(%rsp),$xa1		# "xc3"

	movdqa		$xb0,$xt2
	punpckldq	$xb1,$xb0
	movdqa		$xb2,$xt3
	punpckldq	$xb3,$xb2
	punpckhdq	$xb1,$xt2
	punpckhdq	$xb3,$xt3
	movdqa		$xb0,$xb1
	punpcklqdq	$xb2,$xb0		# "b0"
	movdqa		$xt2,$xb3
	punpcklqdq	$xt3,$xt2		# "b2"
	punpckhqdq	$xb2,$xb1		# "b1"
	punpckhqdq	$xt3,$xb3		# "b3"
___
	($xb2,$xt2)=($xt2,$xb2);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	paddd		0xc0-0x100(%rcx),$xc0
	paddd		0xd0-0x100(%rcx),$xc1
	paddd		0xe0-0x100(%rcx),$xc2
	paddd		0xf0-0x100(%rcx),$xc3

	movdqa		$xa2,0x20(%rsp)		# keep offloading \$xaN
	movdqa		$xa3,0x30(%rsp)

	movdqa		$xc0,$xt2
	punpckldq	$xc1,$xc0
	movdqa		$xc2,$xt3
	punpckldq	$xc3,$xc2
	punpckhdq	$xc1,$xt2
	punpckhdq	$xc3,$xt3
	movdqa		$xc0,$xc1
	punpcklqdq	$xc2,$xc0		# "c0"
	movdqa		$xt2,$xc3
	punpcklqdq	$xt3,$xt2		# "c2"
	punpckhqdq	$xc2,$xc1		# "c1"
	punpckhqdq	$xt3,$xc3		# "c3"
___
	($xc2,$xt2)=($xt2,$xc2);
	($xt0,$xt1)=($xa2,$xa3);		# use $xaN as temporary
$code.=<<___;
	paddd		0x100-0x100(%rcx),$xd0
	paddd		0x110-0x100(%rcx),$xd1
	paddd		0x120-0x100(%rcx),$xd2
	paddd		0x130-0x100(%rcx),$xd3

	movdqa		$xd0,$xt2
	punpckldq	$xd1,$xd0
	movdqa		$xd2,$xt3
	punpckldq	$xd3,$xd2
	punpckhdq	$xd1,$xt2
	punpckhdq	$xd3,$xt3
	movdqa		$xd0,$xd1
	punpcklqdq	$xd2,$xd0		# "d0"
	movdqa		$xt2,$xd3
	punpcklqdq	$xt3,$xt2		# "d2"
	punpckhqdq	$xd2,$xd1		# "d1"
	punpckhqdq	$xt3,$xd3		# "d3"
___
	($xd2,$xt2)=($xt2,$xd2);
$code.=<<___;
	cmp		\$64*4,$len
	jb		.Ltail4x

	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# \$xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# size optimization
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3

	 movdqu		$xt0,0x40($out)
	movdqu		0x00($inp),$xt0
	 movdqu		$xt1,0x50($out)
	movdqu		0x10($inp),$xt1
	 movdqu		$xt2,0x60($out)
	movdqu		0x20($inp),$xt2
	 movdqu		$xt3,0x70($out)
	 lea		0x80($out),$out		# size optimization
	movdqu		0x30($inp),$xt3
	pxor		0x20(%rsp),$xt0
	pxor		$xb2,$xt1
	pxor		$xc2,$xt2
	pxor		$xd2,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# inp+=64*4
	pxor		0x30(%rsp),$xt0
	pxor		$xb3,$xt1
	pxor		$xc3,$xt2
	pxor		$xd3,$xt3
	movdqu		$xt0,0x40($out)
	movdqu		$xt1,0x50($out)
	movdqu		$xt2,0x60($out)
	movdqu		$xt3,0x70($out)
	lea		0x80($out),$out		# out+=64*4

	sub		\$64*4,$len
	jnz		.Loop_outer4x

	jmp		.Ldone4x

.Ltail4x:
	cmp		\$192,$len
	jae		.L192_or_more4x
	cmp		\$128,$len
	jae		.L128_or_more4x
	cmp		\$64,$len
	jae		.L64_or_more4x

	#movdqa		0x00(%rsp),$xt0		# \$xaN is offloaded, remember?
	xor		%r10,%r10
	#movdqa		$xt0,0x00(%rsp)
	movdqa		$xb0,0x10(%rsp)
	movdqa		$xc0,0x20(%rsp)
	movdqa		$xd0,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L64_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# \$xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3
	movdqu		$xt0,0x00($out)
	movdqu		$xt1,0x10($out)
	movdqu		$xt2,0x20($out)
	movdqu		$xt3,0x30($out)
	je		.Ldone4x

	movdqa		0x10(%rsp),$xt0		# \$xaN is offloaded, remember?
	lea		0x40($inp),$inp		# inp+=64*1
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb1,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*1
	movdqa		$xc1,0x20(%rsp)
	sub		\$64,$len		# len-=64*1
	movdqa		$xd1,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L128_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# \$xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3
	movdqu		$xt0,0x40($out)
	movdqu		$xt1,0x50($out)
	movdqu		$xt2,0x60($out)
	movdqu		$xt3,0x70($out)
	je		.Ldone4x

	movdqa		0x20(%rsp),$xt0		# \$xaN is offloaded, remember?
	lea		0x80($inp),$inp		# inp+=64*2
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb2,0x10(%rsp)
	lea		0x80($out),$out		# out+=64*2
	movdqa		$xc2,0x20(%rsp)
	sub		\$128,$len		# len-=64*2
	movdqa		$xd2,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L192_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# \$xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# size optimization
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3

	 movdqu		$xt0,0x40($out)
	movdqu		0x00($inp),$xt0
	 movdqu		$xt1,0x50($out)
	movdqu		0x10($inp),$xt1
	 movdqu		$xt2,0x60($out)
	movdqu		0x20($inp),$xt2
	 movdqu		$xt3,0x70($out)
	 lea		0x80($out),$out		# size optimization
	movdqu		0x30($inp),$xt3
	pxor		0x20(%rsp),$xt0
	pxor		$xb2,$xt1
	pxor		$xc2,$xt2
	pxor		$xd2,$xt3
	movdqu		$xt0,0x00($out)
	movdqu		$xt1,0x10($out)
	movdqu		$xt2,0x20($out)
	movdqu		$xt3,0x30($out)
	je		.Ldone4x

	movdqa		0x30(%rsp),$xt0		# \$xaN is offloaded, remember?
	lea		0x40($inp),$inp		# inp+=64*3
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb3,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*3
	movdqa		$xc3,0x20(%rsp)
	sub		\$192,$len		# len-=64*3
	movdqa		$xd3,0x30(%rsp)

.Loop_tail4x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail4x

.Ldone4x:
___
$code.=<<___	if ($win64);
	lea		0x140+0x30(%rsp),%r11
	movaps		-0x30(%r11),%xmm6
	movaps		-0x20(%r11),%xmm7
	movaps		-0x10(%r11),%xmm8
	movaps		0x00(%r11),%xmm9
	movaps		0x10(%r11),%xmm10
	movaps		0x20(%r11),%xmm11
	movaps		0x30(%r11),%xmm12
	movaps		0x40(%r11),%xmm13
	movaps		0x50(%r11),%xmm14
	movaps		0x60(%r11),%xmm15
___
$code.=<<___;
	add		\$0x148+$xframe,%rsp
	ret
.size	ChaCha20_4x,.-ChaCha20_4x
___
}

########################################################################
# XOP code path that handles all lengths.
if ($avx) {
# There is some "anomaly" observed depending on instructions' size or
# alignment. If you look closely at below code you'll notice that
# sometimes argument order varies. The order affects instruction
# encoding by making it larger, and such fiddling gives 5% performance
# improvement. This is on FX-4100...

my ($xb0,$xb1,$xb2,$xb3, $xd0,$xd1,$xd2,$xd3,
    $xa0,$xa1,$xa2,$xa3, $xt0,$xt1,$xt2,$xt3)=map("%xmm$_",(0..15));
my  @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	 $xt0,$xt1,$xt2,$xt3, $xd0,$xd1,$xd2,$xd3);

sub XOP_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));

<<___;
	vpaddd		@xx[$b0],@xx[$a0],@xx[$a0]	# Q1
	 vpaddd		@xx[$b1],@xx[$a1],@xx[$a1]	# Q2
	  vpaddd	@xx[$b2],@xx[$a2],@xx[$a2]	# Q3
	   vpaddd	@xx[$b3],@xx[$a3],@xx[$a3]	# Q4
	vpxor		@xx[$d0],@xx[$a0],@xx[$d0]
	 vpxor		@xx[$d1],@xx[$a1],@xx[$d1]
	  vpxor		@xx[$d2],@xx[$a2],@xx[$d2]
	   vpxor	@xx[$d3],@xx[$a3],@xx[$d3]
	vprotd		\$16,@xx[$d0],@xx[$d0]
	 vprotd		\$16,@xx[$d1],@xx[$d1]
	  vprotd	\$16,@xx[$d2],@xx[$d2]
	   vprotd	\$16,@xx[$d3],@xx[$d3]

	vpaddd		@xx[$d0],@xx[$c0],@xx[$c0]
	 vpaddd		@xx[$d1],@xx[$c1],@xx[$c1]
	  vpaddd	@xx[$d2],@xx[$c2],@xx[$c2]
	   vpaddd	@xx[$d3],@xx[$c3],@xx[$c3]
	vpxor		@xx[$b0],@xx[$c0],@xx[$b0]
	 vpxor		@xx[$b1],@xx[$c1],@xx[$b1]
	  vpxor		@xx[$c2],@xx[$b2],@xx[$b2]	# flip
	   vpxor	@xx[$c3],@xx[$b3],@xx[$b3]	# flip
	vprotd		\$12,@xx[$b0],@xx[$b0]
	 vprotd		\$12,@xx[$b1],@xx[$b1]
	  vprotd	\$12,@xx[$b2],@xx[$b2]
	   vprotd	\$12,@xx[$b3],@xx[$b3]

	vpaddd		@xx[$a0],@xx[$b0],@xx[$a0]	# flip
	 vpaddd		@xx[$a1],@xx[$b1],@xx[$a1]	# flip
	  vpaddd	@xx[$b2],@xx[$a2],@xx[$a2]
	   vpaddd	@xx[$b3],@xx[$a3],@xx[$a3]
	vpxor		@xx[$d0],@xx[$a0],@xx[$d0]
	 vpxor		@xx[$d1],@xx[$a1],@xx[$d1]
	  vpxor		@xx[$d2],@xx[$a2],@xx[$d2]
	   vpxor	@xx[$d3],@xx[$a3],@xx[$d3]
	vprotd		\$8,@xx[$d0],@xx[$d0]
	 vprotd		\$8,@xx[$d1],@xx[$d1]
	  vprotd	\$8,@xx[$d2],@xx[$d2]
	   vprotd	\$8,@xx[$d3],@xx[$d3]

	vpaddd		@xx[$d0],@xx[$c0],@xx[$c0]
	 vpaddd		@xx[$d1],@xx[$c1],@xx[$c1]
	  vpaddd	@xx[$d2],@xx[$c2],@xx[$c2]
	   vpaddd	@xx[$d3],@xx[$c3],@xx[$c3]
	vpxor		@xx[$b0],@xx[$c0],@xx[$b0]
	 vpxor		@xx[$b1],@xx[$c1],@xx[$b1]
	  vpxor		@xx[$c2],@xx[$b2],@xx[$b2]	# flip
	   vpxor	@xx[$c3],@xx[$b3],@xx[$b3]	# flip
	vprotd		\$7,@xx[$b0],@xx[$b0]
	 vprotd		\$7,@xx[$b1],@xx[$b1]
	  vprotd	\$7,@xx[$b2],@xx[$b2]
	   vprotd	\$7,@xx[$b3],@xx[$b3]
___
}

my $xframe = $win64 ? 0xa0 : 0;

$code.=<<___;
.type	ChaCha20_4xop,\@function,5
.align	32
ChaCha20_4xop:
.LChaCha20_4xop:
	lea		-0x78(%rsp),%r11
	sub		\$0x148+$xframe,%rsp
___
	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x40		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x100	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x140
$code.=<<___	if ($win64);
	movaps		%xmm6,-0x30(%r11)
	movaps		%xmm7,-0x20(%r11)
	movaps		%xmm8,-0x10(%r11)
	movaps		%xmm9,0x00(%r11)
	movaps		%xmm10,0x10(%r11)
	movaps		%xmm11,0x20(%r11)
	movaps		%xmm12,0x30(%r11)
	movaps		%xmm13,0x40(%r11)
	movaps		%xmm14,0x50(%r11)
	movaps		%xmm15,0x60(%r11)
___
$code.=<<___;
	vzeroupper

	vmovdqa		.Lsigma(%rip),$xa3	# key[0]
	vmovdqu		($key),$xb3		# key[1]
	vmovdqu		16($key),$xt3		# key[2]
	vmovdqu		($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vmovdqa		$xa0,0x40(%rsp)		# ... and offload
	vpshufd		\$0xaa,$xa3,$xa2
	vmovdqa		$xa1,0x50(%rsp)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa		$xa2,0x60(%rsp)
	vmovdqa		$xa3,0x70(%rsp)

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vmovdqa		$xb0,0x80-0x100(%rcx)
	vpshufd		\$0xaa,$xb3,$xb2
	vmovdqa		$xb1,0x90-0x100(%rcx)
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa		$xb2,0xa0-0x100(%rcx)
	vmovdqa		$xb3,0xb0-0x100(%rcx)

	vpshufd		\$0x00,$xt3,$xt0	# "\$xc0"
	vpshufd		\$0x55,$xt3,$xt1	# "\$xc1"
	vmovdqa		$xt0,0xc0-0x100(%rcx)
	vpshufd		\$0xaa,$xt3,$xt2	# "\$xc2"
	vmovdqa		$xt1,0xd0-0x100(%rcx)
	vpshufd		\$0xff,$xt3,$xt3	# "\$xc3"
	vmovdqa		$xt2,0xe0-0x100(%rcx)
	vmovdqa		$xt3,0xf0-0x100(%rcx)

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpaddd		.Linc(%rip),$xd0,$xd0	# don't save counters yet
	vpshufd		\$0xaa,$xd3,$xd2
	vmovdqa		$xd1,0x110-0x100(%rcx)
	vpshufd		\$0xff,$xd3,$xd3
	vmovdqa		$xd2,0x120-0x100(%rcx)
	vmovdqa		$xd3,0x130-0x100(%rcx)

	jmp		.Loop_enter4xop

.align	32
.Loop_outer4xop:
	vmovdqa		0x40(%rsp),$xa0		# re-load smashed key
	vmovdqa		0x50(%rsp),$xa1
	vmovdqa		0x60(%rsp),$xa2
	vmovdqa		0x70(%rsp),$xa3
	vmovdqa		0x80-0x100(%rcx),$xb0
	vmovdqa		0x90-0x100(%rcx),$xb1
	vmovdqa		0xa0-0x100(%rcx),$xb2
	vmovdqa		0xb0-0x100(%rcx),$xb3
	vmovdqa		0xc0-0x100(%rcx),$xt0	# "\$xc0"
	vmovdqa		0xd0-0x100(%rcx),$xt1	# "\$xc1"
	vmovdqa		0xe0-0x100(%rcx),$xt2	# "\$xc2"
	vmovdqa		0xf0-0x100(%rcx),$xt3	# "\$xc3"
	vmovdqa		0x100-0x100(%rcx),$xd0
	vmovdqa		0x110-0x100(%rcx),$xd1
	vmovdqa		0x120-0x100(%rcx),$xd2
	vmovdqa		0x130-0x100(%rcx),$xd3
	vpaddd		.Lfour(%rip),$xd0,$xd0	# next SIMD counters

.Loop_enter4xop:
	mov		\$10,%eax
	vmovdqa		$xd0,0x100-0x100(%rcx)	# save SIMD counters
	jmp		.Loop4xop

.align	32
.Loop4xop:
	${\XOP_lane_ROUND(0, 4, 8,12)}
	${\XOP_lane_ROUND(0, 5,10,15)}
	dec		%eax
	jnz		.Loop4xop

	vpaddd		0x40(%rsp),$xa0,$xa0	# accumulate key material
	vpaddd		0x50(%rsp),$xa1,$xa1
	vpaddd		0x60(%rsp),$xa2,$xa2
	vpaddd		0x70(%rsp),$xa3,$xa3

	vmovdqa		$xt2,0x20(%rsp)		# offload \$xc2,3
	vmovdqa		$xt3,0x30(%rsp)

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
        ($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		0x80-0x100(%rcx),$xb0,$xb0
	vpaddd		0x90-0x100(%rcx),$xb1,$xb1
	vpaddd		0xa0-0x100(%rcx),$xb2,$xb2
	vpaddd		0xb0-0x100(%rcx),$xb3,$xb3

	vmovdqa		$xa0,0x00(%rsp)		# offload $xa0,1
	vmovdqa		$xa1,0x10(%rsp)
	vmovdqa		0x20(%rsp),$xa0		# "xc2"
	vmovdqa		0x30(%rsp),$xa1		# "xc3"

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	vpaddd		0xc0-0x100(%rcx),$xc0,$xc0
	vpaddd		0xd0-0x100(%rcx),$xc1,$xc1
	vpaddd		0xe0-0x100(%rcx),$xc2,$xc2
	vpaddd		0xf0-0x100(%rcx),$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		0x100-0x100(%rcx),$xd0,$xd0
	vpaddd		0x110-0x100(%rcx),$xd1,$xd1
	vpaddd		0x120-0x100(%rcx),$xd2,$xd2
	vpaddd		0x130-0x100(%rcx),$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
	($xa0,$xa1)=($xt2,$xt3);
$code.=<<___;
	vmovdqa		0x00(%rsp),$xa0		# restore $xa0,1
	vmovdqa		0x10(%rsp),$xa1

	cmp		\$64*4,$len
	jb		.Ltail4xop

	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x10($inp),$xb2,$xb2
	vpxor		0x20($inp),$xc2,$xc2
	vpxor		0x30($inp),$xd2,$xd2
	vpxor		0x40($inp),$xa3,$xa3
	vpxor		0x50($inp),$xb3,$xb3
	vpxor		0x60($inp),$xc3,$xc3
	vpxor		0x70($inp),$xd3,$xd3
	lea		0x80($inp),$inp		# inp+=64*4

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	lea		0x80($out),$out		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x10($out)
	vmovdqu		$xc2,0x20($out)
	vmovdqu		$xd2,0x30($out)
	vmovdqu		$xa3,0x40($out)
	vmovdqu		$xb3,0x50($out)
	vmovdqu		$xc3,0x60($out)
	vmovdqu		$xd3,0x70($out)
	lea		0x80($out),$out		# out+=64*4

	sub		\$64*4,$len
	jnz		.Loop_outer4xop

	jmp		.Ldone4xop

.align	32
.Ltail4xop:
	cmp		\$192,$len
	jae		.L192_or_more4xop
	cmp		\$128,$len
	jae		.L128_or_more4xop
	cmp		\$64,$len
	jae		.L64_or_more4xop

	xor		%r10,%r10
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x10(%rsp)
	vmovdqa		$xc0,0x20(%rsp)
	vmovdqa		$xd0,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L64_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	je		.Ldone4xop

	lea		0x40($inp),$inp		# inp+=64*1
	vmovdqa		$xa1,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb1,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*1
	vmovdqa		$xc1,0x20(%rsp)
	sub		\$64,$len		# len-=64*1
	vmovdqa		$xd1,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L128_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	je		.Ldone4xop

	lea		0x80($inp),$inp		# inp+=64*2
	vmovdqa		$xa2,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb2,0x10(%rsp)
	lea		0x80($out),$out		# out+=64*2
	vmovdqa		$xc2,0x20(%rsp)
	sub		\$128,$len		# len-=64*2
	vmovdqa		$xd2,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L192_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x10($inp),$xb2,$xb2
	vpxor		0x20($inp),$xc2,$xc2
	vpxor		0x30($inp),$xd2,$xd2

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	lea		0x80($out),$out		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x10($out)
	vmovdqu		$xc2,0x20($out)
	vmovdqu		$xd2,0x30($out)
	je		.Ldone4xop

	lea		0x40($inp),$inp		# inp+=64*3
	vmovdqa		$xa3,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb3,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*3
	vmovdqa		$xc3,0x20(%rsp)
	sub		\$192,$len		# len-=64*3
	vmovdqa		$xd3,0x30(%rsp)

.Loop_tail4xop:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail4xop

.Ldone4xop:
	vzeroupper
___
$code.=<<___	if ($win64);
	lea		0x140+0x30(%rsp),%r11
	movaps		-0x30(%r11),%xmm6
	movaps		-0x20(%r11),%xmm7
	movaps		-0x10(%r11),%xmm8
	movaps		0x00(%r11),%xmm9
	movaps		0x10(%r11),%xmm10
	movaps		0x20(%r11),%xmm11
	movaps		0x30(%r11),%xmm12
	movaps		0x40(%r11),%xmm13
	movaps		0x50(%r11),%xmm14
	movaps		0x60(%r11),%xmm15
___
$code.=<<___;
	add		\$0x148+$xframe,%rsp
	ret
.size	ChaCha20_4xop,.-ChaCha20_4xop
___
}

########################################################################
# AVX2 code path
if ($avx>1) {
my ($xb0,$xb1,$xb2,$xb3, $xd0,$xd1,$xd2,$xd3,
    $xa0,$xa1,$xa2,$xa3, $xt0,$xt1,$xt2,$xt3)=map("%ymm$_",(0..15));
my @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	"%nox","%nox","%nox","%nox", $xd0,$xd1,$xd2,$xd3);

sub AVX2_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_,$t0,$t1)=($xt0,$xt1,$xt2,$xt3);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @xx[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

<<___;
	vpaddd		@xx[$b0],@xx[$a0],@xx[$a0]	# Q1
	vpxor		@xx[$d0],@xx[$a0],@xx[$d0]
	vpshufb		$t1,@xx[$d0],@xx[$d0]
	 vpaddd		@xx[$b1],@xx[$a1],@xx[$a1]	# Q2
	 vpxor		@xx[$d1],@xx[$a1],@xx[$d1]
	 vpshufb	$t1,@xx[$d1],@xx[$d1]

	vpaddd		@xx[$d0],$xc,$xc
	vpxor		@xx[$b0],$xc,@xx[$b0]
	vpslld		\$12,@xx[$b0],$t0
	vpsrld		\$20,@xx[$b0],@xx[$b0]
	vpor		@xx[$b0],$t0,@xx[$b0]
	vbroadcasti128	(%r11),$t0			# .Lrot24(%rip)
	 vpaddd		@xx[$d1],$xc_,$xc_
	 vpxor		@xx[$b1],$xc_,@xx[$b1]
	 vpslld		\$12,@xx[$b1],$t1
	 vpsrld		\$20,@xx[$b1],@xx[$b1]
	 vpor		@xx[$b1],$t1,@xx[$b1]

	vpaddd		@xx[$b0],@xx[$a0],@xx[$a0]
	vpxor		@xx[$d0],@xx[$a0],@xx[$d0]
	vpshufb		$t0,@xx[$d0],@xx[$d0]
	 vpaddd		@xx[$b1],@xx[$a1],@xx[$a1]
	 vpxor		@xx[$d1],@xx[$a1],@xx[$d1]
	 vpshufb	$t0,@xx[$d1],@xx[$d1]

	vpaddd		@xx[$d0],$xc,$xc
	vpxor		@xx[$b0],$xc,@xx[$b0]
	vpslld		\$7,@xx[$b0],$t1
	vpsrld		\$25,@xx[$b0],@xx[$b0]
	vpor		@xx[$b0],$t1,@xx[$b0]
	vbroadcasti128	(%r10),$t1			# .Lrot16(%rip)
	 vpaddd		@xx[$d1],$xc_,$xc_
	 vpxor		@xx[$b1],$xc_,@xx[$b1]
	 vpslld		\$7,@xx[$b1],$t0
	 vpsrld		\$25,@xx[$b1],@xx[$b1]
	 vpor		@xx[$b1],$t0,@xx[$b1]

	vmovdqa		$xc,`32*($c0-8)`(%rsp)		# reload pair of 'c's
	 vmovdqa	$xc_,`32*($c1-8)`(%rsp)
	vmovdqa		`32*($c2-8)`(%rsp),$xc
	 vmovdqa	`32*($c3-8)`(%rsp),$xc_

	vpaddd		@xx[$b2],@xx[$a2],@xx[$a2]	# Q3
	vpxor		@xx[$d2],@xx[$a2],@xx[$d2]
	vpshufb		$t1,@xx[$d2],@xx[$d2]
	 vpaddd		@xx[$b3],@xx[$a3],@xx[$a3]	# Q4
	 vpxor		@xx[$d3],@xx[$a3],@xx[$d3]
	 vpshufb	$t1,@xx[$d3],@xx[$d3]

	vpaddd		@xx[$d2],$xc,$xc
	vpxor		@xx[$b2],$xc,@xx[$b2]
	vpslld		\$12,@xx[$b2],$t0
	vpsrld		\$20,@xx[$b2],@xx[$b2]
	vpor		@xx[$b2],$t0,@xx[$b2]
	vbroadcasti128	(%r11),$t0			# .Lrot24(%rip)
	 vpaddd		@xx[$d3],$xc_,$xc_
	 vpxor		@xx[$b3],$xc_,@xx[$b3]
	 vpslld		\$12,@xx[$b3],$t1
	 vpsrld		\$20,@xx[$b3],@xx[$b3]
	 vpor		@xx[$b3],$t1,@xx[$b3]

	vpaddd		@xx[$b2],@xx[$a2],@xx[$a2]
	vpxor		@xx[$d2],@xx[$a2],@xx[$d2]
	vpshufb		$t0,@xx[$d2],@xx[$d2]
	 vpaddd		@xx[$b3],@xx[$a3],@xx[$a3]
	 vpxor		@xx[$d3],@xx[$a3],@xx[$d3]
	 vpshufb	$t0,@xx[$d3],@xx[$d3]

	vpaddd		@xx[$d2],$xc,$xc
	vpxor		@xx[$b2],$xc,@xx[$b2]
	vpslld		\$7,@xx[$b2],$t1
	vpsrld		\$25,@xx[$b2],@xx[$b2]
	vpor		@xx[$b2],$t1,@xx[$b2]
	vbroadcasti128	(%r10),$t1			# .Lrot16(%rip)
	 vpaddd		@xx[$d3],$xc_,$xc_
	 vpxor		@xx[$b3],$xc_,@xx[$b3]
	 vpslld		\$7,@xx[$b3],$t0
	 vpsrld		\$25,@xx[$b3],@xx[$b3]
	 vpor		@xx[$b3],$t0,@xx[$b3]
___
}

my $xframe = $win64 ? 0xb0 : 8;

$code.=<<___;
.type	ChaCha20_8x,\@function,5
.align	32
ChaCha20_8x:
.LChaCha20_8x:
	mov		%rsp,%r10
	sub		\$0x280+$xframe,%rsp
	and		\$-32,%rsp
___
$code.=<<___	if ($win64);
	lea		0x290+0x30(%rsp),%r11
	movaps		%xmm6,-0x30(%r11)
	movaps		%xmm7,-0x20(%r11)
	movaps		%xmm8,-0x10(%r11)
	movaps		%xmm9,0x00(%r11)
	movaps		%xmm10,0x10(%r11)
	movaps		%xmm11,0x20(%r11)
	movaps		%xmm12,0x30(%r11)
	movaps		%xmm13,0x40(%r11)
	movaps		%xmm14,0x50(%r11)
	movaps		%xmm15,0x60(%r11)
___
$code.=<<___;
	vzeroupper
	mov		%r10,0x280(%rsp)

	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x80		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x200	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x280	saved %rsp

	vbroadcasti128	.Lsigma(%rip),$xa3	# key[0]
	vbroadcasti128	($key),$xb3		# key[1]
	vbroadcasti128	16($key),$xt3		# key[2]
	vbroadcasti128	($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization
	lea		0x200(%rsp),%rax	# size optimization
	lea		.Lrot16(%rip),%r10
	lea		.Lrot24(%rip),%r11

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vmovdqa		$xa0,0x80-0x100(%rcx)	# ... and offload
	vpshufd		\$0xaa,$xa3,$xa2
	vmovdqa		$xa1,0xa0-0x100(%rcx)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa		$xa2,0xc0-0x100(%rcx)
	vmovdqa		$xa3,0xe0-0x100(%rcx)

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vmovdqa		$xb0,0x100-0x100(%rcx)
	vpshufd		\$0xaa,$xb3,$xb2
	vmovdqa		$xb1,0x120-0x100(%rcx)
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa		$xb2,0x140-0x100(%rcx)
	vmovdqa		$xb3,0x160-0x100(%rcx)

	vpshufd		\$0x00,$xt3,$xt0	# "xc0"
	vpshufd		\$0x55,$xt3,$xt1	# "xc1"
	vmovdqa		$xt0,0x180-0x200(%rax)
	vpshufd		\$0xaa,$xt3,$xt2	# "xc2"
	vmovdqa		$xt1,0x1a0-0x200(%rax)
	vpshufd		\$0xff,$xt3,$xt3	# "xc3"
	vmovdqa		$xt2,0x1c0-0x200(%rax)
	vmovdqa		$xt3,0x1e0-0x200(%rax)

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpaddd		.Lincy(%rip),$xd0,$xd0	# don't save counters yet
	vpshufd		\$0xaa,$xd3,$xd2
	vmovdqa		$xd1,0x220-0x200(%rax)
	vpshufd		\$0xff,$xd3,$xd3
	vmovdqa		$xd2,0x240-0x200(%rax)
	vmovdqa		$xd3,0x260-0x200(%rax)

	jmp		.Loop_enter8x

.align	32
.Loop_outer8x:
	vmovdqa		0x80-0x100(%rcx),$xa0	# re-load smashed key
	vmovdqa		0xa0-0x100(%rcx),$xa1
	vmovdqa		0xc0-0x100(%rcx),$xa2
	vmovdqa		0xe0-0x100(%rcx),$xa3
	vmovdqa		0x100-0x100(%rcx),$xb0
	vmovdqa		0x120-0x100(%rcx),$xb1
	vmovdqa		0x140-0x100(%rcx),$xb2
	vmovdqa		0x160-0x100(%rcx),$xb3
	vmovdqa		0x180-0x200(%rax),$xt0	# "xc0"
	vmovdqa		0x1a0-0x200(%rax),$xt1	# "xc1"
	vmovdqa		0x1c0-0x200(%rax),$xt2	# "xc2"
	vmovdqa		0x1e0-0x200(%rax),$xt3	# "xc3"
	vmovdqa		0x200-0x200(%rax),$xd0
	vmovdqa		0x220-0x200(%rax),$xd1
	vmovdqa		0x240-0x200(%rax),$xd2
	vmovdqa		0x260-0x200(%rax),$xd3
	vpaddd		.Leight(%rip),$xd0,$xd0	# next SIMD counters

.Loop_enter8x:
	vmovdqa		$xt2,0x40(%rsp)		# SIMD equivalent of "@x[10]"
	vmovdqa		$xt3,0x60(%rsp)		# SIMD equivalent of "@x[11]"
	vbroadcasti128	(%r10),$xt3
	vmovdqa		$xd0,0x200-0x200(%rax)	# save SIMD counters
	mov		\$10,%eax
	jmp		.Loop8x

.align	32
.Loop8x:
	${\AVX2_lane_ROUND(0, 4, 8,12)}
	${\AVX2_lane_ROUND(0, 5,10,15)}
	dec		%eax
	jnz		.Loop8x

	lea		0x200(%rsp),%rax	# size optimization
	vpaddd		0x80-0x100(%rcx),$xa0,$xa0	# accumulate key
	vpaddd		0xa0-0x100(%rcx),$xa1,$xa1
	vpaddd		0xc0-0x100(%rcx),$xa2,$xa2
	vpaddd		0xe0-0x100(%rcx),$xa3,$xa3

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		0x100-0x100(%rcx),$xb0,$xb0
	vpaddd		0x120-0x100(%rcx),$xb1,$xb1
	vpaddd		0x140-0x100(%rcx),$xb2,$xb2
	vpaddd		0x160-0x100(%rcx),$xb3,$xb3

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vperm2i128	\$0x20,$xb0,$xa0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xb0,$xa0,$xb0
	vperm2i128	\$0x20,$xb1,$xa1,$xa0
	vperm2i128	\$0x31,$xb1,$xa1,$xb1
	vperm2i128	\$0x20,$xb2,$xa2,$xa1
	vperm2i128	\$0x31,$xb2,$xa2,$xb2
	vperm2i128	\$0x20,$xb3,$xa3,$xa2
	vperm2i128	\$0x31,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	vmovdqa		$xa0,0x00(%rsp)		# offload \$xaN
	vmovdqa		$xa1,0x20(%rsp)
	vmovdqa		0x40(%rsp),$xc2		# $xa0
	vmovdqa		0x60(%rsp),$xc3		# $xa1

	vpaddd		0x180-0x200(%rax),$xc0,$xc0
	vpaddd		0x1a0-0x200(%rax),$xc1,$xc1
	vpaddd		0x1c0-0x200(%rax),$xc2,$xc2
	vpaddd		0x1e0-0x200(%rax),$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		0x200-0x200(%rax),$xd0,$xd0
	vpaddd		0x220-0x200(%rax),$xd1,$xd1
	vpaddd		0x240-0x200(%rax),$xd2,$xd2
	vpaddd		0x260-0x200(%rax),$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vperm2i128	\$0x20,$xd0,$xc0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xd0,$xc0,$xd0
	vperm2i128	\$0x20,$xd1,$xc1,$xc0
	vperm2i128	\$0x31,$xd1,$xc1,$xd1
	vperm2i128	\$0x20,$xd2,$xc2,$xc1
	vperm2i128	\$0x31,$xd2,$xc2,$xd2
	vperm2i128	\$0x20,$xd3,$xc3,$xc2
	vperm2i128	\$0x31,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
	($xb0,$xb1,$xb2,$xb3,$xc0,$xc1,$xc2,$xc3)=
	($xc0,$xc1,$xc2,$xc3,$xb0,$xb1,$xb2,$xb3);
	($xa0,$xa1)=($xt2,$xt3);
$code.=<<___;
	vmovdqa		0x00(%rsp),$xa0		# \$xaN was offloaded, remember?
	vmovdqa		0x20(%rsp),$xa1

	cmp		\$64*8,$len
	jb		.Ltail8x

	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa1,$xa1
	vpxor		0x20($inp),$xb1,$xb1
	vpxor		0x40($inp),$xc1,$xc1
	vpxor		0x60($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa1,0x00($out)
	vmovdqu		$xb1,0x20($out)
	vmovdqu		$xc1,0x40($out)
	vmovdqu		$xd1,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x20($inp),$xb2,$xb2
	vpxor		0x40($inp),$xc2,$xc2
	vpxor		0x60($inp),$xd2,$xd2
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x20($out)
	vmovdqu		$xc2,0x40($out)
	vmovdqu		$xd2,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa3,$xa3
	vpxor		0x20($inp),$xb3,$xb3
	vpxor		0x40($inp),$xc3,$xc3
	vpxor		0x60($inp),$xd3,$xd3
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa3,0x00($out)
	vmovdqu		$xb3,0x20($out)
	vmovdqu		$xc3,0x40($out)
	vmovdqu		$xd3,0x60($out)
	lea		0x80($out),$out		# size optimization

	sub		\$64*8,$len
	jnz		.Loop_outer8x

	jmp		.Ldone8x

.Ltail8x:
	cmp		\$448,$len
	jae		.L448_or_more8x
	cmp		\$384,$len
	jae		.L384_or_more8x
	cmp		\$320,$len
	jae		.L320_or_more8x
	cmp		\$256,$len
	jae		.L256_or_more8x
	cmp		\$192,$len
	jae		.L192_or_more8x
	cmp		\$128,$len
	jae		.L128_or_more8x
	cmp		\$64,$len
	jae		.L64_or_more8x

	xor		%r10,%r10
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L64_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	je		.Ldone8x

	lea		0x40($inp),$inp		# inp+=64*1
	xor		%r10,%r10
	vmovdqa		$xc0,0x00(%rsp)
	lea		0x40($out),$out		# out+=64*1
	sub		\$64,$len		# len-=64*1
	vmovdqa		$xd0,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L128_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	je		.Ldone8x

	lea		0x80($inp),$inp		# inp+=64*2
	xor		%r10,%r10
	vmovdqa		$xa1,0x00(%rsp)
	lea		0x80($out),$out		# out+=64*2
	sub		\$128,$len		# len-=64*2
	vmovdqa		$xb1,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L192_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	je		.Ldone8x

	lea		0xc0($inp),$inp		# inp+=64*3
	xor		%r10,%r10
	vmovdqa		$xc1,0x00(%rsp)
	lea		0xc0($out),$out		# out+=64*3
	sub		\$192,$len		# len-=64*3
	vmovdqa		$xd1,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L256_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	je		.Ldone8x

	lea		0x100($inp),$inp	# inp+=64*4
	xor		%r10,%r10
	vmovdqa		$xa2,0x00(%rsp)
	lea		0x100($out),$out	# out+=64*4
	sub		\$256,$len		# len-=64*4
	vmovdqa		$xb2,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L320_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	je		.Ldone8x

	lea		0x140($inp),$inp	# inp+=64*5
	xor		%r10,%r10
	vmovdqa		$xc2,0x00(%rsp)
	lea		0x140($out),$out	# out+=64*5
	sub		\$320,$len		# len-=64*5
	vmovdqa		$xd2,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L384_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	je		.Ldone8x

	lea		0x180($inp),$inp	# inp+=64*6
	xor		%r10,%r10
	vmovdqa		$xa3,0x00(%rsp)
	lea		0x180($out),$out	# out+=64*6
	sub		\$384,$len		# len-=64*6
	vmovdqa		$xb3,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L448_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vpxor		0x180($inp),$xa3,$xa3
	vpxor		0x1a0($inp),$xb3,$xb3
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	vmovdqu		$xa3,0x180($out)
	vmovdqu		$xb3,0x1a0($out)
	je		.Ldone8x

	lea		0x1c0($inp),$inp	# inp+=64*7
	xor		%r10,%r10
	vmovdqa		$xc3,0x00(%rsp)
	lea		0x1c0($out),$out	# out+=64*7
	sub		\$448,$len		# len-=64*7
	vmovdqa		$xd3,0x20(%rsp)

.Loop_tail8x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail8x

.Ldone8x:
	vzeroall
___
$code.=<<___	if ($win64);
	lea		0x290+0x30(%rsp),%r11
	movaps		-0x30(%r11),%xmm6
	movaps		-0x20(%r11),%xmm7
	movaps		-0x10(%r11),%xmm8
	movaps		0x00(%r11),%xmm9
	movaps		0x10(%r11),%xmm10
	movaps		0x20(%r11),%xmm11
	movaps		0x30(%r11),%xmm12
	movaps		0x40(%r11),%xmm13
	movaps		0x50(%r11),%xmm14
	movaps		0x60(%r11),%xmm15
___
$code.=<<___;
	mov		0x280(%rsp),%rsp
	ret
.size	ChaCha20_8x,.-ChaCha20_8x
___
}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/geo;

	s/%x#%y/%x/go;

	print $_,"\n";
}

close STDOUT;
