#!/usr/bin/env perl

# ====================================================================
# Written by David S. Miller <davem@devemloft.net> and Andy Polyakov
# <appro@openssl.org>. The module is licensed under 2-clause BSD
# license. November 2012. All rights reserved.
# ====================================================================

######################################################################
# Montgomery squaring-n-multiplication module for SPARC T4.
#
# The module consists of three parts:
#
# 1) collection of "single-op" subroutines that perform single
#    operation, Montgomery squaring or multiplication, on 512-,
#    1024-, 1536- and 2048-bit operands;
# 2) collection of "multi-op" subroutines that perform 5 squaring and
#    1 multiplication operations on operands of above lengths;
# 3) fall-back and helper VIS3 subroutines.
#
# RSA sign is dominated by multi-op subroutine, while RSA verify and
# DSA - by single-op. Special note about 4096-bit RSA verify result.
# Operands are too long for dedicated hardware and it's handled by
# VIS3 code, which is why you don't see any improvement. It's surely
# possible to improve it [by deploying 'mpmul' instruction], maybe in
# the future...
#
# Performance improvement.
#
# 64-bit process, VIS3:
#                   sign    verify    sign/s verify/s
# rsa 1024 bits 0.000633s 0.000033s   1578.9  30513.3
# rsa 2048 bits 0.003297s 0.000116s    303.3   8585.8
# rsa 4096 bits 0.026000s 0.000387s     38.5   2587.0
# dsa 1024 bits 0.000301s 0.000332s   3323.7   3013.9
# dsa 2048 bits 0.001056s 0.001233s    946.9    810.8
#
# 64-bit process, this module:
#                   sign    verify    sign/s verify/s
# rsa 1024 bits 0.000341s 0.000021s   2931.5  46873.8
# rsa 2048 bits 0.001244s 0.000044s    803.9  22569.1
# rsa 4096 bits 0.006203s 0.000387s    161.2   2586.3
# dsa 1024 bits 0.000179s 0.000195s   5573.9   5115.6
# dsa 2048 bits 0.000311s 0.000350s   3212.3   2856.6
#
######################################################################
# 32-bit process, VIS3:
#                   sign    verify    sign/s verify/s
# rsa 1024 bits 0.000675s 0.000033s   1480.9  30159.0
# rsa 2048 bits 0.003383s 0.000118s    295.6   8499.9
# rsa 4096 bits 0.026178s 0.000394s     38.2   2541.3
# dsa 1024 bits 0.000326s 0.000343s   3070.0   2918.8
# dsa 2048 bits 0.001121s 0.001291s    891.9    774.4
#
# 32-bit process, this module:
#                   sign    verify    sign/s verify/s
# rsa 1024 bits 0.000386s 0.000022s   2589.6  45704.9
# rsa 2048 bits 0.001335s 0.000046s    749.3  21766.8
# rsa 4096 bits 0.006390s 0.000393s    156.5   2544.8
# dsa 1024 bits 0.000208s 0.000204s   4817.6   4896.6
# dsa 2048 bits 0.000345s 0.000364s   2898.8   2747.3
#
# 32-bit code is prone to performance degradation as interrupt rate
# dispatched to CPU executing the code grows. This is because in
# standard process of handling interrupt in 32-bit process context
# upper halves of most integer registers used as input or output are
# zeroed. This renders result invalid, and operation has to be re-run.
# If CPU is "bothered" with timer interrupts only, the penalty is
# hardly measurable. But in order to mitigate this problem for higher
# interrupt rates contemporary Linux kernel recognizes biased stack
# even in 32-bit process context and preserves full register contents.
# See http://git.kernel.org/?p=linux/kernel/git/torvalds/linux.git;h=517ffce4e1a03aea979fe3a18a3dd1761a24fafb
# for details.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "sparcv9_modes.pl";

$code.=<<___;
#include "sparc_arch.h"

#ifdef	__arch64__
.register	%g2,#scratch
.register	%g3,#scratch
#endif

.section	".text",#alloc,#execinstr

#ifdef	__PIC__
SPARC_PIC_THUNK(%g1)
#endif
___

########################################################################
# Register layout for mont[mul|sqr] instructions.
# For details see "Oracle SPARC Architecture 2011" manual at
# http://www.oracle.com/technetwork/server-storage/sun-sparc-enterprise/documentation/.
#
my @R=map("%f".2*$_,(0..11,30,31,12..29));
my @N=(map("%l$_",(0..7)),map("%o$_",(0..5))); @N=(@N,@N,@N[0..3]);
my @B=(map("%o$_",(0..5)),@N[0..13],@N[0..11]);
my @A=(@N[0..13],@R[14..31]);

########################################################################
# int bn_mul_mont_t4_$NUM(u64 *rp,const u64 *ap,const u64 *bp,
#			  const u64 *np,const BN_ULONG *n0);
#
sub generate_bn_mul_mont_t4() {
my $NUM=shift;
my ($rp,$ap,$bp,$np,$sentinel)=map("%g$_",(1..5));

$code.=<<___;
.globl	bn_mul_mont_t4_$NUM
.align	32
bn_mul_mont_t4_$NUM:
#ifdef	__arch64__
	mov	0,$sentinel
	mov	-128,%g4
#elif defined(SPARCV9_64BIT_STACK)
	SPARC_LOAD_ADDRESS_LEAF(OPENSSL_sparcv9cap_P,%g1,%g5)
	ld	[%g1+0],%g1	! OPENSSL_sparcv9_P[0]
	mov	-2047,%g4
	and	%g1,SPARCV9_64BIT_STACK,%g1
	movrz	%g1,0,%g4
	mov	-1,$sentinel
	add	%g4,-128,%g4
#else
	mov	-1,$sentinel
	mov	-128,%g4
#endif
	sllx	$sentinel,32,$sentinel
	save	%sp,%g4,%sp
#ifndef	__arch64__
	save	%sp,-128,%sp	! warm it up
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	restore
	restore
	restore
	restore
	restore
	restore
#endif
	and	%sp,1,%g4
	or	$sentinel,%fp,%fp
	or	%g4,$sentinel,$sentinel

	! copy arguments to global registers
	mov	%i0,$rp
	mov	%i1,$ap
	mov	%i2,$bp
	mov	%i3,$np
	ld	[%i4+0],%f1	! load *n0
	ld	[%i4+4],%f0
	fsrc2	%f0,%f60
___

# load ap[$NUM] ########################################################
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for($i=0; $i<14 && $i<$NUM; $i++) {
my $lo=$i<13?@A[$i+1]:"%o7";
$code.=<<___;
	ld	[$ap+$i*8+0],$lo
	ld	[$ap+$i*8+4],@A[$i]
	sllx	@A[$i],32,@A[$i]
	or	$lo,@A[$i],@A[$i]
___
}
for(; $i<$NUM; $i++) {
my ($hi,$lo)=("%f".2*($i%4),"%f".(2*($i%4)+1));
$code.=<<___;
	ld	[$ap+$i*8+0],$lo
	ld	[$ap+$i*8+4],$hi
	fsrc2	$hi,@A[$i]
___
}
# load np[$NUM] ########################################################
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for($i=0; $i<14 && $i<$NUM; $i++) {
my $lo=$i<13?@N[$i+1]:"%o7";
$code.=<<___;
	ld	[$np+$i*8+0],$lo
	ld	[$np+$i*8+4],@N[$i]
	sllx	@N[$i],32,@N[$i]
	or	$lo,@N[$i],@N[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<28 && $i<$NUM; $i++) {
my $lo=$i<27?@N[$i+1]:"%o7";
$code.=<<___;
	ld	[$np+$i*8+0],$lo
	ld	[$np+$i*8+4],@N[$i]
	sllx	@N[$i],32,@N[$i]
	or	$lo,@N[$i],@N[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<$NUM; $i++) {
my $lo=($i<$NUM-1)?@N[$i+1]:"%o7";
$code.=<<___;
	ld	[$np+$i*8+0],$lo
	ld	[$np+$i*8+4],@N[$i]
	sllx	@N[$i],32,@N[$i]
	or	$lo,@N[$i],@N[$i]
___
}
$code.=<<___;
	cmp	$ap,$bp
	be	SIZE_T_CC,.Lmsquare_$NUM
	nop
___

# load bp[$NUM] ########################################################
for($i=0; $i<6 && $i<$NUM; $i++) {
my $lo=$i<5?@B[$i+1]:"%o7";
$code.=<<___;
	ld	[$bp+$i*8+0],$lo
	ld	[$bp+$i*8+4],@B[$i]
	sllx	@B[$i],32,@B[$i]
	or	$lo,@B[$i],@B[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<20 && $i<$NUM; $i++) {
my $lo=$i<19?@B[$i+1]:"%o7";
$code.=<<___;
	ld	[$bp+$i*8+0],$lo
	ld	[$bp+$i*8+4],@B[$i]
	sllx	@B[$i],32,@B[$i]
	or	$lo,@B[$i],@B[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<$NUM; $i++) {
my $lo=($i<$NUM-1)?@B[$i+1]:"%o7";
$code.=<<___;
	ld	[$bp+$i*8+0],$lo
	ld	[$bp+$i*8+4],@B[$i]
	sllx	@B[$i],32,@B[$i]
	or	$lo,@B[$i],@B[$i]
___
}
# magic ################################################################
$code.=<<___;
	.word	0x81b02920+$NUM-1	! montmul	$NUM-1
.Lmresume_$NUM:
	fbu,pn	%fcc3,.Lmabort_$NUM
#ifndef	__arch64__
	and	%fp,$sentinel,$sentinel
	brz,pn	$sentinel,.Lmabort_$NUM
#endif
	nop
#ifdef	__arch64__
	restore
	restore
	restore
	restore
	restore
#else
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	 brz,pn	$sentinel,.Lmabort1_$NUM
	restore
#endif
___

# save tp[$NUM] ########################################################
for($i=0; $i<14 && $i<$NUM; $i++) {
$code.=<<___;
	movxtod	@A[$i],@R[$i]
___
}
$code.=<<___;
#ifdef	__arch64__
	restore
#else
	 and	%fp,$sentinel,$sentinel
	restore
	 and	$sentinel,1,%o7
	 and	%fp,$sentinel,$sentinel
	 srl	%fp,0,%fp		! just in case?
	 or	%o7,$sentinel,$sentinel
	brz,a,pn $sentinel,.Lmdone_$NUM
	mov	0,%i0		! return failure
#endif
___
for($i=0; $i<12 && $i<$NUM; $i++) {
@R[$i] =~ /%f([0-9]+)/;
my $lo = "%f".($1+1);
$code.=<<___;
	st	$lo,[$rp+$i*8+0]
	st	@R[$i],[$rp+$i*8+4]
___
}
for(; $i<$NUM; $i++) {
my ($hi,$lo)=("%f".2*($i%4),"%f".(2*($i%4)+1));
$code.=<<___;
	fsrc2	@R[$i],$hi
	st	$lo,[$rp+$i*8+0]
	st	$hi,[$rp+$i*8+4]
___
}
$code.=<<___;
	mov	1,%i0		! return success
.Lmdone_$NUM:
	ret
	restore

.Lmabort_$NUM:
	restore
	restore
	restore
	restore
	restore
.Lmabort1_$NUM:
	restore

	mov	0,%i0		! return failure
	ret
	restore

.align	32
.Lmsquare_$NUM:
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
	.word   0x81b02940+$NUM-1	! montsqr	$NUM-1
	ba	.Lmresume_$NUM
	nop
.type	bn_mul_mont_t4_$NUM, #function
.size	bn_mul_mont_t4_$NUM, .-bn_mul_mont_t4_$NUM
___
}

for ($i=8;$i<=32;$i+=8) {
	&generate_bn_mul_mont_t4($i);
}

########################################################################
#
sub load_fcc() {
my ($ptbl,$pwr,$tmp)=@_;
$code.=<<___;
	sethi	%hi(.Lmagic-1f),$tmp
1:	call	.+8
	add	%o7,	$tmp,	%o7
	inc	%lo(.Lmagic-1b),%o7
	and	$pwr,	7<<2,	$tmp	! offset within "magic table"
	add	$tmp,	%o7,	%o7
	and	$pwr,	3,	$tmp
	sll	$tmp,	3,	$tmp	! offset within first cache line
	add	$tmp,	$ptbl,	$ptbl	! of the pwrtbl

	! "magic table" is organized in such way that below comparisons
	! make %fcc3:%fcc2:%fcc1:%fcc0 form a byte of 1s with one 0,
	! e.g. 0b11011111, with 0 denoting relevant cache line.
	ld	[%o7+0],	%f0	! load column
	ld	[%o7+32],	%f1
	ld	[%o7+64],	%f2
	fcmps	%fcc0,	%f0,	%f1
	ld	[%o7+96],	%f3
	fcmps	%fcc1,	%f1,	%f2
	fcmps	%fcc2,	%f2,	%f3
	fcmps	%fcc3,	%f3,	%f0
___
}
sub load_f16() {
my $ptbl=shift;
$code.=<<___;
	ldd	[$ptbl+0*32],%f0	! load all cache lines
	ldd	[$ptbl+1*32],%f2
	ldd	[$ptbl+2*32],%f4
	fmovdg	%fcc0,%f0,%f16		! pick one value
	ldd	[$ptbl+3*32],%f6
	fmovdl	%fcc0,%f2,%f16
	ldd	[$ptbl+4*32],%f8
	fmovdg	%fcc1,%f4,%f16
	ldd	[$ptbl+5*32],%f10
	fmovdl	%fcc1,%f6,%f16
	ldd	[$ptbl+6*32],%f12
	fmovdg	%fcc2,%f8,%f16
	ldd	[$ptbl+7*32],%f14
	fmovdl	%fcc2,%f10,%f16
	fmovdg	%fcc3,%f12,%f16
	fmovdl	%fcc3,%f14,%f16
	add	$ptbl,8*32,$ptbl
___
}

########################################################################
# int bn_pwr5_mont_t4_$NUM(u64 *tp,const u64 *np,const BN_ULONG *n0,
#			   const u64 *pwrtbl,int pwr);
#
sub generate_bn_pwr5_mont_t4() {
my $NUM=shift;
my ($tp,$np,$pwrtbl,$pwr,$sentinel)=map("%g$_",(1..5));

$code.=<<___;
.globl	bn_pwr5_mont_t4_$NUM
.align	32
bn_pwr5_mont_t4_$NUM:
#ifdef	__arch64__
	mov	0,$sentinel
	mov	-128,%g4
#elif defined(SPARCV9_64BIT_STACK)
	SPARC_LOAD_ADDRESS_LEAF(OPENSSL_sparcv9cap_P,%g1,%g5)
	ld	[%g1+0],%g1	! OPENSSL_sparcv9_P[0]
	mov	-2047,%g4
	and	%g1,SPARCV9_64BIT_STACK,%g1
	movrz	%g1,0,%g4
	mov	-1,$sentinel
	add	%g4,-128,%g4
#else
	mov	-1,$sentinel
	mov	-128,%g4
#endif
	sllx	$sentinel,32,$sentinel
	save	%sp,%g4,%sp
#ifndef	__arch64__
	save	%sp,-128,%sp	! warm it up
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	save	%sp,-128,%sp
	restore
	restore
	restore
	restore
	restore
	restore
#endif
	and	%sp,1,%g4
	or	$sentinel,%fp,%fp
	or	%g4,$sentinel,$sentinel

	! copy arguments to global registers
	mov	%i0,$tp
	mov	%i1,$np
	ld	[%i2+0],%f1	! load *n0
	ld	[%i2+4],%f0
	mov	%i3,$pwrtbl
	mov	%i4,$pwr
	fsrc2	%f0,%f60
___

# load tp[$NUM] ########################################################
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for($i=0; $i<14 && $i<$NUM; $i++) {
$code.=<<___;
	ldx	[$tp+$i*8],@A[$i]
___
}
for(; $i<$NUM; $i++) {
$code.=<<___;
	ldd	[$tp+$i*8],@A[$i]
___
}
# load np[$NUM] ########################################################
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for($i=0; $i<14 && $i<$NUM; $i++) {
$code.=<<___;
	ldx	[$np+$i*8],@N[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<28 && $i<$NUM; $i++) {
$code.=<<___;
	ldx	[$np+$i*8],@N[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<$NUM; $i++) {
$code.=<<___;
	ldx	[$np+$i*8],@N[$i]
___
}
# load pwrtbl[pwr] ########################################################
	&load_fcc($pwrtbl,$pwr,@B[0]);
for($i=0; $i<6 && $i<$NUM; $i++) {
	&load_f16($pwrtbl);
$code.=<<___;
	movdtox	%f16,@B[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<20 && $i<$NUM; $i++) {
	&load_f16($pwrtbl);
$code.=<<___;
	movdtox	%f16,@B[$i]
___
}
$code.=<<___;
	save	%sp,-128,%sp;		or	$sentinel,%fp,%fp
___
for(; $i<$NUM; $i++) {
	&load_f16($pwrtbl);
$code.=<<___;
	movdtox	%f16,@B[$i]
___
}

# magic ################################################################
for($i=0; $i<5; $i++) {
$code.=<<___;
	.word	0x81b02940+$NUM-1	! montsqr	$NUM-1
	fbu,pn	%fcc3,.Labort_$NUM
#ifndef	__arch64__
	and	%fp,$sentinel,$sentinel
	brz,pn	$sentinel,.Labort_$NUM
#endif
	nop
___
}
$code.=<<___;
	.word	0x81b02920+$NUM-1	! montmul	$NUM-1
	fbu,pn	%fcc3,.Labort_$NUM
#ifndef	__arch64__
	and	%fp,$sentinel,$sentinel
	brz,pn	$sentinel,.Labort_$NUM
#endif
	nop

#ifdef	__arch64__
	restore
	restore
	restore
	restore
	restore
#else
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	restore;		and	%fp,$sentinel,$sentinel
	 brz,pn	$sentinel,.Labort1_$NUM
	restore
#endif
___

# save tp[$NUM] ########################################################
for($i=0; $i<14 && $i<$NUM; $i++) {
$code.=<<___;
	movxtod	@A[$i],@R[$i]
___
}
$code.=<<___;
#ifdef	__arch64__
	restore
#else
	 and	%fp,$sentinel,$sentinel
	restore
	 and	$sentinel,1,%o7
	 and	%fp,$sentinel,$sentinel
	 srl	%fp,0,%fp		! just in case?
	 or	%o7,$sentinel,$sentinel
	brz,a,pn $sentinel,.Ldone_$NUM
	mov	0,%i0		! return failure
#endif
___
for($i=0; $i<$NUM; $i++) {
$code.=<<___;
	std	@R[$i],[$tp+$i*8]
___
}
$code.=<<___;
	mov	1,%i0		! return success
.Ldone_$NUM:
	ret
	restore

.Labort_$NUM:
	restore
	restore
	restore
	restore
	restore
.Labort1_$NUM:
	restore

	mov	0,%i0		! return failure
	ret
	restore
.type	bn_pwr5_mont_t4_$NUM, #function
.size	bn_pwr5_mont_t4_$NUM, .-bn_pwr5_mont_t4_$NUM
___
}

for ($i=8;$i<=32;$i+=8) {
	&generate_bn_pwr5_mont_t4($i);
}

{
########################################################################
# Fall-back subroutines
#
# copy of bn_mul_mont_vis3 adjusted for vectors of 64-bit values
#
($n0,$m0,$m1,$lo0,$hi0, $lo1,$hi1,$aj,$alo,$nj,$nlo,$tj)=
	(map("%g$_",(1..5)),map("%o$_",(0..5,7)));

# int bn_mul_mont(
$rp="%o0";	# u64 *rp,
$ap="%o1";	# const u64 *ap,
$bp="%o2";	# const u64 *bp,
$np="%o3";	# const u64 *np,
$n0p="%o4";	# const BN_ULONG *n0,
$num="%o5";	# int num);	# caller ensures that num is >=3
$code.=<<___;
.globl	bn_mul_mont_t4
.align	32
bn_mul_mont_t4:
	add	%sp,	STACK_BIAS,	%g4	! real top of stack
	sll	$num,	3,	$num		! size in bytes
	add	$num,	63,	%g1
	andn	%g1,	63,	%g1		! buffer size rounded up to 64 bytes
	sub	%g4,	%g1,	%g1
	andn	%g1,	63,	%g1		! align at 64 byte
	sub	%g1,	STACK_FRAME,	%g1	! new top of stack
	sub	%g1,	%g4,	%g1

	save	%sp,	%g1,	%sp
___
#	+-------------------------------+<-----	%sp
#	.				.
#	+-------------------------------+<-----	aligned at 64 bytes
#	| __int64 tmp[0]		|
#	+-------------------------------+
#	.				.
#	.				.
#	+-------------------------------+<-----	aligned at 64 bytes
#	.				.
($rp,$ap,$bp,$np,$n0p,$num)=map("%i$_",(0..5));
($t0,$t1,$t2,$t3,$cnt,$tp,$bufsz)=map("%l$_",(0..7));
($ovf,$i)=($t0,$t1);
$code.=<<___;
	ld	[$n0p+0],	$t0	! pull n0[0..1] value
	ld	[$n0p+4],	$t1
	add	%sp, STACK_BIAS+STACK_FRAME, $tp
	ldx	[$bp+0],	$m0	! m0=bp[0]
	sllx	$t1,	32,	$n0
	add	$bp,	8,	$bp
	or	$t0,	$n0,	$n0

	ldx	[$ap+0],	$aj	! ap[0]

	mulx	$aj,	$m0,	$lo0	! ap[0]*bp[0]
	umulxhi	$aj,	$m0,	$hi0

	ldx	[$ap+8],	$aj	! ap[1]
	add	$ap,	16,	$ap
	ldx	[$np+0],	$nj	! np[0]

	mulx	$lo0,	$n0,	$m1	! "tp[0]"*n0

	mulx	$aj,	$m0,	$alo	! ap[1]*bp[0]
	umulxhi	$aj,	$m0,	$aj	! ahi=aj

	mulx	$nj,	$m1,	$lo1	! np[0]*m1
	umulxhi	$nj,	$m1,	$hi1

	ldx	[$np+8],	$nj	! np[1]

	addcc	$lo0,	$lo1,	$lo1
	add	$np,	16,	$np
	addxc	%g0,	$hi1,	$hi1

	mulx	$nj,	$m1,	$nlo	! np[1]*m1
	umulxhi	$nj,	$m1,	$nj	! nhi=nj

	ba	.L1st
	sub	$num,	24,	$cnt	! cnt=num-3

.align	16
.L1st:
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0

	ldx	[$ap+0],	$aj	! ap[j]
	addcc	$nlo,	$hi1,	$lo1
	add	$ap,	8,	$ap
	addxc	$nj,	%g0,	$hi1	! nhi=nj

	ldx	[$np+0],	$nj	! np[j]
	mulx	$aj,	$m0,	$alo	! ap[j]*bp[0]
	add	$np,	8,	$np
	umulxhi	$aj,	$m0,	$aj	! ahi=aj

	mulx	$nj,	$m1,	$nlo	! np[j]*m1
	addcc	$lo0,	$lo1,	$lo1	! np[j]*m1+ap[j]*bp[0]
	umulxhi	$nj,	$m1,	$nj	! nhi=nj
	addxc	%g0,	$hi1,	$hi1
	stxa	$lo1,	[$tp]0xe2	! tp[j-1]
	add	$tp,	8,	$tp	! tp++

	brnz,pt	$cnt,	.L1st
	sub	$cnt,	8,	$cnt	! j--
!.L1st
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0	! ahi=aj

	addcc	$nlo,	$hi1,	$lo1
	addxc	$nj,	%g0,	$hi1
	addcc	$lo0,	$lo1,	$lo1	! np[j]*m1+ap[j]*bp[0]
	addxc	%g0,	$hi1,	$hi1
	stxa	$lo1,	[$tp]0xe2	! tp[j-1]
	add	$tp,	8,	$tp

	addcc	$hi0,	$hi1,	$hi1
	addxc	%g0,	%g0,	$ovf	! upmost overflow bit
	stxa	$hi1,	[$tp]0xe2
	add	$tp,	8,	$tp

	ba	.Louter
	sub	$num,	16,	$i	! i=num-2

.align	16
.Louter:
	ldx	[$bp+0],	$m0	! m0=bp[i]
	add	$bp,	8,	$bp

	sub	$ap,	$num,	$ap	! rewind
	sub	$np,	$num,	$np
	sub	$tp,	$num,	$tp

	ldx	[$ap+0],	$aj	! ap[0]
	ldx	[$np+0],	$nj	! np[0]

	mulx	$aj,	$m0,	$lo0	! ap[0]*bp[i]
	ldx	[$tp],		$tj	! tp[0]
	umulxhi	$aj,	$m0,	$hi0
	ldx	[$ap+8],	$aj	! ap[1]
	addcc	$lo0,	$tj,	$lo0	! ap[0]*bp[i]+tp[0]
	mulx	$aj,	$m0,	$alo	! ap[1]*bp[i]
	addxc	%g0,	$hi0,	$hi0
	mulx	$lo0,	$n0,	$m1	! tp[0]*n0
	umulxhi	$aj,	$m0,	$aj	! ahi=aj
	mulx	$nj,	$m1,	$lo1	! np[0]*m1
	add	$ap,	16,	$ap
	umulxhi	$nj,	$m1,	$hi1
	ldx	[$np+8],	$nj	! np[1]
	add	$np,	16,	$np
	addcc	$lo1,	$lo0,	$lo1
	mulx	$nj,	$m1,	$nlo	! np[1]*m1
	addxc	%g0,	$hi1,	$hi1
	umulxhi	$nj,	$m1,	$nj	! nhi=nj

	ba	.Linner
	sub	$num,	24,	$cnt	! cnt=num-3
.align	16
.Linner:
	addcc	$alo,	$hi0,	$lo0
	ldx	[$tp+8],	$tj	! tp[j]
	addxc	$aj,	%g0,	$hi0	! ahi=aj
	ldx	[$ap+0],	$aj	! ap[j]
	add	$ap,	8,	$ap
	addcc	$nlo,	$hi1,	$lo1
	mulx	$aj,	$m0,	$alo	! ap[j]*bp[i]
	addxc	$nj,	%g0,	$hi1	! nhi=nj
	ldx	[$np+0],	$nj	! np[j]
	add	$np,	8,	$np
	umulxhi	$aj,	$m0,	$aj	! ahi=aj
	addcc	$lo0,	$tj,	$lo0	! ap[j]*bp[i]+tp[j]
	mulx	$nj,	$m1,	$nlo	! np[j]*m1
	addxc	%g0,	$hi0,	$hi0
	umulxhi	$nj,	$m1,	$nj	! nhi=nj
	addcc	$lo1,	$lo0,	$lo1	! np[j]*m1+ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi1,	$hi1
	stx	$lo1,	[$tp]		! tp[j-1]
	add	$tp,	8,	$tp
	brnz,pt	$cnt,	.Linner
	sub	$cnt,	8,	$cnt
!.Linner
	ldx	[$tp+8],	$tj	! tp[j]
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0	! ahi=aj
	addcc	$lo0,	$tj,	$lo0	! ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi0,	$hi0

	addcc	$nlo,	$hi1,	$lo1
	addxc	$nj,	%g0,	$hi1	! nhi=nj
	addcc	$lo1,	$lo0,	$lo1	! np[j]*m1+ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi1,	$hi1
	stx	$lo1,	[$tp]		! tp[j-1]

	subcc	%g0,	$ovf,	%g0	! move upmost overflow to CCR.xcc
	addxccc	$hi1,	$hi0,	$hi1
	addxc	%g0,	%g0,	$ovf
	stx	$hi1,	[$tp+8]
	add	$tp,	16,	$tp

	brnz,pt	$i,	.Louter
	sub	$i,	8,	$i

	sub	$ap,	$num,	$ap	! rewind
	sub	$np,	$num,	$np
	sub	$tp,	$num,	$tp
	ba	.Lsub
	subcc	$num,	8,	$cnt	! cnt=num-1 and clear CCR.xcc

.align	16
.Lsub:
	ldx	[$tp],		$tj
	add	$tp,	8,	$tp
	ldx	[$np+0],	$nj
	add	$np,	8,	$np
	subccc	$tj,	$nj,	$t2	! tp[j]-np[j]
	srlx	$tj,	32,	$tj
	srlx	$nj,	32,	$nj
	subccc	$tj,	$nj,	$t3
	add	$rp,	8,	$rp
	st	$t2,	[$rp-4]		! reverse order
	st	$t3,	[$rp-8]
	brnz,pt	$cnt,	.Lsub
	sub	$cnt,	8,	$cnt

	sub	$np,	$num,	$np	! rewind
	sub	$tp,	$num,	$tp
	sub	$rp,	$num,	$rp

	subc	$ovf,	%g0,	$ovf	! handle upmost overflow bit
	and	$tp,	$ovf,	$ap
	andn	$rp,	$ovf,	$np
	or	$np,	$ap,	$ap	! ap=borrow?tp:rp
	ba	.Lcopy
	sub	$num,	8,	$cnt

.align	16
.Lcopy:					! copy or in-place refresh
	ldx	[$ap+0],	$t2
	add	$ap,	8,	$ap
	stx	%g0,	[$tp]		! zap
	add	$tp,	8,	$tp
	stx	$t2,	[$rp+0]
	add	$rp,	8,	$rp
	brnz	$cnt,	.Lcopy
	sub	$cnt,	8,	$cnt

	mov	1,	%o0
	ret
	restore
.type	bn_mul_mont_t4, #function
.size	bn_mul_mont_t4, .-bn_mul_mont_t4
___

# int bn_mul_mont_gather5(
$rp="%o0";	# u64 *rp,
$ap="%o1";	# const u64 *ap,
$bp="%o2";	# const u64 *pwrtbl,
$np="%o3";	# const u64 *np,
$n0p="%o4";	# const BN_ULONG *n0,
$num="%o5";	# int num,	# caller ensures that num is >=3
		# int power);
$code.=<<___;
.globl	bn_mul_mont_gather5_t4
.align	32
bn_mul_mont_gather5_t4:
	add	%sp,	STACK_BIAS,	%g4	! real top of stack
	sll	$num,	3,	$num		! size in bytes
	add	$num,	63,	%g1
	andn	%g1,	63,	%g1		! buffer size rounded up to 64 bytes
	sub	%g4,	%g1,	%g1
	andn	%g1,	63,	%g1		! align at 64 byte
	sub	%g1,	STACK_FRAME,	%g1	! new top of stack
	sub	%g1,	%g4,	%g1
	LDPTR	[%sp+STACK_7thARG],	%g4	! load power, 7th argument

	save	%sp,	%g1,	%sp
___
#	+-------------------------------+<-----	%sp
#	.				.
#	+-------------------------------+<-----	aligned at 64 bytes
#	| __int64 tmp[0]		|
#	+-------------------------------+
#	.				.
#	.				.
#	+-------------------------------+<-----	aligned at 64 bytes
#	.				.
($rp,$ap,$bp,$np,$n0p,$num)=map("%i$_",(0..5));
($t0,$t1,$t2,$t3,$cnt,$tp,$bufsz)=map("%l$_",(0..7));
($ovf,$i)=($t0,$t1);
	&load_fcc($bp,"%g4","%g1");
	&load_f16($bp);
$code.=<<___;
	movdtox	%f16,	$m0		! m0=bp[0]

	ld	[$n0p+0],	$t0	! pull n0[0..1] value
	ld	[$n0p+4],	$t1
	add	%sp, STACK_BIAS+STACK_FRAME, $tp
	sllx	$t1,	32,	$n0
	or	$t0,	$n0,	$n0

	ldx	[$ap+0],	$aj	! ap[0]

	mulx	$aj,	$m0,	$lo0	! ap[0]*bp[0]
	umulxhi	$aj,	$m0,	$hi0

	ldx	[$ap+8],	$aj	! ap[1]
	add	$ap,	16,	$ap
	ldx	[$np+0],	$nj	! np[0]

	mulx	$lo0,	$n0,	$m1	! "tp[0]"*n0

	mulx	$aj,	$m0,	$alo	! ap[1]*bp[0]
	umulxhi	$aj,	$m0,	$aj	! ahi=aj

	mulx	$nj,	$m1,	$lo1	! np[0]*m1
	umulxhi	$nj,	$m1,	$hi1

	ldx	[$np+8],	$nj	! np[1]

	addcc	$lo0,	$lo1,	$lo1
	add	$np,	16,	$np
	addxc	%g0,	$hi1,	$hi1

	mulx	$nj,	$m1,	$nlo	! np[1]*m1
	umulxhi	$nj,	$m1,	$nj	! nhi=nj

	ba	.L1st_g5
	sub	$num,	24,	$cnt	! cnt=num-3

.align	16
.L1st_g5:
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0

	ldx	[$ap+0],	$aj	! ap[j]
	addcc	$nlo,	$hi1,	$lo1
	add	$ap,	8,	$ap
	addxc	$nj,	%g0,	$hi1	! nhi=nj

	ldx	[$np+0],	$nj	! np[j]
	mulx	$aj,	$m0,	$alo	! ap[j]*bp[0]
	add	$np,	8,	$np
	umulxhi	$aj,	$m0,	$aj	! ahi=aj

	mulx	$nj,	$m1,	$nlo	! np[j]*m1
	addcc	$lo0,	$lo1,	$lo1	! np[j]*m1+ap[j]*bp[0]
	umulxhi	$nj,	$m1,	$nj	! nhi=nj
	addxc	%g0,	$hi1,	$hi1
	stxa	$lo1,	[$tp]0xe2	! tp[j-1]
	add	$tp,	8,	$tp	! tp++

	brnz,pt	$cnt,	.L1st_g5
	sub	$cnt,	8,	$cnt	! j--
!.L1st_g5
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0	! ahi=aj

	addcc	$nlo,	$hi1,	$lo1
	addxc	$nj,	%g0,	$hi1
	addcc	$lo0,	$lo1,	$lo1	! np[j]*m1+ap[j]*bp[0]
	addxc	%g0,	$hi1,	$hi1
	stxa	$lo1,	[$tp]0xe2	! tp[j-1]
	add	$tp,	8,	$tp

	addcc	$hi0,	$hi1,	$hi1
	addxc	%g0,	%g0,	$ovf	! upmost overflow bit
	stxa	$hi1,	[$tp]0xe2
	add	$tp,	8,	$tp

	ba	.Louter_g5
	sub	$num,	16,	$i	! i=num-2

.align	16
.Louter_g5:
___
	&load_f16($bp);
$code.=<<___;
	movdtox	%f16,	$m0		! m0=bp[i]

	sub	$ap,	$num,	$ap	! rewind
	sub	$np,	$num,	$np
	sub	$tp,	$num,	$tp

	ldx	[$ap+0],	$aj	! ap[0]
	ldx	[$np+0],	$nj	! np[0]

	mulx	$aj,	$m0,	$lo0	! ap[0]*bp[i]
	ldx	[$tp],		$tj	! tp[0]
	umulxhi	$aj,	$m0,	$hi0
	ldx	[$ap+8],	$aj	! ap[1]
	addcc	$lo0,	$tj,	$lo0	! ap[0]*bp[i]+tp[0]
	mulx	$aj,	$m0,	$alo	! ap[1]*bp[i]
	addxc	%g0,	$hi0,	$hi0
	mulx	$lo0,	$n0,	$m1	! tp[0]*n0
	umulxhi	$aj,	$m0,	$aj	! ahi=aj
	mulx	$nj,	$m1,	$lo1	! np[0]*m1
	add	$ap,	16,	$ap
	umulxhi	$nj,	$m1,	$hi1
	ldx	[$np+8],	$nj	! np[1]
	add	$np,	16,	$np
	addcc	$lo1,	$lo0,	$lo1
	mulx	$nj,	$m1,	$nlo	! np[1]*m1
	addxc	%g0,	$hi1,	$hi1
	umulxhi	$nj,	$m1,	$nj	! nhi=nj

	ba	.Linner_g5
	sub	$num,	24,	$cnt	! cnt=num-3
.align	16
.Linner_g5:
	addcc	$alo,	$hi0,	$lo0
	ldx	[$tp+8],	$tj	! tp[j]
	addxc	$aj,	%g0,	$hi0	! ahi=aj
	ldx	[$ap+0],	$aj	! ap[j]
	add	$ap,	8,	$ap
	addcc	$nlo,	$hi1,	$lo1
	mulx	$aj,	$m0,	$alo	! ap[j]*bp[i]
	addxc	$nj,	%g0,	$hi1	! nhi=nj
	ldx	[$np+0],	$nj	! np[j]
	add	$np,	8,	$np
	umulxhi	$aj,	$m0,	$aj	! ahi=aj
	addcc	$lo0,	$tj,	$lo0	! ap[j]*bp[i]+tp[j]
	mulx	$nj,	$m1,	$nlo	! np[j]*m1
	addxc	%g0,	$hi0,	$hi0
	umulxhi	$nj,	$m1,	$nj	! nhi=nj
	addcc	$lo1,	$lo0,	$lo1	! np[j]*m1+ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi1,	$hi1
	stx	$lo1,	[$tp]		! tp[j-1]
	add	$tp,	8,	$tp
	brnz,pt	$cnt,	.Linner_g5
	sub	$cnt,	8,	$cnt
!.Linner_g5
	ldx	[$tp+8],	$tj	! tp[j]
	addcc	$alo,	$hi0,	$lo0
	addxc	$aj,	%g0,	$hi0	! ahi=aj
	addcc	$lo0,	$tj,	$lo0	! ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi0,	$hi0

	addcc	$nlo,	$hi1,	$lo1
	addxc	$nj,	%g0,	$hi1	! nhi=nj
	addcc	$lo1,	$lo0,	$lo1	! np[j]*m1+ap[j]*bp[i]+tp[j]
	addxc	%g0,	$hi1,	$hi1
	stx	$lo1,	[$tp]		! tp[j-1]

	subcc	%g0,	$ovf,	%g0	! move upmost overflow to CCR.xcc
	addxccc	$hi1,	$hi0,	$hi1
	addxc	%g0,	%g0,	$ovf
	stx	$hi1,	[$tp+8]
	add	$tp,	16,	$tp

	brnz,pt	$i,	.Louter_g5
	sub	$i,	8,	$i

	sub	$ap,	$num,	$ap	! rewind
	sub	$np,	$num,	$np
	sub	$tp,	$num,	$tp
	ba	.Lsub_g5
	subcc	$num,	8,	$cnt	! cnt=num-1 and clear CCR.xcc

.align	16
.Lsub_g5:
	ldx	[$tp],		$tj
	add	$tp,	8,	$tp
	ldx	[$np+0],	$nj
	add	$np,	8,	$np
	subccc	$tj,	$nj,	$t2	! tp[j]-np[j]
	srlx	$tj,	32,	$tj
	srlx	$nj,	32,	$nj
	subccc	$tj,	$nj,	$t3
	add	$rp,	8,	$rp
	st	$t2,	[$rp-4]		! reverse order
	st	$t3,	[$rp-8]
	brnz,pt	$cnt,	.Lsub_g5
	sub	$cnt,	8,	$cnt

	sub	$np,	$num,	$np	! rewind
	sub	$tp,	$num,	$tp
	sub	$rp,	$num,	$rp

	subc	$ovf,	%g0,	$ovf	! handle upmost overflow bit
	and	$tp,	$ovf,	$ap
	andn	$rp,	$ovf,	$np
	or	$np,	$ap,	$ap	! ap=borrow?tp:rp
	ba	.Lcopy_g5
	sub	$num,	8,	$cnt

.align	16
.Lcopy_g5:				! copy or in-place refresh
	ldx	[$ap+0],	$t2
	add	$ap,	8,	$ap
	stx	%g0,	[$tp]		! zap
	add	$tp,	8,	$tp
	stx	$t2,	[$rp+0]
	add	$rp,	8,	$rp
	brnz	$cnt,	.Lcopy_g5
	sub	$cnt,	8,	$cnt

	mov	1,	%o0
	ret
	restore
.type	bn_mul_mont_gather5_t4, #function
.size	bn_mul_mont_gather5_t4, .-bn_mul_mont_gather5_t4
___
}

$code.=<<___;
.globl	bn_flip_t4
.align	32
bn_flip_t4:
.Loop_flip:
	ld	[%o1+0],	%o4
	sub	%o2,	1,	%o2
	ld	[%o1+4],	%o5
	add	%o1,	8,	%o1
	st	%o5,	[%o0+0]
	st	%o4,	[%o0+4]
	brnz	%o2,	.Loop_flip
	add	%o0,	8,	%o0
	retl
	nop
.type	bn_flip_t4, #function
.size	bn_flip_t4, .-bn_flip_t4

.globl	bn_scatter5_t4
.align	32
bn_scatter5_t4:
	sll	%o3,	3,	%o3
	sub	%o1,	1,	%o1
	add	%o3,	%o2,	%o2	! &pwrtbl[pwr]
	nop
.Loop_scatter5:
	ldx	[%o0],	%g1		! inp[i]
	add	%o0,	8,	%o0
	stx	%g1,	[%o2]
	add	%o2,	32*8,	%o2
	brnz	%o1,	.Loop_scatter5
	sub	%o1,	1,	%o1
	retl
	nop
.type	bn_scatter5_t4, #function
.size	bn_scatter5_t4, .-bn_scatter5_t4

.globl	bn_gather5_t4
.align	32
bn_gather5_t4:
	mov	%o7,	%o5
___
	&load_fcc("%o2","%o3","%o4");
$code.=<<___;
	mov	%o5,	%o7
	sub	%o1,	1,	%o1
.Loop_gather5:
___
	&load_f16("%o2");
$code.=<<___;
	std	%f16,	[%o0]
	add	%o0,	8,	%o0
	brnz	%o1,	.Loop_gather5
	sub	%o1,	1,	%o1

	retl
	nop
.type	bn_gather5_t4, #function
.size	bn_gather5_t4, .-bn_gather5_t4
___

$code.=<<___;
#define	ONE	0x3f800000
#define	NUL	0x00000000
#define NaN	0xffffffff

.align	64
.Lmagic:
	.long	ONE,NUL,NaN,NaN,NaN,NaN,NUL,ONE
	.long	NUL,ONE,ONE,NUL,NaN,NaN,NaN,NaN
	.long	NaN,NaN,NUL,ONE,ONE,NUL,NaN,NaN
	.long	NaN,NaN,NaN,NaN,NUL,ONE,ONE,NUL
.asciz	"Montgomery Multiplication for SPARC T4, David S. Miller, Andy Polyakov"
.align	4
___

&emit_assembler();

close STDOUT;
