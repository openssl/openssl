#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# March 2015
#
# "Teaser" Montgomery multiplication module for ARMv8. Needs more
# work. While it does improve RSA sign performance by 20-30% (less for
# longer keys) on most processors, for some reason RSA2048 is not
# faster and RSA4096 goes 15-20% slower on Cortex-A57. Multiplication
# instruction issue rate is limited on processor in question, meaning
# that dedicated squaring procedure is a must. Well, actually all
# contemporary AArch64 processors seem to have limited multiplication
# issue rate, i.e. they can't issue multiplication every cycle, which
# explains moderate improvement coefficients in comparison to
# compiler-generated code. Recall that compiler is instructed to use
# umulh and therefore uses same amount of multiplication instructions
# to do the job. Assembly's edge is to minimize number of "collateral"
# instructions and of course instruction scheduling.

$flavour = shift;
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

($lo0,$hi0,$aj,$m0,$alo,$ahi,
 $lo1,$hi1,$nj,$m1,$nlo,$nhi,
 $ovf, $i,$j,$tp,$tj) = map("x$_",6..17,19..24);

# int bn_mul_mont(
$rp="x0";	# BN_ULONG *rp,
$ap="x1";	# const BN_ULONG *ap,
$bp="x2";	# const BN_ULONG *bp,
$np="x3";	# const BN_ULONG *np,
$n0="x4";	# const BN_ULONG *n0,
$num="x5";	# int num);

$code.=<<___;
.text

.globl	bn_mul_mont
.type	bn_mul_mont,%function
.align	5
bn_mul_mont:
	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	ldr	$m0,[$bp],#8		// bp[0]
	sub	$tp,sp,$num,lsl#3
	ldp	$hi0,$aj,[$ap],#16	// ap[0..1]
	lsl	$num,$num,#3
	ldr	$n0,[$n0]		// *n0
	and	$tp,$tp,#-16		// ABI says so
	ldp	$hi1,$nj,[$np],#16	// np[0..1]

	mul	$lo0,$hi0,$m0		// ap[0]*bp[0]
	sub	$j,$num,#16		// j=num-2
	umulh	$hi0,$hi0,$m0
	mul	$alo,$aj,$m0		// ap[1]*bp[0]
	umulh	$ahi,$aj,$m0

	mul	$m1,$lo0,$n0		// "tp[0]"*n0
	mov	sp,$tp			// alloca

	mul	$lo1,$hi1,$m1		// np[0]*m1
	umulh	$hi1,$hi1,$m1
	mul	$nlo,$nj,$m1		// np[1]*m1
	adds	$lo1,$lo1,$lo0		// discarded
	umulh	$nhi,$nj,$m1
	adc	$hi1,$hi1,xzr
	cbz	$j,.L1st_skip

.L1st:
	ldr	$aj,[$ap],#8
	adds	$lo0,$alo,$hi0
	sub	$j,$j,#8		// j--
	adc	$hi0,$ahi,xzr

	ldr	$nj,[$np],#8
	adds	$lo1,$nlo,$hi1
	mul	$alo,$aj,$m0		// ap[j]*bp[0]
	adc	$hi1,$nhi,xzr
	umulh	$ahi,$aj,$m0

	adds	$lo1,$lo1,$lo0
	mul	$nlo,$nj,$m1		// np[j]*m1
	adc	$hi1,$hi1,xzr
	umulh	$nhi,$nj,$m1
	str	$lo1,[$tp],#8		// tp[j-1]
	cbnz	$j,.L1st

.L1st_skip:
	adds	$lo0,$alo,$hi0
	sub	$ap,$ap,$num		// rewind $ap
	adc	$hi0,$ahi,xzr

	adds	$lo1,$nlo,$hi1
	sub	$np,$np,$num		// rewind $np
	adc	$hi1,$nhi,xzr

	adds	$lo1,$lo1,$lo0
	sub	$i,$num,#8		// i=num-1
	adcs	$hi1,$hi1,$hi0

	adc	$ovf,xzr,xzr		// upmost overflow bit
	stp	$lo1,$hi1,[$tp]

.Louter:
	ldr	$m0,[$bp],#8		// bp[i]
	ldp	$hi0,$aj,[$ap],#16
	ldr	$tj,[sp]		// tp[0]
	add	$tp,sp,#8

	mul	$lo0,$hi0,$m0		// ap[0]*bp[i]
	sub	$j,$num,#16		// j=num-2
	umulh	$hi0,$hi0,$m0
	ldp	$hi1,$nj,[$np],#16
	mul	$alo,$aj,$m0		// ap[1]*bp[i]
	adds	$lo0,$lo0,$tj
	umulh	$ahi,$aj,$m0
	adc	$hi0,$hi0,xzr

	mul	$m1,$lo0,$n0
	sub	$i,$i,#8		// i--

	mul	$lo1,$hi1,$m1		// np[0]*m1
	umulh	$hi1,$hi1,$m1
	mul	$nlo,$nj,$m1		// np[1]*m1
	adds	$lo1,$lo1,$lo0
	umulh	$nhi,$nj,$m1
	cbz	$j,.Linner_skip

.Linner:
	ldr	$aj,[$ap],#8
	adc	$hi1,$hi1,xzr
	ldr	$tj,[$tp],#8		// tp[j]
	adds	$lo0,$alo,$hi0
	sub	$j,$j,#8		// j--
	adc	$hi0,$ahi,xzr

	adds	$lo1,$nlo,$hi1
	ldr	$nj,[$np],#8
	adc	$hi1,$nhi,xzr

	mul	$alo,$aj,$m0		// ap[j]*bp[i]
	adds	$lo0,$lo0,$tj
	umulh	$ahi,$aj,$m0
	adc	$hi0,$hi0,xzr

	mul	$nlo,$nj,$m1		// np[j]*m1
	adds	$lo1,$lo1,$lo0
	umulh	$nhi,$nj,$m1
	str	$lo1,[$tp,#-16]		// tp[j-1]
	cbnz	$j,.Linner

.Linner_skip:
	ldr	$tj,[$tp],#8		// tp[j]
	adc	$hi1,$hi1,xzr
	adds	$lo0,$alo,$hi0
	sub	$ap,$ap,$num		// rewind $ap
	adc	$hi0,$ahi,xzr

	adds	$lo1,$nlo,$hi1
	sub	$np,$np,$num		// rewind $np
	adc	$hi1,$nhi,$ovf

	adds	$lo0,$lo0,$tj
	adc	$hi0,$hi0,xzr

	adds	$lo1,$lo1,$lo0
	adcs	$hi1,$hi1,$hi0
	adc	$ovf,xzr,xzr		// upmost overflow bit
	stp	$lo1,$hi1,[$tp,#-16]

	cbnz	$i,.Louter

	// Final step. We see if result is larger than modulus, and
	// if it is, subtract the modulus. But comparison implies
	// subtraction. So we subtract modulus, see if it borrowed,
	// and conditionally copy original value. 
	ldr	$tj,[sp]		// tp[0]
	add	$tp,sp,#8
	ldr	$nj,[$np],#8		// np[0]
	subs	$j,$num,#8		// j=num-1 and clear borrow
	mov	$ap,$rp
.Lsub:
	sbcs	$aj,$tj,$nj		// tp[j]-np[j]
	ldr	$tj,[$tp],#8
	sub	$j,$j,#8		// j--
	ldr	$nj,[$np],#8
	str	$aj,[$ap],#8		// rp[j]=tp[j]-np[j]
	cbnz	$j,.Lsub

	sbcs	$aj,$tj,$nj
	sbcs	$ovf,$ovf,xzr		// did it borrow?
	str	$aj,[$ap],#8		// rp[num-1]

	ldr	$tj,[sp]		// tp[0]
	add	$tp,sp,#8
	ldr	$aj,[$rp],#8		// rp[0]
	sub	$num,$num,#8		// num--
	nop
.Lcond_copy:
	sub	$num,$num,#8		// num--
	csel	$nj,$aj,$tj,cs		// did it borrow?
	ldr	$tj,[$tp],#8
	ldr	$aj,[$rp],#8
	str	xzr,[$tp,#-16]		// wipe tp
	str	$nj,[$rp,#-16]
	cbnz	$num,.Lcond_copy

	csel	$nj,$aj,$tj,cs
	str	xzr,[$tp,#-8]		// wipe tp
	str	$nj,[$rp,#-8]

	ldp	x19,x20,[x29,#16]
	mov	sp,x29
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldr	x29,[sp],#64
	ret
.size	bn_mul_mont,.-bn_mul_mont

.asciz	"Montgomery Multiplication for ARMv8, CRYPTOGAMS by <appro\@openssl.org>"
.align	4
___

print $code;

close STDOUT;
