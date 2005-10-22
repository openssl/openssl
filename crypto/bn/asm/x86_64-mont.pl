#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================

# October 2005.
#
# Montgomery multiplication routine for x86_64. While it gives modest
# 9% improvement of rsa4096 sign on Opteron, rsa512 sign runs more
# than twice, >2x, as fast. Most common rsa1024 sign is improved by
# respectful 50%. It remains to be seen if loop unrolling and
# dedicated squaring routine can provide further improvement...

$output=shift;
open STDOUT,"| $^X ../perlasm/x86_64-xlate.pl $output";

# int bn_mul_mont(
$rp="%rdi";	# BN_ULONG *rp,
$ap="%rsi";	# const BN_ULONG *ap,
$bp="%rdx";	# const BN_ULONG *bp,
$np="%rcx";	# const BN_ULONG *np,
$n0="%r8";	# const BN_ULONG *n0,
$num="%r9";	# int num);
$lo0="%r10";
$hi0="%r11";
$bp="%r12";	# reassign $bp
$hi1="%r13";
$i="%r14";
$j="%r15";
$m0="%rbx";
$m1="%rbp";

$code=<<___;
.text

.globl	bn_mul_mont
.type	bn_mul_mont,\@function,6
.align	16
bn_mul_mont:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	lea	2($num),%rax
	mov	%rsp,%rbp
	neg	%rax
	lea	(%rsp,%rax,8),%rsp	# tp=alloca(8*(num+2))
	and	\$-1024,%rsp		# minimize TLB usage
	mov	%rbp,8(%rsp,$num,8)	# tp[num+1]=%rsp
	mov	%rdx,$bp		# $bp reassigned, remember?

	mov	($n0),$n0		# pull n0[0] value

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	mov	($bp),$m0		# m0=bp[0]
	mov	($ap),%rax
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$lo0
	mov	%rdx,$hi0

	imulq	$n0,%rax		# "tp[0]"*n0
	mov	%rax,$m1

	mulq	($np)			# np[0]*m1
	add	$lo0,%rax		# discarded
	adc	\$0,%rdx
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
.L1st:
	mov	($ap,$j,8),%rax
	mulq	$m0			# ap[j]*bp[0]
	add	$hi0,%rax
	adc	\$0,%rdx
	mov	%rax,$lo0
	mov	%rdx,$hi0

	mov	($np,$j,8),%rax
	mulq	$m1			# np[j]*m1
	add	$hi1,%rax
	adc	\$0,%rdx
	add	$lo0,%rax		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	%rax,-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	cmp	$num,$j
	jl	.L1st

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
.align	4
.Louter:
	xor	$j,$j			# j=0

	mov	($bp,$i,8),$m0		# m0=bp[i]
	mov	($ap),%rax		# ap[0]
	mulq	$m0			# ap[0]*bp[i]
	add	(%rsp),%rax		# ap[0]*bp[i]+tp[0]
	adc	\$0,%rdx
	mov	%rax,$lo0
	mov	%rdx,$hi0

	imulq	$n0,%rax		# tp[0]*n0
	mov	%rax,$m1

	mulq	($np,$j,8)		# np[0]*m1
	add	$lo0,%rax		# discarded
	adc	\$0,%rdx
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
.align	4
.Linner:
	mov	($ap,$j,8),%rax
	mulq	$m0			# ap[j]*bp[i]
	add	$hi0,%rax
	adc	\$0,%rdx
	add	(%rsp,$j,8),%rax	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rax,$lo0
	mov	%rdx,$hi0

	mov	($np,$j,8),%rax
	mulq	$m1			# np[j]*m1
	add	$hi1,%rax
	adc	\$0,%rdx
	add	$lo0,%rax		# np[j]*m1+ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rax,-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	cmp	$num,$j
	jl	.Linner

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	add	(%rsp,$num,8),$hi1	# pull upmost overflow bit
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
	cmp	$num,$i
	jl	.Louter

	xor	$i,$i			# i=0
	lea	-1($num),$j		# j=num-1
	cmp	\$0,%rdx		# %rdx still holds upmost overflow bit
	jnz	.Lsub			# CF is cleared by compare with 0
	mov	(%rsp,$j,8),%rax
	cmp	($np,$j,8),%rax		# tp[num-1]-np[num-1]
	jae	.Lsub			# if taken CF was cleared by above cmp
.align	4
.Lcopy:
	mov	(%rsp,$j,8),%rax
	mov	%rax,($rp,$j,8)		# rp[i]=tp[i]
	mov	$i,(%rsp,$j,8)		# zap temporary vector
	dec	$j
	jge	.Lcopy
.align	4
.Lexit:
	mov	8(%rsp,$num,8),%rsp	# restore %rsp
	mov	\$1,%rax
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret

.align	16
.Lsub:	mov	(%rsp,$i,8),%rax
	sbb	($np,$i,8),%rax
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]-np[j]
	lea	1($i),$i		# i++
	dec	$j			# doesn't affect CF!
	jge	.Lsub
	lea	-1($num),$j		# j=num-1
	sbb	\$0,%rdx
	jc	.Lcopy			# tp was less than np
.align	4
.Lzap:	mov	$i,(%rsp,$j,8)		# zap temporary vector
	dec	$j
	jge	.Lzap
	jmp	.Lexit
.size	bn_mul_mont,.-bn_mul_mont
___

print $code;
close STDOUT;
