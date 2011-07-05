#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# October 2005.
#
# Montgomery multiplication routine for x86_64. While it gives modest
# 9% improvement of rsa4096 sign on Opteron, rsa512 sign runs more
# than twice, >2x, as fast. Most common rsa1024 sign is improved by
# respectful 50%. It remains to be seen if loop unrolling and
# dedicated squaring routine can provide further improvement...

# July 2011.
#
# Add dedicated squaring procedure. Performance improvement varies
# from platform to platform, but in average it's ~5%/15%/25%/33%
# for 512-/1024-/2048-/4096-bit RSA *sign* benchmarks respectively.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

# int bn_mul_mont(
$rp="%rdi";	# BN_ULONG *rp,
$ap="%rsi";	# const BN_ULONG *ap,
$bp="%rdx";	# const BN_ULONG *bp,
$np="%rcx";	# const BN_ULONG *np,
$n0="%r8";	# const BN_ULONG *n0,
$num="%r9";	# int num);
$lo0="%r10";
$hi0="%r11";
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
	cmp	$ap,$bp
	jne	.Lmul_enter
	test	\$1,${num}d
	jnz	.Lmul_enter
	cmp	\$4,${num}d
	jb	.Lmul_enter
	jmp	__bn_sqr_enter

.align	16
.Lmul_enter:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	2($num),%r10
	mov	%rsp,%r11
	neg	%r10
	lea	(%rsp,%r10,8),%rsp	# tp=alloca(8*(num+2))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%r11,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lprologue:
	mov	$bp,%r12		# reassign $bp
___
		$bp="%r12";
$code.=<<___;
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
	mov	($np,$j,8),%rax
	mov	%rdx,$hi0

	mulq	$m1			# np[j]*m1
	add	$hi1,%rax
	lea	1($j),$j		# j++
	adc	\$0,%rdx
	add	$lo0,%rax		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	%rax,-16(%rsp,$j,8)	# tp[j-1]
	cmp	$num,$j
	mov	%rdx,$hi1
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
	mov	8(%rsp),$lo0		# tp[1]
	adc	\$0,%rdx
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	jmp	.Linner
.align	16
.Linner:
	mov	($ap,$j,8),%rax
	mulq	$m0			# ap[j]*bp[i]
	add	$hi0,%rax
	adc	\$0,%rdx
	add	%rax,$lo0		# ap[j]*bp[i]+tp[j]
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$hi0

	mulq	$m1			# np[j]*m1
	add	$hi1,%rax
	lea	1($j),$j		# j++
	adc	\$0,%rdx
	add	$lo0,%rax		# np[j]*m1+ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	(%rsp,$j,8),$lo0
	cmp	$num,$j
	mov	%rax,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1
	jl	.Linner

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	add	$lo0,$hi1		# pull upmost overflow bit
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
	cmp	$num,$i
	jl	.Louter

	lea	(%rsp),$ap		# borrow ap for tp
	lea	-1($num),$j		# j=num-1

	mov	($ap),%rax		# tp[0]
	xor	$i,$i			# i=0 and clear CF!
	jmp	.Lsub
.align	16
.Lsub:	sbb	($np,$i,8),%rax
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]-np[i]
	dec	$j			# doesn't affect CF!
	mov	8($ap,$i,8),%rax	# tp[i+1]
	lea	1($i),$i		# i++
	jge	.Lsub

	sbb	\$0,%rax		# handle upmost overflow bit
	and	%rax,$ap
	not	%rax
	mov	$rp,$np
	and	%rax,$np
	lea	-1($num),$j
	or	$np,$ap			# ap=borrow?tp:rp
.align	16
.Lcopy:					# copy or in-place refresh
	mov	($ap,$j,8),%rax
	mov	%rax,($rp,$j,8)		# rp[i]=tp[i]
	mov	$i,(%rsp,$j,8)		# zap temporary vector
	dec	$j
	jge	.Lcopy

	mov	8(%rsp,$num,8),%rsi	# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lepilogue:
	ret
.size	bn_mul_mont,.-bn_mul_mont
___
{{{
######################################################################
# void bn_sqr_mont(
my $rptr="%rdi";	# const BN_ULONG *rptr,
my $aptr="%rsi";	# const BN_ULONG *aptr,
my $bptr="%rdx";	# not used
my $nptr="%rcx";	# const BN_ULONG *nptr,
my $n0  ="%r8";		# const BN_ULONG *n0);
my $num ="%r9";		# int num, has to be even and not less than 4

my ($i,$j,$tptr)=("%rbp","%rcx",$rptr);
my @A0=("%r10","%r11");
my @A1=("%r12","%r13");
my ($a0,$a1,$ai)=("%r14","%r15","%rbx");

$code.=<<___;
.type	bn_sqr_mont,\@function,5
.align	16
bn_sqr_mont:
__bn_sqr_enter:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	shl	\$3,${num}d		# convert $num to bytes
	xor	%r10,%r10
	mov	%rsp,%r11		# put aside %rsp
	sub	$num,%r10		# -$num
	mov	($n0),$n0		# *n0
	lea	-72(%rsp,%r10,2),%rsp	# alloca(frame+2*$num)
	and	\$-1024,%rsp		# minimize TLB usage
	##############################################################
	# Stack layout
	#
	# +0	saved $num, used in reduction section
	# +8	&t[2*$num], used in reduction section
	# +32	saved $rptr
	# +40	saved $nptr
	# +48	saved *n0
	# +56	saved %rsp
	# +64	t[2*$num]
	#
	mov	$rptr,32(%rsp)		# save $rptr
	mov	$nptr,40(%rsp)
	mov	$n0,  48(%rsp)
	mov	%r11, 56(%rsp)		# save original %rsp
.Lsqr_body:
	##############################################################
	# Squaring part:
	#
	# a) multiply-n-add everything but a[i]*a[i];
	# b) shift result of a) by 1 to the left and accumulate
	#    a[i]*a[i] products;
	#
	lea	16(%r10),$i		# $i=-($num-16)
	lea	($aptr,$num),$aptr	# end of a[] buffer, ($aptr,$i)=&ap[2]

	mov	$num,$j			# $j=$num
	pxor	%xmm0,%xmm0
	lea	64(%rsp),$tptr
.Lbzero:				# clear t[$num]
	movdqa	%xmm0,($tptr)
	lea	16($tptr),$tptr
	sub	\$16,$j
	jnz	.Lbzero
	jmp	.Lsqr_outer

.align	16
.Lsqr_outer:				# comments apply to $num==4 case
	mov	-16($aptr,$i),$a0	# a[0]
	lea	64(%rsp,$num,2),$tptr	# end of tp[] buffer, &tp[2*$num]
	mov	-8($aptr,$i),%rax	# a[1]
	lea	-16($tptr,$i),$tptr	# end of tp[] window, &tp[2*$num-"$i"]
	mov	($aptr,$i),$ai		# a[2]
	mov	%rax,$a1

	mov	-8($tptr,$i),$A0[0]	# t[1]
	xor	$A0[1],$A0[1]
	mul	$a0			# a[1]*a[0]
	add	%rax,$A0[0]		# a[1]*a[0]+t[1]
	 mov	$ai,%rax		# a[2]
	adc	%rdx,$A0[1]
	mov	$A0[0],-8($tptr,$i)	# t[1]

	xor	$A0[0],$A0[0]
	add	($tptr,$i),$A0[1]	# a[2]*a[0]+t[2]
	adc	\$0,$A0[0]
	mul	$a0			# a[2]*a[0]
	add	%rax,$A0[1]
	 mov	$ai,%rax
	adc	%rdx,$A0[0]
	mov	$A0[1],($tptr,$i)	# t[2]

	lea	($i),$j			# j=-16
	xor	$A1[0],$A1[0]
	jmp	.Lsqr_inner

.align	16
.Lsqr_inner:
	 mov	8($aptr,$j),$ai		# a[3]
	xor	$A1[1],$A1[1]
	add	8($tptr,$j),$A1[0]
	adc	\$0,$A1[1]
	mul	$a1			# a[2]*a[1]
	add	%rax,$A1[0]		# a[2]*a[1]+t[3]
	 mov	$ai,%rax
	adc	%rdx,$A1[1]

	xor	$A0[1],$A0[1]
	add	$A1[0],$A0[0]
	adc	\$0,$A0[1]
	mul	$a0			# a[3]*a[0]
	add	%rax,$A0[0]		# a[3]*a[0]+a[2]*a[1]+t[3]
	 mov	$ai,%rax
	adc	%rdx,$A0[1]
	mov	$A0[0],8($tptr,$j)	# t[3]

	add	\$16,$j
	jz	.Lsqr_inner_done

	 mov	($aptr,$j),$ai		# a[4]
	xor	$A1[0],$A1[0]
	add	($tptr,$j),$A1[1]
	adc	\$0,$A1[0]
	mul	$a1			# a[3]*a[1]
	add	%rax,$A1[1]		# a[3]*a[1]+t[4]
	 mov	$ai,%rax
	adc	%rdx,$A1[0]

	xor	$A0[0],$A0[0]
	add	$A1[1],$A0[1]
	adc	\$0,$A0[0]
	mul	$a0			# a[4]*a[0]
	add	%rax,$A0[1]		# a[4]*a[0]+a[3]*a[1]+t[4]
	 mov	$ai,%rax		# a[3]
	adc	%rdx,$A0[0]
	mov	$A0[1],($tptr,$j)	# t[4]
	jmp	.Lsqr_inner

.align	16
.Lsqr_inner_done:
	xor	$A1[0],$A1[0]
	add	$A0[1],$A1[1]
	adc	\$0,$A1[0]
	mul	$a1			# a[3]*a[1]
	add	%rax,$A1[1]
	 mov	-16($aptr),%rax		# a[2]
	adc	%rdx,$A1[0]

	mov	$A1[1],($tptr)		# t[4]
	mov	$A1[0],8($tptr)		# t[5]

	add	\$16,$i
	jnz	.Lsqr_outer

	mul	$ai			# a[2]*a[3]
___
{
my ($shift,$carry)=($a0,$a1);
$code.=<<___;
	 add	\$8,$i
	 xor	$shift,$shift
	 sub	$num,$i			# $i=8-$num
	 xor	$carry,$carry

	add	$A1[0],%rax		# t[5]
	adc	\$0,%rdx
	mov	%rax,8($tptr)		# t[5]
	mov	%rdx,16($tptr)		# t[6]
	mov	$carry,24($tptr)	# t[7]

	 mov	-8($aptr,$i),%rax	# a[0]
	lea	64(%rsp,$num,2),$tptr
	 mov	-16($tptr,$i,2),$A0[0]	# t[0]
	 mov	-8($tptr,$i,2),$A0[1]	# t[1]
	jmp	.Lsqr_shift_n_add

.align	16
.Lsqr_shift_n_add:
	lea	($shift,$A0[0],2),$A1[0]# t[2*i]<<1 | shift
	shr	\$63,$A0[0]
	lea	(,$A0[1],2),$A1[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$A1[1]		# | t[2*i]>>63
	 mov	0($tptr,$i,2),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	 mov	8($tptr,$i,2),$A0[1]	# t[2*i+2+1]	# prefetch
	neg	$carry			# mov $carry,cf
	adc	%rax,$A1[0]
	 mov	0($aptr,$i),%rax	# a[i+1]	# prefetch
	adc	%rdx,$A1[1]
	mov	$A1[0],-16($tptr,$i,2)
	sbb	$carry,$carry		# mov cf,$carry
	mov	$A1[1],-8($tptr,$i,2)
	add	\$8,$i
	jnz	.Lsqr_shift_n_add

	lea	($shift,$A0[0],2),$A1[0]# t[2*i]<<1|shift
	shr	\$63,$A0[0]
	lea	(,$A0[1],2),$A1[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$A1[1]		# | t[2*i]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	adc	%rax,$A1[0]
	adc	%rdx,$A1[1]
	mov	$A1[0],-16($tptr)
	mov	$A1[1],-8($tptr)
___
}
##############################################################
# Montgomery reduction part, "word-by-word" algorithm.
#
{
my ($topbit,$nptr)=("%rbp",$aptr);
my ($m0,$m1)=($a0,$a1);
my @Ni=("%rbx","%r9");
$code.=<<___;
	mov	40(%rsp),$nptr		# restore $nptr
	xor	$j,$j
	mov	$num,0(%rsp)		# save $num
	sub	$num,$j			# $j=-$num
	 mov	64(%rsp),$A0[0]		# t[0]		# modsched #
	 mov	$n0,$m0			#		# modsched #
	lea	64(%rsp,$num,2),%rax	# end of t[] buffer
	lea	64(%rsp,$num),$tptr	# end of t[] window
	mov	%rax,8(%rsp)		# save end of t[] buffer
	lea	($nptr,$num),$nptr	# end of n[] buffer
	xor	$topbit,$topbit		# $topbit=0

	mov	0($nptr,$j),%rax	# n[0]		# modsched #
	mov	8($nptr,$j),$Ni[1]	# n[1]		# modsched #
	 imulq	$A0[0],$m0		# m0=t[0]*n0	# modsched #
	 mov	%rax,$Ni[0]		#		# modsched #
	jmp	.Lmont_outer

.align	16
.Lmont_outer:
	xor	$A0[1],$A0[1]
	mul	$m0			# n[0]*m0
	add	%rax,$A0[0]		# n[0]*m0+t[0]
	 mov	$Ni[1],%rax
	adc	%rdx,$A0[1]
	mov	$n0,$m1

	xor	$A0[0],$A0[0]
	add	8($tptr,$j),$A0[1]
	adc	\$0,$A0[0]
	mul	$m0			# n[1]*m0
	add	%rax,$A0[1]		# n[1]*m0+t[1]
	 mov	$Ni[0],%rax
	adc	%rdx,$A0[0]

	imulq	$A0[1],$m1
	lea	16($j),$j
	jmp	.Lmont_inner

.align	16
.Lmont_inner:
	mov	($nptr,$j),$Ni[0]	# n[2]
	xor	$A1[1],$A1[1]
	add	$A0[1],$A1[0]
	adc	\$0,$A1[1]
	mul	$m1			# n[0]*m1
	add	%rax,$A1[0]		# n[0]*m1+"t[1]"
	 mov	$Ni[0],%rax
	adc	%rdx,$A1[1]
	mov	$A1[0],-8($tptr,$j)	# "t[1]"

	xor	$A0[1],$A0[1]
	add	($tptr,$j),$A0[0]
	adc	\$0,$A0[1]
	mul	$m0			# n[2]*m0
	add	%rax,$A0[0]		# n[2]*m0+t[2]
	 mov	$Ni[1],%rax
	adc	%rdx,$A0[1]

	mov	8($nptr,$j),$Ni[1]	# n[3]
	xor	$A1[0],$A1[0]
	add	$A0[0],$A1[1]
	adc	\$0,$A1[0]
	mul	$m1			# n[1]*m1
	add	%rax,$A1[1]		# n[1]*m1+"t[2]"
	 mov	$Ni[1],%rax
	adc	%rdx,$A1[0]
	mov	$A1[1],($tptr,$j)	# "t[2]"

	xor	$A0[0],$A0[0]
	add	8($tptr,$j),$A0[1]
	lea	16($j),$j
	adc	\$0,$A0[0]
	mul	$m0			# n[3]*m0
	add	%rax,$A0[1]		# n[3]*m0+t[3]
	 mov	$Ni[0],%rax
	adc	%rdx,$A0[0]
	cmp	\$0,$j
	jne	.Lmont_inner

	 sub	0(%rsp),$j		# $j=-$num	# modsched #
	 mov	$n0,$m0			#		# modsched #

	xor	$A1[1],$A1[1]
	add	$A0[1],$A1[0]
	adc	\$0,$A1[1]
	mul	$m1			# n[2]*m1
	add	%rax,$A1[0]		# n[2]*m1+"t[3]"
	mov	$Ni[1],%rax
	adc	%rdx,$A1[1]
	mov	$A1[0],-8($tptr)	# "t[3]"

	xor	$A0[1],$A0[1]
	add	($tptr),$A0[0]		# +t[4]
	adc	\$0,$A0[1]
	 mov	0($nptr,$j),$Ni[0]	# n[0]		# modsched #
	add	$topbit,$A0[0]
	adc	\$0,$A0[1]

	 imulq	16($tptr,$j),$m0	# m0=t[0]*n0	# modsched #
	xor	$A1[0],$A1[0]
	 mov	8($nptr,$j),$Ni[1]	# n[1]		# modsched #
	add	$A0[0],$A1[1]
	 mov	16($tptr,$j),$A0[0]	# t[0]		# modsched #
	adc	\$0,$A1[0]
	mul	$m1			# n[3]*m1
	add	%rax,$A1[1]		# n[3]*m1+"t[4]"
	 mov	$Ni[0],%rax		#		# modsched #
	adc	%rdx,$A1[0]
	mov	$A1[1],($tptr)		# "t[4]"

	xor	$topbit,$topbit
	add	8($tptr),$A1[0]		# +t[5]
	adc	$topbit,$topbit
	add	$A0[1],$A1[0]
	lea	16($tptr),$tptr		# "t[$num]>>128"
	adc	\$0,$topbit
	mov	$A1[0],-8($tptr)	# "t[5]"
	cmp	8(%rsp),$tptr		# are we done?
	jb	.Lmont_outer

	mov	0(%rsp),$num		# restore $num
	mov	$topbit,($tptr)		# save $topbit
___
}
##############################################################
# Post-condition, 2x unrolled copy from bn_mul_mont
#
{
my ($tptr,$nptr)=("%rbx",$aptr);
$code.=<<___;
	lea	64(%rsp,$num),$tptr	# upper half of t[2*$num] holds result
	shr	\$4,$num		# num/2
	mov	32(%rsp),$rptr		# restore $rptr
	mov	40(%rsp),$nptr		# restore $nptr
	lea	-1($num),$j		# j=num/2-1

	mov	($tptr),%rax		# tp[0]
	xor	$i,$i			# i=0 and clear CF!
	jmp	.Lsqr_sub
.align	16
.Lsqr_sub:
	mov	8($tptr,$i,8),%rdx
	sbb	0($nptr,$i,8),%rax
	sbb	8($nptr,$i,8),%rdx
	mov	%rax,0($rptr,$i,8)	# rp[i]=tp[i]-np[i]
	mov	%rdx,8($rptr,$i,8)	# rp[i]=tp[i]-np[i]
	mov	16($tptr,$i,8),%rax	# tp[i+1]
	lea	2($i),$i		# i++
	dec	$j			# doesn't affect CF!
	jge	.Lsqr_sub

	sbb	\$0,%rax		# handle upmost overflow bit
	xor	$i,$i			# i=0
	and	%rax,$tptr
	not	%rax
	mov	$rptr,$nptr
	and	%rax,$nptr
	lea	-1($num),$j
	or	$nptr,$tptr		# tp=borrow?tp:rp

	lea	64(%rsp,$num,8),$nptr
	lea	($nptr,$num,8),$nptr
	jmp	.Lsqr_copy
.align	16
.Lsqr_copy:				# copy or in-place refresh
	movdqu	($tptr,$i),%xmm1
	movdqa	%xmm0,64(%rsp,$i)	# zap lower half of temporary vector
	movdqa	%xmm0,($nptr,$i)	# zap upper half of temporary vector
	movdqu	%xmm1,($rptr,$i)
	lea	16($i),$i
	dec	$j
	jge	.Lsqr_copy
___
}
$code.=<<___;
	mov	56(%rsp),%rsi		# restore %rsp
	mov	\$1,%rax
	mov	0(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lsqr_epilogue:
	ret
.size	bn_sqr_mont,.-bn_sqr_mont
___
}}}
$code.=<<___;
.asciz	"Montgomery Multiplication for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	16
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	mul_handler,\@abi-omnipotent
.align	16
mul_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lprologue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lprologue
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	lea	.Lepilogue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=.Lepilogue
	jae	.Lcommon_seh_tail

	mov	192($context),%r10	# pull $num
	mov	8(%rax,%r10,8),%rax	# pull saved stack pointer
	lea	48(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

	jmp	.Lcommon_seh_tail
.size	mul_handler,.-mul_handler

.type	sqr_handler,\@abi-omnipotent
.align	16
sqr_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lsqr_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lsqr_body
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	lea	.Lsqr_epilogue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=.Lsqr_epilogue
	jae	.Lcommon_seh_tail

	mov	56(%rax),%rax		# pull saved stack pointer
	lea	48(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lcommon_seh_tail:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	sqr_handler,.-sqr_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_bn_mul_mont
	.rva	.LSEH_end_bn_mul_mont
	.rva	.LSEH_info_bn_mul_mont

	.rva	.LSEH_begin_bn_sqr_mont
	.rva	.LSEH_end_bn_sqr_mont
	.rva	.LSEH_info_bn_sqr_mont

.section	.xdata
.align	8
.LSEH_info_bn_mul_mont:
	.byte	9,0,0,0
	.rva	mul_handler
.LSEH_info_bn_sqr_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
___
}

print $code;
close STDOUT;
