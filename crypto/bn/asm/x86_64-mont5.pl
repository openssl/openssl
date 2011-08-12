#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# August 2011.
#
# Companion to x86_64-mont.pl that optimizes cache-timing attack
# countermeasures. The subroutines are produced by replacing bp[i]
# references in their x86_64-mont.pl counterparts with cache-neutral
# references to powers table computed in BN_mod_exp_mont_consttime.
# In addition subroutine that scatters elements of the powers table
# is implemented, so that scatter-/gathering can be tuned without
# bn_exp.c modifications.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

# int bn_mul_mont_gather5(
$rp="%rdi";	# BN_ULONG *rp,
$ap="%rsi";	# const BN_ULONG *ap,
$bp="%rdx";	# const BN_ULONG *bp,
$np="%rcx";	# const BN_ULONG *np,
$n0="%r8";	# const BN_ULONG *n0,
$num="%r9";	# int num,
		# int idx);	# 0 to 2^5-1, "index" in $bp holding
				# pre-computed powers of a', interlaced
				# in such manner that b[0] is $bp[idx],
				# b[1] is [2^5+idx], etc.
$lo0="%r10";
$hi0="%r11";
$hi1="%r13";
$i="%r14";
$j="%r15";
$m0="%rbx";
$m1="%rbp";

$code=<<___;
.text

.globl	bn_mul_mont_gather5
.type	bn_mul_mont_gather5,\@function,6
.align	64
bn_mul_mont_gather5:
	test	\$3,${num}d
	jnz	.Lmul_enter
	cmp	\$8,${num}d
	jb	.Lmul_enter
	jmp	.Lmul4x_enter

.align	16
.Lmul_enter:
	mov	`($win64?56:8)`(%rsp),%r10d	# load 7th argument
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	2($num),%r11
	mov	%rsp,%rax
	neg	%r11
	lea	(%rsp,%r11,8),%rsp	# tp=alloca(8*(num+2))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%rax,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lmul_body:
	mov	$bp,%r12		# reassign $bp
___
		$bp="%r12";
		$STRIDE=2**5*8;		# 5 is "window size"
		$N=$STRIDE/4;		# should match cache line size
$code.=<<___;
	mov	%r10,%r11
	shr	\$`log($N/8)/log(2)`,%r10
	and	\$`$N/8-1`,%r11
	not	%r10
	lea	.Lmagic_masks(%rip),%rax
	and	\$`2**5/($N/8)-1`,%r10	# 5 is "window size"
	lea	96($bp,%r11,8),$bp	# pointer within 1st cache line
	movq	0(%rax,%r10,8),%xmm4	# set of masks denoting which
	movq	8(%rax,%r10,8),%xmm5	# cache line contains element
	movq	16(%rax,%r10,8),%xmm6	# denoted by 7th argument
	movq	24(%rax,%r10,8),%xmm7

	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1
	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	movq	%xmm0,$m0		# m0=bp[0]

	mov	($n0),$n0		# pull n0[0] value
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$lo0
	mov	($np),%rax

	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	$lo0,$m1		# "tp[0]"*n0
	mov	%rdx,$hi0

	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	mulq	$m1			# np[0]*m1
	add	%rax,$lo0		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	jmp	.L1st_enter

.align	16
.L1st:
	add	%rax,$hi1
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$hi0,$hi1		# np[j]*m1+ap[j]*bp[0]
	mov	$lo0,$hi0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

.L1st_enter:
	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$hi0
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	lea	1($j),$j		# j++
	mov	%rdx,$lo0

	mulq	$m1			# np[j]*m1
	cmp	$num,$j
	jne	.L1st

	movq	%xmm0,$m0		# bp[1]

	add	%rax,$hi1
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$hi0,$hi1		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1
	mov	$lo0,$hi0

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
	jmp	.Louter
.align	16
.Louter:
	xor	$j,$j			# j=0
	mov	$n0,$m1
	mov	(%rsp),$lo0

	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1

	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$lo0		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	$lo0,$m1		# tp[0]*n0
	mov	%rdx,$hi0

	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	mulq	$m1			# np[0]*m1
	add	%rax,$lo0		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	8(%rsp),$lo0		# tp[1]
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	jmp	.Linner_enter

.align	16
.Linner:
	add	%rax,$hi1
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$lo0,$hi1		# np[j]*m1+ap[j]*bp[i]+tp[j]
	mov	(%rsp,$j,8),$lo0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

.Linner_enter:
	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$hi0
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	add	$hi0,$lo0		# ap[j]*bp[i]+tp[j]
	mov	%rdx,$hi0
	adc	\$0,$hi0
	lea	1($j),$j		# j++

	mulq	$m1			# np[j]*m1
	cmp	$num,$j
	jne	.Linner

	movq	%xmm0,$m0		# bp[i+1]

	add	%rax,$hi1
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$lo0,$hi1		# np[j]*m1+ap[j]*bp[i]+tp[j]
	mov	(%rsp,$j,8),$lo0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

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

	xor	$i,$i			# i=0 and clear CF!
	mov	(%rsp),%rax		# tp[0]
	lea	(%rsp),$ap		# borrow ap for tp
	mov	$num,$j			# j=num
	jmp	.Lsub
.align	16
.Lsub:	sbb	($np,$i,8),%rax
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]-np[i]
	mov	8($ap,$i,8),%rax	# tp[i+1]
	lea	1($i),$i		# i++
	dec	$j			# doesnn't affect CF!
	jnz	.Lsub

	sbb	\$0,%rax		# handle upmost overflow bit
	xor	$i,$i
	and	%rax,$ap
	not	%rax
	mov	$rp,$np
	and	%rax,$np
	mov	$num,$j			# j=num
	or	$np,$ap			# ap=borrow?tp:rp
.align	16
.Lcopy:					# copy or in-place refresh
	mov	($ap,$i,8),%rax
	mov	$i,(%rsp,$i,8)		# zap temporary vector
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]
	lea	1($i),$i
	sub	\$1,$j
	jnz	.Lcopy

	mov	8(%rsp,$num,8),%rsi	# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lmul_epilogue:
	ret
.size	bn_mul_mont_gather5,.-bn_mul_mont_gather5
___
{{{
my @A=("%r10","%r11");
my @N=("%r13","%rdi");
$code.=<<___;
.type	bn_mul4x_mont_gather5,\@function,6
.align	16
bn_mul4x_mont_gather5:
.Lmul4x_enter:
	mov	`($win64?56:8)`(%rsp),%r10d	# load 7th argument
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	4($num),%r11
	mov	%rsp,%rax		# !!!!
	neg	%r11
	lea	(%rsp,%r11,8),%rsp	# tp=alloca(8*(num+4))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%rax,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lmul4x_body:
	mov	$rp,16(%rsp,$num,8)	# tp[num+2]=$rp
	mov	%rdx,%r12		# reassign $bp
___
		$bp="%r12";
		$STRIDE=2**5*8;		# 5 is "window size"
		$N=$STRIDE/4;		# should match cache line size
$code.=<<___;
	mov	%r10,%r11
	shr	\$`log($N/8)/log(2)`,%r10
	and	\$`$N/8-1`,%r11
	not	%r10
	lea	.Lmagic_masks(%rip),%rax
	and	\$`2**5/($N/8)-1`,%r10	# 5 is "window size"
	lea	96($bp,%r11,8),$bp	# pointer within 1st cache line
	movq	0(%rax,%r10,8),%xmm4	# set of masks denoting which
	movq	8(%rax,%r10,8),%xmm5	# cache line contains element
	movq	16(%rax,%r10,8),%xmm6	# denoted by 7th argument
	movq	24(%rax,%r10,8),%xmm7

	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1
	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3
	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	movq	%xmm0,$m0		# m0=bp[0]
	mov	($n0),$n0		# pull n0[0] value
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$A[0]
	mov	($np),%rax

	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	$A[0],$m1		# "tp[0]"*n0
	mov	%rdx,$A[1]

	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	mulq	$m1			# np[0]*m1
	add	%rax,$A[0]		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$N[1]

	mulq	$m0
	add	%rax,$A[1]
	mov	8($np),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1
	add	%rax,$N[1]
	mov	16($ap),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	lea	4($j),$j		# j++
	adc	\$0,%rdx
	mov	$N[1],(%rsp)
	mov	%rdx,$N[0]
	jmp	.L1st4x
.align	16
.L1st4x:
	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	8($np,$j,8),%rax
	adc	\$0,%rdx
	lea	4($j),$j		# j++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	-16($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-32(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]
	cmp	$num,$j
	jl	.L1st4x

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	movq	%xmm0,$m0		# bp[1]

	xor	$N[1],$N[1]
	add	$A[0],$N[0]
	adc	\$0,$N[1]
	mov	$N[0],-8(%rsp,$j,8)
	mov	$N[1],(%rsp,$j,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
.align	4
.Louter4x:
	xor	$j,$j			# j=0
	movq	`0*$STRIDE/4-96`($bp),%xmm0
	movq	`1*$STRIDE/4-96`($bp),%xmm1
	pand	%xmm4,%xmm0
	movq	`2*$STRIDE/4-96`($bp),%xmm2
	pand	%xmm5,%xmm1

	mov	(%rsp),$A[0]
	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$A[0]		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	movq	`3*$STRIDE/4-96`($bp),%xmm3
	pand	%xmm6,%xmm2
	por	%xmm1,%xmm0
	pand	%xmm7,%xmm3

	imulq	$A[0],$m1		# tp[0]*n0
	mov	%rdx,$A[1]

	por	%xmm2,%xmm0
	lea	$STRIDE($bp),$bp
	por	%xmm3,%xmm0

	mulq	$m1			# np[0]*m1
	add	%rax,$A[0]		# "$N[0]", discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	8($np),%rax
	adc	\$0,%rdx
	add	8(%rsp),$A[1]		# +tp[1]
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	16($ap),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[i]+tp[j]
	lea	4($j),$j		# j+=2
	adc	\$0,%rdx
	mov	$N[1],(%rsp)		# tp[j-1]
	mov	%rdx,$N[0]
	jmp	.Linner4x
.align	16
.Linner4x:
	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	add	-16(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	add	-8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	add	(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	8($np,$j,8),%rax
	adc	\$0,%rdx
	add	8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	lea	4($j),$j		# j++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	-16($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-32(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]
	cmp	$num,$j
	jl	.Linner4x

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	add	-16(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	add	-8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	lea	1($i),$i		# i++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	movq	%xmm0,$m0		# bp[i+1]

	xor	$N[1],$N[1]
	add	$A[0],$N[0]
	adc	\$0,$N[1]
	add	(%rsp,$num,8),$N[0]	# pull upmost overflow bit
	adc	\$0,$N[1]
	mov	$N[0],-8(%rsp,$j,8)
	mov	$N[1],(%rsp,$j,8)	# store upmost overflow bit

	cmp	$num,$i
	jl	.Louter4x
___
{
my @ri=("%rax","%rdx",$m0,$m1);
$code.=<<___;
	mov	16(%rsp,$num,8),$rp	# restore $rp
	mov	0(%rsp),@ri[0]		# tp[0]
	pxor	%xmm0,%xmm0
	mov	8(%rsp),@ri[1]		# tp[1]
	shr	\$2,$num		# num/=4
	lea	(%rsp),$ap		# borrow ap for tp
	xor	$i,$i			# i=0 and clear CF!

	sub	0($np),@ri[0]
	mov	16($ap),@ri[2]		# tp[2]
	mov	24($ap),@ri[3]		# tp[3]
	sbb	8($np),@ri[1]
	lea	-1($num),$j		# j=num/4-1
	jmp	.Lsub4x
.align	16
.Lsub4x:
	mov	@ri[0],0($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	@ri[1],8($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	16($np,$i,8),@ri[2]
	mov	32($ap,$i,8),@ri[0]	# tp[i+1]
	mov	40($ap,$i,8),@ri[1]
	sbb	24($np,$i,8),@ri[3]
	mov	@ri[2],16($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	@ri[3],24($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	32($np,$i,8),@ri[0]
	mov	48($ap,$i,8),@ri[2]
	mov	56($ap,$i,8),@ri[3]
	sbb	40($np,$i,8),@ri[1]
	lea	4($i),$i		# i++
	dec	$j			# doesnn't affect CF!
	jnz	.Lsub4x

	mov	@ri[0],0($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	32($ap,$i,8),@ri[0]	# load overflow bit
	sbb	16($np,$i,8),@ri[2]
	mov	@ri[1],8($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	24($np,$i,8),@ri[3]
	mov	@ri[2],16($rp,$i,8)	# rp[i]=tp[i]-np[i]

	sbb	\$0,@ri[0]		# handle upmost overflow bit
	mov	@ri[3],24($rp,$i,8)	# rp[i]=tp[i]-np[i]
	xor	$i,$i			# i=0
	and	@ri[0],$ap
	not	@ri[0]
	mov	$rp,$np
	and	@ri[0],$np
	lea	-1($num),$j
	or	$np,$ap			# ap=borrow?tp:rp

	movdqu	($ap),%xmm1
	movdqa	%xmm0,(%rsp)
	movdqu	%xmm1,($rp)
	jmp	.Lcopy4x
.align	16
.Lcopy4x:					# copy or in-place refresh
	movdqu	16($ap,$i),%xmm2
	movdqu	32($ap,$i),%xmm1
	movdqa	%xmm0,16(%rsp,$i)
	movdqu	%xmm2,16($rp,$i)
	movdqa	%xmm0,32(%rsp,$i)
	movdqu	%xmm1,32($rp,$i)
	lea	32($i),$i
	dec	$j
	jnz	.Lcopy4x

	shl	\$2,$num
	movdqu	16($ap,$i),%xmm2
	movdqa	%xmm0,16(%rsp,$i)
	movdqu	%xmm2,16($rp,$i)
___
}
$code.=<<___;
	mov	8(%rsp,$num,8),%rsi	# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lmul4x_epilogue:
	ret
.size	bn_mul4x_mont_gather5,.-bn_mul4x_mont_gather5
___
}}}

{
my ($inp,$num,$tbl,$idx)=$win64?("%rcx","%rdx","%r8", "%r9") : # Win64 order
				("%rdi","%rsi","%rdx","%rcx"); # Unix order
$code.=<<___;
.globl	bn_scatter5
.type	bn_scatter5,\@abi-omnipotent
.align	16
bn_scatter5:
	lea	($tbl,$idx,8),$tbl
.Lscatter:
	mov	($inp),%rax
	lea	8($inp),$inp
	mov	%rax,($tbl)
	lea	32*8($tbl),$tbl
	sub	\$1,$num
	jnz	.Lscatter
	ret
.size	bn_scatter5,.-bn_scatter5
___
}
$code.=<<___;
.align	64
.Lmagic_masks:
	.long	0,0, 0,0, 0,0, -1,-1
	.long	0,0, 0,0, 0,0,  0,0
.asciz	"Montgomery Multiplication with scatter/gather for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;
close STDOUT;
