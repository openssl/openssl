#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
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

# August 2011.
#
# Unroll and modulo-schedule inner loops in such manner that they
# are "fallen through" for input lengths of 8, which is critical for
# 1024-bit RSA *sign*. Average performance improvement in comparison
# to *initial* version of this module from 2005 is ~0%/30%/40%/45%
# for 512-/1024-/2048-/4096-bit RSA *sign* benchmarks respectively.

# June 2013.
#
# Optimize reduction in squaring procedure and improve 1024+-bit RSA
# sign performance by 10-16% on Intel Sandy Bridge and later
# (virtually same on non-Intel processors).

# August 2013.
#
# Add MULX/ADOX/ADCX code path.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$addx = ($1>=2.22);
}

if (!$addx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	    `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
	$addx = ($1>=2.10);
}

if (!$addx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
	    `ml64 2>&1` =~ /Version ([0-9]+)\./) {
	$addx = ($1>=11);
}

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

.extern	OPENSSL_ia32cap_P

.globl	bn_mul_mont
.type	bn_mul_mont,\@function,6
.align	16
bn_mul_mont:
	test	\$3,${num}d
	jnz	.Lmul_enter
	cmp	\$8,${num}d
	jb	.Lmul_enter
___
$code.=<<___ if ($addx);
	mov	OPENSSL_ia32cap_P+8(%rip),%r11d
___
$code.=<<___;
	cmp	$ap,$bp
	jne	.Lmul4x_enter
	test	\$7,${num}d
	jz	.Lsqr8x_enter
	jmp	.Lmul4x_enter

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
.Lmul_body:
	mov	$bp,%r12		# reassign $bp
___
		$bp="%r12";
$code.=<<___;
	mov	($n0),$n0		# pull n0[0] value
	mov	($bp),$m0		# m0=bp[0]
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$lo0
	mov	($np),%rax

	imulq	$lo0,$m1		# "tp[0]"*n0
	mov	%rdx,$hi0

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
	mov	($bp,$i,8),$m0		# m0=bp[i]
	xor	$j,$j			# j=0
	mov	$n0,$m1
	mov	(%rsp),$lo0
	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$lo0		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	imulq	$lo0,$m1		# tp[0]*n0
	mov	%rdx,$hi0

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
.size	bn_mul_mont,.-bn_mul_mont
___
{{{
my @A=("%r10","%r11");
my @N=("%r13","%rdi");
$code.=<<___;
.type	bn_mul4x_mont,\@function,6
.align	16
bn_mul4x_mont:
.Lmul4x_enter:
___
$code.=<<___ if ($addx);
	and	\$0x80100,%r11d
	cmp	\$0x80100,%r11d
	je	.Lmulx4x_enter
___
$code.=<<___;
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	4($num),%r10
	mov	%rsp,%r11
	neg	%r10
	lea	(%rsp,%r10,8),%rsp	# tp=alloca(8*(num+4))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%r11,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lmul4x_body:
	mov	$rp,16(%rsp,$num,8)	# tp[num+2]=$rp
	mov	%rdx,%r12		# reassign $bp
___
		$bp="%r12";
$code.=<<___;
	mov	($n0),$n0		# pull n0[0] value
	mov	($bp),$m0		# m0=bp[0]
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$A[0]
	mov	($np),%rax

	imulq	$A[0],$m1		# "tp[0]"*n0
	mov	%rdx,$A[1]

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

	xor	$N[1],$N[1]
	add	$A[0],$N[0]
	adc	\$0,$N[1]
	mov	$N[0],-8(%rsp,$j,8)
	mov	$N[1],(%rsp,$j,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
.align	4
.Louter4x:
	mov	($bp,$i,8),$m0		# m0=bp[i]
	xor	$j,$j			# j=0
	mov	(%rsp),$A[0]
	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$A[0]		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	imulq	$A[0],$m1		# tp[0]*n0
	mov	%rdx,$A[1]

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
.size	bn_mul4x_mont,.-bn_mul4x_mont
___
}}}
{{{
######################################################################
# void bn_sqr8x_mont(
my $rptr="%rdi";	# const BN_ULONG *rptr,
my $aptr="%rsi";	# const BN_ULONG *aptr,
my $bptr="%rdx";	# not used
my $nptr="%rcx";	# const BN_ULONG *nptr,
my $n0  ="%r8";		# const BN_ULONG *n0);
my $num ="%r9";		# int num, has to be divisible by 8

my ($i,$j,$tptr)=("%rbp","%rcx",$rptr);
my @A0=("%r10","%r11");
my @A1=("%r12","%r13");
my ($a0,$a1,$ai)=("%r14","%r15","%rbx");

$code.=<<___;
.type	bn_sqr8x_mont,\@function,6
.align	32
bn_sqr8x_mont:
.Lsqr8x_enter:
___
$code.=<<___ if ($addx);
	and	\$0x80100,%r11d
	cmp	\$0x80100,%r11d
	je	.Lsqrx8x_enter
___
$code.=<<___;
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
.Lsqr8x_body:
	##############################################################
	# Squaring part:
	#
	# a) multiply-n-add everything but a[i]*a[i];
	# b) shift result of a) by 1 to the left and accumulate
	#    a[i]*a[i] products;
	#
	##############################################################
	#                                                     a[1]a[0]
	#                                                 a[2]a[0]
	#                                             a[3]a[0]
	#                                             a[2]a[1]
	#                                         a[4]a[0]
	#                                         a[3]a[1]
	#                                     a[5]a[0]
	#                                     a[4]a[1]
	#                                     a[3]a[2]
	#                                 a[6]a[0]
	#                                 a[5]a[1]
	#                                 a[4]a[2]
	#                             a[7]a[0]
	#                             a[6]a[1]
	#                             a[5]a[2]
	#                             a[4]a[3]
	#                         a[7]a[1]
	#                         a[6]a[2]
	#                         a[5]a[3]
	#                     a[7]a[2]
	#                     a[6]a[3]
	#                     a[5]a[4]
	#                 a[7]a[3]
	#                 a[6]a[4]
	#             a[7]a[4]
	#             a[6]a[5]
	#         a[7]a[5]
	#     a[7]a[6]
	#                                                     a[1]a[0]
	#                                                 a[2]a[0]
	#                                             a[3]a[0]
	#                                         a[4]a[0]
	#                                     a[5]a[0]
	#                                 a[6]a[0]
	#                             a[7]a[0]
	#                                             a[2]a[1]
	#                                         a[3]a[1]
	#                                     a[4]a[1]
	#                                 a[5]a[1]
	#                             a[6]a[1]
	#                         a[7]a[1]
	#                                     a[3]a[2]
	#                                 a[4]a[2]
	#                             a[5]a[2]
	#                         a[6]a[2]
	#                     a[7]a[2]
	#                             a[4]a[3]
	#                         a[5]a[3]
	#                     a[6]a[3]
	#                 a[7]a[3]
	#                     a[5]a[4]
	#                 a[6]a[4]
	#             a[7]a[4]
	#             a[6]a[5]
	#         a[7]a[5]
	#     a[7]a[6]
	#                                                         a[0]a[0]
	#                                                 a[1]a[1]
	#                                         a[2]a[2]
	#                                 a[3]a[3]
	#                         a[4]a[4]
	#                 a[5]a[5]
	#         a[6]a[6]
	# a[7]a[7]

	lea	32(%r10),$i		# $i=-($num-32)
	lea	($aptr,$num),$aptr	# end of a[] buffer, ($aptr,$i)=&ap[2]

	mov	$num,$j			# $j=$num

					# comments apply to $num==8 case
	mov	-32($aptr,$i),$a0	# a[0]
	lea	64(%rsp,$num,2),$tptr	# end of tp[] buffer, &tp[2*$num]
	mov	-24($aptr,$i),%rax	# a[1]
	lea	-32($tptr,$i),$tptr	# end of tp[] window, &tp[2*$num-"$i"]
	mov	-16($aptr,$i),$ai	# a[2]
	mov	%rax,$a1

	mul	$a0			# a[1]*a[0]
	mov	%rax,$A0[0]		# a[1]*a[0]
	 mov	$ai,%rax		# a[2]
	mov	%rdx,$A0[1]
	mov	$A0[0],-24($tptr,$i)	# t[1]

	mul	$a0			# a[2]*a[0]
	add	%rax,$A0[1]
	 mov	$ai,%rax
	adc	\$0,%rdx
	mov	$A0[1],-16($tptr,$i)	# t[2]
	mov	%rdx,$A0[0]

	lea	-16($i),$j		# j=-16


	 mov	8($aptr,$j),$ai		# a[3]
	mul	$a1			# a[2]*a[1]
	mov	%rax,$A1[0]		# a[2]*a[1]+t[3]
	 mov	$ai,%rax
	mov	%rdx,$A1[1]

	 lea	16($j),$j
	mul	$a0			# a[3]*a[0]
	add	%rax,$A0[0]		# a[3]*a[0]+a[2]*a[1]+t[3]
	 mov	$ai,%rax
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	add	$A1[0],$A0[0]
	adc	\$0,$A0[1]
	mov	$A0[0],-8($tptr,$j)	# t[3]
	jmp	.Lsqr4x_1st

.align	32
.Lsqr4x_1st:
	 mov	($aptr,$j),$ai		# a[4]
	mul	$a1			# a[3]*a[1]
	add	%rax,$A1[1]		# a[3]*a[1]+t[4]
	 mov	$ai,%rax
	mov	%rdx,$A1[0]
	adc	\$0,$A1[0]

	mul	$a0			# a[4]*a[0]
	add	%rax,$A0[1]		# a[4]*a[0]+a[3]*a[1]+t[4]
	 mov	$ai,%rax		# a[3]
	 mov	8($aptr,$j),$ai		# a[5]
	mov	%rdx,$A0[0]
	adc	\$0,$A0[0]
	add	$A1[1],$A0[1]
	adc	\$0,$A0[0]


	mul	$a1			# a[4]*a[3]
	add	%rax,$A1[0]		# a[4]*a[3]+t[5]
	 mov	$ai,%rax
	 mov	$A0[1],($tptr,$j)	# t[4]
	mov	%rdx,$A1[1]
	adc	\$0,$A1[1]

	mul	$a0			# a[5]*a[2]
	add	%rax,$A0[0]		# a[5]*a[2]+a[4]*a[3]+t[5]
	 mov	$ai,%rax
	 mov	16($aptr,$j),$ai	# a[6]
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	add	$A1[0],$A0[0]
	adc	\$0,$A0[1]

	mul	$a1			# a[5]*a[3]
	add	%rax,$A1[1]		# a[5]*a[3]+t[6]
	 mov	$ai,%rax
	 mov	$A0[0],8($tptr,$j)	# t[5]
	mov	%rdx,$A1[0]
	adc	\$0,$A1[0]

	mul	$a0			# a[6]*a[2]
	add	%rax,$A0[1]		# a[6]*a[2]+a[5]*a[3]+t[6]
	 mov	$ai,%rax		# a[3]
	 mov	24($aptr,$j),$ai	# a[7]
	mov	%rdx,$A0[0]
	adc	\$0,$A0[0]
	add	$A1[1],$A0[1]
	adc	\$0,$A0[0]


	mul	$a1			# a[6]*a[5]
	add	%rax,$A1[0]		# a[6]*a[5]+t[7]
	 mov	$ai,%rax
	 mov	$A0[1],16($tptr,$j)	# t[6]
	mov	%rdx,$A1[1]
	adc	\$0,$A1[1]

	mul	$a0			# a[7]*a[4]
	add	%rax,$A0[0]		# a[7]*a[4]+a[6]*a[5]+t[6]
	 mov	$ai,%rax
	 lea	32($j),$j
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	add	$A1[0],$A0[0]
	adc	\$0,$A0[1]
	mov	$A0[0],-8($tptr,$j)	# t[7]

	cmp	\$0,$j
	jne	.Lsqr4x_1st

	mul	$a1			# a[7]*a[5]
	add	%rax,$A1[1]
	lea	16($i),$i
	adc	\$0,%rdx
	add	$A0[1],$A1[1]
	adc	\$0,%rdx

	mov	$A1[1],($tptr)		# t[8]
	mov	%rdx,$A1[0]
	mov	%rdx,8($tptr)		# t[9]
	jmp	.Lsqr4x_outer

.align	32
.Lsqr4x_outer:				# comments apply to $num==6 case
	mov	-32($aptr,$i),$a0	# a[0]
	lea	64(%rsp,$num,2),$tptr	# end of tp[] buffer, &tp[2*$num]
	mov	-24($aptr,$i),%rax	# a[1]
	lea	-32($tptr,$i),$tptr	# end of tp[] window, &tp[2*$num-"$i"]
	mov	-16($aptr,$i),$ai	# a[2]
	mov	%rax,$a1

	mov	-24($tptr,$i),$A0[0]	# t[1]
	mul	$a0			# a[1]*a[0]
	add	%rax,$A0[0]		# a[1]*a[0]+t[1]
	 mov	$ai,%rax		# a[2]
	adc	\$0,%rdx
	mov	$A0[0],-24($tptr,$i)	# t[1]
	mov	%rdx,$A0[1]

	mul	$a0			# a[2]*a[0]
	add	%rax,$A0[1]
	 mov	$ai,%rax
	adc	\$0,%rdx
	add	-16($tptr,$i),$A0[1]	# a[2]*a[0]+t[2]
	mov	%rdx,$A0[0]
	adc	\$0,$A0[0]
	mov	$A0[1],-16($tptr,$i)	# t[2]

	lea	-16($i),$j		# j=-16
	xor	$A1[0],$A1[0]


	 mov	8($aptr,$j),$ai		# a[3]
	mul	$a1			# a[2]*a[1]
	add	%rax,$A1[0]		# a[2]*a[1]+t[3]
	 mov	$ai,%rax
	adc	\$0,%rdx
	add	8($tptr,$j),$A1[0]
	mov	%rdx,$A1[1]
	adc	\$0,$A1[1]

	mul	$a0			# a[3]*a[0]
	add	%rax,$A0[0]		# a[3]*a[0]+a[2]*a[1]+t[3]
	 mov	$ai,%rax
	adc	\$0,%rdx
	add	$A1[0],$A0[0]
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	mov	$A0[0],8($tptr,$j)	# t[3]

	lea	16($j),$j
	jmp	.Lsqr4x_inner

.align	32
.Lsqr4x_inner:
	 mov	($aptr,$j),$ai		# a[4]
	mul	$a1			# a[3]*a[1]
	add	%rax,$A1[1]		# a[3]*a[1]+t[4]
	 mov	$ai,%rax
	mov	%rdx,$A1[0]
	adc	\$0,$A1[0]
	add	($tptr,$j),$A1[1]
	adc	\$0,$A1[0]

	mul	$a0			# a[4]*a[0]
	add	%rax,$A0[1]		# a[4]*a[0]+a[3]*a[1]+t[4]
	 mov	$ai,%rax		# a[3]
	 mov	8($aptr,$j),$ai		# a[5]
	mov	%rdx,$A0[0]
	adc	\$0,$A0[0]
	add	$A1[1],$A0[1]
	adc	\$0,$A0[0]

	mul	$a1			# a[4]*a[3]
	add	%rax,$A1[0]		# a[4]*a[3]+t[5]
	mov	$A0[1],($tptr,$j)	# t[4]
	 mov	$ai,%rax
	mov	%rdx,$A1[1]
	adc	\$0,$A1[1]
	add	8($tptr,$j),$A1[0]
	lea	16($j),$j		# j++
	adc	\$0,$A1[1]

	mul	$a0			# a[5]*a[2]
	add	%rax,$A0[0]		# a[5]*a[2]+a[4]*a[3]+t[5]
	 mov	$ai,%rax
	adc	\$0,%rdx
	add	$A1[0],$A0[0]
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	mov	$A0[0],-8($tptr,$j)	# t[5], "preloaded t[1]" below

	cmp	\$0,$j
	jne	.Lsqr4x_inner

	mul	$a1			# a[5]*a[3]
	add	%rax,$A1[1]
	adc	\$0,%rdx
	add	$A0[1],$A1[1]
	adc	\$0,%rdx

	mov	$A1[1],($tptr)		# t[6], "preloaded t[2]" below
	mov	%rdx,$A1[0]
	mov	%rdx,8($tptr)		# t[7], "preloaded t[3]" below

	add	\$16,$i
	jnz	.Lsqr4x_outer

					# comments apply to $num==4 case
	mov	-32($aptr),$a0		# a[0]
	lea	64(%rsp,$num,2),$tptr	# end of tp[] buffer, &tp[2*$num]
	mov	-24($aptr),%rax		# a[1]
	lea	-32($tptr,$i),$tptr	# end of tp[] window, &tp[2*$num-"$i"]
	mov	-16($aptr),$ai		# a[2]
	mov	%rax,$a1

	mul	$a0			# a[1]*a[0]
	add	%rax,$A0[0]		# a[1]*a[0]+t[1], preloaded t[1]
	 mov	$ai,%rax		# a[2]
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]

	mul	$a0			# a[2]*a[0]
	add	%rax,$A0[1]
	 mov	$ai,%rax
	 mov	$A0[0],-24($tptr)	# t[1]
	mov	%rdx,$A0[0]
	adc	\$0,$A0[0]
	add	$A1[1],$A0[1]		# a[2]*a[0]+t[2], preloaded t[2]
	 mov	-8($aptr),$ai		# a[3]
	adc	\$0,$A0[0]

	mul	$a1			# a[2]*a[1]
	add	%rax,$A1[0]		# a[2]*a[1]+t[3], preloaded t[3]
	 mov	$ai,%rax
	 mov	$A0[1],-16($tptr)	# t[2]
	mov	%rdx,$A1[1]
	adc	\$0,$A1[1]

	mul	$a0			# a[3]*a[0]
	add	%rax,$A0[0]		# a[3]*a[0]+a[2]*a[1]+t[3]
	 mov	$ai,%rax
	mov	%rdx,$A0[1]
	adc	\$0,$A0[1]
	add	$A1[0],$A0[0]
	adc	\$0,$A0[1]
	mov	$A0[0],-8($tptr)	# t[3]

	mul	$a1			# a[3]*a[1]
	add	%rax,$A1[1]
	 mov	-16($aptr),%rax		# a[2]
	adc	\$0,%rdx
	add	$A0[1],$A1[1]
	adc	\$0,%rdx

	mov	$A1[1],($tptr)		# t[4]
	mov	%rdx,$A1[0]
	mov	%rdx,8($tptr)		# t[5]

	mul	$ai			# a[2]*a[3]
___
{
my ($shift,$carry)=($a0,$a1);
my @S=(@A1,$ai,$n0);
$code.=<<___;
	 add	\$16,$i
	 xor	$shift,$shift
	 sub	$num,$i			# $i=16-$num
	 xor	$carry,$carry

	add	$A1[0],%rax		# t[5]
	adc	\$0,%rdx
	mov	%rax,8($tptr)		# t[5]
	mov	%rdx,16($tptr)		# t[6]
	mov	$carry,24($tptr)	# t[7]

	 mov	-16($aptr,$i),%rax	# a[0]
	lea	64(%rsp),$tptr
	 xor	$A0[0],$A0[0]		# t[0]
	 mov	8($tptr),$A0[1]		# t[1]

	lea	($shift,$A0[0],2),$S[0]	# t[2*i]<<1 | shift
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[1]		# | t[2*i]>>63
	 mov	16($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	24($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[0]
	 mov	-8($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[0],($tptr)
	adc	%rdx,$S[1]

	lea	($shift,$A0[0],2),$S[2]	# t[2*i]<<1 | shift
	 mov	$S[1],8($tptr)
	 sbb	$carry,$carry		# mov cf,$carry
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[3]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[3]		# | t[2*i]>>63
	 mov	32($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	40($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[2]
	 mov	0($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[2],16($tptr)
	adc	%rdx,$S[3]
	lea	16($i),$i
	mov	$S[3],24($tptr)
	sbb	$carry,$carry		# mov cf,$carry
	lea	64($tptr),$tptr
	jmp	.Lsqr4x_shift_n_add

.align	32
.Lsqr4x_shift_n_add:
	lea	($shift,$A0[0],2),$S[0]	# t[2*i]<<1 | shift
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[1]		# | t[2*i]>>63
	 mov	-16($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	-8($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[0]
	 mov	-8($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[0],-32($tptr)
	adc	%rdx,$S[1]

	lea	($shift,$A0[0],2),$S[2]	# t[2*i]<<1 | shift
	 mov	$S[1],-24($tptr)
	 sbb	$carry,$carry		# mov cf,$carry
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[3]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[3]		# | t[2*i]>>63
	 mov	0($tptr),$A0[0]		# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	8($tptr),$A0[1]		# t[2*i+2+1]	# prefetch
	adc	%rax,$S[2]
	 mov	0($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[2],-16($tptr)
	adc	%rdx,$S[3]

	lea	($shift,$A0[0],2),$S[0]	# t[2*i]<<1 | shift
	 mov	$S[3],-8($tptr)
	 sbb	$carry,$carry		# mov cf,$carry
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[1]		# | t[2*i]>>63
	 mov	16($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	24($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[0]
	 mov	8($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[0],0($tptr)
	adc	%rdx,$S[1]

	lea	($shift,$A0[0],2),$S[2]	# t[2*i]<<1 | shift
	 mov	$S[1],8($tptr)
	 sbb	$carry,$carry		# mov cf,$carry
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[3]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[3]		# | t[2*i]>>63
	 mov	32($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	40($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[2]
	 mov	16($aptr,$i),%rax	# a[i+1]	# prefetch
	mov	$S[2],16($tptr)
	adc	%rdx,$S[3]
	mov	$S[3],24($tptr)
	sbb	$carry,$carry		# mov cf,$carry
	lea	64($tptr),$tptr
	add	\$32,$i
	jnz	.Lsqr4x_shift_n_add

	lea	($shift,$A0[0],2),$S[0]	# t[2*i]<<1 | shift
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[1]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[1]		# | t[2*i]>>63
	 mov	-16($tptr),$A0[0]	# t[2*i+2]	# prefetch
	mov	$A0[1],$shift		# shift=t[2*i+1]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	 mov	-8($tptr),$A0[1]	# t[2*i+2+1]	# prefetch
	adc	%rax,$S[0]
	 mov	-8($aptr),%rax		# a[i+1]	# prefetch
	mov	$S[0],-32($tptr)
	adc	%rdx,$S[1]

	lea	($shift,$A0[0],2),$S[2]	# t[2*i]<<1|shift
	 mov	$S[1],-24($tptr)
	 sbb	$carry,$carry		# mov cf,$carry
	shr	\$63,$A0[0]
	lea	($j,$A0[1],2),$S[3]	# t[2*i+1]<<1 |
	shr	\$63,$A0[1]
	or	$A0[0],$S[3]		# | t[2*i]>>63
	mul	%rax			# a[i]*a[i]
	neg	$carry			# mov $carry,cf
	adc	%rax,$S[2]
	adc	%rdx,$S[3]
	mov	$S[2],-16($tptr)
	mov	$S[3],-8($tptr)
___
}
######################################################################
# Montgomery reduction part, "word-by-word" algorithm.
#
# This new path is inspired by multiple submissions from Intel, by
# Shay Gueron, Vlad Krasnov, Erdinc Ozturk, James Guilford,
# Vinodh Gopal...
{
my ($nptr,$tptr,$carry,$m0)=("%rbp","%rdi","%rsi","%rbx");

$code.=<<___;
	mov	40(%rsp),$nptr		# pull $nptr
	xor	%rax,%rax
	lea	($nptr,$num),%rdx	# end of n[]
	lea	64(%rsp,$num,2),$tptr	# end of t[] buffer
	mov	%rdx,0(%rsp)
	mov	$tptr,8(%rsp)
	mov	%rax,($tptr)		# clear top-most carry bit
	lea	64(%rsp,$num),$tptr	# end of initial t[] window
	neg	$num
	jmp	.L8x_reduction_loop

.align	32
.L8x_reduction_loop:
	lea	($tptr,$num),$tptr	# start of current t[] window
	mov	8*0($tptr),$m0
	mov	8*1($tptr),%r9
	mov	8*2($tptr),%r10
	mov	8*3($tptr),%r11
	mov	8*4($tptr),%r12
	mov	8*5($tptr),%r13
	mov	8*6($tptr),%r14
	mov	8*7($tptr),%r15
	lea	8*8($tptr),$tptr

	mov	$m0,%r8
	imulq	48(%rsp),$m0		# n0*a[0]
	mov	8*0($nptr),%rax		# n[0]
	mov	\$8,%ecx
	jmp	.L8x_reduce

.align	32
.L8x_reduce:
	mulq	$m0
	 mov	8*1($nptr),%rax		# n[1]
	neg	%r8
	mov	%rdx,%r8
	adc	\$0,%r8

	mulq	$m0
	add	%rax,%r9
	 mov	8*2($nptr),%rax
	adc	\$0,%rdx
	add	%r9,%r8
	 mov	$m0,64-8(%rsp,%rcx,8)	# put aside n0*a[i]
	mov	%rdx,%r9
	adc	\$0,%r9

	mulq	$m0
	add	%rax,%r10
	 mov	8*3($nptr),%rax
	adc	\$0,%rdx
	add	%r10,%r9
	 mov	48(%rsp),$carry		# pull n0, borrow $carry
	mov	%rdx,%r10
	adc	\$0,%r10

	mulq	$m0
	add	%rax,%r11
	 mov	8*4($nptr),%rax
	adc	\$0,%rdx
	 imulq	%r8,$carry		# modulo-scheduled
	add	%r11,%r10
	mov	%rdx,%r11
	adc	\$0,%r11

	mulq	$m0
	add	%rax,%r12
	 mov	8*5($nptr),%rax
	adc	\$0,%rdx
	add	%r12,%r11
	mov	%rdx,%r12
	adc	\$0,%r12

	mulq	$m0
	add	%rax,%r13
	 mov	8*6($nptr),%rax
	adc	\$0,%rdx
	add	%r13,%r12
	mov	%rdx,%r13
	adc	\$0,%r13

	mulq	$m0
	add	%rax,%r14
	 mov	8*7($nptr),%rax
	adc	\$0,%rdx
	add	%r14,%r13
	mov	%rdx,%r14
	adc	\$0,%r14

	mulq	$m0
	 mov	$carry,$m0		# n0*a[i]
	add	%rax,%r15
	 mov	8*0($nptr),%rax		# n[0]
	adc	\$0,%rdx
	add	%r15,%r14
	mov	%rdx,%r15
	adc	\$0,%r15

	dec	%ecx
	jnz	.L8x_reduce

	lea	8*8($nptr),$nptr
	xor	%rax,%rax
	mov	8(%rsp),%rdx		# pull end of t[]
	cmp	0(%rsp),$nptr		# end of n[]?
	jae	.L8x_no_tail

	add	8*0($tptr),%r8
	adc	8*1($tptr),%r9
	adc	8*2($tptr),%r10
	adc	8*3($tptr),%r11
	adc	8*4($tptr),%r12
	adc	8*5($tptr),%r13
	adc	8*6($tptr),%r14
	adc	8*7($tptr),%r15
	sbb	$carry,$carry		# top carry

	mov	64+56(%rsp),$m0		# pull n0*a[0]
	mov	\$8,%ecx
	mov	8*0($nptr),%rax
	jmp	.L8x_tail

.align	32
.L8x_tail:
	mulq	$m0
	add	%rax,%r8
	 mov	8*1($nptr),%rax
	 mov	%r8,($tptr)		# save result
	mov	%rdx,%r8
	adc	\$0,%r8

	mulq	$m0
	add	%rax,%r9
	 mov	8*2($nptr),%rax
	adc	\$0,%rdx
	add	%r9,%r8
	 lea	8($tptr),$tptr		# $tptr++
	mov	%rdx,%r9
	adc	\$0,%r9

	mulq	$m0
	add	%rax,%r10
	 mov	8*3($nptr),%rax
	adc	\$0,%rdx
	add	%r10,%r9
	mov	%rdx,%r10
	adc	\$0,%r10

	mulq	$m0
	add	%rax,%r11
	 mov	8*4($nptr),%rax
	adc	\$0,%rdx
	add	%r11,%r10
	mov	%rdx,%r11
	adc	\$0,%r11

	mulq	$m0
	add	%rax,%r12
	 mov	8*5($nptr),%rax
	adc	\$0,%rdx
	add	%r12,%r11
	mov	%rdx,%r12
	adc	\$0,%r12

	mulq	$m0
	add	%rax,%r13
	 mov	8*6($nptr),%rax
	adc	\$0,%rdx
	add	%r13,%r12
	mov	%rdx,%r13
	adc	\$0,%r13

	mulq	$m0
	add	%rax,%r14
	 mov	8*7($nptr),%rax
	adc	\$0,%rdx
	add	%r14,%r13
	mov	%rdx,%r14
	adc	\$0,%r14

	mulq	$m0
	 mov	64-16(%rsp,%rcx,8),$m0	# pull n0*a[i]
	add	%rax,%r15
	adc	\$0,%rdx
	add	%r15,%r14
	 mov	8*0($nptr),%rax		# pull n[0]
	mov	%rdx,%r15
	adc	\$0,%r15

	dec	%ecx
	jnz	.L8x_tail

	lea	8*8($nptr),$nptr
	mov	8(%rsp),%rdx		# pull end of t[]
	cmp	0(%rsp),$nptr		# end of n[]?
	jae	.L8x_tail_done		# break out of loop

	 mov	64+56(%rsp),$m0		# pull n0*a[0]
	neg	$carry
	 mov	8*0($nptr),%rax		# pull n[0]
	adc	8*0($tptr),%r8
	adc	8*1($tptr),%r9
	adc	8*2($tptr),%r10
	adc	8*3($tptr),%r11
	adc	8*4($tptr),%r12
	adc	8*5($tptr),%r13
	adc	8*6($tptr),%r14
	adc	8*7($tptr),%r15
	sbb	$carry,$carry		# top carry

	mov	\$8,%ecx
	jmp	.L8x_tail

.align	32
.L8x_tail_done:
	add	(%rdx),%r8		# can this overflow?
	xor	%rax,%rax

	neg	$carry
.L8x_no_tail:
	adc	8*0($tptr),%r8
	adc	8*1($tptr),%r9
	adc	8*2($tptr),%r10
	adc	8*3($tptr),%r11
	adc	8*4($tptr),%r12
	adc	8*5($tptr),%r13
	adc	8*6($tptr),%r14
	adc	8*7($tptr),%r15
	adc	\$0,%rax		# top-most carry

	mov	40(%rsp),$nptr		# restore $nptr

	mov	%r8,8*0($tptr)		# store top 512 bits
	mov	%r9,8*1($tptr)
	 mov	$nptr,$num		# $num is %r9, can't be moved upwards
	mov	%r10,8*2($tptr)
	 sub	0(%rsp),$num		# -$num
	mov	%r11,8*3($tptr)
	mov	%r12,8*4($tptr)
	mov	%r13,8*5($tptr)
	mov	%r14,8*6($tptr)
	mov	%r15,8*7($tptr)
	lea	8*8($tptr),$tptr
	mov	%rax,(%rdx)		# store top-most carry

	cmp	%rdx,$tptr		# end of t[]?
	jb	.L8x_reduction_loop

	neg	$num			# restore $num
___
}
##############################################################
# Post-condition, 4x unrolled copy from bn_mul_mont
#
{
my ($tptr,$nptr)=("%rbx",$aptr);
my @ri=("%rax","%rdx","%r10","%r11");
$code.=<<___;
	mov	64(%rsp,$num),@ri[0]	# tp[0]
	lea	64(%rsp,$num),$tptr	# upper half of t[2*$num] holds result
	mov	40(%rsp),$nptr		# restore $nptr
	shr	\$5,$num		# num/4
	mov	8($tptr),@ri[1]		# t[1]
	xor	$i,$i			# i=0 and clear CF!

	mov	32(%rsp),$rptr		# restore $rptr
	sub	0($nptr),@ri[0]
	mov	16($tptr),@ri[2]	# t[2]
	mov	24($tptr),@ri[3]	# t[3]
	sbb	8($nptr),@ri[1]
	lea	-1($num),$j		# j=num/4-1
	jmp	.Lsqr4x_sub
.align	32
.Lsqr4x_sub:
	mov	@ri[0],0($rptr)		# rp[i]=tp[i]-np[i]
	mov	@ri[1],8($rptr)		# rp[i]=tp[i]-np[i]
	sbb	16($nptr,$i,8),@ri[2]
	mov	32($tptr,$i,8),@ri[0]	# tp[i+1]
	mov	40($tptr,$i,8),@ri[1]
	sbb	24($nptr,$i,8),@ri[3]
	mov	@ri[2],16($rptr)	# rp[i]=tp[i]-np[i]
	mov	@ri[3],24($rptr)	# rp[i]=tp[i]-np[i]
	lea	32($rptr),$rptr
	sbb	32($nptr,$i,8),@ri[0]
	mov	48($tptr,$i,8),@ri[2]
	mov	56($tptr,$i,8),@ri[3]
	sbb	40($nptr,$i,8),@ri[1]
	lea	4($i),$i		# i++
	dec	$j			# doesn't affect CF!
	jnz	.Lsqr4x_sub

	mov	@ri[0],0($rptr)		# rp[i]=tp[i]-np[i]
	mov	32($tptr,$i,8),@ri[0]	# load overflow bit
	sbb	16($nptr,$i,8),@ri[2]
	mov	@ri[1],8($rptr)		# rp[i]=tp[i]-np[i]
	sbb	24($nptr,$i,8),@ri[3]
	mov	@ri[2],16($rptr)	# rp[i]=tp[i]-np[i]

	sbb	\$0,@ri[0]		# handle upmost overflow bit
	mov	@ri[3],24($rptr)	# rp[i]=tp[i]-np[i]
	mov	32(%rsp),$rptr		# restore $rptr
	xor	$i,$i			# i=0
	and	@ri[0],$tptr
	not	@ri[0]
	mov	$rptr,$nptr
	and	@ri[0],$nptr
	lea	-1($num),$j
	or	$nptr,$tptr		# tp=borrow?tp:rp

	pxor	%xmm0,%xmm0
	lea	64(%rsp,$num,8),$nptr
	movdqu	($tptr),%xmm1
	lea	($nptr,$num,8),$nptr
	movdqa	%xmm0,64(%rsp)		# zap lower half of temporary vector
	movdqa	%xmm0,($nptr)		# zap upper half of temporary vector
	movdqu	%xmm1,($rptr)
	jmp	.Lsqr4x_copy
.align	32
.Lsqr4x_copy:				# copy or in-place refresh
	movdqu	16($tptr,$i),%xmm2
	movdqu	32($tptr,$i),%xmm1
	movdqa	%xmm0,80(%rsp,$i)	# zap lower half of temporary vector
	movdqa	%xmm0,96(%rsp,$i)	# zap lower half of temporary vector
	movdqa	%xmm0,16($nptr,$i)	# zap upper half of temporary vector
	movdqa	%xmm0,32($nptr,$i)	# zap upper half of temporary vector
	movdqu	%xmm2,16($rptr,$i)
	movdqu	%xmm1,32($rptr,$i)
	lea	32($i),$i
	dec	$j
	jnz	.Lsqr4x_copy

	movdqu	16($tptr,$i),%xmm2
	movdqa	%xmm0,80(%rsp,$i)	# zap lower half of temporary vector
	movdqa	%xmm0,16($nptr,$i)	# zap upper half of temporary vector
	movdqu	%xmm2,16($rptr,$i)
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
.Lsqr8x_epilogue:
	ret
.size	bn_sqr8x_mont,.-bn_sqr8x_mont
___
}}}

if ($addx) {{{
my $bp="%rdx";	# original value

$code.=<<___;
.type	bn_mulx4x_mont,\@function,6
.align	32
bn_mulx4x_mont:
.Lmulx4x_enter:
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
	lea	-72(%rsp,%r10),%rsp	# alloca(frame+$num+8)
	lea	($bp,$num),%r10
	and	\$-128,%rsp
	##############################################################
	# Stack layout
	# +0	num
	# +8	off-loaded &b[i]
	# +16	end of b[num]
	# +24	saved n0
	# +32	saved rp
	# +40
	# +48	inner counter
	# +56	saved %rsp
	# +64	tmp[num+1]
	#
	mov	$num,0(%rsp)		# save $num
	shr	\$5,$num
	mov	%r10,16(%rsp)		# end of b[num]
	sub	\$1,$num
	mov	$n0, 24(%rsp)		# save *n0
	mov	$rp, 32(%rsp)		# save $rp
	mov	$num,48(%rsp)		# inner counter
	mov	%r11,56(%rsp)		# save original %rsp
	jmp	.Lmulx4x_body

.align	32
.Lmulx4x_body:
___
my ($aptr, $bptr, $nptr, $tptr, $mi,  $bi,  $zero, $num)=
   ("%rsi","%rdi","%rcx","%rbx","%r8","%r9","%rbp","%rax");
my $rptr=$bptr;
$code.=<<___;
	lea	8($bp),$bptr
	mov	($bp),%rdx		# b[0], $bp==%rdx actually
	lea	64+32(%rsp),$tptr
	mov	%rdx,$bi
	xor	$zero,$zero		# of=0,cf=0

	mulx	0*8($aptr),$mi,%rax	# a[0]*b[0]
	mulx	1*8($aptr),%r11,%r14	# a[1]*b[0]
	adcx	%rax,%r11
	mov	$bptr,8(%rsp)		# off-load &b[i]
	mulx	2*8($aptr),%r12,%r13	# ...
	adcx	%r14,%r12
	adcx	$zero,%r13

	mov	$mi,$bptr		# borrow $bptr
	imulq	24(%rsp),$mi		# "t[0]"*n0
	xor	$zero,$zero		# cf=0, of=0

	mulx	3*8($aptr),%rax,%r14
	 mov	$mi,%rdx
	lea	4*8($aptr),$aptr
	adcx	%rax,%r13
	adcx	$zero,%r14		# cf=0

	mulx	0*8($nptr),%rax,%r10
	adcx	%rax,$bptr		# discarded
	adox	%r11,%r10
	mulx	1*8($nptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11
	mulx	2*8($nptr),%rax,%r12
	mov	48(%rsp),$bptr		# counter value
	mov	%r10,-4*8($tptr)
	adcx	%rax,%r11
	adox	%r13,%r12
	mulx	3*8($nptr),%rax,%r15
	 .byte	0x66,0x66
	 mov	$bi,%rdx
	mov	%r11,-3*8($tptr)
	adcx	%rax,%r12
	adox	$zero,%r15		# of=0
	lea	4*8($nptr),$nptr
	mov	%r12,-2*8($tptr)

	#jmp	.Lmulx4x_1st

.align	32
.Lmulx4x_1st:
	adcx	$zero,%r15		# cf=0, modulo-scheduled
	mulx	0*8($aptr),%r10,%rax	# a[4]*b[0]
	adcx	%r14,%r10
	mulx	1*8($aptr),%r11,%r14	# a[5]*b[0]
	adcx	%rax,%r11
	mulx	2*8($aptr),%r12,%rax	# ...
	adcx	%r14,%r12
	mulx	3*8($aptr),%r13,%r14
	 .byte	0x66,0x66
	 mov	$mi,%rdx
	adcx	%rax,%r13
	adcx	$zero,%r14		# cf=0
	lea	4*8($aptr),$aptr
	lea	4*8($tptr),$tptr

	adox	%r15,%r10
	mulx	0*8($nptr),%rax,%r15
	adcx	%rax,%r10
	adox	%r15,%r11
	mulx	1*8($nptr),%rax,%r15
	adcx	%rax,%r11
	adox	%r15,%r12
	mulx	2*8($nptr),%rax,%r15
	mov	%r10,-5*8($tptr)
	adcx	%rax,%r12
	mov	%r11,-4*8($tptr)
	adox	%r15,%r13
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r12,-3*8($tptr)
	adcx	%rax,%r13
	adox	$zero,%r15
	lea	4*8($nptr),$nptr
	mov	%r13,-2*8($tptr)

	dec	$bptr			# of=0, pass cf
	jnz	.Lmulx4x_1st

	mov	0(%rsp),$num		# load num
	mov	8(%rsp),$bptr		# re-load &b[i]
	adc	$zero,%r15		# modulo-scheduled
	add	%r15,%r14
	sbb	%r15,%r15		# top-most carry
	mov	%r14,-1*8($tptr)
	jmp	.Lmulx4x_outer

.align	32
.Lmulx4x_outer:
	mov	($bptr),%rdx		# b[i]
	lea	8($bptr),$bptr
	sub	$num,$aptr		# rewind $aptr
	mov	%r15,($tptr)		# save top-most carry
	mov	64(%rsp),%r10
	lea	64(%rsp),$tptr
	sub	$num,$nptr		# rewind $nptr
	xor	$zero,$zero		# cf=0, of=0
	mov	%rdx,$bi

	mulx	0*8($aptr),$mi,%rax	# a[0]*b[i]
	adox	%r10,$mi
	mov	1*8($tptr),%r10
	mulx	1*8($aptr),%r11,%r14	# a[1]*b[i]
	adcx	%rax,%r11
	mov	$bptr,8(%rsp)		# off-load &b[i]
	mulx	2*8($aptr),%r12,%r13	# ...
	adox	%r10,%r11
	adcx	%r14,%r12
	adox	$zero,%r12
	.byte	0x66,0x66
	adcx	$zero,%r13
	mov	2*8($tptr),%r10

	mov	$mi,$bptr		# borrow $bptr
	imulq	24(%rsp),$mi		# "t[0]"*n0
	xor	$zero,$zero		# cf=0, of=0

	mulx	3*8($aptr),%rax,%r14
	 mov	$mi,%rdx
	adox	%r10,%r12
	adcx	%rax,%r13
	adox	3*8($tptr),%r13
	adcx	$zero,%r14
	lea	4*8($aptr),$aptr
	lea	4*8($tptr),$tptr
	adox	$zero,%r14

	mulx	0*8($nptr),%rax,%r10
	adcx	%rax,$bptr		# discarded
	adox	%r11,%r10
	mulx	1*8($nptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11
	mulx	2*8($nptr),%rax,%r12
	mov	%r10,-4*8($tptr)
	mov	0*8($tptr),%r10
	adcx	%rax,%r11
	adox	%r13,%r12
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r11,-3*8($tptr)
	adcx	%rax,%r12
	adox	$zero,%r15		# of=0
	mov	48(%rsp),$bptr		# counter value
	.byte	0x66,0x3e
	mov	%r12,-2*8($tptr)
	lea	4*8($nptr),$nptr

	jmp	.Lmulx4x_inner

.align	32
.Lmulx4x_inner:
	adcx	$zero,%r15		# cf=0, modulo-scheduled
	adox	%r10,%r14
	mulx	0*8($aptr),%r10,%rax	# a[4]*b[i]
	mov	1*8($tptr),%r13
	adcx	%r14,%r10
	mulx	1*8($aptr),%r11,%r14	# a[5]*b[i]
	adox	%rax,%r11
	mulx	2*8($aptr),%r12,%rax	# ...
	adcx	%r13,%r11
	adox	%r14,%r12
	mulx	3*8($aptr),%r13,%r14
	 mov	$mi,%rdx
	adcx	2*8($tptr),%r12
	adox	%rax,%r13
	adcx	3*8($tptr),%r13
	adox	$zero,%r14		# of=0
	.byte	0x48,0x8d,0xb6,0x20,0x00,0x00,0x00	# lea	4*8($aptr),$aptr
	.byte	0x48,0x8d,0x9b,0x20,0x00,0x00,0x00	# lea	4*8($tptr),$tptr
	adcx	$zero,%r14		# cf=0

	adox	%r15,%r10
	mulx	0*8($nptr),%rax,%r15
	adcx	%rax,%r10
	adox	%r15,%r11
	mulx	1*8($nptr),%rax,%r15
	adcx	%rax,%r11
	adox	%r15,%r12
	mulx	2*8($nptr),%rax,%r15
	mov	%r10,-5*8($tptr)
	mov	0*8($tptr),%r10
	adcx	%rax,%r12
	adox	%r15,%r13
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r11,-4*8($tptr)
	mov	%r12,-3*8($tptr)
	adcx	%rax,%r13
	adox	$zero,%r15
	lea	4*8($nptr),$nptr
	mov	%r13,-2*8($tptr)

	dec	$bptr			# of=0, pass cf
	jnz	.Lmulx4x_inner

	mov	0(%rsp),$num		# load num
	mov	8(%rsp),$bptr		# re-load &b[i]
	adc	$zero,%r15		# modulo-scheduled
	sub	%r10,$zero		# pull top-most carry
	adc	%r15,%r14
	sbb	%r15,%r15		# top-most carry
	mov	%r14,-1*8($tptr)

	cmp	16(%rsp),$bptr
	jne	.Lmulx4x_outer

	neg	$num
	mov	32(%rsp),$rptr		# restore rp
	lea	64(%rsp),$tptr

	xor	%rdx,%rdx
	pxor	%xmm0,%xmm0
	mov	0*8($nptr,$num),%r8
	mov	1*8($nptr,$num),%r9
	neg	%r8
	jmp	.Lmulx4x_sub_entry

.align	32
.Lmulx4x_sub:
	mov	0*8($nptr,$num),%r8
	mov	1*8($nptr,$num),%r9
	not	%r8
.Lmulx4x_sub_entry:
	mov	2*8($nptr,$num),%r10
	not	%r9
	and	%r15,%r8
	mov	3*8($nptr,$num),%r11
	not	%r10
	and	%r15,%r9
	not	%r11
	and	%r15,%r10
	and	%r15,%r11

	neg	%rdx			# mov %rdx,%cf
	adc	0*8($tptr),%r8
	adc	1*8($tptr),%r9
	movdqa	%xmm0,($tptr)
	adc	2*8($tptr),%r10
	adc	3*8($tptr),%r11
	movdqa	%xmm0,16($tptr)
	lea	4*8($tptr),$tptr
	sbb	%rdx,%rdx		# mov %cf,%rdx

	mov	%r8,0*8($rptr)
	mov	%r9,1*8($rptr)
	mov	%r10,2*8($rptr)
	mov	%r11,3*8($rptr)
	lea	4*8($rptr),$rptr

	add	\$32,$num
	jnz	.Lmulx4x_sub

	mov	56(%rsp),%rsi		# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lmulx4x_epilogue:
	ret
.size	bn_mulx4x_mont,.-bn_mulx4x_mont
___
}{
######################################################################
# void bn_sqr8x_mont(
my $rptr="%rdi";	# const BN_ULONG *rptr,
my $aptr="%rsi";	# const BN_ULONG *aptr,
my $bptr="%rdx";	# not used
my $nptr="%rcx";	# const BN_ULONG *nptr,
my $n0  ="%r8";		# const BN_ULONG *n0);
my $num ="%r9";		# int num, has to be divisible by 8

my ($i,$j,$tptr)=("%rbp","%rcx",$rptr);
my @A0=("%r10","%r11");
my @A1=("%r12","%r13");
my ($a0,$a1,$ai)=("%r14","%r15","%rbx");

$code.=<<___;
.type	bn_sqrx8x_mont,\@function,6
.align	32
bn_sqrx8x_mont:
.Lsqrx8x_enter:
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
	lea	-64(%rsp,%r10,2),%rsp	# alloca(frame+2*$num)
	and	\$-1024,%rsp		# minimize TLB usage
	##############################################################
	# Stack layout
	#
	# +0	saved $num, used in reduction section
	# +8	&t[2*$num], used in reduction section
	# +16	intermediate carry bit
	# +24	top-most carry bit, used in reduction section
	# +32	saved *n0
	# +48	t[2*$num]
	#
	movq	$rptr,%xmm1		# save $rptr
	movq	$nptr,%xmm2		# save $nptr
	movq	%r10, %xmm3		# -$num
	movq	%r11, %xmm4		# save original %rsp
	mov	$n0,  32(%rsp)
.Lsqrx8x_body:
	##################################################################
	# Squaring part:
	#
	# a) multiply-n-add everything but a[i]*a[i];
	# b) shift result of a) by 1 to the left and accumulate
	#    a[i]*a[i] products;
	#
	##################################################################
	# a[7]a[7]a[6]a[6]a[5]a[5]a[4]a[4]a[3]a[3]a[2]a[2]a[1]a[1]a[0]a[0]
	#                                                     a[1]a[0]
	#                                                 a[2]a[0]
	#                                             a[3]a[0]
	#                                             a[2]a[1]
	#                                         a[3]a[1]
	#                                     a[3]a[2]
	#
	#                                         a[4]a[0]
	#                                     a[5]a[0]
	#                                 a[6]a[0]
	#                             a[7]a[0]
	#                                     a[4]a[1]
	#                                 a[5]a[1]
	#                             a[6]a[1]
	#                         a[7]a[1]
	#                                 a[4]a[2]
	#                             a[5]a[2]
	#                         a[6]a[2]
	#                     a[7]a[2]
	#                             a[4]a[3]
	#                         a[5]a[3]
	#                     a[6]a[3]
	#                 a[7]a[3]
	#
	#                     a[5]a[4]
	#                 a[6]a[4]
	#             a[7]a[4]
	#             a[6]a[5]
	#         a[7]a[5]
	#     a[7]a[6]
	# a[7]a[7]a[6]a[6]a[5]a[5]a[4]a[4]a[3]a[3]a[2]a[2]a[1]a[1]a[0]a[0]
___
{
my ($zero,$carry)=("%rbp","%rcx");
my $aaptr=$zero;
$code.=<<___;
	pxor	%xmm0,%xmm0
	lea	48(%rsp),$tptr
	lea	($aptr,$num),$aaptr
	mov	$num,(%rsp)		# save $num
	mov	$aaptr,8(%rsp)		# save end of $aptr
	jmp	.Lsqr8x_zero_start

.Lsqrx8x_zero:
	movdqa	%xmm0,0*8($tptr)
	movdqa	%xmm0,2*8($tptr)
	movdqa	%xmm0,4*8($tptr)
	movdqa	%xmm0,6*8($tptr)
.Lsqr8x_zero_start:
	movdqa	%xmm0,8*8($tptr)
	movdqa	%xmm0,10*8($tptr)
	movdqa	%xmm0,12*8($tptr)
	movdqa	%xmm0,14*8($tptr)
	lea	16*8($tptr),$tptr
	sub	\$64,$num
	jnz	.Lsqrx8x_zero

	mov	0*8($aptr),%rdx		# a[0], modulo-scheduled
	xor	%r8,%r8
	xor	%r9,%r9
	xor	%r10,%r10
	xor	%r11,%r11
	xor	%r12,%r12
	xor	%r13,%r13
	xor	%r14,%r14
	lea	48(%rsp),$tptr
	xor	$zero,$zero		# cf=0, cf=0
	jmp	.Lsqrx8x_outer_loop

.align	32
.Lsqrx8x_outer_loop:
	mulx	1*8($aptr),%rax,%rbx	# a[1]*a[0]
	adcx	%rax,%r8		# a[1]*a[0]+=t[1]
	adox	%rbx,%r9
	mulx	2*8($aptr),%rax,%rbx	# a[2]*a[0]
	adcx	%rax,%r9
	adox	%rbx,%r10
	.byte	0xc4,0xe2,0xfb,0xf6,0x9e,0x18,0x00,0x00,0x00	# mulx	3*8($aptr),%rax,%rbx	# ...
	adcx	%rax,%r10
	adox	%rbx,%r11
	.byte	0xc4,0xe2,0xfb,0xf6,0x9e,0x20,0x00,0x00,0x00	# mulx	4*8($aptr),%rax,%rbx
	adcx	%rax,%r11
	adox	%rbx,%r12
	mulx	5*8($aptr),%rax,%rbx
	adcx	%rax,%r12
	adox	%rbx,%r13
	mulx	6*8($aptr),%rax,%rbx
	adcx	%rax,%r13
	adox	%rbx,%r14
	mulx	7*8($aptr),%rax,%r15
	 mov	1*8($aptr),%rdx		# a[1]
	adcx	%rax,%r14
	adox	$zero,%r15
	adc	8*8($tptr),%r15
	sbb	$carry,$carry		# mov %cf,$carry
	xor	$zero,$zero		# cf=0, of=0

	mov	%r8,1*8($tptr)		# t[1]
	mov	%r9,2*8($tptr)		# t[2]

	mulx	2*8($aptr),%r8,%rbx	# a[2]*a[1]
	mulx	3*8($aptr),%r9,%rax	# a[3]*a[1]
	adcx	%r10,%r8
	adox	%rbx,%r9
	mulx	4*8($aptr),%r10,%rbx	# ...
	adcx	%r11,%r9
	adox	%rax,%r10
	.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x28,0x00,0x00,0x00	# mulx	5*8($aptr),%r11,%rax
	adcx	%r12,%r10
	adox	%rbx,%r11
	.byte	0xc4,0xe2,0x9b,0xf6,0x9e,0x30,0x00,0x00,0x00	# mulx	6*8($aptr),%r12,%rbx
	adcx	%r13,%r11
	adox	%r14,%r12
	.byte	0xc4,0x62,0x93,0xf6,0xb6,0x38,0x00,0x00,0x00	# mulx	7*8($aptr),%r13,%r14
	 mov	2*8($aptr),%rdx		# a[2]
	adcx	%rax,%r12
	adox	%rbx,%r13
	adcx	%r15,%r13
	adox	$zero,%r14		# of=0
	adcx	$zero,%r14		# cf=0

	mov	%r8,3*8($tptr)		# t[3]
	mov	%r9,4*8($tptr)		# t[4]

	mulx	3*8($aptr),%r8,%rbx	# a[3]*a[2]
	mulx	4*8($aptr),%r9,%rax	# a[4]*a[2]
	adcx	%r10,%r8
	adox	%rbx,%r9
	mulx	5*8($aptr),%r10,%rbx	# ...
	adcx	%r11,%r9
	adox	%rax,%r10
	.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x30,0x00,0x00,0x00	# mulx	6*8($aptr),%r11,%rax
	adcx	%r12,%r10
	adox	%r13,%r11
	.byte	0xc4,0x62,0x9b,0xf6,0xae,0x38,0x00,0x00,0x00	# mulx	7*8($aptr),%r12,%r13
	.byte	0x3e
	 mov	3*8($aptr),%rdx		# a[3]
	adcx	%rbx,%r11
	adox	%rax,%r12
	adcx	%r14,%r12
	adox	$zero,%r13		# of=0
	adcx	$zero,%r13		# cf=0

	mov	%r8,5*8($tptr)		# t[5]
	mov	%r9,6*8($tptr)		# t[6]

	mulx	4*8($aptr),%r8,%rax	# a[4]*a[3]
	mulx	5*8($aptr),%r9,%rbx	# a[5]*a[3]
	adcx	%r10,%r8
	adox	%rax,%r9
	mulx	6*8($aptr),%r10,%rax	# ...
	adcx	%r11,%r9
	adox	%r12,%r10
	mulx	7*8($aptr),%r11,%r12
	 mov	4*8($aptr),%rdx		# a[4]
	 mov	5*8($aptr),%r14		# a[5]
	adcx	%rbx,%r10
	adox	%rax,%r11
	 mov	6*8($aptr),%r15		# a[6]
	adcx	%r13,%r11
	adox	$zero,%r12		# of=0
	adcx	$zero,%r12		# cf=0

	mov	%r8,7*8($tptr)		# t[7]
	mov	%r9,8*8($tptr)		# t[8]

	mulx	%r14,%r9,%rax		# a[5]*a[4]
	 mov	7*8($aptr),%r8		# a[7]
	adcx	%r10,%r9
	mulx	%r15,%r10,%rbx		# a[6]*a[4]
	adox	%rax,%r10
	adcx	%r11,%r10
	mulx	%r8,%r11,%rax		# a[7]*a[4]
	 mov	%r14,%rdx		# a[5]
	adox	%rbx,%r11
	adcx	%r12,%r11
	#adox	$zero,%rax		# of=0
	adcx	$zero,%rax		# cf=0

	mulx	%r15,%r14,%rbx		# a[6]*a[5]
	mulx	%r8,%r12,%r13		# a[7]*a[5]
	 mov	%r15,%rdx		# a[6]
	 lea	8*8($aptr),$aptr
	adcx	%r14,%r11
	adox	%rbx,%r12
	adcx	%rax,%r12
	.byte	0x66,0x66
	adox	$zero,%r13

	mulx	%r8,%r8,%r14		# a[7]*a[6]
	adcx	%r8,%r13
	adcx	$zero,%r14

	cmp	8(%rsp),$aptr
	je	.Lsqrx8x_outer_break

	neg	$carry			# mov $carry,%cf
	mov	$zero,%r15
	mov	8*8($tptr),%r8
	adc	9*8($tptr),%r9		# +=t[9]
	adc	10*8($tptr),%r10	# ...
	adc	11*8($tptr),%r11
	adc	12*8($tptr),%r12
	adc	13*8($tptr),%r13
	adc	14*8($tptr),%r14
	adc	15*8($tptr),%r15
	lea	8*8($tptr),$tptr
	sbb	$carry,$carry		# mov %cf,$carry

	mov	-64($aptr),%rdx		# a[0]
	lea	($aptr),$aaptr
	mov	$carry,16(%rsp)		# offload $carry
	mov	$tptr,24(%rsp)

	lea	8*8($tptr),$tptr
	xor	%eax,%eax		# cf=0, of=0
	mov	\$-8,%rcx
	jmp	.Lsqrx8x_loop

.align	32
.Lsqrx8x_loop:
	mov	%r8,%rbx
	mulx	0*8($aaptr),%rax,%r8	# a[8]*a[i]
	adcx	%rax,%rbx		# +=t[8]
	adox	%r9,%r8

	mulx	1*8($aaptr),%rax,%r9	# ...
	adcx	%rax,%r8
	adox	%r10,%r9

	mulx	2*8($aaptr),%rax,%r10
	adcx	%rax,%r9
	adox	%r11,%r10

	mulx	3*8($aaptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11

	.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x20,0x00,0x00,0x00	# mulx	4*8($aaptr),%rax,%r12
	adcx	%rax,%r11
	adox	%r13,%r12

	mulx	5*8($aaptr),%rax,%r13
	adcx	%rax,%r12
	adox	%r14,%r13

	mulx	6*8($aaptr),%rax,%r14
	 mov	%rbx,($tptr,%rcx,8)	# store t[8+i]
	 mov	\$0,%ebx
	adcx	%rax,%r13
	adox	%r15,%r14

	.byte	0xc4,0x62,0xfb,0xf6,0xbd,0x38,0x00,0x00,0x00	# mulx	7*8($aaptr),%rax,%r15
	 mov	8($aptr,%rcx,8),%rdx	# a[i]
	adcx	%rax,%r14
	adox	%rbx,%r15		# %rbx is 0, of=0
	adcx	%rbx,%r15		# cf=0

	inc	%rcx			# of=0
	jnz	.Lsqrx8x_loop

	lea	8*8($aaptr),$aaptr
	cmp	8(%rsp),$aaptr		# done?
	je	.Lsqrx8x_break

	sub	16(%rsp),%rbx		# mov 16(%rsp),%cf
	mov	-64($aptr),%rdx
	adc	0*8($tptr),%r8
	adc	1*8($tptr),%r9
	adc	2*8($tptr),%r10
	adc	3*8($tptr),%r11
	adc	4*8($tptr),%r12
	adc	5*8($tptr),%r13
	adc	6*8($tptr),%r14
	adc	7*8($tptr),%r15
	lea	8*8($tptr),$tptr
	sbb	%rbx,%rbx		# mov %cf,%rbx
	xor	%eax,%eax		# cf=0, of=0
	mov	%rbx,16(%rsp)		# offload carry
	mov	\$-8,%rcx
	jmp	.Lsqrx8x_loop

.align	32
.Lsqrx8x_break:
	sub	16(%rsp),%r8		# consume last carry
	mov	24(%rsp),$aaptr		# initial $tptr
	mov	0*8($aptr),%rdx		# a[8], modulo-scheduled
	mov	%r8,0*8($tptr)
	lea	8*8($aaptr),$aaptr
	mov	%r9,1*8($tptr)
	 mov	1*8($aaptr),%r8		# potentially forwarded store
	mov	%r10,2*8($tptr)
	 mov	2*8($aaptr),%r9		# ...
	mov	%r11,3*8($tptr)
	 mov	3*8($aaptr),%r10
	mov	%r12,4*8($tptr)
	 mov	4*8($aaptr),%r11
	mov	%r13,5*8($tptr)
	 mov	5*8($aaptr),%r12
	mov	%r14,6*8($tptr)
	 mov	6*8($aaptr),%r13
	mov	%r15,7*8($tptr)
	 mov	7*8($aaptr),%r14
	mov	$aaptr,$tptr
	xor	$zero,$zero		# cf=0, cf=0
	jmp	.Lsqrx8x_outer_loop

.align	32
.Lsqrx8x_outer_break:
	mov	%r9,9*8($tptr)		# t[9]
	 movq	%xmm3,%rcx		# -$num
	mov	%r10,10*8($tptr)	# ...
	mov	%r11,11*8($tptr)
	mov	%r12,12*8($tptr)
	mov	%r13,13*8($tptr)
	mov	%r14,14*8($tptr)
___
}{
my $i="%rcx";
$code.=<<___;
	mov	(%rsp),$num		# restore $num

	lea	48(%rsp),$tptr
	mov	($aptr,$i),%rdx		# a[0]

	mov	8($tptr),$A0[1]		# t[1]
	xor	$A0[0],$A0[0]		# t[0], of=0, cf=0
	adox	$A0[1],$A0[1]
	 mov	16($tptr),$A1[0]	# t[2]	# prefetch
	 mov	24($tptr),$A1[1]	# t[3]	# prefetch
	nop
	#jmp	.Lsqrx4x_shift_n_add	# happens to be aligned

.align	32
.Lsqrx4x_shift_n_add:
	mulx	%rdx,%rax,%rbx
	 adox	$A1[0],$A1[0]
	adcx	$A0[0],%rax
	 .byte	0x48,0x8b,0x94,0x0e,0x08,0x00,0x00,0x00	# mov	8($aptr,$i),%rdx	# a[i+1]	# prefetch
	 .byte	0x4c,0x8b,0x97,0x20,0x00,0x00,0x00	# mov	32($tptr),$A0[0]	# t[2*i+4]	# prefetch
	 adox	$A1[1],$A1[1]
	adcx	$A0[1],%rbx
	 mov	40($tptr),$A0[1]		# t[2*i+4+1]	# prefetch
	mov	%rax,0($tptr)
	mov	%rbx,8($tptr)

	mulx	%rdx,%rax,%rbx
	 adox	$A0[0],$A0[0]
	adcx	$A1[0],%rax
	 mov	16($aptr,$i),%rdx	# a[i+2]	# prefetch
	 mov	48($tptr),$A1[0]	# t[2*i+6]	# prefetch
	 adox	$A0[1],$A0[1]
	adcx	$A1[1],%rbx
	 mov	56($tptr),$A1[1]	# t[2*i+6+1]	# prefetch
	mov	%rax,16($tptr)
	mov	%rbx,24($tptr)

	mulx	%rdx,%rax,%rbx
	 adox	$A1[0],$A1[0]
	adcx	$A0[0],%rax
	 mov	24($aptr,$i),%rdx	# a[i+3]	# prefetch
	 lea	32($i),$i
	 mov	64($tptr),$A0[0]	# t[2*i+8]	# prefetch
	 adox	$A1[1],$A1[1]
	adcx	$A0[1],%rbx
	 mov	72($tptr),$A0[1]	# t[2*i+8+1]	# prefetch
	mov	%rax,32($tptr)
	mov	%rbx,40($tptr)

	mulx	%rdx,%rax,%rbx
	 adox	$A0[0],$A0[0]
	adcx	$A1[0],%rax
	jrcxz	.Lsqrx4x_shift_n_add_break
	 .byte	0x48,0x8b,0x94,0x0e,0x00,0x00,0x00,0x00	# mov	0($aptr,$i),%rdx	# a[i+4]	# prefetch
	 adox	$A0[1],$A0[1]
	adcx	$A1[1],%rbx
	 mov	80($tptr),$A1[0]	# t[2*i+10]	# prefetch
	 mov	88($tptr),$A1[1]	# t[2*i+10+1]	# prefetch
	mov	%rax,48($tptr)
	mov	%rbx,56($tptr)
	lea	64($tptr),$tptr
	nop
	jmp	.Lsqrx4x_shift_n_add

.align	32
.Lsqrx4x_shift_n_add_break:
	adcx	$A1[1],%rbx
	.byte	0x48,0x89,0x87,0x30,0x00,0x00,0x00	# mov	%rax,48($tptr)
	.byte	0x48,0x89,0x9f,0x38,0x00,0x00,0x00	# mov	%rbx,56($tptr)
	.byte	0x48,0x8d,0xbf,0x40,0x00,0x00,0x00	# lea	64($tptr),$tptr
___
}
######################################################################
# Montgomery reduction part, "word-by-word" algorithm.
#
# This new path is inspired by multiple submissions from Intel, by
# Shay Gueron, Vlad Krasnov, Erdinc Ozturk, James Guilford,
# Vinodh Gopal...
{
my ($nptr,$carry,$m0)=("%rbp","%rsi","%rdx");

$code.=<<___;
	movq	%xmm2,$nptr
	mov	32(%rsp),%rbx		# n0
	mov	48(%rsp),%rdx		# "%r8", 8*0($tptr)
	lea	($nptr,$num),%rax	# end of n[]
	#lea	48(%rsp,$num,2),$tptr	# end of t[] buffer
	mov	%rax, 0(%rsp)		# save end of n[]
	mov	$tptr,8(%rsp)		# save end of t[]

	lea	48(%rsp),$tptr		# initial t[] window
	xor	%rax,%rax
	nop
	#jmp	.Lsqrx8x_reduction_loop

.align	32
.Lsqrx8x_reduction_loop:
	mov	8*1($tptr),%r9
	mov	8*2($tptr),%r10
	mov	8*3($tptr),%r11
	mov	8*4($tptr),%r12
	mov	%rdx,%r8
	imulq	%rbx,%rdx		# n0*a[i]
	mov	8*5($tptr),%r13
	mov	8*6($tptr),%r14
	mov	8*7($tptr),%r15
	mov	%rax,24(%rsp)		# store top-most carry bit

	lea	8*8($tptr),$tptr
	xor	$carry,$carry		# cf=0,of=0
	mov	\$-8,%rcx
	jmp	.Lsqrx8x_reduce

.align	32
.Lsqrx8x_reduce:
	mov	%r8, %rbx
	mulx	8*0($nptr),%rax,%r8	# n[0]
	adcx	%rbx,%rax		# discarded
	adox	%r9,%r8

	mulx	8*1($nptr),%rbx,%r9	# n[1]
	adcx	%rbx,%r8
	adox	%r10,%r9

	mulx	8*2($nptr),%rbx,%r10
	adcx	%rbx,%r9
	adox	%r11,%r10

	mulx	8*3($nptr),%rbx,%r11
	adcx	%rbx,%r10
	adox	%r12,%r11

	.byte	0xc4,0x62,0xe3,0xf6,0xa5,0x20,0x00,0x00,0x00	# mulx	8*4($nptr),%rbx,%r12
	 mov	%rdx,%rax
	 mov	%r8,%rdx
	adcx	%rbx,%r11
	adox	%r13,%r12

	 mulx	32(%rsp),%rbx,%rdx	# %rdx discarded
	 mov	%rax,%rdx
	 mov	%rax,48+64(%rsp,%rcx,8)	# put aside n0*a[i]

	mulx	8*5($nptr),%rax,%r13
	adcx	%rax,%r12
	adox	%r14,%r13

	mulx	8*6($nptr),%rax,%r14
	adcx	%rax,%r13
	adox	%r15,%r14

	mulx	8*7($nptr),%rax,%r15
	 mov	%rbx,%rdx
	adcx	%rax,%r14
	adox	$carry,%r15		# $carry is 0
	adcx	$carry,%r15		# cf=0

	inc	%rcx			# of=0
	jnz	.Lsqrx8x_reduce

	lea	8*8($nptr),$nptr
	xor	%rax,%rax
	cmp	0(%rsp),$nptr		# end of n[]?
	jae	.Lsqrx8x_no_tail

	mov	48(%rsp),%rdx		# pull n0*a[0]
	add	8*0($tptr),%r8
	adcx	8*1($tptr),%r9
	adcx	8*2($tptr),%r10
	adcx	8*3($tptr),%r11
	adcx	8*4($tptr),%r12
	adcx	8*5($tptr),%r13
	adcx	8*6($tptr),%r14
	adcx	8*7($tptr),%r15
	lea	8*8($tptr),$tptr
	sbb	$carry,$carry		# top carry

	mov	\$-8,%rcx
	mov	$carry,16(%rsp)
	xor	$carry,$carry		# of=0, cf=0
	jmp	.Lsqrx8x_tail

.align	32
.Lsqrx8x_tail:
	mov	%r8,%rbx
	mulx	8*0($nptr),%rax,%r8
	adcx	%rax,%rbx
	adox	%r9,%r8

	mulx	8*1($nptr),%rax,%r9
	adcx	%rax,%r8
	adox	%r10,%r9

	mulx	8*2($nptr),%rax,%r10
	adcx	%rax,%r9
	adox	%r11,%r10

	mulx	8*3($nptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11

	.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x20,0x00,0x00,0x00	# mulx	8*4($nptr),%rax,%r12
	adcx	%rax,%r11
	adox	%r13,%r12

	mulx	8*5($nptr),%rax,%r13
	adcx	%rax,%r12
	adox	%r14,%r13

	mulx	8*6($nptr),%rax,%r14
	adcx	%rax,%r13
	adox	%r15,%r14

	mulx	8*7($nptr),%rax,%r15
	 mov	48+72(%rsp,%rcx,8),%rdx	# pull n0*a[i]
	adcx	%rax,%r14
	.byte	0x66
	adox	$carry,%r15
	 mov	%rbx,($tptr,%rcx,8)	# save result
	 mov	%r8,%rbx
	adcx	$carry,%r15		# cf=0

	inc	%rcx			# of=0
	jnz	.Lsqrx8x_tail

	lea	8*8($nptr),$nptr
	cmp	0(%rsp),$nptr		# end of n[]?
	jae	.Lsqrx8x_tail_done	# break out of loop

	sub	16(%rsp),$carry		# neg	$carry
	 mov	48(%rsp),%rdx		# pull n0*a[0]
	adcx	8*0($tptr),%r8
	adcx	8*1($tptr),%r9
	adcx	8*2($tptr),%r10
	adcx	8*3($tptr),%r11
	adcx	8*4($tptr),%r12
	adcx	8*5($tptr),%r13
	adcx	8*6($tptr),%r14
	adcx	8*7($tptr),%r15
	lea	8*8($tptr),$tptr
	sbb	$carry,$carry

	mov	\$-8,%rcx
	mov	$carry,16(%rsp)
	xor	$carry,$carry		# of=0, cf=0
	jmp	.Lsqrx8x_tail

.align	32
.Lsqrx8x_tail_done:
	add	24(%rsp),%r8		# can this overflow?
	xor	%rax,%rax

	sub	16(%rsp),$carry		# neg $carry
.Lsqrx8x_no_tail:			# carry flag is 0
	adc	8*0($tptr),%r8
	 movq	%xmm3,%rcx
	adc	8*1($tptr),%r9
	 movq	%xmm2,$nptr		# restore $nptr
	adc	8*2($tptr),%r10
	 lea	8*8($tptr),$carry	# borrow $carry
	adc	8*3($tptr),%r11
	adc	8*4($tptr),%r12
	adc	8*5($tptr),%r13
	adc	8*6($tptr),%r14
	adc	8*7($tptr),%r15
	adc	%rax,%rax		# top-most carry

	cmp	8(%rsp),$carry		# end of t[]?
	mov	32(%rsp),%rbx		# n0
	mov	8*8($tptr,%rcx),%rdx	# modulo-scheduled "%r8"

	lea	8*8($tptr,%rcx),$tptr	# start of current t[] window
	mov	%r8,-8*8($carry)	# store top 512 bits
	mov	%r9,-8*7($carry)
	mov	%r10,-8*6($carry)
	mov	%r11,-8*5($carry)
	mov	%r12,-8*4($carry)
	mov	%r13,-8*3($carry)
	mov	%r14,-8*2($carry)
	mov	%r15,-8*1($carry)

	jb	.Lsqrx8x_reduction_loop

	mov	%rcx,$num
	neg	$num			# restore $num
___
}
##############################################################
# Post-condition, 8x unrolled
#
{
my ($rptr,$nptr,$lptr,$i)=($aptr,"%rbp","%rbx","%rcx");
my @ri=map("%r$_",(10..13));
my @ni=map("%r$_",(14..15));
$code.=<<___;
	lea	($nptr,$num),$nptr	# end of $nptr
	lea	48(%rsp,$num),$lptr	# end of lower half of t[2*num]
	lea	48(%rsp,$num),$tptr
	neg	%rax			# top-most carry as mask
	xor	%rdx,%rdx
	movq	%xmm1,$rptr		# restore $rptr

	mov	0*8($nptr,$i),%r8
	mov	1*8($nptr,$i),%r9
	neg	%r8
	jmp	.Lsqrx8x_sub_entry

.align	32
.Lsqrx8x_sub:
	mov	0*8($nptr,$i),%r8
	mov	1*8($nptr,$i),%r9
	not	%r8
.Lsqrx8x_sub_entry:
	mov	2*8($nptr,$i),%r10
	not	%r9
	and	%rax,%r8
	mov	3*8($nptr,$i),%r11
	not	%r10
	and	%rax,%r9
	mov	4*8($nptr,$i),%r12
	not	%r11
	and	%rax,%r10
	mov	5*8($nptr,$i),%r13
	not	%r12
	and	%rax,%r11
	mov	6*8($nptr,$i),%r14
	not	%r13
	and	%rax,%r12
	mov	7*8($nptr,$i),%r15
	not	%r14
	and	%rax,%r13
	movdqa	%xmm0,0*8($lptr,$i)	# zap lower half
	not	%r15
	and	%rax,%r14
	movdqa	%xmm0,2*8($lptr,$i)
	and	%rax,%r15

	neg	%rdx			# mov %rdx,%cf
	movdqa	%xmm0,4*8($lptr,$i)
	adc	0*8($tptr),%r8
	adc	1*8($tptr),%r9
	movdqa	%xmm0,6*8($lptr,$i)
	adc	2*8($tptr),%r10
	adc	3*8($tptr),%r11
	movdqa	%xmm0,0*8($tptr)	# zap upper half
	adc	4*8($tptr),%r12
	adc	5*8($tptr),%r13
	movdqa	%xmm0,2*8($tptr)
	adc	6*8($tptr),%r14
	adc	7*8($tptr),%r15
	movdqa	%xmm0,4*8($tptr)
	sbb	%rdx,%rdx		# mov %cf,%rdx
	movdqa	%xmm0,6*8($tptr)
	lea	8*8($tptr),$tptr

	mov	%r8,0*8($rptr)
	mov	%r9,1*8($rptr)
	mov	%r10,2*8($rptr)
	mov	%r11,3*8($rptr)
	mov	%r12,4*8($rptr)
	mov	%r13,5*8($rptr)
	mov	%r14,6*8($rptr)
	mov	%r15,7*8($rptr)
	lea	8*8($rptr),$rptr

	add	\$64,$i
	jnz	.Lsqrx8x_sub
___
}
$code.=<<___;
	movq	%xmm4,%rsi		# restore %rsp
	mov	\$1,%rax
	mov	0(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lsqrx8x_epilogue:
	ret
.size	bn_sqrx8x_mont,.-bn_sqrx8x_mont
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

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# end of prologue label
	cmp	%r10,%rbx		# context->Rip<end of prologue label
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
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

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# end of prologue label
	cmp	%r10,%rbx		# context->Rip<.Lsqr_body
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
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

	.rva	.LSEH_begin_bn_mul4x_mont
	.rva	.LSEH_end_bn_mul4x_mont
	.rva	.LSEH_info_bn_mul4x_mont

	.rva	.LSEH_begin_bn_sqr8x_mont
	.rva	.LSEH_end_bn_sqr8x_mont
	.rva	.LSEH_info_bn_sqr8x_mont
___
$code.=<<___ if ($addx);
	.rva	.LSEH_begin_bn_mulx4x_mont
	.rva	.LSEH_end_bn_mulx4x_mont
	.rva	.LSEH_info_bn_mulx4x_mont

	.rva	.LSEH_begin_bn_sqrx8x_mont
	.rva	.LSEH_end_bn_sqrx8x_mont
	.rva	.LSEH_info_bn_sqrx8x_mont
___
$code.=<<___;
.section	.xdata
.align	8
.LSEH_info_bn_mul_mont:
	.byte	9,0,0,0
	.rva	mul_handler
	.rva	.Lmul_body,.Lmul_epilogue	# HandlerData[]
.LSEH_info_bn_mul4x_mont:
	.byte	9,0,0,0
	.rva	mul_handler
	.rva	.Lmul4x_body,.Lmul4x_epilogue	# HandlerData[]
.LSEH_info_bn_sqr8x_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
	.rva	.Lsqr8x_body,.Lsqr8x_epilogue	# HandlerData[]
___
$code.=<<___ if ($addx);
.LSEH_info_bn_mulx4x_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
	.rva	.Lmulx4x_body,.Lmulx4x_epilogue	# HandlerData[]
.LSEH_info_bn_sqrx8x_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
	.rva	.Lsqrx8x_body,.Lsqrx8x_epilogue	# HandlerData[]
___
}

print $code;
close STDOUT;
