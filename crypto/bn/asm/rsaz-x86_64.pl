#!/usr/bin/env perl

#******************************************************************************#
#* Copyright(c) 2012, Intel Corp.                                             *#
#* Developers and authors:                                                    *#
#* Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *#
#* (1) Intel Architecture Group, Microprocessor and Chipset Development,      *#
#*     Israel Development Center, Haifa, Israel                               *#
#* (2) University of Haifa                                                    *#
#******************************************************************************#
#* This submission to OpenSSL is to be made available under the OpenSSL       *#
#* license, and only to the OpenSSL project, in order to allow integration    *#
#* into the publicly distributed code. ?                                      *#
#* The use of this code, or portions of this code, or concepts embedded in    *#
#* this code, or modification of this code and/or algorithm(s) in it, or the  *#
#* use of this code for any other purpose than stated above, requires special *#
#* licensing.                                                                 *#
#******************************************************************************#
#******************************************************************************#
#* DISCLAIMER:                                                                *#
#* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS AND THE COPYRIGHT OWNERS     *#
#* ``AS IS''. ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED *#
#* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR *#
#* PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE CONTRIBUTORS OR THE COPYRIGHT*#
#* OWNERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, *#
#* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    *#
#* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS   *#
#* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN    *#
#* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)    *#
#* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE *#
#* POSSIBILITY OF SUCH DAMAGE.                                                *#
#******************************************************************************#
#* Reference:                                                                 *#
#* [1] S. Gueron, "Efficient Software Implementations of Modular              *#
#*     Exponentiation", http://eprint.iacr.org/2011/239                       *#
#* [2] S. Gueron, V. Krasnov. "Speeding up Big-Numbers Squaring".             *#
#*     IEEE Proceedings of 9th International Conference on Information        *#
#*     Technology: New Generations (ITNG 2012), 821-823 (2012).               *#
#* [3] S. Gueron, Efficient Software Implementations of Modular Exponentiation*#
#*     Journal of Cryptographic Engineering 2:31-43 (2012).                   *#
#* [4] S. Gueron, V. Krasnov: "[PATCH] Efficient and side channel analysis    *#
#*     resistant 512-bit and 1024-bit modular exponentiation for optimizing   *#
#*     RSA1024 and RSA2048 on x86_64 platforms",                              *#
#*     http://rt.openssl.org/Ticket/Display.html?id=2582&user=guest&pass=guest*#
################################################################################

# While original submission covers 512- and 1024-bit exponentiation,
# this module is limited to 512-bit version only (and as such
# accelerates RSA1024 sign). This is because improvement for longer
# keys is not high enough to justify the effort, highest measured
# was ~5% on Westmere. [This is relative to OpenSSL 1.0.2, upcoming
# for the moment of this writing!] Nor does this module implement
# "monolithic" complete exponentiation jumbo-subroutine, but adheres
# to more modular mixture of C and assembly. And it's optimized even
# for processors other than Intel Core family (see table below for
# improvement coefficients).
# 						<appro@openssl.org>
#
# RSA1024 sign/sec	this/original	|this/rsax(*)	this/fips(*)
#			----------------+---------------------------
# Opteron		+13%		|+5%		+20%
# Bulldozer		-0%		|-1%		+10%
# P4			+11%		|+7%		+8%
# Westmere		+5%		|+14%		+17%
# Sandy Bridge		+2%		|+12%		+29%
# Ivy Bridge		+1%		|+11%		+35%
# Haswell(**)		-0%		|+12%		+39%
# Atom			+13%		|+11%		+4%
# VIA Nano		+70%		|+9%		+25%
#
# (*)	rsax engine and fips numbers are presented for reference
#	purposes;
# (**)	you might notice MULX code below, strangely enough gain is
#	marginal, which is why code remains disabled;

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| $^X $xlate $flavour $output";
*STDOUT=*OUT;

($out, $inp, $mod) = ("%rdi", "%rsi", "%rbp");	# common internal API
{
my ($out,$inp,$mod,$n0,$times) = ("%rdi","%rsi","%rdx","%rcx","%r8d");

$code.=<<___;
.text

.globl	rsaz_512_sqr
.type	rsaz_512_sqr,\@function,5
.align	32
rsaz_512_sqr:				# 25-29% faster than rsaz_512_mul
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	subq	\$128+24, %rsp
.Lsqr_body:
	movq	$mod, %rbp		# common argument
	movq	($inp), %rdx
	movq	8($inp), %rax
	movq	$n0, 128(%rsp)
	jmp	.Loop_sqr

.align	32
.Loop_sqr:
	movl	$times,128+8(%rsp)
___
if (1) {
$code.=<<___;
#first iteration
	movq	%rdx, %rbx
	mulq	%rdx
	movq	%rax, %r8
	movq	16($inp), %rax
	movq	%rdx, %r9

	mulq	%rbx
	addq	%rax, %r9
	movq	24($inp), %rax
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	addq	%rax, %r10
	movq	32($inp), %rax
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	addq	%rax, %r11
	movq	40($inp), %rax
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r12
	movq	48($inp), %rax
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	addq	%rax, %r13
	movq	56($inp), %rax
	movq	%rdx, %r14
	adcq	\$0, %r14

	mulq	%rbx
	addq	%rax, %r14
	movq	%rbx, %rax
	movq	%rdx, %r15
	adcq	\$0, %r15

	addq	%r8, %r8		#shlq	\$1, %r8
	movq	%r9, %rcx
	adcq	%r9, %r9		#shld	\$1, %r8, %r9

	mulq	%rax
	movq	%rax, (%rsp)
	addq	%rdx, %r8
	adcq	\$0, %r9

	movq	%r8, 8(%rsp)
	shrq	\$63, %rcx

#second iteration
	movq	8($inp), %r8
	movq	16($inp), %rax
	mulq	%r8
	addq	%rax, %r10
	movq	24($inp), %rax
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r8
	addq	%rax, %r11
	movq	32($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r11
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r8
	addq	%rax, %r12
	movq	40($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r12
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r8
	addq	%rax, %r13
	movq	48($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r13
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r8
	addq	%rax, %r14
	movq	56($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r14
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r8
	addq	%rax, %r15
	movq	%r8, %rax
	adcq	\$0, %rdx
	addq	%rbx, %r15
	movq	%rdx, %r8
	movq	%r10, %rdx
	adcq	\$0, %r8

	add	%rdx, %rdx
	lea	(%rcx,%r10,2), %r10	#shld	\$1, %rcx, %r10
	movq	%r11, %rbx
	adcq	%r11, %r11		#shld	\$1, %r10, %r11

	mulq	%rax
	addq	%rax, %r9
	adcq	%rdx, %r10
	adcq	\$0, %r11

	movq	%r9, 16(%rsp)
	movq	%r10, 24(%rsp)
	shrq	\$63, %rbx
	
#third iteration
	movq	16($inp), %r9	
	movq	24($inp), %rax
	mulq	%r9
	addq	%rax, %r12
	movq	32($inp), %rax
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r9
	addq	%rax, %r13
	movq	40($inp), %rax
	adcq	\$0, %rdx
	addq	%rcx, %r13
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r9
	addq	%rax, %r14
	movq	48($inp), %rax
	adcq	\$0, %rdx
	addq	%rcx, %r14
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r9
	 movq	%r12, %r10
	 lea	(%rbx,%r12,2), %r12	#shld	\$1, %rbx, %r12
	addq	%rax, %r15
	movq	56($inp), %rax
	adcq	\$0, %rdx
	addq	%rcx, %r15
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r9
	 shrq	\$63, %r10
	addq	%rax, %r8
	movq	%r9, %rax
	adcq	\$0, %rdx
	addq	%rcx, %r8
	movq	%rdx, %r9
	adcq	\$0, %r9

	movq	%r13, %rcx
	leaq	(%r10,%r13,2), %r13	#shld	\$1, %r12, %r13

	mulq	%rax
	addq	%rax, %r11
	adcq	%rdx, %r12
	adcq	\$0, %r13

	movq	%r11, 32(%rsp)
	movq	%r12, 40(%rsp)
	shrq	\$63, %rcx

#fourth iteration
	movq	24($inp), %r10
	movq	32($inp), %rax
	mulq	%r10
	addq	%rax, %r14
	movq	40($inp), %rax
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r10
	addq	%rax, %r15
	movq	48($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r15
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r10
	 movq	%r14, %r12
	 leaq	(%rcx,%r14,2), %r14	#shld	\$1, %rcx, %r14
	addq	%rax, %r8
	movq	56($inp), %rax
	adcq	\$0, %rdx
	addq	%rbx, %r8
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r10
	 shrq	\$63, %r12
	addq	%rax, %r9
	movq	%r10, %rax
	adcq	\$0, %rdx
	addq	%rbx, %r9
	movq	%rdx, %r10
	adcq	\$0, %r10

	movq	%r15, %rbx
	leaq	(%r12,%r15,2),%r15	#shld	\$1, %r14, %r15

	mulq	%rax
	addq	%rax, %r13
	adcq	%rdx, %r14
	adcq	\$0, %r15

	movq	%r13, 48(%rsp)
	movq	%r14, 56(%rsp)
	shrq	\$63, %rbx

#fifth iteration
	movq	32($inp), %r11
	movq	40($inp), %rax
	mulq	%r11
	addq	%rax, %r8
	movq	48($inp), %rax
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r11
	addq	%rax, %r9
	movq	56($inp), %rax
	adcq	\$0, %rdx
	 movq	%r8, %r12
	 leaq	(%rbx,%r8,2), %r8	#shld	\$1, %rbx, %r8
	addq	%rcx, %r9
	movq	%rdx, %rcx
	adcq	\$0, %rcx

	mulq	%r11
	 shrq	\$63, %r12
	addq	%rax, %r10
	movq	%r11, %rax
	adcq	\$0, %rdx
	addq	%rcx, %r10
	movq	%rdx, %r11
	adcq	\$0, %r11

	movq	%r9, %rcx
	leaq	(%r12,%r9,2), %r9	#shld	\$1, %r8, %r9

	mulq	%rax
	addq	%rax, %r15
	adcq	%rdx, %r8
	adcq	\$0, %r9

	movq	%r15, 64(%rsp)
	movq	%r8, 72(%rsp)
	shrq	\$63, %rcx

#sixth iteration
	movq	40($inp), %r12
	movq	48($inp), %rax
	mulq	%r12
	addq	%rax, %r10
	movq	56($inp), %rax
	movq	%rdx, %rbx
	adcq	\$0, %rbx

	mulq	%r12
	addq	%rax, %r11
	movq	%r12, %rax
	 movq	%r10, %r15
	 leaq	(%rcx,%r10,2), %r10	#shld	\$1, %rcx, %r10
	adcq	\$0, %rdx
	 shrq	\$63, %r15
	addq	%rbx, %r11
	movq	%rdx, %r12
	adcq	\$0, %r12

	movq	%r11, %rbx
	leaq	(%r15,%r11,2), %r11	#shld	\$1, %r10, %r11

	mulq	%rax
	addq	%rax, %r9
	adcq	%rdx, %r10
	adcq	\$0, %r11

	movq	%r9, 80(%rsp)
	movq	%r10, 88(%rsp)

#seventh iteration
	movq	48($inp), %r13
	movq	56($inp), %rax
	mulq	%r13
	addq	%rax, %r12
	movq	%r13, %rax
	movq	%rdx, %r13
	adcq	\$0, %r13

	xorq	%r14, %r14
	shlq	\$1, %rbx
	adcq	%r12, %r12		#shld	\$1, %rbx, %r12
	adcq	%r13, %r13		#shld	\$1, %r12, %r13
	adcq	%r14, %r14		#shld	\$1, %r13, %r14

	mulq	%rax
	addq	%rax, %r11
	adcq	%rdx, %r12
	adcq	\$0, %r13

	movq	%r11, 96(%rsp)
	movq	%r12, 104(%rsp)

#eighth iteration
	movq	56($inp), %rax
	mulq	%rax
	addq	%rax, %r13
	adcq	\$0, %rdx

	addq	%rdx, %r14

	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
___
} else {
$code.=<<___;
	movq	$out, %xmm0		# off-load
#first iteration	
	mulx	%rax, %r8, %r9

	mulx	16($inp), %rcx, %r10

	mulx	24($inp), %rax, %r11
	add	%rcx, %r9

	mulx	32($inp), %rcx, %r12
	adc	%rax, %r10

	mulx	40($inp), %rax, %r13
	adc	%rcx, %r11

	mulx	48($inp), %rcx, %r14
	adc	%rax, %r12

	mulx	56($inp), %rax, %r15
	adc	%rcx, %r13
	mov	%r9, %rcx
	adc	%rax, %r14
	adc	\$0, %r15

	shld	\$1, %r8, %r9
	shl	\$1, %r8

	mulx	%rdx, %rax, %rdx
	add	%rdx, %r8
	adc	\$0, %r9

	mov	%rax, (%rsp)
	mov	%r8, 8(%rsp)

#second iteration	
	mov	8($inp), %rdx
	mulx	16($inp), %rax, %rbx

	mulx	24($inp), $out, %r8
	add	%rax, %r10
	adc	%rbx, %r11
	adc	\$0, %r8

	mulx	32($inp), %rax, %rbx
	add	$out, %r11
	adc	%r8, %r12
	adc	\$0, %rbx

	mulx	40($inp), $out, %r8
	add	%rax, %r12
	adc	%rbx, %r13
	adc	\$0, %r8

	mulx	48($inp), %rax, %rbx
	add	$out, %r13
	adc	%r8, %r14
	adc	\$0, %rbx

	mulx	56($inp), $out, %r8
	add	%rax, %r14
	adc	%rbx, %r15
	mov	%r11, %rbx
	adc	\$0, %r8
	add	$out, %r15
	adc	\$0, %r8

	shld	\$1, %r10, %r11
	shld	\$1, %rcx, %r10

	mulx	%rdx, %rax, %rcx
	add	%rax, %r9
	adc	%rcx, %r10
	adc	\$0, %r11

	mov	%r9, 16(%rsp)
	mov	%r10, 24(%rsp)
	
#third iteration	
	mov	16($inp), %rdx
	mulx	24($inp), $out, %r9

	mulx	32($inp), %rax, %rcx
	add	$out, %r12
	adc	%r9, %r13
	adc	\$0, %rcx

	mulx	40($inp), $out, %r9
	add	%rax, %r13
	adc	%rcx, %r14
	adc	\$0, %r9

	mulx	48($inp), %rax, %rcx
	add	$out, %r14
	adc	%r9, %r15
	adc	\$0, %rcx

	mulx	56($inp), $out, %r9
	add	%rax, %r15
	adc	%rcx, %r8
	mov	%r13, %rcx
	adc	\$0, %r9
	add	$out, %r8
	adc	\$0, %r9

	shld	\$1, %r12, %r13
	shld	\$1, %rbx, %r12

	mulx	%rdx, %rax, %rdx
	add	%rax, %r11
	adc	%rdx, %r12
	adc	\$0, %r13

	mov	%r11, 32(%rsp)
	mov	%r12, 40(%rsp)
	
#fourth iteration	
	mov	24($inp), %rdx
	mulx	32($inp), %rax, %rbx

	mulx	40($inp), $out, %r10
	add	%rax, %r14
	adc	%rbx, %r15
	adc	\$0, %r10

	mulx	48($inp), %rax, %rbx
	add	$out, %r15
	adc	%r10, %r8
	adc	\$0, %rbx

	mulx	56($inp), $out, %r10
	add	%rax, %r8
	adc	\$0, %rbx
	add	$out, %r9
	adc	\$0, %r10
	add	%rbx, %r9
	mov	%r15, %rbx
	adc	\$0, %r10

	shld	\$1, %r14, %r15
	shld	\$1, %rcx, %r14

	mulx	%rdx, %rax, %rdx
	add	%rax, %r13
	adc	%rdx, %r14
	adc	\$0, %r15

	mov	%r13, 48(%rsp)
	mov	%r14, 56(%rsp)
	
#fifth iteration	
	mov	32($inp), %rdx
	mulx	40($inp), $out, %r11

	mulx	48($inp), %rax, %rcx
	add	$out, %r8
	adc	%r11, %r9
	adc	\$0, %rcx

	mulx	56($inp), $out, %r11
	add	%rax, %r9
	adc	%rcx, %r10
	adc	\$0, %r11
	add	$out, %r10
	adc	\$0, %r11

	mov	%r9, %rcx
	shld	\$1, %r8, %r9
	shld	\$1, %rbx, %r8

	mulx	%rdx, %rax, %rdx
	add	%rax, %r15
	adc	%rdx, %r8
	adc	\$0, %r9

	mov	%r15, 64(%rsp)
	mov	%r8, 72(%rsp)
	
#sixth iteration	
	mov	40($inp), %rdx
	mulx	48($inp), %rax, %rbx

	mulx	56($inp), $out, %r12
	add	%rax, %r10
	adc	%rbx, %r11
	adc	\$0, %r12
	add	$out, %r11
	adc	\$0, %r12

	mov	%r11, %rbx
	shld	\$1, %r10, %r11
	shld	\$1, %rcx, %r10

	mulx	%rdx, %rax, %rdx
	add	%rax, %r9
	adc	%rdx, %r10
	adc	\$0, %r11

	mov	%r9, 80(%rsp)
	mov	%r10, 88(%rsp)

#seventh iteration
	mov	48($inp), %rdx
	mulx	56($inp), %rax, %r13
	add	%rax, %r12
	adc	\$0, %r13

	xor	%r14, %r14
	shld	\$1, %r13, %r14
	shld	\$1, %r12, %r13
	shld	\$1, %rbx, %r12

	mulx	%rdx, %rax, %rdx
	add	%rax, %r11
	adc	%rdx, %r12
	adc	\$0, %r13

	mov	%r11, 96(%rsp)
	mov	%r12, 104(%rsp)

#eighth iteration
	mov	56($inp), %rdx
	mulx	%rdx, %rax, %rdx
	add	%rax, %r13
	adc	\$0, %rdx
	
	add	%rdx, %r14

	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
	movq	%xmm0, $out
___
}
$code.=<<___;
	movq	(%rsp), %r8
	movq	8(%rsp), %r9
	movq	16(%rsp), %r10
	movq	24(%rsp), %r11
	movq	32(%rsp), %r12
	movq	40(%rsp), %r13
	movq	48(%rsp), %r14
	movq	56(%rsp), %r15

	call	_rsaz_512_reduce

	addq	64(%rsp), %r8
	adcq	72(%rsp), %r9
	adcq	80(%rsp), %r10
	adcq	88(%rsp), %r11
	adcq	96(%rsp), %r12
	adcq	104(%rsp), %r13
	adcq	112(%rsp), %r14
	adcq	120(%rsp), %r15
	sbbq	%rcx, %rcx

	call	_rsaz_512_subtract

	movq	%r8, %rdx
	movq	%r9, %rax
	movl	128+8(%rsp), $times
	movq	$out, $inp

	decl	$times
	jnz	.Loop_sqr

	leaq	128+24+48(%rsp), %rax
	movq	-48(%rax), %r15
	movq	-40(%rax), %r14
	movq	-32(%rax), %r13
	movq	-24(%rax), %r12
	movq	-16(%rax), %rbp
	movq	-8(%rax), %rbx
	leaq	(%rax), %rsp
.Lsqr_epilogue:
	ret
.size	rsaz_512_sqr,.-rsaz_512_sqr
___
}
{
my ($out,$ap,$bp,$mod,$n0) = ("%rdi","%rsi","%rdx","%rcx","%r8");
$code.=<<___;
.globl	rsaz_512_mul
.type	rsaz_512_mul,\@function,5
.align	32
rsaz_512_mul:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	subq	\$128+24, %rsp
.Lmul_body:
	movq	$out, %xmm0		# off-load arguments
	movq	$mod, %xmm1
	movq	$n0, 128(%rsp)

	movq	$bp, %rbp		# pass argument
	call	__rsaz_512_mul

	movq	%xmm0, $out
	movq	%xmm1, %rbp

	movq	(%rsp), %r8
	movq	8(%rsp), %r9
	movq	16(%rsp), %r10
	movq	24(%rsp), %r11
	movq	32(%rsp), %r12
	movq	40(%rsp), %r13
	movq	48(%rsp), %r14
	movq	56(%rsp), %r15

	call	_rsaz_512_reduce

	addq	64(%rsp), %r8
	adcq	72(%rsp), %r9
	adcq	80(%rsp), %r10
	adcq	88(%rsp), %r11
	adcq	96(%rsp), %r12
	adcq	104(%rsp), %r13
	adcq	112(%rsp), %r14
	adcq	120(%rsp), %r15
	sbbq	%rcx, %rcx

	call	_rsaz_512_subtract

	leaq	128+24+48(%rsp), %rax
	movq	-48(%rax), %r15
	movq	-40(%rax), %r14
	movq	-32(%rax), %r13
	movq	-24(%rax), %r12
	movq	-16(%rax), %rbp
	movq	-8(%rax), %rbx
	leaq	(%rax), %rsp
.Lmul_epilogue:
	ret
.size	rsaz_512_mul,.-rsaz_512_mul
___
}
{
my ($out,$ap,$bp,$mod,$n0,$pwr) = ("%rdi","%rsi","%rdx","%rcx","%r8","%r9d");
$code.=<<___;
.globl	rsaz_512_mul_gather4
.type	rsaz_512_mul_gather4,\@function,6
.align	32
rsaz_512_mul_gather4:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	subq	\$128+24, %rsp
.Lmul_gather4_body:
	movl	64($bp,$pwr,4), %eax
	movq	$out, %xmm0		# off-load arguments
	movl	($bp,$pwr,4), %ebx
	movq	$mod, %xmm1
	movq	$n0, 128(%rsp)

	shlq	\$32, %rax
	or	%rax, %rbx
	movq	($ap), %rax
	 movq	8($ap), %rcx
	 leaq	128($bp,$pwr,4), %rbp
	mulq	%rbx			# 0 iteration
	movq	%rax, (%rsp)
	movq	%rcx, %rax
	movq	%rdx, %r8

	mulq	%rbx
	 movd	(%rbp), %xmm4
	addq	%rax, %r8
	movq	16($ap), %rax
	movq	%rdx, %r9
	adcq	\$0, %r9

	mulq	%rbx
	 movd	64(%rbp), %xmm5
	addq	%rax, %r9
	movq	24($ap), %rax
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	 pslldq	\$4, %xmm5
	addq	%rax, %r10
	movq	32($ap), %rax
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	 por	%xmm5, %xmm4
	addq	%rax, %r11
	movq	40($ap), %rax
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r12
	movq	48($ap), %rax
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	 leaq	128(%rbp), %rbp
	addq	%rax, %r13
	movq	56($ap), %rax
	movq	%rdx, %r14
	adcq	\$0, %r14
	
	mulq	%rbx
	 movq	%xmm4, %rbx
	addq	%rax, %r14
	 movq	($ap), %rax
	movq	%rdx, %r15
	adcq	\$0, %r15

	leaq	8(%rsp), %rdi
	movl	\$7, %ecx
	jmp	.Loop_mul_gather

.align	32
.Loop_mul_gather:
	mulq	%rbx
	addq	%rax, %r8
	movq	8($ap), %rax
	movq	%r8, (%rdi)
	movq	%rdx, %r8
	adcq	\$0, %r8

	mulq	%rbx
	 movd	(%rbp), %xmm4
	addq	%rax, %r9
	movq	16($ap), %rax
	adcq	\$0, %rdx
	addq	%r9, %r8
	movq	%rdx, %r9
	adcq	\$0, %r9

	mulq	%rbx
	 movd	64(%rbp), %xmm5
	addq	%rax, %r10
	movq	24($ap), %rax
	adcq	\$0, %rdx
	addq	%r10, %r9
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	 pslldq	\$4, %xmm5
	addq	%rax, %r11
	movq	32($ap), %rax
	adcq	\$0, %rdx
	addq	%r11, %r10
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	 por	%xmm5, %xmm4
	addq	%rax, %r12
	movq	40($ap), %rax
	adcq	\$0, %rdx
	addq	%r12, %r11
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r13
	movq	48($ap), %rax
	adcq	\$0, %rdx
	addq	%r13, %r12
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	addq	%rax, %r14
	movq	56($ap), %rax
	adcq	\$0, %rdx
	addq	%r14, %r13
	movq	%rdx, %r14
	adcq	\$0, %r14

	mulq	%rbx
	 movq	%xmm4, %rbx
	addq	%rax, %r15
	 movq	($ap), %rax
	adcq	\$0, %rdx
	addq	%r15, %r14
	movq	%rdx, %r15	
	adcq	\$0, %r15

	leaq	128(%rbp), %rbp
	leaq	8(%rdi), %rdi

	decl	%ecx
	jnz	.Loop_mul_gather

	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)

	movq	%xmm0, $out
	movq	%xmm1, %rbp

	movq	(%rsp), %r8
	movq	8(%rsp), %r9
	movq	16(%rsp), %r10
	movq	24(%rsp), %r11
	movq	32(%rsp), %r12
	movq	40(%rsp), %r13
	movq	48(%rsp), %r14
	movq	56(%rsp), %r15

	call	_rsaz_512_reduce

	addq	64(%rsp), %r8
	adcq	72(%rsp), %r9
	adcq	80(%rsp), %r10
	adcq	88(%rsp), %r11
	adcq	96(%rsp), %r12
	adcq	104(%rsp), %r13
	adcq	112(%rsp), %r14
	adcq	120(%rsp), %r15
	sbbq	%rcx, %rcx

	call	_rsaz_512_subtract

	leaq	128+24+48(%rsp), %rax
	movq	-48(%rax), %r15
	movq	-40(%rax), %r14
	movq	-32(%rax), %r13
	movq	-24(%rax), %r12
	movq	-16(%rax), %rbp
	movq	-8(%rax), %rbx
	leaq	(%rax), %rsp
.Lmul_gather4_epilogue:
	ret
.size	rsaz_512_mul_gather4,.-rsaz_512_mul_gather4
___
}
{
my ($out,$ap,$mod,$n0,$tbl,$pwr) = ("%rdi","%rsi","%rdx","%rcx","%r8","%r9d");
$code.=<<___;
.globl	rsaz_512_mul_scatter4
.type	rsaz_512_mul_scatter4,\@function,6
.align	32
rsaz_512_mul_scatter4:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	subq	\$128+24, %rsp
.Lmul_scatter4_body:
	leaq	($tbl,$pwr,4), $tbl
	movq	$out, %xmm0		# off-load arguments
	movq	$mod, %xmm1
	movq	$tbl, %xmm2
	movq	$n0, 128(%rsp)

	movq	$out, %rbp
	call	__rsaz_512_mul

	movq	%xmm0, $out
	movq	%xmm1, %rbp

	movq	(%rsp), %r8
	movq	8(%rsp), %r9
	movq	16(%rsp), %r10
	movq	24(%rsp), %r11
	movq	32(%rsp), %r12
	movq	40(%rsp), %r13
	movq	48(%rsp), %r14
	movq	56(%rsp), %r15

	call	_rsaz_512_reduce

	addq	64(%rsp), %r8
	adcq	72(%rsp), %r9
	adcq	80(%rsp), %r10
	adcq	88(%rsp), %r11
	adcq	96(%rsp), %r12
	adcq	104(%rsp), %r13
	adcq	112(%rsp), %r14
	adcq	120(%rsp), %r15
	movq	%xmm2, $inp
	sbbq	%rcx, %rcx

	call	_rsaz_512_subtract

	movl	%r8d, 64*0($inp)	# scatter
	shrq	\$32, %r8
	movl	%r9d, 64*2($inp)
	shrq	\$32, %r9
	movl	%r10d, 64*4($inp)
	shrq	\$32, %r10
	movl	%r11d, 64*6($inp)
	shrq	\$32, %r11
	movl	%r12d, 64*8($inp)
	shrq	\$32, %r12
	movl	%r13d, 64*10($inp)
	shrq	\$32, %r13
	movl	%r14d, 64*12($inp)
	shrq	\$32, %r14
	movl	%r15d, 64*14($inp)
	shrq	\$32, %r15
	movl	%r8d, 64*1($inp)
	movl	%r9d, 64*3($inp)
	movl	%r10d, 64*5($inp)
	movl	%r11d, 64*7($inp)
	movl	%r12d, 64*9($inp)
	movl	%r13d, 64*11($inp)
	movl	%r14d, 64*13($inp)
	movl	%r15d, 64*15($inp)

	leaq	128+24+48(%rsp), %rax
	movq	-48(%rax), %r15
	movq	-40(%rax), %r14
	movq	-32(%rax), %r13
	movq	-24(%rax), %r12
	movq	-16(%rax), %rbp
	movq	-8(%rax), %rbx
	leaq	(%rax), %rsp
.Lmul_scatter4_epilogue:
	ret
.size	rsaz_512_mul_scatter4,.-rsaz_512_mul_scatter4
___
}
{
my ($out,$inp,$mod,$n0) = ("%rdi","%rsi","%rdx","%rcx");
$code.=<<___;
.globl	rsaz_512_mul_by_one
.type	rsaz_512_mul_by_one,\@function,4
.align	32
rsaz_512_mul_by_one:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	subq	\$128+24, %rsp
.Lmul_by_one_body:
	movq	$mod, %rbp	# reassign argument
	movq	$n0, 128(%rsp)

	movq	($inp), %r8
	pxor	%xmm0, %xmm0
	movq	8($inp), %r9
	movq	16($inp), %r10
	movq	24($inp), %r11
	movq	32($inp), %r12
	movq	40($inp), %r13
	movq	48($inp), %r14
	movq	56($inp), %r15

	movdqa	%xmm0, (%rsp)
	movdqa	%xmm0, 16(%rsp)
	movdqa	%xmm0, 32(%rsp)
	movdqa	%xmm0, 48(%rsp)
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm0, 80(%rsp)
	movdqa	%xmm0, 96(%rsp)

	call	_rsaz_512_reduce

	movq	%r8, ($out)
	movq	%r9, 8($out)
	movq	%r10, 16($out)
	movq	%r11, 24($out)
	movq	%r12, 32($out)
	movq	%r13, 40($out)
	movq	%r14, 48($out)
	movq	%r15, 56($out)

	leaq	128+24+48(%rsp), %rax
	movq	-48(%rax), %r15
	movq	-40(%rax), %r14
	movq	-32(%rax), %r13
	movq	-24(%rax), %r12
	movq	-16(%rax), %rbp
	movq	-8(%rax), %rbx
	leaq	(%rax), %rsp
.Lmul_by_one_epilogue:
	ret
.size	rsaz_512_mul_by_one,.-rsaz_512_mul_by_one
___
}
{	# _rsaz_512_reduce
	#
	# input:	%r8-%r15, %rbp - mod, 128(%rsp) - n0
	# output:	%r8-%r15
	# clobbers:	everything except %rbp and %rdi
$code.=<<___;
.type	_rsaz_512_reduce,\@abi-omnipotent
.align	32
_rsaz_512_reduce:
___
if (1) {
$code.=<<___;
	movq	%r8, %rbx
	imulq	128+8(%rsp), %rbx
	movq	0(%rbp), %rax
	movl	\$8, %ecx
	jmp	.Lreduction_loop

.align	32
.Lreduction_loop:
	mulq	%rbx
	movq	8(%rbp), %rax
	negq	%r8
	movq	%rdx, %r8
	adcq	\$0, %r8

	mulq	%rbx
	addq	%rax, %r9
	movq	16(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r9, %r8
	movq	%rdx, %r9
	adcq	\$0, %r9

	mulq	%rbx
	addq	%rax, %r10
	movq	24(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r10, %r9
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	addq	%rax, %r11
	movq	32(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r11, %r10
	 movq	128+8(%rsp), %rsi
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	addq	%rax, %r12
	movq	40(%rbp), %rax
	adcq	\$0, %rdx
	 imulq	%r8, %rsi
	addq	%r12, %r11
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r13
	movq	48(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r13, %r12
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	addq	%rax, %r14
	movq	56(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r14, %r13
	movq	%rdx, %r14
	adcq	\$0, %r14

	mulq	%rbx
	 movq	%rsi, %rbx
	addq	%rax, %r15
	 movq	0(%rbp), %rax
	adcq	\$0, %rdx
	addq	%r15, %r14
	movq	%rdx, %r15
	adcq	\$0, %r15

	decl	%ecx
	jne	.Lreduction_loop
___
} else {
$code.=<<___;
	movq	128+8(%rsp), %rdx		# pull $n0
	imulq	%r8, %rdx
	movl	\$8, %ecx
	jmp	.Lreduction_loop

.align	32
.Lreduction_loop:
	neg	%r8
	mulx	0(%rbp), %rax, %r8
	adc	%r9, %r8

	mulx	8(%rbp), %rax, %r9
	adc	\$0, %r9
	add	%rax, %r8
	adc	%r10, %r9

	mulx	16(%rbp), %rax, %r10
	adc	\$0, %r10
	 mov	128+8(%rsp), %rbx		# pull $n0
	 imul	%r8, %rbx
	add	%rax, %r9
	adc	%r11, %r10

	mulx	24(%rbp), %rax, %r11
	adc	\$0, %r11
	add	%rax, %r10
	adc	%r12, %r11

	mulx	32(%rbp), %rax, %r12
	adc	\$0, %r12
	add	%rax, %r11
	adc	%r13, %r12

	mulx	40(%rbp), %rax, %r13
	adc	\$0, %r13
	add	%rax, %r12
	adc	%r14, %r13

	mulx	48(%rbp), %rax, %r14
	adc	\$0, %r14
	add	%rax, %r13
	adc	%r15, %r14

	mulx	56(%rbp), %rax, %r15
	 mov	%rbx, %rdx
	adc	\$0, %r15
	add	%rax, %r14
	adc	\$0, %r15

	dec	%ecx
	jne	.Lreduction_loop
___
}
$code.=<<___;
	ret
.size	_rsaz_512_reduce,.-_rsaz_512_reduce
___
}
{	# _rsaz_512_subtract
	# input: %r8-%r15, %rdi - $out, %rbp - $mod, %rcx - mask
	# output:
	# clobbers: everything but %rdi, %rsi and %rbp
$code.=<<___;
.type	_rsaz_512_subtract,\@abi-omnipotent
.align	32
_rsaz_512_subtract:
	movq	%r8, ($out)
	movq	%r9, 8($out)
	movq	%r10, 16($out)
	movq	%r11, 24($out)
	movq	%r12, 32($out)
	movq	%r13, 40($out)
	movq	%r14, 48($out)
	movq	%r15, 56($out)

	movq	0($mod), %r8
	movq	8($mod), %r9
	negq	%r8
	notq	%r9
	andq	%rcx, %r8
	movq	16($mod), %r10
	andq	%rcx, %r9
	notq	%r10
	movq	24($mod), %r11
	andq	%rcx, %r10
	notq	%r11
	movq	32($mod), %r12
	andq	%rcx, %r11
	notq	%r12
	movq	40($mod), %r13
	andq	%rcx, %r12
	notq	%r13
	movq	48($mod), %r14
	andq	%rcx, %r13
	notq	%r14
	movq	56($mod), %r15
	andq	%rcx, %r14
	notq	%r15
	andq	%rcx, %r15

	addq	($out), %r8
	adcq	8($out), %r9
	adcq	16($out), %r10
	adcq	24($out), %r11
	adcq	32($out), %r12
	adcq	40($out), %r13
	adcq	48($out), %r14
	adcq	56($out), %r15

	movq	%r8, ($out)
	movq	%r9, 8($out)
	movq	%r10, 16($out)
	movq	%r11, 24($out)
	movq	%r12, 32($out)
	movq	%r13, 40($out)
	movq	%r14, 48($out)
	movq	%r15, 56($out)

	ret
.size	_rsaz_512_subtract,.-_rsaz_512_subtract
___
}
{	# __rsaz_512_mul
	#
	# input: %rsi - ap, %rbp - bp
	# ouput:
	# clobbers: everything
my ($ap,$bp) = ("%rsi","%rbp");
$code.=<<___;
.type	__rsaz_512_mul,\@abi-omnipotent
.align	32
__rsaz_512_mul:
	leaq	8(%rsp), %rdi

	movq	($bp), %rbx
	movq	($ap), %rax
	mulq	%rbx
	movq	%rax, (%rdi)
	movq	8($ap), %rax
	movq	%rdx, %r8

	mulq	%rbx
	addq	%rax, %r8
	movq	16($ap), %rax
	movq	%rdx, %r9
	adcq	\$0, %r9

	mulq	%rbx
	addq	%rax, %r9
	movq	24($ap), %rax
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	addq	%rax, %r10
	movq	32($ap), %rax
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	addq	%rax, %r11
	movq	40($ap), %rax
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r12
	movq	48($ap), %rax
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	addq	%rax, %r13
	movq	56($ap), %rax
	movq	%rdx, %r14
	adcq	\$0, %r14
	
	mulq	%rbx
	addq	%rax, %r14
	 movq	($ap), %rax
	movq	%rdx, %r15
	adcq	\$0, %r15

	leaq	8($bp), $bp
	leaq	8(%rdi), %rdi

	movl	\$7, %ecx
	jmp	.Loop_mul

.align	32
.Loop_mul:
	movq	($bp), %rbx
	mulq	%rbx
	addq	%rax, %r8
	movq	8($ap), %rax
	movq	%r8, (%rdi)
	movq	%rdx, %r8
	adcq	\$0, %r8

	mulq	%rbx
	addq	%rax, %r9
	movq	16($ap), %rax
	adcq	\$0, %rdx
	addq	%r9, %r8
	movq	%rdx, %r9
	adcq	\$0, %r9

	mulq	%rbx
	addq	%rax, %r10
	movq	24($ap), %rax
	adcq	\$0, %rdx
	addq	%r10, %r9
	movq	%rdx, %r10
	adcq	\$0, %r10

	mulq	%rbx
	addq	%rax, %r11
	movq	32($ap), %rax
	adcq	\$0, %rdx
	addq	%r11, %r10
	movq	%rdx, %r11
	adcq	\$0, %r11

	mulq	%rbx
	addq	%rax, %r12
	movq	40($ap), %rax
	adcq	\$0, %rdx
	addq	%r12, %r11
	movq	%rdx, %r12
	adcq	\$0, %r12

	mulq	%rbx
	addq	%rax, %r13
	movq	48($ap), %rax
	adcq	\$0, %rdx
	addq	%r13, %r12
	movq	%rdx, %r13
	adcq	\$0, %r13

	mulq	%rbx
	addq	%rax, %r14
	movq	56($ap), %rax
	adcq	\$0, %rdx
	addq	%r14, %r13
	movq	%rdx, %r14
	 leaq	8($bp), $bp
	adcq	\$0, %r14

	mulq	%rbx
	addq	%rax, %r15
	 movq	($ap), %rax
	adcq	\$0, %rdx
	addq	%r15, %r14
	movq	%rdx, %r15	
	adcq	\$0, %r15

	leaq	8(%rdi), %rdi

	decl	%ecx
	jnz	.Loop_mul

	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)

	ret
.size	__rsaz_512_mul,.-__rsaz_512_mul
___
}
{
my ($out,$inp,$power)= $win64 ? ("%rcx","%rdx","%r8d") : ("%rdi","%rsi","%edx");
$code.=<<___;
.globl	rsaz_512_scatter4
.type	rsaz_512_scatter4,\@abi-omnipotent
.align	16
rsaz_512_scatter4:
	leaq	($out,$power,4), $out
	movl	\$8, %r9d
	jmp	.Loop_scatter
.align	16
.Loop_scatter:
	movq	($inp), %rax
	leaq	8($inp), $inp
	movl	%eax, ($out)
	shrq	\$32, %rax
	movl	%eax, 64($out)
	leaq	128($out), $out
	decl	%r9d
	jnz	.Loop_scatter
	ret
.size	rsaz_512_scatter4,.-rsaz_512_scatter4

.globl	rsaz_512_gather4
.type	rsaz_512_gather4,\@abi-omnipotent
.align	16
rsaz_512_gather4:
	leaq	($inp,$power,4), $inp
	movl	\$8, %r9d
	jmp	.Loop_gather
.align	16
.Loop_gather:
	movl	($inp), %eax
	movl	64($inp), %r8d
	leaq	128($inp), $inp
	shlq	\$32, %r8
	or	%r8, %rax
	movq	%rax, ($out)
	leaq	8($out), $out
	decl	%r9d
	jnz	.Loop_gather
	ret
.size	rsaz_512_gather4,.-rsaz_512_gather4
___
}

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	se_handler,\@abi-omnipotent
.align	16
se_handler:
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

	lea	128+24+48(%rax),%rax

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
	.rva	.LSEH_begin_rsaz_512_sqr
	.rva	.LSEH_end_rsaz_512_sqr
	.rva	.LSEH_info_rsaz_512_sqr

	.rva	.LSEH_begin_rsaz_512_mul
	.rva	.LSEH_end_rsaz_512_mul
	.rva	.LSEH_info_rsaz_512_mul

	.rva	.LSEH_begin_rsaz_512_mul_gather4
	.rva	.LSEH_end_rsaz_512_mul_gather4
	.rva	.LSEH_info_rsaz_512_mul_gather4

	.rva	.LSEH_begin_rsaz_512_mul_scatter4
	.rva	.LSEH_end_rsaz_512_mul_scatter4
	.rva	.LSEH_info_rsaz_512_mul_scatter4

	.rva	.LSEH_begin_rsaz_512_mul_by_one
	.rva	.LSEH_end_rsaz_512_mul_by_one
	.rva	.LSEH_info_rsaz_512_mul_by_one

.section	.xdata
.align	8
.LSEH_info_rsaz_512_sqr:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lsqr_body,.Lsqr_epilogue			# HandlerData[]
.LSEH_info_rsaz_512_mul:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lmul_body,.Lmul_epilogue			# HandlerData[]
.LSEH_info_rsaz_512_mul_gather4:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lmul_gather4_body,.Lmul_gather4_epilogue	# HandlerData[]
.LSEH_info_rsaz_512_mul_scatter4:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lmul_scatter4_body,.Lmul_scatter4_epilogue	# HandlerData[]
.LSEH_info_rsaz_512_mul_by_one:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lmul_by_one_body,.Lmul_by_one_epilogue		# HandlerData[]
___
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
