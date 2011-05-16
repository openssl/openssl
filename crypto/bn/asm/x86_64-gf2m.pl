#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# May 2011
#
# The module implements bn_GF2m_mul_2x2 polynomial multiplication used
# in bn_gf2m.c. It's kind of low-hanging mechanical port from C for
# the time being... Except that it has two code paths: code suitable
# for any x86_64 CPU and PCLMULQDQ one suitable for Westmere and
# later. Improvement varies from one benchmark and µ-arch to another.
# Vanilla code path is at most 20% faster than compiler-generated code
# [not very impressive], while PCLMULQDQ - whole 85%-160% better on
# 163- and 571-bit ECDH benchmarks on Intel CPUs. Keep in mind that
# these coefficients are not ones for bn_GF2m_mul_2x2 itself, as not
# all CPU time is burnt in it...

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

($lo,$hi)=("%rax","%rdx");	$a=$lo;
($i0,$i1)=("%rsi","%rdi");
($t0,$t1)=("%rbx","%rcx");
($b,$mask)=("%rbp","%r8");
($a1,$a2,$a4,$a8,$a12,$a48)=map("%r$_",(9..15));
($R,$Tx)=("%xmm0","%xmm1");

$code.=<<___;
.text

.type	_mul_1x1,\@abi-omnipotent
.align	16
_mul_1x1:
	sub	\$128+8,%rsp
	mov	\$-1,$a1
	lea	($a,$a),$i0
	shr	\$3,$a1
	lea	(,$a,4),$i1
	and	$a,$a1			# a1=a&0x1fffffffffffffff
	lea	(,$a,8),$a8
	sar	\$63,$a			# broadcast 63rd bit
	lea	($a1,$a1),$a2
	sar	\$63,$i0		# broadcast 62nd bit
	lea	(,$a1,4),$a4
	and	$b,$a
	sar	\$63,$i1		# boardcast 61st bit
	mov	$a,$hi			# $a is $lo
	shl	\$63,$lo
	and	$b,$i0
	shr	\$1,$hi
	mov	$i0,$t1
	shl	\$62,$i0
	and	$b,$i1
	shr	\$2,$t1
	xor	$i0,$lo
	mov	$i1,$t0
	shl	\$61,$i1
	xor	$t1,$hi
	shr	\$3,$t0
	xor	$i1,$lo
	xor	$t0,$hi

	mov	$a1,$a12
	movq	\$0,0(%rsp)		# tab[0]=0
	xor	$a2,$a12		# a1^a2
	mov	$a1,8(%rsp)		# tab[1]=a1
	 mov	$a4,$a48
	mov	$a2,16(%rsp)		# tab[2]=a2
	 xor	$a8,$a48		# a4^a8
	mov	$a12,24(%rsp)		# tab[3]=a1^a2

	xor	$a4,$a1
	mov	$a4,32(%rsp)		# tab[4]=a4
	xor	$a4,$a2
	mov	$a1,40(%rsp)		# tab[5]=a1^a4
	xor	$a4,$a12
	mov	$a2,48(%rsp)		# tab[6]=a2^a4
	 xor	$a48,$a1		# a1^a4^a4^a8=a1^a8
	mov	$a12,56(%rsp)		# tab[7]=a1^a2^a4
	 xor	$a48,$a2		# a2^a4^a4^a8=a1^a8

	mov	$a8,64(%rsp)		# tab[8]=a8
	xor	$a48,$a12		# a1^a2^a4^a4^a8=a1^a2^a8
	mov	$a1,72(%rsp)		# tab[9]=a1^a8
	 xor	$a4,$a1			# a1^a8^a4
	mov	$a2,80(%rsp)		# tab[10]=a2^a8
	 xor	$a4,$a2			# a2^a8^a4
	mov	$a12,88(%rsp)		# tab[11]=a1^a2^a8

	xor	$a4,$a12		# a1^a2^a8^a4
	mov	$a48,96(%rsp)		# tab[12]=a4^a8
	 mov	$mask,$i0
	mov	$a1,104(%rsp)		# tab[13]=a1^a4^a8
	 and	$b,$i0
	mov	$a2,112(%rsp)		# tab[14]=a2^a4^a8
	 shr	\$4,$b
	mov	$a12,120(%rsp)		# tab[15]=a1^a2^a4^a8
	 mov	$mask,$i1
	 and	$b,$i1
	 shr	\$4,$b

	movq	(%rsp,$i0,8),$R		# half of calculations is done in SSE2
	mov	$mask,$i0
	and	$b,$i0
	shr	\$4,$b
___
    for ($n=1;$n<8;$n++) {
	$code.=<<___;
	mov	(%rsp,$i1,8),$t1
	mov	$mask,$i1
	mov	$t1,$t0
	shl	\$`8*$n-4`,$t1
	and	$b,$i1
	 movq	(%rsp,$i0,8),$Tx
	shr	\$`64-(8*$n-4)`,$t0
	xor	$t1,$lo
	 pslldq	\$$n,$Tx
	 mov	$mask,$i0
	shr	\$4,$b
	xor	$t0,$hi
	 and	$b,$i0
	 shr	\$4,$b
	 pxor	$Tx,$R
___
    }
$code.=<<___;
	mov	(%rsp,$i1,8),$t1
	mov	$t1,$t0
	shl	\$`8*$n-4`,$t1
	movq	$R,$i0
	shr	\$`64-(8*$n-4)`,$t0
	xor	$t1,$lo
	psrldq	\$8,$R
	xor	$t0,$hi
	movq	$R,$i1
	xor	$i0,$lo
	xor	$i1,$hi

	add	\$128+8,%rsp
	ret
.size	_mul_1x1,.-_mul_1x1
___

($rp,$a1,$a0,$b1,$b0) = $win64?	("%rcx","%rdx","%r8", "%r9","%r10") :	# Win64 order
				("%rdi","%rsi","%rdx","%rcx","%r8");	# Unix order

$code.=<<___;
.extern	OPENSSL_ia32cap_P
.globl	bn_GF2m_mul_2x2
.type	bn_GF2m_mul_2x2,\@abi-omnipotent
.align	16
bn_GF2m_mul_2x2:
	mov	OPENSSL_ia32cap_P(%rip),%rax
	bt	\$33,%rax
	jnc	.Lvanilla

	movq		$a1,%xmm0
	movq		$b1,%xmm1
	movq		$a0,%xmm2
___
$code.=<<___ if ($win64);
	movq		40(%rsp),%xmm3
___
$code.=<<___ if (!$win64);
	movq		$b0,%xmm3
___
$code.=<<___;
	movdqa		%xmm0,%xmm4
	movdqa		%xmm1,%xmm5
	pclmulqdq	\$0,%xmm1,%xmm0	# a1·b1
	pxor		%xmm2,%xmm4
	pxor		%xmm3,%xmm5
	pclmulqdq	\$0,%xmm3,%xmm2	# a0·b0
	pclmulqdq	\$0,%xmm5,%xmm4	# (a0+a1)·(b0+b1)
	xorps		%xmm0,%xmm4
	xorps		%xmm2,%xmm4
	movdqa		%xmm4,%xmm5
	pslldq		\$8,%xmm4
	psrldq		\$8,%xmm5
	pxor		%xmm4,%xmm2
	pxor		%xmm5,%xmm0
	movdqu		%xmm2,0($rp)
	movdqu		%xmm0,16($rp)
	ret

.align	16
.Lvanilla:
	lea	-8*17(%rsp),%rsp
___
$code.=<<___ if ($win64);
	mov	`8*17+40`(%rsp),$b0
	mov	%rdi,8*15(%rsp)
	mov	%rsi,8*16(%rsp)
___
$code.=<<___;
	mov	%r14,8*10(%rsp)
	mov	%r13,8*11(%rsp)
	mov	%r12,8*12(%rsp)
	mov	%rbp,8*13(%rsp)
	mov	%rbx,8*14(%rsp)
.Lbody:
	mov	$rp,32(%rsp)		# save the arguments
	mov	$a1,40(%rsp)
	mov	$a0,48(%rsp)
	mov	$b1,56(%rsp)
	mov	$b0,64(%rsp)

	mov	\$0xf,$mask
	mov	$a1,$a
	mov	$b1,$b
	call	_mul_1x1		# a1·b1
	mov	$lo,16(%rsp)
	mov	$hi,24(%rsp)

	mov	48(%rsp),$a
	mov	64(%rsp),$b
	call	_mul_1x1		# a0·b0
	mov	$lo,0(%rsp)
	mov	$hi,8(%rsp)

	mov	40(%rsp),$a
	mov	56(%rsp),$b
	xor	48(%rsp),$a
	xor	64(%rsp),$b
	call	_mul_1x1		# (a0+a1)·(b0+b1)
___
	@r=("%rbx","%rcx","%rdi","%rsi");
$code.=<<___;
	mov	0(%rsp),@r[0]
	mov	8(%rsp),@r[1]
	mov	16(%rsp),@r[2]
	mov	24(%rsp),@r[3]
	mov	32(%rsp),%rbp

	xor	$hi,$lo
	xor	@r[1],$hi
	xor	@r[0],$lo
	mov	@r[0],0(%rbp)
	xor	@r[2],$hi
	mov	@r[3],24(%rbp)
	xor	@r[3],$lo
	xor	@r[3],$hi
	xor	$hi,$lo
	mov	$hi,16(%rbp)
	mov	$lo,8(%rbp)

	mov	8*10(%rsp),%r14
	mov	8*11(%rsp),%r13
	mov	8*12(%rsp),%r12
	mov	8*13(%rsp),%rbp
	mov	8*14(%rsp),%rbx
___
$code.=<<___ if ($win64);
	mov	8*15(%rsp),%rdi
	mov	8*16(%rsp),%rsi
___
$code.=<<___;
	lea	8*17(%rsp),%rsp
	ret
.size	bn_GF2m_mul_2x2,.-bn_GF2m_mul_2x2
.asciz	"GF(2^m) Multiplication for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
print $code;
close STDOUT;
