#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# Multi-buffer SHA256 procedure processes n buffers in parallel by
# placing buffer data to designated lane of SIMD register. n is
# naturally limited to 4 on pre-AVX2 processors and to 8 on
# AVX2-capable processors such as Haswell.
#
#		this	+aesni(i)	sha256	aesni-sha256	gain(iv)
# -------------------------------------------------------------------
# Westmere(ii)	23.3/n	+1.28=7.11(n=4)	12.3	+3.75=16.1	+126%
# Atom(ii)	?39.1/n	+3.93=13.7(n=4)	20.8	+5.69=26.5	+93%
# Sandy Bridge	(20.5	+5.15=25.7)/n	11.6	13.0		+103%
# Ivy Bridge	(20.4	+5.14=25.5)/n	10.3	11.6		+82%
# Haswell(iii)	(21.0	+5.00=26.0)/n	7.80	8.79		+170%
# Bulldozer	(21.6	+5.76=27.4)/n	13.6	13.7		+100%
#
# (i)	multi-block CBC encrypt with 128-bit key;
# (ii)	(HASH+AES)/n does not apply to Westmere for n>3 and Atom,
#	because of lower AES-NI instruction throughput, nor is there
#	AES-NI-SHA256 stitch for these processors;
# (iii)	"this" is for n=8, when we gather twice as much data, result
#	for n=4 is 20.3+4.44=24.7;
# (iv)	presented improvement coefficients are asymptotic limits and
#	in real-life application are somewhat lower, e.g. for 2KB 
#	fragments they range from 75% to 13% (on Haswell);

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

$avx=0;

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

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

# void sha256_multi_block (
#     struct {	unsigned int A[8];
#		unsigned int B[8];
#		unsigned int C[8];
#		unsigned int D[8];
#		unsigned int E[8];
#		unsigned int F[8];
#		unsigned int G[8];
#		unsigned int H[8];	} *ctx,
#     struct {	void *ptr; int blocks;	} inp[8],
#     int num);		/* 1 or 2 */
#
$ctx="%rdi";	# 1st arg
$inp="%rsi";	# 2nd arg
$num="%edx";	# 3rd arg
@ptr=map("%r$_",(8..11));
$Tbl="%rbp";

@V=($A,$B,$C,$D,$E,$F,$G,$H)=map("%xmm$_",(8..15));
($t1,$t2,$t3,$axb,$bxc,$Xi,$Xn,$sigma)=map("%xmm$_",(0..7));

$REG_SZ=16;

sub Xi_off {
my $off = shift;

    $off %= 16; $off *= $REG_SZ;
    $off<256 ? "$off-128(%rax)" : "$off-256-128(%rbx)";
}

sub ROUND_00_15 {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;

$code.=<<___ if ($i<15);
	movd		`4*$i`(@ptr[0]),$Xi
	movd		`4*$i`(@ptr[1]),$t1
	movd		`4*$i`(@ptr[2]),$t2
	movd		`4*$i`(@ptr[3]),$t3
	punpckldq	$t2,$Xi
	punpckldq	$t3,$t1
	punpckldq	$t1,$Xi
	pshufb		$Xn,$Xi
___
$code.=<<___ if ($i==15);
	movd		`4*$i`(@ptr[0]),$Xi
	 lea		`16*4`(@ptr[0]),@ptr[0]
	movd		`4*$i`(@ptr[1]),$t1
	 lea		`16*4`(@ptr[1]),@ptr[1]
	movd		`4*$i`(@ptr[2]),$t2
	 lea		`16*4`(@ptr[2]),@ptr[2]
	movd		`4*$i`(@ptr[3]),$t3
	 lea		`16*4`(@ptr[3]),@ptr[3]
	punpckldq	$t2,$Xi
	punpckldq	$t3,$t1
	punpckldq	$t1,$Xi
	pshufb		$Xn,$Xi
___
$code.=<<___;
	movdqa	$e,$sigma
	movdqa	$e,$t3
	psrld	\$6,$sigma
	movdqa	$e,$t2
	pslld	\$7,$t3
	movdqa	$Xi,`&Xi_off($i)`
	 paddd	$h,$Xi				# Xi+=h

	psrld	\$11,$t2
	pxor	$t3,$sigma
	pslld	\$21-7,$t3
	 paddd	`32*($i%8)-128`($Tbl),$Xi	# Xi+=K[round]
	pxor	$t2,$sigma

	psrld	\$25-11,$t2
	 movdqa	$e,$t1
	 `"prefetch	63(@ptr[0])"		if ($i==15)`
	pxor	$t3,$sigma
	 movdqa	$e,$axb				# borrow $axb
	pslld	\$26-21,$t3
	 pandn	$g,$t1
	 pand	$f,$axb
	pxor	$t2,$sigma

	 `"prefetch	63(@ptr[1])"		if ($i==15)`
	movdqa	$a,$t2
	pxor	$t3,$sigma			# Sigma1(e)
	movdqa	$a,$t3
	psrld	\$2,$t2
	paddd	$sigma,$Xi			# Xi+=Sigma1(e)
	 pxor	$axb,$t1			# Ch(e,f,g)
	 movdqa	$b,$axb
	movdqa	$a,$sigma
	pslld	\$10,$t3
	 pxor	$a,$axb				# a^b, b^c in next round

	 `"prefetch	63(@ptr[2])"		if ($i==15)`
	psrld	\$13,$sigma
	pxor	$t3,$t2
	 paddd	$t1,$Xi				# Xi+=Ch(e,f,g)
	pslld	\$19-10,$t3
	 pand	$axb,$bxc
	pxor	$sigma,$t2

	 `"prefetch	63(@ptr[3])"		if ($i==15)`
	psrld	\$22-13,$sigma
	pxor	$t3,$t2
	 movdqa	$b,$h
	pslld	\$30-19,$t3
	pxor	$t2,$sigma
	 pxor	$bxc,$h				# h=Maj(a,b,c)=Ch(a^b,c,b)
	 paddd	$Xi,$d				# d+=Xi
	pxor	$t3,$sigma			# Sigma0(a)

	paddd	$Xi,$h				# h+=Xi
	paddd	$sigma,$h			# h+=Sigma0(a)
___
$code.=<<___ if (($i%8)==7);
	lea	`32*8`($Tbl),$Tbl
___
	($axb,$bxc)=($bxc,$axb);
}

sub ROUND_16_XX {
my $i=shift;

$code.=<<___;
	movdqa	`&Xi_off($i+1)`,$Xn
	paddd	`&Xi_off($i+9)`,$Xi		# Xi+=X[i+9]

	movdqa	$Xn,$sigma
	movdqa	$Xn,$t2
	psrld	\$3,$sigma
	movdqa	$Xn,$t3

	psrld	\$7,$t2
	movdqa	`&Xi_off($i+14)`,$t1
	pslld	\$14,$t3
	pxor	$t2,$sigma
	psrld	\$18-7,$t2
	movdqa	$t1,$axb			# borrow $axb
	pxor	$t3,$sigma
	pslld	\$25-14,$t3
	pxor	$t2,$sigma
	psrld	\$10,$t1
	movdqa	$axb,$t2

	psrld	\$17,$axb
	pxor	$t3,$sigma			# sigma0(X[i+1])
	pslld	\$13,$t2
	 paddd	$sigma,$Xi			# Xi+=sigma0(e)
	pxor	$axb,$t1
	psrld	\$19-17,$axb
	pxor	$t2,$t1
	pslld	\$15-13,$t2
	pxor	$axb,$t1
	pxor	$t2,$t1				# sigma0(X[i+14])
	paddd	$t1,$Xi				# Xi+=sigma1(X[i+14])
___
	&ROUND_00_15($i,@_);
	($Xi,$Xn)=($Xn,$Xi);
}

$code.=<<___;
.text

.extern	OPENSSL_ia32cap_P

.globl	sha256_multi_block
.type	sha256_multi_block,\@function,3
.align	32
sha256_multi_block:
___
$code.=<<___ if ($avx);
	mov	OPENSSL_ia32cap_P+4(%rip),%rcx
	test	\$`1<<28`,%ecx
	jnz	_avx_shortcut
___
$code.=<<___;
	mov	%rsp,%rax
	push	%rbx
	push	%rbp
___
$code.=<<___ if ($win64);
	lea	-0xa8(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
	movaps	%xmm10,-0x78(%rax)
	movaps	%xmm11,-0x68(%rax)
	movaps	%xmm12,-0x58(%rax)
	movaps	%xmm13,-0x48(%rax)
	movaps	%xmm14,-0x38(%rax)
	movaps	%xmm15,-0x28(%rax)
___
$code.=<<___;
	sub	\$`$REG_SZ*18`, %rsp
	and	\$-256,%rsp
	mov	%rax,`$REG_SZ*17`(%rsp)		# original %rsp
	lea	K256+128(%rip),$Tbl
	lea	`$REG_SZ*16`(%rsp),%rbx
	lea	0x80($ctx),$ctx			# size optimization

.Loop_grande:
	mov	$num,`$REG_SZ*17+8`(%rsp)	# original $num
	xor	$num,$num
___
for($i=0;$i<4;$i++) {
    $code.=<<___;
	mov	`16*$i+0`($inp),@ptr[$i]	# input pointer
	mov	`16*$i+8`($inp),%ecx		# number of blocks
	cmp	$num,%ecx
	cmovg	%ecx,$num			# find maximum
	test	%ecx,%ecx
	mov	%ecx,`4*$i`(%rbx)		# initialize counters
	cmovle	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	test	$num,$num
	jz	.Ldone

	movdqu	0x00-0x80($ctx),$A		# load context
	 lea	128(%rsp),%rax
	movdqu	0x20-0x80($ctx),$B
	movdqu	0x40-0x80($ctx),$C
	movdqu	0x60-0x80($ctx),$D
	movdqu	0x80-0x80($ctx),$E
	movdqu	0xa0-0x80($ctx),$F
	movdqu	0xc0-0x80($ctx),$G
	movdqu	0xe0-0x80($ctx),$H
	movdqu	.Lpbswap(%rip),$Xn
	jmp	.Loop

.align	32
.Loop:
	movdqa	$C,$bxc
	pxor	$B,$bxc				# magic seed
___
for($i=0;$i<16;$i++)	{ &ROUND_00_15($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	movdqu	`&Xi_off($i)`,$Xi
	mov	\$3,%ecx
	jmp	.Loop_16_xx
.align	32
.Loop_16_xx:
___
for(;$i<32;$i++)	{ &ROUND_16_XX($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	dec	%ecx
	jnz	.Loop_16_xx

	mov	\$1,%ecx
	lea	K256+128(%rip),$Tbl

	movdqa	(%rbx),$sigma			# pull counters
	cmp	4*0(%rbx),%ecx			# examine counters
	pxor	$t1,$t1
	cmovge	$Tbl,@ptr[0]			# cancel input
	cmp	4*1(%rbx),%ecx
	movdqa	$sigma,$Xn
	cmovge	$Tbl,@ptr[1]
	cmp	4*2(%rbx),%ecx
	pcmpgtd	$t1,$Xn				# mask value
	cmovge	$Tbl,@ptr[2]
	cmp	4*3(%rbx),%ecx
	paddd	$Xn,$sigma			# counters--
	cmovge	$Tbl,@ptr[3]

	movdqu	0x00-0x80($ctx),$t1
	pand	$Xn,$A
	movdqu	0x20-0x80($ctx),$t2
	pand	$Xn,$B
	movdqu	0x40-0x80($ctx),$t3
	pand	$Xn,$C
	movdqu	0x60-0x80($ctx),$Xi
	pand	$Xn,$D
	paddd	$t1,$A
	movdqu	0x80-0x80($ctx),$t1
	pand	$Xn,$E
	paddd	$t2,$B
	movdqu	0xa0-0x80($ctx),$t2
	pand	$Xn,$F
	paddd	$t3,$C
	movdqu	0xc0-0x80($ctx),$t3
	pand	$Xn,$G
	paddd	$Xi,$D
	movdqu	0xe0-0x80($ctx),$Xi
	pand	$Xn,$H
	paddd	$t1,$E
	paddd	$t2,$F
	movdqu	$A,0x00-0x80($ctx)
	paddd	$t3,$G
	movdqu	$B,0x20-0x80($ctx)
	paddd	$Xi,$H
	movdqu	$C,0x40-0x80($ctx)
	movdqu	$D,0x60-0x80($ctx)
	movdqu	$E,0x80-0x80($ctx)
	movdqu	$F,0xa0-0x80($ctx)
	movdqu	$G,0xc0-0x80($ctx)
	movdqu	$H,0xe0-0x80($ctx)

	movdqa	$sigma,(%rbx)			# save counters
	movdqa	.Lpbswap(%rip),$Xn
	dec	$num
	jnz	.Loop

	mov	`$REG_SZ*17+8`(%rsp),$num
	lea	$REG_SZ($ctx),$ctx
	lea	`16*$REG_SZ/4`($inp),$inp
	dec	$num
	jnz	.Loop_grande

.Ldone:
	mov	`$REG_SZ*17`(%rsp),%rax		# orignal %rsp
___
$code.=<<___ if ($win64);
	movaps	-0xb8(%rax),%xmm6
	movaps	-0xa8(%rax),%xmm7
	movaps	-0x98(%rax),%xmm8
	movaps	-0x88(%rax),%xmm9
	movaps	-0x78(%rax),%xmm10
	movaps	-0x68(%rax),%xmm11
	movaps	-0x58(%rax),%xmm12
	movaps	-0x48(%rax),%xmm13
	movaps	-0x38(%rax),%xmm14
	movaps	-0x28(%rax),%xmm15
___
$code.=<<___;
	mov	-16(%rax),%rbp
	mov	-8(%rax),%rbx
	lea	(%rax),%rsp
	ret
.size	sha256_multi_block,.-sha256_multi_block
___
						if ($avx) {{{
sub ROUND_00_15_avx {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;

$code.=<<___ if ($i<15 && $REG_SZ==16);
	vmovd		`4*$i`(@ptr[0]),$Xi
	vmovd		`4*$i`(@ptr[1]),$t1
	vpinsrd		\$1,`4*$i`(@ptr[2]),$Xi,$Xi
	vpinsrd		\$1,`4*$i`(@ptr[3]),$t1,$t1
	vpunpckldq	$t1,$Xi,$Xi
	vpshufb		$Xn,$Xi,$Xi
___
$code.=<<___ if ($i==15 && $REG_SZ==16);
	vmovd		`4*$i`(@ptr[0]),$Xi
	 lea		`16*4`(@ptr[0]),@ptr[0]
	vmovd		`4*$i`(@ptr[1]),$t1
	 lea		`16*4`(@ptr[1]),@ptr[1]
	vpinsrd		\$1,`4*$i`(@ptr[2]),$Xi,$Xi
	 lea		`16*4`(@ptr[2]),@ptr[2]
	vpinsrd		\$1,`4*$i`(@ptr[3]),$t1,$t1
	 lea		`16*4`(@ptr[3]),@ptr[3]
	vpunpckldq	$t1,$Xi,$Xi
	vpshufb		$Xn,$Xi,$Xi
___
$code.=<<___ if ($i<15 && $REG_SZ==32);
	vmovd		`4*$i`(@ptr[0]),$Xi
	vmovd		`4*$i`(@ptr[4]),$t1
	vmovd		`4*$i`(@ptr[1]),$t2
	vmovd		`4*$i`(@ptr[5]),$t3
	vpinsrd		\$1,`4*$i`(@ptr[2]),$Xi,$Xi
	vpinsrd		\$1,`4*$i`(@ptr[6]),$t1,$t1
	vpinsrd		\$1,`4*$i`(@ptr[3]),$t2,$t2
	vpunpckldq	$t2,$Xi,$Xi
	vpinsrd		\$1,`4*$i`(@ptr[7]),$t3,$t3
	vpunpckldq	$t3,$t1,$t1
	vinserti128	$t1,$Xi,$Xi
	vpshufb		$Xn,$Xi,$Xi
___
$code.=<<___ if ($i==15 && $REG_SZ==32);
	vmovd		`4*$i`(@ptr[0]),$Xi
	 lea		`16*4`(@ptr[0]),@ptr[0]
	vmovd		`4*$i`(@ptr[4]),$t1
	 lea		`16*4`(@ptr[4]),@ptr[4]
	vmovd		`4*$i`(@ptr[1]),$t2
	 lea		`16*4`(@ptr[1]),@ptr[1]
	vmovd		`4*$i`(@ptr[5]),$t3
	 lea		`16*4`(@ptr[5]),@ptr[5]
	vpinsrd		\$1,`4*$i`(@ptr[2]),$Xi,$Xi
	 lea		`16*4`(@ptr[2]),@ptr[2]
	vpinsrd		\$1,`4*$i`(@ptr[6]),$t1,$t1
	 lea		`16*4`(@ptr[6]),@ptr[6]
	vpinsrd		\$1,`4*$i`(@ptr[3]),$t2,$t2
	 lea		`16*4`(@ptr[3]),@ptr[3]
	vpunpckldq	$t2,$Xi,$Xi
	vpinsrd		\$1,`4*$i`(@ptr[7]),$t3,$t3
	 lea		`16*4`(@ptr[7]),@ptr[7]
	vpunpckldq	$t3,$t1,$t1
	vinserti128	$t1,$Xi,$Xi
	vpshufb		$Xn,$Xi,$Xi
___
$code.=<<___;
	vpsrld	\$6,$e,$sigma
	vpslld	\$26,$e,$t3
	vmovdqu	$Xi,`&Xi_off($i)`
	 vpaddd	$h,$Xi,$Xi			# Xi+=h

	vpsrld	\$11,$e,$t2
	vpxor	$t3,$sigma,$sigma
	vpslld	\$21,$e,$t3
	 vpaddd	`32*($i%8)-128`($Tbl),$Xi,$Xi	# Xi+=K[round]
	vpxor	$t2,$sigma,$sigma

	vpsrld	\$25,$e,$t2
	vpxor	$t3,$sigma,$sigma
	 `"prefetch	63(@ptr[0])"		if ($i==15)`
	vpslld	\$7,$e,$t3
	 vpandn	$g,$e,$t1
	 vpand	$f,$e,$axb			# borrow $axb
	 `"prefetch	63(@ptr[1])"		if ($i==15)`
	vpxor	$t2,$sigma,$sigma

	vpsrld	\$2,$a,$h			# borrow $h
	vpxor	$t3,$sigma,$sigma		# Sigma1(e)
	 `"prefetch	63(@ptr[2])"		if ($i==15)`
	vpslld	\$30,$a,$t2
	 vpxor	$axb,$t1,$t1			# Ch(e,f,g)
	 vpxor	$a,$b,$axb			# a^b, b^c in next round
	 `"prefetch	63(@ptr[3])"		if ($i==15)`
	vpxor	$t2,$h,$h
	vpaddd	$sigma,$Xi,$Xi			# Xi+=Sigma1(e)

	vpsrld	\$13,$a,$t2
	 `"prefetch	63(@ptr[4])"		if ($i==15 && $REG_SZ==32)`
	vpslld	\$19,$a,$t3
	 vpaddd	$t1,$Xi,$Xi			# Xi+=Ch(e,f,g)
	 vpand	$axb,$bxc,$bxc
	 `"prefetch	63(@ptr[5])"		if ($i==15 && $REG_SZ==32)`
	vpxor	$t2,$h,$sigma

	vpsrld	\$22,$a,$t2
	vpxor	$t3,$sigma,$sigma
	 `"prefetch	63(@ptr[6])"		if ($i==15 && $REG_SZ==32)`
	vpslld	\$10,$a,$t3
	 vpxor	$bxc,$b,$h			# h=Maj(a,b,c)=Ch(a^b,c,b)
	 vpaddd	$Xi,$d,$d			# d+=Xi
	 `"prefetch	63(@ptr[7])"		if ($i==15 && $REG_SZ==32)`
	vpxor	$t2,$sigma,$sigma
	vpxor	$t3,$sigma,$sigma		# Sigma0(a)

	vpaddd	$Xi,$h,$h			# h+=Xi
	vpaddd	$sigma,$h,$h			# h+=Sigma0(a)
___
$code.=<<___ if (($i%8)==7);
	add	\$`32*8`,$Tbl
___
	($axb,$bxc)=($bxc,$axb);
}

sub ROUND_16_XX_avx {
my $i=shift;

$code.=<<___;
	vmovdqu	`&Xi_off($i+1)`,$Xn
	vpaddd	`&Xi_off($i+9)`,$Xi,$Xi		# Xi+=X[i+9]

	vpsrld	\$3,$Xn,$sigma
	vpsrld	\$7,$Xn,$t2
	vpslld	\$25,$Xn,$t3
	vpxor	$t2,$sigma,$sigma
	vpsrld	\$18,$Xn,$t2
	vpxor	$t3,$sigma,$sigma
	vpslld	\$14,$Xn,$t3
	vmovdqu	`&Xi_off($i+14)`,$t1
	vpsrld	\$10,$t1,$axb			# borrow $axb

	vpxor	$t2,$sigma,$sigma
	vpsrld	\$17,$t1,$t2
	vpxor	$t3,$sigma,$sigma		# sigma0(X[i+1])
	vpslld	\$15,$t1,$t3
	 vpaddd	$sigma,$Xi,$Xi			# Xi+=sigma0(e)
	vpxor	$t2,$axb,$sigma
	vpsrld	\$19,$t1,$t2
	vpxor	$t3,$sigma,$sigma
	vpslld	\$13,$t1,$t3
	vpxor	$t2,$sigma,$sigma
	vpxor	$t3,$sigma,$sigma		# sigma0(X[i+14])
	vpaddd	$sigma,$Xi,$Xi			# Xi+=sigma1(X[i+14])
___
	&ROUND_00_15_avx($i,@_);
	($Xi,$Xn)=($Xn,$Xi);
}

$code.=<<___;
.type	sha256_multi_block_avx,\@function,3
.align	32
sha256_multi_block_avx:
_avx_shortcut:
___
$code.=<<___ if ($avx>1);
	shr	\$32,%rcx
	cmp	\$2,$num
	jb	.Lavx
	test	\$`1<<5`,%ecx
	jnz	_avx2_shortcut
	jmp	.Lavx
.align	32
.Lavx:
___
$code.=<<___;
	mov	%rsp,%rax
	push	%rbx
	push	%rbp
___
$code.=<<___ if ($win64);
	lea	-0xa8(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
	movaps	%xmm10,-0x78(%rax)
	movaps	%xmm11,-0x68(%rax)
	movaps	%xmm12,-0x58(%rax)
	movaps	%xmm13,-0x48(%rax)
	movaps	%xmm14,-0x38(%rax)
	movaps	%xmm15,-0x28(%rax)
___
$code.=<<___;
	sub	\$`$REG_SZ*18`, %rsp
	and	\$-256,%rsp
	mov	%rax,`$REG_SZ*17`(%rsp)		# original %rsp
	lea	K256+128(%rip),$Tbl
	lea	`$REG_SZ*16`(%rsp),%rbx
	lea	0x80($ctx),$ctx			# size optimization

.Loop_grande_avx:
	mov	$num,`$REG_SZ*17+8`(%rsp)	# original $num
	xor	$num,$num
___
for($i=0;$i<4;$i++) {
    $code.=<<___;
	mov	`16*$i+0`($inp),@ptr[$i]	# input pointer
	mov	`16*$i+8`($inp),%ecx		# number of blocks
	cmp	$num,%ecx
	cmovg	%ecx,$num			# find maximum
	test	%ecx,%ecx
	mov	%ecx,`4*$i`(%rbx)		# initialize counters
	cmovle	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	test	$num,$num
	jz	.Ldone_avx

	vmovdqu	0x00-0x80($ctx),$A		# load context
	 lea	128(%rsp),%rax
	vmovdqu	0x20-0x80($ctx),$B
	vmovdqu	0x40-0x80($ctx),$C
	vmovdqu	0x60-0x80($ctx),$D
	vmovdqu	0x80-0x80($ctx),$E
	vmovdqu	0xa0-0x80($ctx),$F
	vmovdqu	0xc0-0x80($ctx),$G
	vmovdqu	0xe0-0x80($ctx),$H
	vmovdqu	.Lpbswap(%rip),$Xn
	jmp	.Loop_avx

.align	32
.Loop_avx:
	vpxor	$B,$C,$bxc			# magic seed
___
for($i=0;$i<16;$i++)	{ &ROUND_00_15_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	vmovdqu	`&Xi_off($i)`,$Xi
	mov	\$3,%ecx
	jmp	.Loop_16_xx_avx
.align	32
.Loop_16_xx_avx:
___
for(;$i<32;$i++)	{ &ROUND_16_XX_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	dec	%ecx
	jnz	.Loop_16_xx_avx

	mov	\$1,%ecx
	lea	K256+128(%rip),$Tbl
___
for($i=0;$i<4;$i++) {
    $code.=<<___;
	cmp	`4*$i`(%rbx),%ecx		# examine counters
	cmovge	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	vmovdqa	(%rbx),$sigma			# pull counters
	vpxor	$t1,$t1,$t1
	vmovdqa	$sigma,$Xn
	vpcmpgtd $t1,$Xn,$Xn			# mask value
	vpaddd	$Xn,$sigma,$sigma		# counters--

	vmovdqu	0x00-0x80($ctx),$t1
	vpand	$Xn,$A,$A
	vmovdqu	0x20-0x80($ctx),$t2
	vpand	$Xn,$B,$B
	vmovdqu	0x40-0x80($ctx),$t3
	vpand	$Xn,$C,$C
	vmovdqu	0x60-0x80($ctx),$Xi
	vpand	$Xn,$D,$D
	vpaddd	$t1,$A,$A
	vmovdqu	0x80-0x80($ctx),$t1
	vpand	$Xn,$E,$E
	vpaddd	$t2,$B,$B
	vmovdqu	0xa0-0x80($ctx),$t2
	vpand	$Xn,$F,$F
	vpaddd	$t3,$C,$C
	vmovdqu	0xc0-0x80($ctx),$t3
	vpand	$Xn,$G,$G
	vpaddd	$Xi,$D,$D
	vmovdqu	0xe0-0x80($ctx),$Xi
	vpand	$Xn,$H,$H
	vpaddd	$t1,$E,$E
	vpaddd	$t2,$F,$F
	vmovdqu	$A,0x00-0x80($ctx)
	vpaddd	$t3,$G,$G
	vmovdqu	$B,0x20-0x80($ctx)
	vpaddd	$Xi,$H,$H
	vmovdqu	$C,0x40-0x80($ctx)
	vmovdqu	$D,0x60-0x80($ctx)
	vmovdqu	$E,0x80-0x80($ctx)
	vmovdqu	$F,0xa0-0x80($ctx)
	vmovdqu	$G,0xc0-0x80($ctx)
	vmovdqu	$H,0xe0-0x80($ctx)

	vmovdqu	$sigma,(%rbx)			# save counters
	vmovdqu	.Lpbswap(%rip),$Xn
	dec	$num
	jnz	.Loop_avx

	mov	`$REG_SZ*17+8`(%rsp),$num
	lea	$REG_SZ($ctx),$ctx
	lea	`16*$REG_SZ/4`($inp),$inp
	dec	$num
	jnz	.Loop_grande_avx

.Ldone_avx:
	mov	`$REG_SZ*17`(%rsp),%rax		# orignal %rsp
	vzeroupper
___
$code.=<<___ if ($win64);
	movaps	-0xb8(%rax),%xmm6
	movaps	-0xa8(%rax),%xmm7
	movaps	-0x98(%rax),%xmm8
	movaps	-0x88(%rax),%xmm9
	movaps	-0x78(%rax),%xmm10
	movaps	-0x68(%rax),%xmm11
	movaps	-0x58(%rax),%xmm12
	movaps	-0x48(%rax),%xmm13
	movaps	-0x38(%rax),%xmm14
	movaps	-0x28(%rax),%xmm15
___
$code.=<<___;
	mov	-16(%rax),%rbp
	mov	-8(%rax),%rbx
	lea	(%rax),%rsp
	ret
.size	sha256_multi_block_avx,.-sha256_multi_block_avx
___
						if ($avx>1) {
$code =~ s/\`([^\`]*)\`/eval $1/gem;

$REG_SZ=32;
@ptr=map("%r$_",(12..15,8..11));

@V=($A,$B,$C,$D,$E,$F,$G,$H)=map("%ymm$_",(8..15));
($t1,$t2,$t3,$axb,$bxc,$Xi,$Xn,$sigma)=map("%ymm$_",(0..7));

$code.=<<___;
.type	sha256_multi_block_avx2,\@function,3
.align	32
sha256_multi_block_avx2:
_avx2_shortcut:
	mov	%rsp,%rax
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
___
$code.=<<___ if ($win64);
	lea	-0xa8(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
	movaps	%xmm10,0x40(%rsp)
	movaps	%xmm11,0x50(%rsp)
	movaps	%xmm12,-0x78(%rax)
	movaps	%xmm13,-0x68(%rax)
	movaps	%xmm14,-0x58(%rax)
	movaps	%xmm15,-0x48(%rax)
___
$code.=<<___;
	sub	\$`$REG_SZ*18`, %rsp
	and	\$-256,%rsp
	mov	%rax,`$REG_SZ*17`(%rsp)		# original %rsp
	lea	K256+128(%rip),$Tbl
	lea	0x80($ctx),$ctx			# size optimization

.Loop_grande_avx2:
	mov	$num,`$REG_SZ*17+8`(%rsp)	# original $num
	xor	$num,$num
	lea	`$REG_SZ*16`(%rsp),%rbx
___
for($i=0;$i<8;$i++) {
    $code.=<<___;
	mov	`16*$i+0`($inp),@ptr[$i]	# input pointer
	mov	`16*$i+8`($inp),%ecx		# number of blocks
	cmp	$num,%ecx
	cmovg	%ecx,$num			# find maximum
	test	%ecx,%ecx
	mov	%ecx,`4*$i`(%rbx)		# initialize counters
	cmovle	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	vmovdqu	0x00-0x80($ctx),$A		# load context
	 lea	128(%rsp),%rax
	vmovdqu	0x20-0x80($ctx),$B
	 lea	256+128(%rsp),%rbx
	vmovdqu	0x40-0x80($ctx),$C
	vmovdqu	0x60-0x80($ctx),$D
	vmovdqu	0x80-0x80($ctx),$E
	vmovdqu	0xa0-0x80($ctx),$F
	vmovdqu	0xc0-0x80($ctx),$G
	vmovdqu	0xe0-0x80($ctx),$H
	vmovdqu	.Lpbswap(%rip),$Xn
	jmp	.Loop_avx2

.align	32
.Loop_avx2:
	vpxor	$B,$C,$bxc			# magic seed
___
for($i=0;$i<16;$i++)	{ &ROUND_00_15_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	vmovdqu	`&Xi_off($i)`,$Xi
	mov	\$3,%ecx
	jmp	.Loop_16_xx_avx2
.align	32
.Loop_16_xx_avx2:
___
for(;$i<32;$i++)	{ &ROUND_16_XX_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	dec	%ecx
	jnz	.Loop_16_xx_avx2

	mov	\$1,%ecx
	lea	`$REG_SZ*16`(%rsp),%rbx
	lea	K256+128(%rip),$Tbl
___
for($i=0;$i<8;$i++) {
    $code.=<<___;
	cmp	`4*$i`(%rbx),%ecx		# examine counters
	cmovge	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	vmovdqa	(%rbx),$sigma			# pull counters
	vpxor	$t1,$t1,$t1
	vmovdqa	$sigma,$Xn
	vpcmpgtd $t1,$Xn,$Xn			# mask value
	vpaddd	$Xn,$sigma,$sigma		# counters--

	vmovdqu	0x00-0x80($ctx),$t1
	vpand	$Xn,$A,$A
	vmovdqu	0x20-0x80($ctx),$t2
	vpand	$Xn,$B,$B
	vmovdqu	0x40-0x80($ctx),$t3
	vpand	$Xn,$C,$C
	vmovdqu	0x60-0x80($ctx),$Xi
	vpand	$Xn,$D,$D
	vpaddd	$t1,$A,$A
	vmovdqu	0x80-0x80($ctx),$t1
	vpand	$Xn,$E,$E
	vpaddd	$t2,$B,$B
	vmovdqu	0xa0-0x80($ctx),$t2
	vpand	$Xn,$F,$F
	vpaddd	$t3,$C,$C
	vmovdqu	0xc0-0x80($ctx),$t3
	vpand	$Xn,$G,$G
	vpaddd	$Xi,$D,$D
	vmovdqu	0xe0-0x80($ctx),$Xi
	vpand	$Xn,$H,$H
	vpaddd	$t1,$E,$E
	vpaddd	$t2,$F,$F
	vmovdqu	$A,0x00-0x80($ctx)
	vpaddd	$t3,$G,$G
	vmovdqu	$B,0x20-0x80($ctx)
	vpaddd	$Xi,$H,$H
	vmovdqu	$C,0x40-0x80($ctx)
	vmovdqu	$D,0x60-0x80($ctx)
	vmovdqu	$E,0x80-0x80($ctx)
	vmovdqu	$F,0xa0-0x80($ctx)
	vmovdqu	$G,0xc0-0x80($ctx)
	vmovdqu	$H,0xe0-0x80($ctx)

	vmovdqu	$sigma,(%rbx)			# save counters
	lea	256+128(%rsp),%rbx
	vmovdqu	.Lpbswap(%rip),$Xn
	dec	$num
	jnz	.Loop_avx2

	#mov	`$REG_SZ*17+8`(%rsp),$num
	#lea	$REG_SZ($ctx),$ctx
	#lea	`16*$REG_SZ/4`($inp),$inp
	#dec	$num
	#jnz	.Loop_grande_avx2

.Ldone_avx2:
	mov	`$REG_SZ*17`(%rsp),%rax		# orignal %rsp
	vzeroupper
___
$code.=<<___ if ($win64);
	movaps	-0xd8(%rax),%xmm6
	movaps	-0xc8(%rax),%xmm7
	movaps	-0xb8(%rax),%xmm8
	movaps	-0xa8(%rax),%xmm9
	movaps	-0x98(%rax),%xmm10
	movaps	-0x88(%rax),%xmm11
	movaps	-0x78(%rax),%xmm12
	movaps	-0x68(%rax),%xmm13
	movaps	-0x58(%rax),%xmm14
	movaps	-0x48(%rax),%xmm15
___
$code.=<<___;
	mov	-48(%rax),%r15
	mov	-40(%rax),%r14
	mov	-32(%rax),%r13
	mov	-24(%rax),%r12
	mov	-16(%rax),%rbp
	mov	-8(%rax),%rbx
	lea	(%rax),%rsp
	ret
.size	sha256_multi_block_avx2,.-sha256_multi_block_avx2
___
					}	}}}
$code.=<<___;
.align	256
K256:
___
sub TABLE {
    foreach (@_) {
	$code.=<<___;
	.long	$_,$_,$_,$_
	.long	$_,$_,$_,$_
___
    }
}
&TABLE(	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 );
$code.=<<___;
.Lpbswap:
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
___

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval($1)/ge;

	s/\b(vmov[dq])\b(.+)%ymm([0-9]+)/$1$2%xmm$3/go		or
	s/\b(vmovdqu)\b(.+)%x%ymm([0-9]+)/$1$2%xmm$3/go		or
	s/\b(vpinsr[qd])\b(.+)%ymm([0-9]+),%ymm([0-9]+)/$1$2%xmm$3,%xmm$4/go	or
	s/\b(vpextr[qd])\b(.+)%ymm([0-9]+)/$1$2%xmm$3/go	or
	s/\b(vinserti128)\b(\s+)%ymm/$1$2\$1,%xmm/go		or
	s/\b(vpbroadcast[qd]\s+)%ymm([0-9]+)/$1%xmm$2/go;
	print $_,"\n";
}

close STDOUT;
