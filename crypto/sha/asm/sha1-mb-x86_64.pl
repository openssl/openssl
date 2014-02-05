#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# Multi-buffer SHA1 procedure processes n buffers in parallel by
# placing buffer data to designated lane of SIMD register. n is
# naturally limited to 4 on pre-AVX2 processors and to 8 on
# AVX2-capable processors such as Haswell.
#
#		this	+aesni(i)	sha1	aesni-sha1	gain(iv)
# -------------------------------------------------------------------
# Westmere(ii)	10.7/n	+1.28=3.96(n=4)	5.30	6.66		+68%
# Atom(ii)	18.9?/n	+3.93=8.66(n=4)	10.0	14.0		+62%
# Sandy Bridge	(8.16	+5.15=13.3)/n	4.99	5.98		+80%
# Ivy Bridge	(8.08	+5.14=13.2)/n	4.60	5.54		+68%
# Haswell(iii)	(8.96	+5.00=14.0)/n	3.57	4.55		+160%
# Bulldozer	(9.76	+5.76=15.5)/n	5.95	6.37		+64%
#
# (i)	multi-block CBC encrypt with 128-bit key;
# (ii)	(HASH+AES)/n does not apply to Westmere for n>3 and Atom,
#	because of lower AES-NI instruction throughput;
# (iii)	"this" is for n=8, when we gather twice as much data, result
#	for n=4 is 8.00+4.44=12.4;
# (iv)	presented improvement coefficients are asymptotic limits and
#	in real-life application are somewhat lower, e.g. for 2KB
#	fragments they range from 30% to 100% (on Haswell);

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

# void sha1_multi_block (
#     struct {	unsigned int A[8];
#		unsigned int B[8];
#		unsigned int C[8];
#		unsigned int D[8];
#		unsigned int E[8];	} *ctx,
#     struct {	void *ptr; int blocks;	} inp[8],
#     int num);		/* 1 or 2 */
#
$ctx="%rdi";	# 1st arg
$inp="%rsi";	# 2nd arg
$num="%edx";
@ptr=map("%r$_",(8..11));
$Tbl="%rbp";

@V=($A,$B,$C,$D,$E)=map("%xmm$_",(0..4));
($t0,$t1,$t2,$t3,$tx)=map("%xmm$_",(5..9));
@Xi=map("%xmm$_",(10..14));
$K="%xmm15";

if (1) {
    # Atom-specific optimization aiming to eliminate pshufb with high
    # registers [and thus get rid of 48 cycles accumulated penalty] 
    @Xi=map("%xmm$_",(0..4));
    ($tx,$t0,$t1,$t2,$t3)=map("%xmm$_",(5..9));
    @V=($A,$B,$C,$D,$E)=map("%xmm$_",(10..14));
}

$REG_SZ=16;

sub Xi_off {
my $off = shift;

    $off %= 16; $off *= $REG_SZ;
    $off<256 ? "$off-128(%rax)" : "$off-256-128(%rbx)";
}

sub BODY_00_19 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
my $k=$i+2;

$code.=<<___ if ($i==0);
	movd		(@ptr[0]),@Xi[0]
	 lea		`16*4`(@ptr[0]),@ptr[0]
	movd		(@ptr[1]),@Xi[2]	# borrow @Xi[2]
	 lea		`16*4`(@ptr[1]),@ptr[1]
	movd		(@ptr[2]),@Xi[3]	# borrow @Xi[3]
	 lea		`16*4`(@ptr[2]),@ptr[2]
	movd		(@ptr[3]),@Xi[4]	# borrow @Xi[4]
	 lea		`16*4`(@ptr[3]),@ptr[3]
	punpckldq	@Xi[3],@Xi[0]
	 movd		`4*$j-16*4`(@ptr[0]),@Xi[1]
	punpckldq	@Xi[4],@Xi[2]
	 movd		`4*$j-16*4`(@ptr[1]),$t3
	punpckldq	@Xi[2],@Xi[0]
	 movd		`4*$j-16*4`(@ptr[2]),$t2
	pshufb		$tx,@Xi[0]
___
$code.=<<___ if ($i<14);			# just load input
	 movd		`4*$j-16*4`(@ptr[3]),$t1
	 punpckldq	$t2,@Xi[1]
	movdqa	$a,$t2
	paddd	$K,$e				# e+=K_00_19
	 punpckldq	$t1,$t3
	movdqa	$b,$t1
	movdqa	$b,$t0
	pslld	\$5,$t2
	pandn	$d,$t1
	pand	$c,$t0
	 punpckldq	$t3,@Xi[1]
	movdqa	$a,$t3

	movdqa	@Xi[0],`&Xi_off($i)`
	paddd	@Xi[0],$e			# e+=X[i]
	 movd		`4*$k-16*4`(@ptr[0]),@Xi[2]
	psrld	\$27,$t3
	pxor	$t1,$t0				# Ch(b,c,d)
	movdqa	$b,$t1

	por	$t3,$t2				# rol(a,5)
	 movd		`4*$k-16*4`(@ptr[1]),$t3
	pslld	\$30,$t1
	paddd	$t0,$e				# e+=Ch(b,c,d)

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	 pshufb	$tx,@Xi[1]
	 movd		`4*$j-16*4`(@ptr[2]),$t2
	por	$t1,$b				# b=rol(b,30)
___
$code.=<<___ if ($i==14);			# just load input
	 movd		`4*$j-16*4`(@ptr[3]),$t1
	 punpckldq	$t2,@Xi[1]
	movdqa	$a,$t2
	paddd	$K,$e				# e+=K_00_19
	 punpckldq	$t1,$t3
	movdqa	$b,$t1
	movdqa	$b,$t0
	pslld	\$5,$t2
	 prefetcht0	63(@ptr[0])
	pandn	$d,$t1
	pand	$c,$t0
	 punpckldq	$t3,@Xi[1]
	movdqa	$a,$t3

	movdqa	@Xi[0],`&Xi_off($i)`
	paddd	@Xi[0],$e			# e+=X[i]
	psrld	\$27,$t3
	pxor	$t1,$t0				# Ch(b,c,d)
	movdqa	$b,$t1
	 prefetcht0	63(@ptr[1])

	por	$t3,$t2				# rol(a,5)
	pslld	\$30,$t1
	paddd	$t0,$e				# e+=Ch(b,c,d)
	 prefetcht0	63(@ptr[2])

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	 pshufb	$tx,@Xi[1]
	 prefetcht0	63(@ptr[3])
	por	$t1,$b				# b=rol(b,30)
___
$code.=<<___ if ($i>=13 && $i<15);
	movdqa	`&Xi_off($j+2)`,@Xi[3]		# preload "X[2]"
___
$code.=<<___ if ($i>=15);			# apply Xupdate
	pxor	@Xi[-2],@Xi[1]			# "X[13]"
	movdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	movdqa	$a,$t2
	 pxor	`&Xi_off($j+8)`,@Xi[1]
	paddd	$K,$e				# e+=K_00_19
	movdqa	$b,$t1
	pslld	\$5,$t2
	 pxor	@Xi[3],@Xi[1]
	movdqa	$b,$t0
	pandn	$d,$t1
	 movdqa	@Xi[1],$tx
	pand	$c,$t0
	movdqa	$a,$t3
	 psrld	\$31,$tx
	 paddd	@Xi[1],@Xi[1]

	movdqa	@Xi[0],`&Xi_off($i)`
	paddd	@Xi[0],$e			# e+=X[i]
	psrld	\$27,$t3
	pxor	$t1,$t0				# Ch(b,c,d)

	movdqa	$b,$t1
	por	$t3,$t2				# rol(a,5)
	pslld	\$30,$t1
	paddd	$t0,$e				# e+=Ch(b,c,d)

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	 por	$tx,@Xi[1]			# rol	\$1,@Xi[1]
	por	$t1,$b				# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

sub BODY_20_39 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;

$code.=<<___ if ($i<79);
	pxor	@Xi[-2],@Xi[1]			# "X[13]"
	movdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	movdqa	$a,$t2
	movdqa	$d,$t0
	 pxor	`&Xi_off($j+8)`,@Xi[1]
	paddd	$K,$e				# e+=K_20_39
	pslld	\$5,$t2
	pxor	$b,$t0

	movdqa	$a,$t3
___
$code.=<<___ if ($i<72);
	movdqa	@Xi[0],`&Xi_off($i)`
___
$code.=<<___ if ($i<79);
	paddd	@Xi[0],$e			# e+=X[i]
	 pxor	@Xi[3],@Xi[1]
	psrld	\$27,$t3
	pxor	$c,$t0				# Parity(b,c,d)
	movdqa	$b,$t1

	pslld	\$30,$t1
	 movdqa	@Xi[1],$tx
	por	$t3,$t2				# rol(a,5)
	 psrld	\$31,$tx
	paddd	$t0,$e				# e+=Parity(b,c,d)
	 paddd	@Xi[1],@Xi[1]

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	 por	$tx,@Xi[1]			# rol(@Xi[1],1)
	por	$t1,$b				# b=rol(b,30)
___
$code.=<<___ if ($i==79);
	movdqa	$a,$t2
	paddd	$K,$e				# e+=K_20_39
	movdqa	$d,$t0
	pslld	\$5,$t2
	pxor	$b,$t0

	movdqa	$a,$t3
	paddd	@Xi[0],$e			# e+=X[i]
	psrld	\$27,$t3
	movdqa	$b,$t1
	pxor	$c,$t0				# Parity(b,c,d)

	pslld	\$30,$t1
	por	$t3,$t2				# rol(a,5)
	paddd	$t0,$e				# e+=Parity(b,c,d)

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	por	$t1,$b				# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

sub BODY_40_59 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;

$code.=<<___;
	pxor	@Xi[-2],@Xi[1]			# "X[13]"
	movdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	movdqa	$a,$t2
	movdqa	$d,$t1
	 pxor	`&Xi_off($j+8)`,@Xi[1]
	pxor	@Xi[3],@Xi[1]
	paddd	$K,$e				# e+=K_40_59
	pslld	\$5,$t2
	movdqa	$a,$t3
	pand	$c,$t1

	movdqa	$d,$t0
	 movdqa	@Xi[1],$tx
	psrld	\$27,$t3
	paddd	$t1,$e
	pxor	$c,$t0

	movdqa	@Xi[0],`&Xi_off($i)`
	paddd	@Xi[0],$e			# e+=X[i]
	por	$t3,$t2				# rol(a,5)
	 psrld	\$31,$tx
	pand	$b,$t0
	movdqa	$b,$t1

	pslld	\$30,$t1
	 paddd	@Xi[1],@Xi[1]
	paddd	$t0,$e				# e+=Maj(b,d,c)

	psrld	\$2,$b
	paddd	$t2,$e				# e+=rol(a,5)
	 por	$tx,@Xi[1]			# rol(@X[1],1)
	por	$t1,$b				# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

$code.=<<___;
.text

.extern	OPENSSL_ia32cap_P

.globl	sha1_multi_block
.type	sha1_multi_block,\@function,3
.align	32
sha1_multi_block:
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
	sub	\$`$REG_SZ*18`,%rsp
	and	\$-256,%rsp
	mov	%rax,`$REG_SZ*17`(%rsp)		# original %rsp
	lea	K_XX_XX(%rip),$Tbl
	lea	`$REG_SZ*16`(%rsp),%rbx

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

	movdqu	0x00($ctx),$A			# load context
	 lea	128(%rsp),%rax
	movdqu	0x20($ctx),$B
	movdqu	0x40($ctx),$C
	movdqu	0x60($ctx),$D
	movdqu	0x80($ctx),$E
	movdqa	0x60($Tbl),$tx			# pbswap_mask
	movdqa	-0x20($Tbl),$K			# K_00_19
	jmp	.Loop

.align	32
.Loop:
___
for($i=0;$i<20;$i++)	{ &BODY_00_19($i,@V); unshift(@V,pop(@V)); }
$code.="	movdqa	0x00($Tbl),$K\n";	# K_20_39
for(;$i<40;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.="	movdqa	0x20($Tbl),$K\n";	# K_40_59
for(;$i<60;$i++)	{ &BODY_40_59($i,@V); unshift(@V,pop(@V)); }
$code.="	movdqa	0x40($Tbl),$K\n";	# K_60_79
for(;$i<80;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	movdqa	(%rbx),@Xi[0]			# pull counters
	mov	\$1,%ecx
	cmp	4*0(%rbx),%ecx			# examinte counters
	pxor	$t2,$t2
	cmovge	$Tbl,@ptr[0]			# cancel input
	cmp	4*1(%rbx),%ecx
	movdqa	@Xi[0],@Xi[1]
	cmovge	$Tbl,@ptr[1]
	cmp	4*2(%rbx),%ecx
	pcmpgtd	$t2,@Xi[1]			# mask value
	cmovge	$Tbl,@ptr[2]
	cmp	4*3(%rbx),%ecx
	paddd	@Xi[1],@Xi[0]			# counters--
	cmovge	$Tbl,@ptr[3]

	movdqu	0x00($ctx),$t0
	pand	@Xi[1],$A
	movdqu	0x20($ctx),$t1
	pand	@Xi[1],$B
	paddd	$t0,$A
	movdqu	0x40($ctx),$t2
	pand	@Xi[1],$C
	paddd	$t1,$B
	movdqu	0x60($ctx),$t3
	pand	@Xi[1],$D
	paddd	$t2,$C
	movdqu	0x80($ctx),$tx
	pand	@Xi[1],$E
	movdqu	$A,0x00($ctx)
	paddd	$t3,$D
	movdqu	$B,0x20($ctx)
	paddd	$tx,$E
	movdqu	$C,0x40($ctx)
	movdqu	$D,0x60($ctx)
	movdqu	$E,0x80($ctx)

	movdqa	@Xi[0],(%rbx)			# save counters
	movdqa	0x60($Tbl),$tx			# pbswap_mask
	movdqa	-0x20($Tbl),$K			# K_00_19
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
.size	sha1_multi_block,.-sha1_multi_block
___

						if ($avx) {{{
sub BODY_00_19_avx {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
my $k=$i+2;
my $vpack = $REG_SZ==16 ? "vpunpckldq" : "vinserti128";
my $ptr_n = $REG_SZ==16 ? @ptr[1] : @ptr[4];

$code.=<<___ if ($i==0 && $REG_SZ==16);
	vmovd		(@ptr[0]),@Xi[0]
	 lea		`16*4`(@ptr[0]),@ptr[0]
	vmovd		(@ptr[1]),@Xi[2]	# borrow Xi[2]
	 lea		`16*4`(@ptr[1]),@ptr[1]
	vpinsrd		\$1,(@ptr[2]),@Xi[0],@Xi[0]
	 lea		`16*4`(@ptr[2]),@ptr[2]
	vpinsrd		\$1,(@ptr[3]),@Xi[2],@Xi[2]
	 lea		`16*4`(@ptr[3]),@ptr[3]
	 vmovd		`4*$j-16*4`(@ptr[0]),@Xi[1]
	vpunpckldq	@Xi[2],@Xi[0],@Xi[0]
	 vmovd		`4*$j-16*4`($ptr_n),$t3
	vpshufb		$tx,@Xi[0],@Xi[0]
___
$code.=<<___ if ($i<15 && $REG_SZ==16);		# just load input
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[2]),@Xi[1],@Xi[1]
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[3]),$t3,$t3
___
$code.=<<___ if ($i==0 && $REG_SZ==32);
	vmovd		(@ptr[0]),@Xi[0]
	 lea		`16*4`(@ptr[0]),@ptr[0]
	vmovd		(@ptr[4]),@Xi[2]	# borrow Xi[2]
	 lea		`16*4`(@ptr[4]),@ptr[4]
	vmovd		(@ptr[1]),$t2
	 lea		`16*4`(@ptr[1]),@ptr[1]
	vmovd		(@ptr[5]),$t1
	 lea		`16*4`(@ptr[5]),@ptr[5]
	vpinsrd		\$1,(@ptr[2]),@Xi[0],@Xi[0]
	 lea		`16*4`(@ptr[2]),@ptr[2]
	vpinsrd		\$1,(@ptr[6]),@Xi[2],@Xi[2]
	 lea		`16*4`(@ptr[6]),@ptr[6]
	vpinsrd		\$1,(@ptr[3]),$t2,$t2
	 lea		`16*4`(@ptr[3]),@ptr[3]
	vpunpckldq	$t2,@Xi[0],@Xi[0]
	vpinsrd		\$1,(@ptr[7]),$t1,$t1
	 lea		`16*4`(@ptr[7]),@ptr[7]
	vpunpckldq	$t1,@Xi[2],@Xi[2]
	 vmovd		`4*$j-16*4`(@ptr[0]),@Xi[1]
	vinserti128	@Xi[2],@Xi[0],@Xi[0]
	 vmovd		`4*$j-16*4`($ptr_n),$t3
	vpshufb		$tx,@Xi[0],@Xi[0]
___
$code.=<<___ if ($i<15 && $REG_SZ==32);		# just load input
	 vmovd		`4*$j-16*4`(@ptr[1]),$t2
	 vmovd		`4*$j-16*4`(@ptr[5]),$t1
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[2]),@Xi[1],@Xi[1]
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[6]),$t3,$t3
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[3]),$t2,$t2
	 vpunpckldq	$t2,@Xi[1],@Xi[1]
	 vpinsrd	\$1,`4*$j-16*4`(@ptr[7]),$t1,$t1
	 vpunpckldq	$t1,$t3,$t3
___
$code.=<<___ if ($i<14);
	vpaddd	$K,$e,$e			# e+=K_00_19
	vpslld	\$5,$a,$t2
	vpandn	$d,$b,$t1
	vpand	$c,$b,$t0

	vmovdqa	@Xi[0],`&Xi_off($i)`
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	 $vpack		$t3,@Xi[1],@Xi[1]
	vpsrld	\$27,$a,$t3
	vpxor	$t1,$t0,$t0			# Ch(b,c,d)
	 vmovd		`4*$k-16*4`(@ptr[0]),@Xi[2]

	vpslld	\$30,$b,$t1
	vpor	$t3,$t2,$t2			# rol(a,5)
	 vmovd		`4*$k-16*4`($ptr_n),$t3
	vpaddd	$t0,$e,$e			# e+=Ch(b,c,d)

	vpsrld	\$2,$b,$b
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	 vpshufb	$tx,@Xi[1],@Xi[1]
	vpor	$t1,$b,$b			# b=rol(b,30)
___
$code.=<<___ if ($i==14);
	vpaddd	$K,$e,$e			# e+=K_00_19
	 prefetcht0	63(@ptr[0])
	vpslld	\$5,$a,$t2
	vpandn	$d,$b,$t1
	vpand	$c,$b,$t0

	vmovdqa	@Xi[0],`&Xi_off($i)`
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	 $vpack		$t3,@Xi[1],@Xi[1]
	vpsrld	\$27,$a,$t3
	 prefetcht0	63(@ptr[1])
	vpxor	$t1,$t0,$t0			# Ch(b,c,d)

	vpslld	\$30,$b,$t1
	vpor	$t3,$t2,$t2			# rol(a,5)
	 prefetcht0	63(@ptr[2])
	vpaddd	$t0,$e,$e			# e+=Ch(b,c,d)

	vpsrld	\$2,$b,$b
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	 prefetcht0	63(@ptr[3])
	 vpshufb	$tx,@Xi[1],@Xi[1]
	vpor	$t1,$b,$b			# b=rol(b,30)
___
$code.=<<___ if ($i>=13 && $i<15);
	vmovdqa	`&Xi_off($j+2)`,@Xi[3]		# preload "X[2]"
___
$code.=<<___ if ($i>=15);			# apply Xupdate
	vpxor	@Xi[-2],@Xi[1],@Xi[1]		# "X[13]"
	vmovdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	vpaddd	$K,$e,$e			# e+=K_00_19
	vpslld	\$5,$a,$t2
	vpandn	$d,$b,$t1
	 `"prefetcht0	63(@ptr[4])"		if ($i==15 && $REG_SZ==32)`
	vpand	$c,$b,$t0

	vmovdqa	@Xi[0],`&Xi_off($i)`
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	 vpxor	`&Xi_off($j+8)`,@Xi[1],@Xi[1]
	vpsrld	\$27,$a,$t3
	vpxor	$t1,$t0,$t0			# Ch(b,c,d)
	 vpxor	@Xi[3],@Xi[1],@Xi[1]
	 `"prefetcht0	63(@ptr[5])"		if ($i==15 && $REG_SZ==32)`

	vpslld	\$30,$b,$t1
	vpor	$t3,$t2,$t2			# rol(a,5)
	vpaddd	$t0,$e,$e			# e+=Ch(b,c,d)
	 `"prefetcht0	63(@ptr[6])"		if ($i==15 && $REG_SZ==32)`
	 vpsrld	\$31,@Xi[1],$tx
	 vpaddd	@Xi[1],@Xi[1],@Xi[1]

	vpsrld	\$2,$b,$b
	 `"prefetcht0	63(@ptr[7])"		if ($i==15 && $REG_SZ==32)`
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	 vpor	$tx,@Xi[1],@Xi[1]		# rol	\$1,@Xi[1]
	vpor	$t1,$b,$b			# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

sub BODY_20_39_avx {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;

$code.=<<___ if ($i<79);
	vpxor	@Xi[-2],@Xi[1],@Xi[1]		# "X[13]"
	vmovdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	vpslld	\$5,$a,$t2
	vpaddd	$K,$e,$e			# e+=K_20_39
	vpxor	$b,$d,$t0
___
$code.=<<___ if ($i<72);
	vmovdqa	@Xi[0],`&Xi_off($i)`
___
$code.=<<___ if ($i<79);
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	 vpxor	`&Xi_off($j+8)`,@Xi[1],@Xi[1]
	vpsrld	\$27,$a,$t3
	vpxor	$c,$t0,$t0			# Parity(b,c,d)
	 vpxor	@Xi[3],@Xi[1],@Xi[1]

	vpslld	\$30,$b,$t1
	vpor	$t3,$t2,$t2			# rol(a,5)
	vpaddd	$t0,$e,$e			# e+=Parity(b,c,d)
	 vpsrld	\$31,@Xi[1],$tx
	 vpaddd	@Xi[1],@Xi[1],@Xi[1]

	vpsrld	\$2,$b,$b
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	 vpor	$tx,@Xi[1],@Xi[1]		# rol(@Xi[1],1)
	vpor	$t1,$b,$b			# b=rol(b,30)
___
$code.=<<___ if ($i==79);
	vpslld	\$5,$a,$t2
	vpaddd	$K,$e,$e			# e+=K_20_39
	vpxor	$b,$d,$t0

	vpsrld	\$27,$a,$t3
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	vpxor	$c,$t0,$t0			# Parity(b,c,d)

	vpslld	\$30,$b,$t1
	vpor	$t3,$t2,$t2			# rol(a,5)
	vpaddd	$t0,$e,$e			# e+=Parity(b,c,d)

	vpsrld	\$2,$b,$b
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	vpor	$t1,$b,$b			# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

sub BODY_40_59_avx {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;

$code.=<<___;
	vpxor	@Xi[-2],@Xi[1],@Xi[1]		# "X[13]"
	vmovdqa	`&Xi_off($j+2)`,@Xi[3]		# "X[2]"

	vpaddd	$K,$e,$e			# e+=K_40_59
	vpslld	\$5,$a,$t2
	vpand	$c,$d,$t1
	 vpxor	`&Xi_off($j+8)`,@Xi[1],@Xi[1]

	vpaddd	$t1,$e,$e
	vpsrld	\$27,$a,$t3
	vpxor	$c,$d,$t0
	 vpxor	@Xi[3],@Xi[1],@Xi[1]

	vmovdqu	@Xi[0],`&Xi_off($i)`
	vpaddd	@Xi[0],$e,$e			# e+=X[i]
	vpor	$t3,$t2,$t2			# rol(a,5)
	 vpsrld	\$31,@Xi[1],$tx
	vpand	$b,$t0,$t0
	 vpaddd	@Xi[1],@Xi[1],@Xi[1]

	vpslld	\$30,$b,$t1
	vpaddd	$t0,$e,$e			# e+=Maj(b,d,c)

	vpsrld	\$2,$b,$b
	vpaddd	$t2,$e,$e			# e+=rol(a,5)
	 vpor	$tx,@Xi[1],@Xi[1]		# rol(@X[1],1)
	vpor	$t1,$b,$b			# b=rol(b,30)
___
push(@Xi,shift(@Xi));
}

$code.=<<___;
.type	sha1_multi_block_avx,\@function,3
.align	32
sha1_multi_block_avx:
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
	lea	K_XX_XX(%rip),$Tbl
	lea	`$REG_SZ*16`(%rsp),%rbx

	vzeroupper
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

	vmovdqu	0x00($ctx),$A			# load context
	 lea	128(%rsp),%rax
	vmovdqu	0x20($ctx),$B
	vmovdqu	0x40($ctx),$C
	vmovdqu	0x60($ctx),$D
	vmovdqu	0x80($ctx),$E
	vmovdqu	0x60($Tbl),$tx			# pbswap_mask
	jmp	.Loop_avx

.align	32
.Loop_avx:
___
$code.="	vmovdqa	-0x20($Tbl),$K\n";	# K_00_19
for($i=0;$i<20;$i++)	{ &BODY_00_19_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x00($Tbl),$K\n";	# K_20_39
for(;$i<40;$i++)	{ &BODY_20_39_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x20($Tbl),$K\n";	# K_40_59
for(;$i<60;$i++)	{ &BODY_40_59_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x40($Tbl),$K\n";	# K_60_79
for(;$i<80;$i++)	{ &BODY_20_39_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	mov	\$1,%ecx
___
for($i=0;$i<4;$i++) {
    $code.=<<___;
	cmp	`4*$i`(%rbx),%ecx		# examine counters
	cmovge	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	vmovdqu	(%rbx),$t0			# pull counters
	vpxor	$t2,$t2,$t2
	vmovdqa	$t0,$t1
	vpcmpgtd $t2,$t1,$t1			# mask value
	vpaddd	$t1,$t0,$t0			# counters--

	vpand	$t1,$A,$A
	vpand	$t1,$B,$B
	vpaddd	0x00($ctx),$A,$A
	vpand	$t1,$C,$C
	vpaddd	0x20($ctx),$B,$B
	vpand	$t1,$D,$D
	vpaddd	0x40($ctx),$C,$C
	vpand	$t1,$E,$E
	vpaddd	0x60($ctx),$D,$D
	vpaddd	0x80($ctx),$E,$E
	vmovdqu	$A,0x00($ctx)
	vmovdqu	$B,0x20($ctx)
	vmovdqu	$C,0x40($ctx)
	vmovdqu	$D,0x60($ctx)
	vmovdqu	$E,0x80($ctx)

	vmovdqu	$t0,(%rbx)			# save counters
	vmovdqu	0x60($Tbl),$tx			# pbswap_mask
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
.size	sha1_multi_block_avx,.-sha1_multi_block_avx
___

						if ($avx>1) {
$code =~ s/\`([^\`]*)\`/eval $1/gem;

$REG_SZ=32;

@ptr=map("%r$_",(12..15,8..11));

@V=($A,$B,$C,$D,$E)=map("%ymm$_",(0..4));
($t0,$t1,$t2,$t3,$tx)=map("%ymm$_",(5..9));
@Xi=map("%ymm$_",(10..14));
$K="%ymm15";

$code.=<<___;
.type	sha1_multi_block_avx2,\@function,3
.align	32
sha1_multi_block_avx2:
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
	lea	K_XX_XX(%rip),$Tbl
	shr	\$1,$num

	vzeroupper
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
	vmovdqu	0x00($ctx),$A			# load context
	 lea	128(%rsp),%rax
	vmovdqu	0x20($ctx),$B
	 lea	256+128(%rsp),%rbx
	vmovdqu	0x40($ctx),$C
	vmovdqu	0x60($ctx),$D
	vmovdqu	0x80($ctx),$E
	vmovdqu	0x60($Tbl),$tx			# pbswap_mask
	jmp	.Loop_avx2

.align	32
.Loop_avx2:
___
$code.="	vmovdqa	-0x20($Tbl),$K\n";	# K_00_19
for($i=0;$i<20;$i++)	{ &BODY_00_19_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x00($Tbl),$K\n";	# K_20_39
for(;$i<40;$i++)	{ &BODY_20_39_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x20($Tbl),$K\n";	# K_40_59
for(;$i<60;$i++)	{ &BODY_40_59_avx($i,@V); unshift(@V,pop(@V)); }
$code.="	vmovdqa	0x40($Tbl),$K\n";	# K_60_79
for(;$i<80;$i++)	{ &BODY_20_39_avx($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	mov	\$1,%ecx
	lea	`$REG_SZ*16`(%rsp),%rbx
___
for($i=0;$i<8;$i++) {
    $code.=<<___;
	cmp	`4*$i`(%rbx),%ecx		# examine counters
	cmovge	$Tbl,@ptr[$i]			# cancel input
___
}
$code.=<<___;
	vmovdqu	(%rbx),$t0		# pull counters
	vpxor	$t2,$t2,$t2
	vmovdqa	$t0,$t1
	vpcmpgtd $t2,$t1,$t1			# mask value
	vpaddd	$t1,$t0,$t0			# counters--

	vpand	$t1,$A,$A
	vpand	$t1,$B,$B
	vpaddd	0x00($ctx),$A,$A
	vpand	$t1,$C,$C
	vpaddd	0x20($ctx),$B,$B
	vpand	$t1,$D,$D
	vpaddd	0x40($ctx),$C,$C
	vpand	$t1,$E,$E
	vpaddd	0x60($ctx),$D,$D
	vpaddd	0x80($ctx),$E,$E
	vmovdqu	$A,0x00($ctx)
	vmovdqu	$B,0x20($ctx)
	vmovdqu	$C,0x40($ctx)
	vmovdqu	$D,0x60($ctx)
	vmovdqu	$E,0x80($ctx)

	vmovdqu	$t0,(%rbx)			# save counters
	lea	256+128(%rsp),%rbx
	vmovdqu	0x60($Tbl),$tx			# pbswap_mask
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
.size	sha1_multi_block_avx2,.-sha1_multi_block_avx2
___
						}	}}}
$code.=<<___;

.align	256
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
K_XX_XX:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
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
