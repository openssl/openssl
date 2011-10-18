#!/usr/bin/env perl

###################################################################
### AES-128 [originally in CTR mode]				###
### bitsliced implementation for Intel Core 2 processors	###
### requires support of SSE extensions up to SSSE3		###
### Author: Emilia Käsper and Peter Schwabe			###
### Date: 2009-03-19						###
### Public domain						###
###								###
### See http://homes.esat.kuleuven.be/~ekasper/#software for	###
### further information.					###
###################################################################
#
# September 2011.
#
# Started as transliteration to "perlasm" the original code has
# undergone following changes:
#
# - code was made position-independent;
# - rounds were folded into a loop resulting in >5x size reduction
#   from 12.5KB to 2.2KB;
# - above was possibile thanks to mixcolumns() modification that
#   allowed to feed its output back to aesenc[last], this was
#   achieved at cost of two additional inter-registers moves;
# - some instruction reordering and interleaving;
# - this module doesn't implement key setup subroutine, instead it
#   relies on conversion of "conventional" key schedule as returned
#   by AES_set_encrypt_key (see discussion below);
# - first and last round keys are treated differently, which allowed
#   to skip one shiftrows(), reduce bit-sliced key schedule and
#   speed-up conversion by 22%;
# - support for 192- and 256-bit keys was added;
#
# Resulting performance in CPU cycles spent to encrypt one byte out
# of 4096-byte buffer with 128-bit key is:
#
#		Emilia's	this(*)		difference
#
# Core 2    	9.30		8.69		+7%
# Nehalem(**) 	7.63		6.98		+9%
# Atom	    	17.1		17.4		-2%(***)
#
# (*)	Comparison is not completely fair, because "this" is ECB,
#	i.e. no extra processing such as counter values calculation
#	and xor-ing input as in Emilia's CTR implementation is
#	performed. However, the CTR calculations stand for not more
#	than 1% of total time, so comparison is *rather* fair.
#
# (**)	Results were collected on Westmere, which is considered to
#	be equivalent to Nehalem for this code.
#
# (***)	Slowdown on Atom is rather strange per se, because original
#	implementation has a number of 9+-bytes instructions, which
#	are bad for Atom front-end, and which I eliminated completely.
#	In attempt to address deterioration sbox() was tested in FP
#	SIMD "domain" (movaps instead of movdqa, xorps instead of
#	pxor, etc.). While it resulted in nominal 4% improvement on
#	Atom, it hurted Westmere by more than 2x factor.
#
# As for key schedule conversion subroutine. Interface to OpenSSL
# relies on per-invocation on-the-fly conversion. This naturally
# has impact on performance, especially for short inputs. Conversion
# time in CPU cycles and its ratio to CPU cycles spent in 8x block
# function is:
#
# 		conversion	conversion/8x block
# Core 2	410		0.37
# Nehalem	310		0.35
# Atom		570		0.26
#
# The ratio values mean that 128-byte blocks will be processed
# 21-27% slower, 256-byte blocks - 12-16%, 384-byte blocks - 8-11%,
# etc. Then keep in mind that input sizes not divisible by 128 are
# *effectively* slower, especially shortest ones, e.g. consecutive
# 144-byte blocks are processed 44% slower than one would expect,
# 272 - 29%, 400 - 22%, etc. Yet, despite all these "shortcomings"
# it's still faster than ["hyper-threading-safe" code path in]
# aes-x86_64.pl on all lengths above 64 bytes...
#
#						<appro@openssl.org>

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

my ($inp,$out,$len,$key,$ivp)=("%rdi","%rsi","%rdx","%rcx");
my @XMM=map("%xmm$_",(15,0..14));	# best on Atom, +10% over (0..15)

{
my ($key,$rounds,$const)=("%rax","%r10d","%r11");

sub sbox {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b0, b1, b4, b6, b3, b7, b2, b5] < msb
my @b=@_[0..7];
my @t=@_[8..11];
my @s=@_[12..15];
	&InBasisChange	(@b);
	&Inv_GF256	(@b[6,5,0,3,7,1,4,2],@t,@s);
	&OutBasisChange	(@b[7,1,4,2,6,5,0,3]);
}

sub InBasisChange {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b6, b5, b0, b3, b7, b1, b4, b2] < msb 
my @b=@_[0..7];
$code.=<<___;
	pxor	@b[6], @b[5]
	pxor	@b[1], @b[2]
	pxor 	@b[0], @b[5]
	pxor	@b[2], @b[6]
	pxor 	@b[0], @b[3]

	pxor	@b[3], @b[6]
	pxor	@b[7], @b[3]
	pxor	@b[5], @b[7]
	pxor	@b[4], @b[3]
	pxor	@b[5], @b[4]
	pxor	@b[1], @b[3]

	pxor	@b[7], @b[2]
	pxor	@b[5], @b[1]
___
}

sub OutBasisChange {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b6, b1, b2, b4, b7, b0, b3, b5] < msb
my @b=@_[0..7];
$code.=<<___;
	pxor	@b[6], @b[0]
	pxor	@b[4], @b[1]
	pxor	@b[0], @b[2]
	pxor	@b[6], @b[4]
	pxor	@b[1], @b[6]

	pxor	@b[5], @b[1]
	pxor	@b[3], @b[5]
	pxor	@b[7], @b[3]
	pxor	@b[5], @b[7]
	pxor	@b[5], @b[2]

	pxor	@b[7], @b[4]
___
}

sub Mul_GF4 {
#;*************************************************************
#;* Mul_GF4: Input x0-x1,y0-y1 Output x0-x1 Temp t0 (8) *
#;*************************************************************
my ($x0,$x1,$y0,$y1,$t0)=@_;
$code.=<<___;
	movdqa	$y0, $t0
	pxor 	$y1, $t0
	pand	$x0, $t0
	pxor	$x1, $x0
	pand	$y0, $x1
	pand	$y1, $x0
	pxor	$x1, $x0
	pxor	$t0, $x1
___
}

sub Mul_GF4_N {				# not used, see next subroutine
# multiply and scale by N
my ($x0,$x1,$y0,$y1,$t0)=@_;
$code.=<<___;
	movdqa	$y0, $t0
	pxor	$y1, $t0
	pand	$x0, $t0
	pxor	$x1, $x0
	pand	$y0, $x1
	pand	$y1, $x0
	pxor	$x0, $x1
	pxor	$t0, $x0
___
}

sub Mul_GF4_N_GF4 {
# interleaved Mul_GF4_N and Mul_GF4
my ($x0,$x1,$y0,$y1,$t0,
    $x2,$x3,$y2,$y3,$t1)=@_;
$code.=<<___;
	movdqa	$y0, $t0
	 movdqa	$y2, $t1
	pxor	$y1, $t0
	 pxor 	$y3, $t1
	pand	$x0, $t0
	 pand	$x2, $t1
	pxor	$x1, $x0
	 pxor	$x3, $x2
	pand	$y0, $x1
	 pand	$y2, $x3
	pand	$y1, $x0
	 pand	$y3, $x2
	pxor	$x0, $x1
	 pxor	$x3, $x2
	pxor	$t0, $x0
	 pxor	$t1, $x3
___
}
sub Mul_GF16_2 {
my @x=@_[0..7];
my @y=@_[8..11];
my @t=@_[12..15];
$code.=<<___;
	movdqa	@x[0], @t[0]
	movdqa	@x[1], @t[1]
___
	&Mul_GF4  	(@x[0], @x[1], @y[0], @y[1], @t[2]);
$code.=<<___;
	pxor	@x[2], @t[0]
	pxor	@x[3], @t[1]
	pxor	@y[2], @y[0]
	pxor	@y[3], @y[1]
___
	Mul_GF4_N_GF4	(@t[0], @t[1], @y[0], @y[1], @t[3],
			 @x[2], @x[3], @y[2], @y[3], @t[2]);
$code.=<<___;
	pxor	@t[0], @x[0]
	pxor	@t[0], @x[2]
	pxor	@t[1], @x[1]
	pxor	@t[1], @x[3]

	movdqa	@x[4], @t[0]
	movdqa	@x[5], @t[1]
	pxor	@x[6], @t[0]
	pxor	@x[7], @t[1]
___
	&Mul_GF4_N_GF4	(@t[0], @t[1], @y[0], @y[1], @t[3],
			 @x[6], @x[7], @y[2], @y[3], @t[2]);
$code.=<<___;
	pxor	@y[2], @y[0]
	pxor	@y[3], @y[1]
___
	&Mul_GF4  	(@x[4], @x[5], @y[0], @y[1], @t[3]);
$code.=<<___;
	pxor	@t[0], @x[4]
	pxor	@t[0], @x[6]
	pxor	@t[1], @x[5]
	pxor	@t[1], @x[7]
___
}
sub Inv_GF256 {
#;********************************************************************
#;* Inv_GF256: Input x0-x7 Output x0-x7 Temp t0-t3,s0-s3 (144)       *
#;********************************************************************
my @x=@_[0..7];
my @t=@_[8..11];
my @s=@_[12..15];
# direct optimizations from hardware
$code.=<<___;
	movdqa	@x[4], @t[3]
	movdqa	@x[5], @t[2]
	movdqa	@x[1], @t[1]
	movdqa	@x[7], @s[1]
	movdqa	@x[0], @s[0]

	pxor	@x[6], @t[3]
	pxor	@x[7], @t[2]
	pxor	@x[3], @t[1]
	 movdqa	@t[3], @s[2]
	pxor	@x[6], @s[1]
	 movdqa	@t[2], @t[0]
	pxor	@x[2], @s[0]
	 movdqa	@t[3], @s[3]

	por	@t[1], @t[2]
	por	@s[0], @t[3]
	pxor	@t[0], @s[3]
	pand	@s[0], @s[2]
	pxor	@t[1], @s[0]
	pand	@t[1], @t[0]
	pand	@s[0], @s[3]
	movdqa	@x[3], @s[0]
	pxor	@x[2], @s[0]
	pand	@s[0], @s[1]
	pxor	@s[1], @t[3]
	pxor	@s[1], @t[2]
	movdqa	@x[4], @s[1]
	movdqa	@x[1], @s[0]
	pxor	@x[5], @s[1]
	pxor	@x[0], @s[0]
	movdqa	@s[1], @t[1]
	pand	@s[0], @s[1]
	por	@s[0], @t[1]
	pxor	@s[1], @t[0]
	pxor	@s[3], @t[3]
	pxor	@s[2], @t[2]
	pxor	@s[3], @t[1]
	movdqa	@x[7], @s[0]
	pxor	@s[2], @t[0]
	movdqa	@x[6], @s[1]
	pxor	@s[2], @t[1]
	movdqa	@x[5], @s[2]
	pand	@x[3], @s[0]
	movdqa	@x[4], @s[3]
	pand	@x[2], @s[1]
	pand	@x[1], @s[2]
	por	@x[0], @s[3]
	pxor	@s[0], @t[3]
	pxor	@s[1], @t[2]
	pxor	@s[2], @t[1]
	pxor	@s[3], @t[0] 

	#Inv_GF16 \t0, \t1, \t2, \t3, \s0, \s1, \s2, \s3

	# new smaller inversion

	movdqa	@t[3], @s[0]
	pand	@t[1], @t[3]
	pxor	@t[2], @s[0]

	movdqa	@t[0], @s[2]
	movdqa	@s[0], @s[3]
	pxor	@t[3], @s[2]
	pand	@s[2], @s[3]

	movdqa	@t[1], @s[1]
	pxor	@t[2], @s[3]
	pxor	@t[0], @s[1]

	pxor	@t[2], @t[3]

	pand	@t[3], @s[1]

	movdqa	@s[2], @t[2]
	pxor	@t[0], @s[1]

	pxor	@s[1], @t[2]
	pxor	@s[1], @t[1]

	pand	@t[0], @t[2]

	pxor	@t[2], @s[2]
	pxor	@t[2], @t[1]

	pand	@s[3], @s[2]

	pxor	@s[0], @s[2]
___
# output in s3, s2, s1, t1

# Mul_GF16_2 \x0, \x1, \x2, \x3, \x4, \x5, \x6, \x7, \t2, \t3, \t0, \t1, \s0, \s1, \s2, \s3

# Mul_GF16_2 \x0, \x1, \x2, \x3, \x4, \x5, \x6, \x7, \s3, \s2, \s1, \t1, \s0, \t0, \t2, \t3
	&Mul_GF16_2(@x,@s[3,2,1],@t[1],@s[0],@t[0,2,3]);

### output msb > [x3,x2,x1,x0,x7,x6,x5,x4] < lsb
}

# AES linear components

sub shiftrows {
my @x=@_[0..7];
my $mask=pop;
$code.=<<___;
	pxor	0x00($key),@x[0]
	pxor	0x10($key),@x[1]
	pshufb	$mask,@x[0]
	pxor	0x20($key),@x[2]
	pshufb	$mask,@x[1]
	pxor	0x30($key),@x[3]
	pshufb	$mask,@x[2]
	pxor	0x40($key),@x[4]
	pshufb	$mask,@x[3]
	pxor	0x50($key),@x[5]
	pshufb	$mask,@x[4]
	pxor	0x60($key),@x[6]
	pshufb	$mask,@x[5]
	pxor	0x70($key),@x[7]
	pshufb	$mask,@x[6]
	lea	0x80($key),$key
	pshufb	$mask,@x[7]
___
}

sub mixcolumns {
# modified to emit output in order suitable for feeding back to aesenc[last]
my @x=@_[0..7];
my @t=@_[8..15];
$code.=<<___;
	pshufd	\$0x93, @x[0], @t[0]	# x0 <<< 32
	pshufd	\$0x93, @x[1], @t[1]
	 pxor	@t[0], @x[0]		# x0 ^ (x0 <<< 32)
	pshufd	\$0x93, @x[2], @t[2]
	 pxor	@t[1], @x[1]
	pshufd	\$0x93, @x[3], @t[3]
	 pxor	@t[2], @x[2]
	pshufd	\$0x93, @x[4], @t[4]
	 pxor	@t[3], @x[3]
	pshufd	\$0x93, @x[5], @t[5]
	 pxor	@t[4], @x[4]
	pshufd	\$0x93, @x[6], @t[6]
	 pxor	@t[5], @x[5]
	pshufd	\$0x93, @x[7], @t[7]
	 pxor	@t[6], @x[6]
	 pxor	@t[7], @x[7]

	pxor	@x[0], @t[1]
	pxor	@x[7], @t[0]
	pxor	@x[7], @t[1]
	 pshufd	\$0x4E, @x[0], @x[0] 	# (x0 ^ (x0 <<< 32)) <<< 64)
	pxor	@x[1], @t[2]
	 pshufd	\$0x4E, @x[1], @x[1]
	pxor	@x[4], @t[5]
	 pxor	@t[0], @x[0]
	pxor	@x[5], @t[6]
	 pxor	@t[1], @x[1]
	pxor	@x[3], @t[4]
	 pshufd	\$0x4E, @x[4], @t[0]
	pxor	@x[6], @t[7]
	 pshufd	\$0x4E, @x[5], @t[1]
	pxor	@x[2], @t[3]
	 pshufd	\$0x4E, @x[3], @x[4]
	pxor	@x[7], @t[3]
	 pshufd	\$0x4E, @x[7], @x[5]
	pxor	@x[7], @t[4]
	 pshufd	\$0x4E, @x[6], @x[3]
	pxor	@t[4], @t[0]
	 pshufd	\$0x4E, @x[2], @x[6]
	pxor	@t[5], @t[1]

	pxor	@t[3], @x[4]
	pxor	@t[7], @x[5]
	pxor	@t[6], @x[3]
	 movdqa	@t[0], @x[2]
	pxor	@t[2], @x[6]
	 movdqa	@t[1], @x[7]
___
}

sub aesenc {				# not used
my @b=@_[0..7];
my @t=@_[8..15];
$code.=<<___;
	movdqa	0x30($const),@t[0]	# .LSR
___
	&shiftrows	(@b,@t[0]);
	&sbox		(@b,@t);
	&mixcolumns	(@b[0,1,4,6,3,7,2,5],@t);
}

sub aesenclast {			# not used
my @b=@_[0..7];
my @t=@_[8..15];
$code.=<<___;
	movdqa	0x40($const),@t[0]	# .LSRM0
___
	&shiftrows	(@b,@t[0]);
	&sbox		(@b,@t);
$code.=<<___
	pxor	0x00($key),@b[0]
	pxor	0x10($key),@b[1]
	pxor	0x20($key),@b[4]
	pxor	0x30($key),@b[6]
	pxor	0x40($key),@b[3]
	pxor	0x50($key),@b[7]
	pxor	0x60($key),@b[2]
	pxor	0x70($key),@b[5]
___
}

sub swapmove {
my ($a,$b,$n,$mask,$t)=@_;
$code.=<<___;
	movdqa	$b,$t
	psrlq	\$$n,$b
	pxor  	$a,$b
	pand	$mask,$b
	pxor	$b,$a
	psllq	\$$n,$b
	pxor	$t,$b
___
}
sub swapmove2x {
my ($a0,$b0,$a1,$b1,$n,$mask,$t0,$t1)=@_;
$code.=<<___;
	movdqa	$b0,$t0
	psrlq	\$$n,$b0
	 movdqa	$b1,$t1
	 psrlq	\$$n,$b1
	pxor  	$a0,$b0
	 pxor  	$a1,$b1
	pand	$mask,$b0
	 pand	$mask,$b1
	pxor	$b0,$a0
	psllq	\$$n,$b0
	 pxor	$b1,$a1
	 psllq	\$$n,$b1
	pxor	$t0,$b0
	 pxor	$t1,$b1
___
}

sub bitslice {
my @x=reverse(@_[0..7]);
my ($t0,$t1,$t2,$t3)=@_[8..11];
$code.=<<___;
	movdqa	0x00($const),$t0	# .LBS0
	movdqa	0x10($const),$t1	# .LBS1
___
	&swapmove2x(@x[0,1,2,3],1,$t0,$t2,$t3);
	&swapmove2x(@x[4,5,6,7],1,$t0,$t2,$t3);
$code.=<<___;
	movdqa	0x20($const),$t0	# .LBS2
___
	&swapmove2x(@x[0,2,1,3],2,$t1,$t2,$t3);
	&swapmove2x(@x[4,6,5,7],2,$t1,$t2,$t3);

	&swapmove2x(@x[0,4,1,5],4,$t0,$t2,$t3);
	&swapmove2x(@x[2,6,3,7],4,$t0,$t2,$t3);
}

$code.=<<___;
.text

.extern	AES_encrypt

.type	_bsaes_encrypt8,\@abi-omnipotent
.align	64
_bsaes_encrypt8:
	lea	.LBS0(%rip), $const	# constants table

	movdqa	($key), @XMM[9]		# round 0 key
	lea	0x10($key), $key
	movdqa	0x60($const), @XMM[8]	# .LM0SR
	pxor	@XMM[9], @XMM[0]	# xor with round0 key
	pxor	@XMM[9], @XMM[1]
	 pshufb	@XMM[8], @XMM[0]
	pxor	@XMM[9], @XMM[2]
	 pshufb	@XMM[8], @XMM[1]
	pxor	@XMM[9], @XMM[3]
	 pshufb	@XMM[8], @XMM[2]
	pxor	@XMM[9], @XMM[4]
	 pshufb	@XMM[8], @XMM[3]
	pxor	@XMM[9], @XMM[5]
	 pshufb	@XMM[8], @XMM[4]
	pxor	@XMM[9], @XMM[6]
	 pshufb	@XMM[8], @XMM[5]
	pxor	@XMM[9], @XMM[7]
	 pshufb	@XMM[8], @XMM[6]
	 pshufb	@XMM[8], @XMM[7]
_bsaes_encrypt8_bitslice:
___
	&bitslice	(@XMM[0..7, 8..11]);
$code.=<<___;
	dec	$rounds
	jmp	.Lenc_sbox
.align	16
.Lenc_loop:
___
	&shiftrows	(@XMM[0..7, 8]);
$code.=".Lenc_sbox:\n";
	&sbox		(@XMM[0..7, 8..15]);
$code.=<<___;
	dec	$rounds
	jl	.Lenc_done
___
	&mixcolumns	(@XMM[0,1,4,6,3,7,2,5, 8..15]);
$code.=<<___;
	movdqa	0x30($const), @XMM[8]	# .LSR
	jnz	.Lenc_loop
	movdqa	0x40($const), @XMM[8]	# .LSRM0
	jmp	.Lenc_loop
.align	16
.Lenc_done:
___
	# output in lsb > [t0, t1, t4, t6, t3, t7, t2, t5] < msb
	&bitslice	(@XMM[0,1,4,6,3,7,2,5, 8..11]);
$code.=<<___;
	movdqa	($key), @XMM[8]		# last round key
	pxor	@XMM[8], @XMM[0]
	pxor	@XMM[8], @XMM[1]
	pxor	@XMM[8], @XMM[4]
	pxor	@XMM[8], @XMM[6]
	pxor	@XMM[8], @XMM[3]
	pxor	@XMM[8], @XMM[7]
	pxor	@XMM[8], @XMM[2]
	pxor	@XMM[8], @XMM[5]
	ret
.size	_bsaes_encrypt8,.-_bsaes_encrypt8
___
}
{
my ($out,$inp,$rounds,$const)=("%rax","%rcx","%r10d","%r11");

sub bitslice_key {
my @x=reverse(@_[0..7]);
my ($bs0,$bs1,$bs2,$t2,$t3)=@_[8..12];

	&swapmove	(@x[0,1],1,$bs0,$t2,$t3);
$code.=<<___;
	#&swapmove(@x[2,3],1,$t0,$t2,$t3);
	movdqa	@x[0], @x[2]
	movdqa	@x[1], @x[3]
___
	#&swapmove2x(@x[4,5,6,7],1,$t0,$t2,$t3);

	&swapmove2x	(@x[0,2,1,3],2,$bs1,$t2,$t3);
$code.=<<___;
	#&swapmove2x(@x[4,6,5,7],2,$t1,$t2,$t3);
	movdqa	@x[0], @x[4]
	movdqa	@x[2], @x[6]
	movdqa	@x[1], @x[5]
	movdqa	@x[3], @x[7]
___
	&swapmove2x	(@x[0,4,1,5],4,$bs2,$t2,$t3);
	&swapmove2x	(@x[2,6,3,7],4,$bs2,$t2,$t3);
}

$code.=<<___;
.type	_bsaes_enc_key_convert,\@abi-omnipotent
.align	16
_bsaes_enc_key_convert:
	lea	.LBS1(%rip), $const
	movdqu	($inp), %xmm7		# load round 0 key
	movdqa	-0x10($const), %xmm8	# .LBS0
	movdqa	0x00($const), %xmm9	# .LBS1
	movdqa	0x10($const), %xmm10	# .LBS2
	movdqa	0x40($const), %xmm13	# .LM0
	movdqa	0x60($const),%xmm14	# .LNOT

	movdqu	0x10($inp), %xmm6	# load round 1 key
	lea	0x10($inp), $inp
	movdqa	%xmm7, ($out)		# save round 0 key
	lea	0x10($out), $out
	dec	$rounds
	jmp	.Lkey_loop
.align	16
.Lkey_loop:
	pshufb	%xmm13, %xmm6
	movdqa	%xmm6, %xmm7
___
	&bitslice_key	(map("%xmm$_",(0..7, 8..12)));
$code.=<<___;
	pxor	%xmm14, %xmm5		# "pnot"
	pxor	%xmm14, %xmm6
	pxor	%xmm14, %xmm0
	pxor	%xmm14, %xmm1
	lea	0x10($inp), $inp
	movdqa	%xmm0, 0x00($out)	# write bit-sliced round key
	movdqa	%xmm1, 0x10($out)
	movdqa	%xmm2, 0x20($out)
	movdqa	%xmm3, 0x30($out)
	movdqa	%xmm4, 0x40($out)
	movdqa	%xmm5, 0x50($out)
	movdqa	%xmm6, 0x60($out)
	movdqa	%xmm7, 0x70($out)
	lea	0x80($out),$out
	movdqu	($inp), %xmm6		# load next round key
	dec	$rounds
	jnz	.Lkey_loop

	pxor	0x70($const), %xmm6	# .L63
	movdqa	%xmm6, ($out)		# save last round key
	ret
.size	_bsaes_enc_key_convert,.-_bsaes_enc_key_convert
___
}

if (1 && !$win64) {	# following two functions are unsupported interface
			# used for benchmarking...
$code.=<<___;
.globl	bsaes_enc_key_convert
.type	bsaes_enc_key_convert,\@function,2
.align	16
bsaes_enc_key_convert:
	mov	240($inp),%r10d		# pass rounds
	mov	$inp,%rcx		# pass key
	mov	$out,%rax		# pass key schedule
	call	_bsaes_enc_key_convert
	ret
.size	bsaes_enc_key_convert,.-bsaes_enc_key_convert

.globl	bsaes_encrypt_128
.type	bsaes_encrypt_128,\@function,4
.align	16
bsaes_encrypt_128:
.Lenc128_loop:
	movdqu	0x00($inp), @XMM[0]	# load input
	movdqu	0x10($inp), @XMM[1]
	movdqu	0x20($inp), @XMM[2]
	movdqu	0x30($inp), @XMM[3]
	movdqu	0x40($inp), @XMM[4]
	movdqu	0x50($inp), @XMM[5]
	movdqu	0x60($inp), @XMM[6]
	movdqu	0x70($inp), @XMM[7]
	mov	$key, %rax		# pass the $key
	lea	0x80($inp), $inp
	mov	\$10,%r10d

	call	_bsaes_encrypt8

	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	movdqu	@XMM[3], 0x40($out)
	movdqu	@XMM[7], 0x50($out)
	movdqu	@XMM[2], 0x60($out)
	movdqu	@XMM[5], 0x70($out)
	lea	0x80($out), $out
	sub	\$0x80,$len
	ja	.Lenc128_loop
	ret
.size	bsaes_encrypt_128,.-bsaes_encrypt_128
___
}
{
######################################################################
#
# OpenSSL interface
#
my ($arg1,$arg2,$arg3,$arg4,$arg5) = $win64	? ("%rcx","%rdx","%r8","%r9","%r10")
						: ("%rdi","%rsi","%rdx","%rcx","%r8");
my ($inp,$out,$len,$key)=("%r12","%r13","%r14","%r15");

$code.=<<___;
.globl	bsaes_ecb_encrypt_blocks
.type	bsaes_ecb_encrypt_blocks,\@abi-omnipotent
.align	16
bsaes_ecb_encrypt_blocks:
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	lea	-0x48(%rsp),%rsp
___
$code.=<<___ if ($win64);
	lea	-0xa0(%rsp), %rsp
	movaps	%xmm6, 0x40(%rsp)
	movaps	%xmm7, 0x50(%rsp)
	movaps	%xmm8, 0x60(%rsp)
	movaps	%xmm9, 0x70(%rsp)
	movaps	%xmm10, 0x80(%rsp)
	movaps	%xmm11, 0x90(%rsp)
	movaps	%xmm12, 0xa0(%rsp)
	movaps	%xmm13, 0xb0(%rsp)
	movaps	%xmm14, 0xc0(%rsp)
	movaps	%xmm15, 0xd0(%rsp)
.Lecb_enc_body:
___
$code.=<<___;
	mov	%rsp,%rbp		# backup %rsp
	mov	240($arg4),%eax		# rounds
	mov	$arg1,$inp		# backup arguments
	mov	$arg2,$out
	mov	$arg3,$len
	mov	$arg4,$key
	cmp	\$8,$arg3
	jb	.Lecb_enc_short

	mov	%eax,%ebx		# backup rounds
	shl	\$7,%rax		# 128 bytes per inner round key
	sub	\$`128-32`,%rax		# size of bit-sliced key schedule
	sub	%rax,%rsp
	mov	%rsp,%rax		# pass key schedule
	mov	$key,%rcx		# pass key
	mov	%ebx,%r10d		# pass rounds
	call	_bsaes_enc_key_convert

	sub	\$8,$len
.Lecb_enc_loop:
	movdqu	0x00($inp), @XMM[0]	# load input
	movdqu	0x10($inp), @XMM[1]
	movdqu	0x20($inp), @XMM[2]
	movdqu	0x30($inp), @XMM[3]
	movdqu	0x40($inp), @XMM[4]
	movdqu	0x50($inp), @XMM[5]
	mov	%rsp, %rax		# pass key schedule
	movdqu	0x60($inp), @XMM[6]
	mov	%ebx,%r10d		# pass rounds
	movdqu	0x70($inp), @XMM[7]
	lea	0x80($inp), $inp

	call	_bsaes_encrypt8

	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	movdqu	@XMM[3], 0x40($out)
	movdqu	@XMM[7], 0x50($out)
	movdqu	@XMM[2], 0x60($out)
	movdqu	@XMM[5], 0x70($out)
	lea	0x80($out), $out
	sub	\$8,$len
	jnc	.Lecb_enc_loop

	add	\$8,$len
	jz	.Lecb_enc_done

	movdqu	0x00($inp), @XMM[0]	# load input
	mov	%rsp, %rax		# pass key schedule
	mov	%ebx,%r10d		# pass rounds
	cmp	\$2,$len
	jb	.Lecb_enc_one
	movdqu	0x10($inp), @XMM[1]
	je	.Lecb_enc_two
	movdqu	0x20($inp), @XMM[2]
	cmp	\$4,$len
	jb	.Lecb_enc_three
	movdqu	0x30($inp), @XMM[3]
	je	.Lecb_enc_four
	movdqu	0x40($inp), @XMM[4]
	cmp	\$6,$len
	jb	.Lecb_enc_five
	movdqu	0x50($inp), @XMM[5]
	je	.Lecb_enc_six
	movdqu	0x60($inp), @XMM[6]
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	movdqu	@XMM[3], 0x40($out)
	movdqu	@XMM[7], 0x50($out)
	movdqu	@XMM[2], 0x60($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_six:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	movdqu	@XMM[3], 0x40($out)
	movdqu	@XMM[7], 0x50($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_five:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	movdqu	@XMM[3], 0x40($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_four:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	movdqu	@XMM[6], 0x30($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_three:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	movdqu	@XMM[4], 0x20($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_two:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	movdqu	@XMM[1], 0x10($out)
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_one:
	call	_bsaes_encrypt8
	movdqu	@XMM[0], 0x00($out)	# write output
	jmp	.Lecb_enc_done
.align	16
.Lecb_enc_short:
	lea	($inp), $arg1
	lea	($out), $arg2
	lea	($key), $arg3
	call	AES_encrypt
	lea	16($inp), $inp
	lea	16($out), $out
	dec	$len
	jnz	.Lecb_enc_short

.Lecb_enc_done:
	lea	(%rsp),%rax
	pxor	%xmm0, %xmm0
.Lecb_enc_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	jb	.Lecb_enc_bzero

	lea	(%rbp),%rsp		# restore %rsp
___
$code.=<<___ if ($win64);
	movaps	0x40(%rbp), %xmm6
	movaps	0x50(%rbp), %xmm7
	movaps	0x60(%rbp), %xmm8
	movaps	0x70(%rbp), %xmm9
	movaps	0x80(%rbp), %xmm10
	movaps	0x90(%rbp), %xmm11
	movaps	0xa0(%rbp), %xmm12
	movaps	0xb0(%rbp), %xmm13
	movaps	0xc0(%rbp), %xmm14
	movaps	0xd0(%rbp), %xmm15
	lea	0xa0(%rbp), %rsp
___
$code.=<<___;
	mov	0x48(%rsp), %r15
	mov	0x50(%rsp), %r14
	mov	0x58(%rsp), %r13
	mov	0x60(%rsp), %r12
	mov	0x68(%rsp), %rbx
	mov	0x70(%rsp), %rbp
	lea	0x78(%rsp), %rsp
.Lecb_enc_epilogue:
	ret
.size	bsaes_ecb_encrypt_blocks,.-bsaes_ecb_encrypt_blocks

.globl	bsaes_ctr32_encrypt_blocks
.type	bsaes_ctr32_encrypt_blocks,\@abi-omnipotent
.align	16
bsaes_ctr32_encrypt_blocks:
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	lea	-0x48(%rsp), %rsp
___
$code.=<<___ if ($win64);
	mov	0xa0(%rsp),$arg5	# pull ivp
	lea	-0xa0(%rsp), %rsp
	movaps	%xmm6, 0x40(%rsp)
	movaps	%xmm7, 0x50(%rsp)
	movaps	%xmm8, 0x60(%rsp)
	movaps	%xmm9, 0x70(%rsp)
	movaps	%xmm10, 0x80(%rsp)
	movaps	%xmm11, 0x90(%rsp)
	movaps	%xmm12, 0xa0(%rsp)
	movaps	%xmm13, 0xb0(%rsp)
	movaps	%xmm14, 0xc0(%rsp)
	movaps	%xmm15, 0xd0(%rsp)
.Lctr_enc_body:
___
$code.=<<___;
	mov	%rsp, %rbp		# backup %rsp
	movdqu	($arg5), %xmm0		# load counter
	mov	240($arg4), %eax	# rounds
	mov	$arg1, $inp		# backup arguments
	mov	$arg2, $out
	mov	$arg3, $len
	mov	$arg4, $key
	movdqa	%xmm0, 0x20(%rbp)	# copy counter
	cmp	\$8, $arg3
	jb	.Lctr_enc_short

	mov	%eax, %ebx		# rounds
	shl	\$7, %rax		# 128 bytes per inner round key
	sub	\$`128-32`, %rax	# size of bit-sliced key schedule
	sub	%rax, %rsp

	mov	%rsp, %rax		# pass key schedule
	mov	$key, %rcx		# pass key
	mov	%ebx, %r10d		# pass rounds
	call	_bsaes_enc_key_convert

	movdqa	(%rsp), @XMM[9]		# load round0 key
	lea	.LADD1(%rip), %r11
	movdqa	0x20(%rbp), @XMM[0]	# counter copy
	movdqa	-0x20(%r11), @XMM[8]	# .LSWPUP
	pshufb	@XMM[8], @XMM[9]	# byte swap upper part
	pshufb	@XMM[8], @XMM[0]
	movdqa	@XMM[9], (%rsp)		# save adjusted round0 key
	jmp	.Lctr_enc_loop
.align	16
.Lctr_enc_loop:
	movdqa	@XMM[0], 0x20(%rbp)	# save counter
	movdqa	@XMM[0], @XMM[1]	# prepare 8 counter values
	movdqa	@XMM[0], @XMM[2]
	paddd	0x00(%r11), @XMM[1]	# .LADD1
	movdqa	@XMM[0], @XMM[3]
	paddd	0x10(%r11), @XMM[2]	# .LADD2
	movdqa	@XMM[0], @XMM[4]
	paddd	0x20(%r11), @XMM[3]	# .LADD3
	movdqa	@XMM[0], @XMM[5]
	paddd	0x30(%r11), @XMM[4]	# .LADD4
	movdqa	@XMM[0], @XMM[6]
	paddd	0x40(%r11), @XMM[5]	# .LADD5
	movdqa	@XMM[0], @XMM[7]
	paddd	0x50(%r11), @XMM[6]	# .LADD6
	paddd	0x60(%r11), @XMM[7]	# .LADD7

	# Borrow prologue from _bsaes_encrypt8 to use the opportunity
	# to flip byte order in 32-bit counter
	movdqa	(%rsp), @XMM[9]		# round 0 key
	lea	0x10(%rsp), %rax	# pass key schedule
	movdqa	-0x10(%r11), @XMM[8]	# .LSWPUPM0SR
	pxor	@XMM[9], @XMM[0]	# xor with round0 key
	pxor	@XMM[9], @XMM[1]
	 pshufb	@XMM[8], @XMM[0]
	pxor	@XMM[9], @XMM[2]
	 pshufb	@XMM[8], @XMM[1]
	pxor	@XMM[9], @XMM[3]
	 pshufb	@XMM[8], @XMM[2]
	pxor	@XMM[9], @XMM[4]
	 pshufb	@XMM[8], @XMM[3]
	pxor	@XMM[9], @XMM[5]
	 pshufb	@XMM[8], @XMM[4]
	pxor	@XMM[9], @XMM[6]
	 pshufb	@XMM[8], @XMM[5]
	pxor	@XMM[9], @XMM[7]
	 pshufb	@XMM[8], @XMM[6]
	lea	.LBS0(%rip), %r11	# constants table
	 pshufb	@XMM[8], @XMM[7]
	mov	%ebx,%r10d		# pass rounds

	call	_bsaes_encrypt8_bitslice

	sub	\$8,$len
	jc	.Lctr_enc_loop_done

	movdqu	0x00($inp), @XMM[8]	# load input
	movdqu	0x10($inp), @XMM[9]
	movdqu	0x20($inp), @XMM[10]
	movdqu	0x30($inp), @XMM[11]
	movdqu	0x40($inp), @XMM[12]
	movdqu	0x50($inp), @XMM[13]
	movdqu	0x60($inp), @XMM[14]
	movdqu	0x70($inp), @XMM[15]
	lea	0x80($inp),$inp
	pxor	@XMM[0], @XMM[8]
	movdqa	0x20(%rbp), @XMM[0]	# load counter
	pxor	@XMM[9], @XMM[1]
	movdqu	@XMM[8], 0x00($out)	# write output
	pxor	@XMM[10], @XMM[4]
	movdqu	@XMM[1], 0x10($out)
	pxor	@XMM[11], @XMM[6]
	movdqu	@XMM[4], 0x20($out)
	pxor	@XMM[12], @XMM[3]
	movdqu	@XMM[6], 0x30($out)
	pxor	@XMM[13], @XMM[7]
	movdqu	@XMM[3], 0x40($out)
	pxor	@XMM[14], @XMM[2]
	movdqu	@XMM[7], 0x50($out)
	pxor	@XMM[15], @XMM[5]
	movdqu	@XMM[2], 0x60($out)
	lea	.LADD1(%rip), %r11
	movdqu	@XMM[5], 0x70($out)
	lea	0x80($out), $out
	paddd	0x70(%r11), @XMM[0]	# .LADD8
	jnz	.Lctr_enc_loop

	jmp	.Lctr_enc_done
.align	16
.Lctr_enc_loop_done:
	movdqu	0x00($inp), @XMM[8]	# load input
	pxor	@XMM[8], @XMM[0]
	movdqu	@XMM[0], 0x00($out)	# write output
	cmp	\$2,$len
	jb	.Lctr_enc_done
	movdqu	0x10($inp), @XMM[9]
	pxor	@XMM[9], @XMM[1]
	movdqu	@XMM[1], 0x10($out)
	je	.Lctr_enc_done
	movdqu	0x20($inp), @XMM[10]
	pxor	@XMM[10], @XMM[4]
	movdqu	@XMM[4], 0x20($out)
	cmp	\$4,$len
	jb	.Lctr_enc_done
	movdqu	0x30($inp), @XMM[11]
	pxor	@XMM[11], @XMM[6]
	movdqu	@XMM[6], 0x30($out)
	je	.Lctr_enc_done
	movdqu	0x40($inp), @XMM[12]
	pxor	@XMM[12], @XMM[3]
	movdqu	@XMM[3], 0x40($out)
	cmp	\$6,$len
	jb	.Lctr_enc_done
	movdqu	0x50($inp), @XMM[13]
	pxor	@XMM[13], @XMM[7]
	movdqu	@XMM[7], 0x50($out)
	je	.Lctr_enc_done
	movdqu	0x60($inp), @XMM[14]
	pxor	@XMM[14], @XMM[2]
	movdqu	@XMM[2], 0x60($out)
	jmp	.Lctr_enc_done

.align	16
.Lctr_enc_short:
	lea	0x20(%rbp), $arg1
	lea	0x30(%rbp), $arg2
	lea	($key), $arg3
	call	AES_encrypt
	movdqu	($inp), @XMM[1]
	lea	16($inp), $inp
	mov	0x2c(%rbp), %eax	# load 32-bit counter
	bswap	%eax
	pxor	0x30(%rbp), @XMM[1]
	inc	%eax			# increment
	movdqu	@XMM[1], ($out)
	bswap	%eax
	lea	16($out), $out
	mov	%eax, 0x2c(%rsp)	# save 32-bit counter
	dec	$len
	jnz	.Lctr_enc_short

.Lctr_enc_done:
	lea	(%rsp), %rax
	pxor	%xmm0, %xmm0
.Lctr_enc_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	ja	.Lctr_enc_bzero

	lea	(%rbp),%rsp		# restore %rsp
___
$code.=<<___ if ($win64);
	movaps	0x40(%rbp), %xmm6
	movaps	0x50(%rbp), %xmm7
	movaps	0x60(%rbp), %xmm8
	movaps	0x70(%rbp), %xmm9
	movaps	0x80(%rbp), %xmm10
	movaps	0x90(%rbp), %xmm11
	movaps	0xa0(%rbp), %xmm12
	movaps	0xb0(%rbp), %xmm13
	movaps	0xc0(%rbp), %xmm14
	movaps	0xd0(%rbp), %xmm15
	lea	0xa0(%rbp), %rsp
___
$code.=<<___;
	mov	0x48(%rsp), %r15
	mov	0x50(%rsp), %r14
	mov	0x58(%rsp), %r13
	mov	0x60(%rsp), %r12
	mov	0x68(%rsp), %rbx
	mov	0x70(%rsp), %rbp
	lea	0x78(%rsp), %rsp
.Lctr_enc_epilogue:
	ret
.size	bsaes_ctr32_encrypt_blocks,.-bsaes_ctr32_encrypt_blocks
___
}
$code.=<<___;
.align	64
.LBS0:		# bit-slice constants
	.quad	0x5555555555555555, 0x5555555555555555
.LBS1:
	.quad	0x3333333333333333, 0x3333333333333333
.LBS2:
	.quad	0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
.LSR:		# shiftrows constants
	.quad	0x0504070600030201, 0x0f0e0d0c0a09080b
.LSRM0:
	.quad	0x0304090e00050a0f, 0x01060b0c0207080d
.LM0:
	.quad	0x02060a0e03070b0f, 0x0004080c0105090d
.LM0SR:
	.quad	0x0a0e02060f03070b, 0x0004080c05090d01
.LNOT:		# magic constants
	.quad	0xffffffffffffffff, 0xffffffffffffffff
.L63:
	.quad	0x6363636363636363, 0x6363636363636363
.LSWPUP:	# byte-swap upper dword
	.quad	0x0706050403020100, 0x0c0d0e0f0b0a0908
.LSWPUPM0SR:
	.quad	0x0a0d02060c03070b, 0x0004080f05090e01
.LADD1:		# counter increment constants
	.quad	0x0000000000000000, 0x0000000100000000
.LADD2:
	.quad	0x0000000000000000, 0x0000000200000000
.LADD3:
	.quad	0x0000000000000000, 0x0000000300000000
.LADD4:
	.quad	0x0000000000000000, 0x0000000400000000
.LADD5:
	.quad	0x0000000000000000, 0x0000000500000000
.LADD6:
	.quad	0x0000000000000000, 0x0000000600000000
.LADD7:
	.quad	0x0000000000000000, 0x0000000700000000
.LADD8:
	.quad	0x0000000000000000, 0x0000000800000000
.asciz	"Bit-sliced AES for x86_64/SSSE3, Emilia Käsper and Peter Schwabe"
.align	64
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
