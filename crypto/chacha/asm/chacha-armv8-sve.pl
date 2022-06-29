#! /usr/bin/env perl
# Copyright 2022  The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
#
# ChaCha20 for ARMv8 via SVE
#
# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

sub AUTOLOAD()		# thunk [simplified] x86-style perlasm
{ my $opcode = $AUTOLOAD; $opcode =~ s/.*:://; $opcode =~ s/_/\./;
  my $arg = pop;
    $arg = "#$arg" if ($arg*1 eq $arg);
    $code .= "\t$opcode\t".join(',',@_,$arg)."\n";
}

my ($outp,$inp,$len,$key,$ctr) = map("x$_",(0..4));
my ($veclen_w,$veclen,$blocks) = ("w5","x5","x6");
my ($sve2flag) = ("x7");
my ($wctr, $xctr) = ("w8", "x8");
my ($tmpw0,$tmp0,$tmpw1,$tmp1) = ("w9","x9", "w10","x10");
my ($tmp,$tmpw) = ("x10", "w10");
my ($counter) = ("x11");
my @K=map("x$_",(12..15,19..22));
my @KL=map("w$_",(12..15,19..22));
my @mx=map("z$_",(0..15));
my ($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
    $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3) = @mx;
my ($zctr) = ("z16");
my @xt=map("z$_",(17..24));
my @perm=map("z$_",(25..30));
my ($rot8) = ("z31");
my ($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7)=@xt;
# in SVE mode we can only use bak0 ~ bak9 (the rest used as scratch register)
# in SVE2 we use all 15 backup register
my ($bak0,$bak1,$bak2,$bak3,$bak4,$bak5,$bak6,$bak7,$bak8,$bak9,$bak10,$bak11,$bak13,$bak14,$bak15)=(@perm[0],@perm[1],@perm[2],@perm[3],@perm[4],@perm[5],$xt4,$xt5,$xt6,$xt7,$xt0,$xt1,$xt2,$xt3,$rot8);
my $debug_encoder=0;

sub SVE_ADD() {
	my $x = shift;
	my $y = shift;

$code.=<<___;
	add	@mx[$x].s,@mx[$x].s,@mx[$y].s
___
	if (@_) {
		&SVE_ADD(@_);
	}
}

sub SVE_EOR() {
	my $x = shift;
	my $y = shift;

$code.=<<___;
	eor	@mx[$x].d,@mx[$x].d,@mx[$y].d
___
	if (@_) {
		&SVE_EOR(@_);
	}
}

sub SVE_LSL() {
	my $bits = shift;
	my $x = shift;
	my $y = shift;
	my $next = $x + 1;

$code.=<<___;
	lsl	@xt[$x].s,@mx[$y].s,$bits
___
	if (@_) {
		&SVE_LSL($bits,$next,@_);
	}
}

sub SVE_LSR() {
	my $bits = shift;
	my $x = shift;

$code.=<<___;
	lsr	@mx[$x].s,@mx[$x].s,$bits
___
	if (@_) {
		&SVE_LSR($bits,@_);
	}
}

sub SVE_ORR() {
	my $x = shift;
	my $y = shift;
	my $next = $x + 1;

$code.=<<___;
	orr	@mx[$y].d,@mx[$y].d,@xt[$x].d
___
	if (@_) {
		&SVE_ORR($next,@_);
	}
}

sub SVE_REV16() {
	my $x = shift;

$code.=<<___;
	revh	@mx[$x].s,p0/m,@mx[$x].s
___
	if (@_) {
		&SVE_REV16(@_);
	}
}

sub SVE_ROT8() {
	my $x = shift;

$code.=<<___;
	tbl	@mx[$x].b,{@mx[$x].b},$rot8.b
___
	if (@_) {
		&SVE_ROT8(@_);
	}
}

sub SVE2_XAR() {
	my $bits = shift;
	my $x = shift;
	my $y = shift;
	my $rbits = 32-$bits;

$code.=<<___;
	xar	@mx[$x].s,@mx[$x].s,@mx[$y].s,$rbits
___
	if (@_) {
		&SVE2_XAR($bits,@_);
	}
}

sub SVE_QR_GROUP() {
	my $have_sve2 = shift;
	my ($a0,$b0,$c0,$d0,$a1,$b1,$c1,$d1,$a2,$b2,$c2,$d2,$a3,$b3,$c3,$d3) = @_;

	&SVE_ADD($a0,$b0,$a1,$b1,$a2,$b2,$a3,$b3);
	if ($have_sve2 == 0) {
		&SVE_EOR($d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
		&SVE_REV16($d0,$d1,$d2,$d3);
	} else {
		&SVE2_XAR(16,$d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
	}

	&SVE_ADD($c0,$d0,$c1,$d1,$c2,$d2,$c3,$d3);
	if ($have_sve2 == 0) {
		&SVE_EOR($b0,$c0,$b1,$c1,$b2,$c2,$b3,$c3);
		&SVE_LSL(12,0,$b0,$b1,$b2,$b3);
		&SVE_LSR(20,$b0,$b1,$b2,$b3);
		&SVE_ORR(0,$b0,$b1,$b2,$b3,);
	} else {
		&SVE2_XAR(12,$b0,$c0,$b1,$c1,$b2,$c2,$b3,$c3);
	}

	&SVE_ADD($a0,$b0,$a1,$b1,$a2,$b2,$a3,$b3);
	if ($have_sve2 == 0) {
		&SVE_EOR($d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
		&SVE_ROT8($d0,$d1,$d2,$d3);
	} else {
		&SVE2_XAR(8,$d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
	}

	&SVE_ADD($c0,$d0,$c1,$d1,$c2,$d2,$c3,$d3);
	if ($have_sve2 == 0) {
		&SVE_EOR($b0,$c0,$b1,$c1,$b2,$c2,$b3,$c3);
		&SVE_LSL(7,0,$b0,$b1,$b2,$b3);
		&SVE_LSR(25,$b0,$b1,$b2,$b3);
		&SVE_ORR(0,$b0,$b1,$b2,$b3);
	} else {
		&SVE2_XAR(7,$b0,$c0,$b1,$c1,$b2,$c2,$b3,$c3);
	}
}

sub SVE_INNER_BLOCK() {
$code.=<<___;
	mov	$counter,#10
1:
.align	5
___
	&SVE_QR_GROUP(0,0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15);
	&SVE_QR_GROUP(0,0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14);
$code.=<<___;
	subs	$counter,$counter,1
	b.ne	1b
___
}

sub SVE2_INNER_BLOCK() {
$code.=<<___;
	mov	$counter,#10
1:
.align	5
___
	&SVE_QR_GROUP(1,0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15);
	&SVE_QR_GROUP(1,0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14);
$code.=<<___;
	subs	$counter,$counter,1
	b.ne	1b
___
}

sub load() {
	my $x0 = shift;
	my $x1 = shift;
	my $x2 = shift;
	my $x3 = shift;
	my $x4 = shift;
	my $x5 = shift;
	my $x6 = shift;
	my $x7 = shift;

$code.=<<___;
	ld1w	{$x0.s},p0/z,[$inp]
	ld1w	{$x1.s},p0/z,[$inp, #1, MUL VL]
	ld1w	{$x2.s},p0/z,[$inp, #2, MUL VL]
	ld1w	{$x3.s},p0/z,[$inp, #3, MUL VL]
	ld1w	{$x4.s},p0/z,[$inp, #4, MUL VL]
	ld1w	{$x5.s},p0/z,[$inp, #5, MUL VL]
	ld1w	{$x6.s},p0/z,[$inp, #6, MUL VL]
	ld1w	{$x7.s},p0/z,[$inp, #7, MUL VL]
	addvl	$inp,$inp,#8
___
}

sub store() {
	my $x0 = shift;
	my $x1 = shift;
	my $x2 = shift;
	my $x3 = shift;
	my $x4 = shift;
	my $x5 = shift;
	my $x6 = shift;
	my $x7 = shift;

$code.=<<___;
	st1w	{$x0.s},p0,[$outp]
	st1w	{$x1.s},p0,[$outp, #1, MUL VL]
	st1w	{$x2.s},p0,[$outp, #2, MUL VL]
	st1w	{$x3.s},p0,[$outp, #3, MUL VL]
	st1w	{$x4.s},p0,[$outp, #4, MUL VL]
	st1w	{$x5.s},p0,[$outp, #5, MUL VL]
	st1w	{$x6.s},p0,[$outp, #6, MUL VL]
	st1w	{$x7.s},p0,[$outp, #7, MUL VL]
	addvl	$outp,$outp,#8
___
}

sub transpose() {
	my $xa = shift;
	my $xb = shift;
	my $xc = shift;
	my $xd = shift;

$code.=<<___;
	zip1	$xt0.s,$xa.s,$xb.s
	zip2	$xt1.s,$xa.s,$xb.s
	zip1	$xt2.s,$xc.s,$xd.s
	zip2	$xt3.s,$xc.s,$xd.s
	zip1	$xa.d,$xt0.d,$xt2.d
	zip2	$xb.d,$xt0.d,$xt2.d
	zip1	$xc.d,$xt1.d,$xt3.d
	zip2	$xd.d,$xt1.d,$xt3.d
___
}

sub SVE_ADD_STATES() {
$code.=<<___;
	lsr	$tmp1,@K[5],#32
	dup	$xt0.s,@KL[5]
	dup	$xt1.s,$tmpw1
	add	@mx[0].s,@mx[0].s,$bak0.s
	add	@mx[1].s,@mx[1].s,$bak1.s
	add	@mx[2].s,@mx[2].s,$bak2.s
	add	@mx[3].s,@mx[3].s,$bak3.s
	add	@mx[4].s,@mx[4].s,$bak4.s
	add	@mx[5].s,@mx[5].s,$bak5.s
	add	@mx[6].s,@mx[6].s,$bak6.s
	add	@mx[7].s,@mx[7].s,$bak7.s
	add	@mx[8].s,@mx[8].s,$bak8.s
	add	@mx[9].s,@mx[9].s,$bak9.s
	lsr	$tmp0,@K[6],#32
	dup	$xt4.s,$tmpw0
	lsr	$tmp1,@K[7],#32
	dup	$xt5.s,@KL[7]
	dup	$xt6.s,$tmpw1
	add	@mx[10].s,@mx[10].s,$xt0.s
	add	@mx[11].s,@mx[11].s,$xt1.s
	add	@mx[12].s,@mx[12].s,$zctr.s
	add	@mx[13].s,@mx[13].s,$xt4.s
	add	@mx[14].s,@mx[14].s,$xt5.s
	add	@mx[15].s,@mx[15].s,$xt6.s
___
}

sub SVE2_ADD_STATES() {
$code.=<<___;
	add	@mx[0].s,@mx[0].s,$bak0.s
	add	@mx[1].s,@mx[1].s,$bak1.s
	add	@mx[2].s,@mx[2].s,$bak2.s
	add	@mx[3].s,@mx[3].s,$bak3.s
	add	@mx[4].s,@mx[4].s,$bak4.s
	add	@mx[5].s,@mx[5].s,$bak5.s
	add	@mx[6].s,@mx[6].s,$bak6.s
	add	@mx[7].s,@mx[7].s,$bak7.s
	add	@mx[8].s,@mx[8].s,$bak8.s
	add	@mx[9].s,@mx[9].s,$bak9.s
	add	@mx[10].s,@mx[10].s,$bak10.s
	add	@mx[11].s,@mx[11].s,$bak11.s
	add	@mx[12].s,@mx[12].s,$zctr.s
	add	@mx[13].s,@mx[13].s,$bak13.s
	add	@mx[14].s,@mx[14].s,$bak14.s
	add	@mx[15].s,@mx[15].s,$bak15.s
___
}

sub SVE_TRANSFORMS() {
	&transpose($xa0,$xb0,$xc0,$xd0);
	&transpose($xa1,$xb1,$xc1,$xd1);
	&transpose($xa2,$xb2,$xc2,$xd2);
	&transpose($xa3,$xb3,$xc3,$xd3);
	&transpose($xa0,$xa1,$xa2,$xa3);
	&transpose($xb0,$xb1,$xb2,$xb3);
	&load($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7);
$code.=<<___;
	eor	$xa0.d,$xa0.d,$xt0.d
	eor	$xa1.d,$xa1.d,$xt1.d
	eor	$xa2.d,$xa2.d,$xt2.d
	eor	$xa3.d,$xa3.d,$xt3.d
	eor	$xb0.d,$xb0.d,$xt4.d
	eor	$xb1.d,$xb1.d,$xt5.d
	eor	$xb2.d,$xb2.d,$xt6.d
	eor	$xb3.d,$xb3.d,$xt7.d
___
	&transpose($xc0,$xc1,$xc2,$xc3);
	&store($xa0,$xa1,$xa2,$xa3,$xb0,$xb1,$xb2,$xb3);
	&transpose($xd0,$xd1,$xd2,$xd3);
	&load($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7);
$code.=<<___;
	eor	$xc0.d,$xc0.d,$xt0.d
	eor	$xc1.d,$xc1.d,$xt1.d
	eor	$xc2.d,$xc2.d,$xt2.d
	eor	$xc3.d,$xc3.d,$xt3.d
	eor	$xd0.d,$xd0.d,$xt4.d
	eor	$xd1.d,$xd1.d,$xt5.d
	eor	$xd2.d,$xd2.d,$xt6.d
	eor	$xd3.d,$xd3.d,$xt7.d
___
	&store($xc0,$xc1,$xc2,$xc3,$xd0,$xd1,$xd2,$xd3);
$code.=<<___;
	incw	$xctr, ALL, MUL #1
	incw	$zctr.s, ALL, MUL #1
___
}

sub SVE_LOAD_STATES() {
$code.=<<___;
	lsr	$tmp0,@K[0],#32
	dup	@mx[0].s,@KL[0]
	dup	$bak0.s,@KL[0]
	dup	@mx[1].s,$tmpw0
	dup	$bak1.s,$tmpw0
	lsr	$tmp1,@K[1],#32
	dup	@mx[2].s,@KL[1]
	dup	$bak2.s,@KL[1]
	dup	@mx[3].s,$tmpw1
	dup	$bak3.s,$tmpw1
	lsr	$tmp0,@K[2],#32
	dup	@mx[4].s,@KL[2]
	dup	$bak4.s,@KL[2]
	dup	@mx[5].s,$tmpw0
	dup	$bak5.s,$tmpw0
	lsr	$tmp1,@K[3],#32
	dup	@mx[6].s,@KL[3]
	dup	$bak6.s,@KL[3]
	dup	@mx[7].s,$tmpw1
	dup	$bak7.s,$tmpw1
	lsr	$tmp0,@K[4],#32
	dup	@mx[8].s,@KL[4]
	dup	$bak8.s,@KL[4]
	dup	@mx[9].s,$tmpw0
	dup	$bak9.s,$tmpw0
	lsr	$tmp1,@K[5],#32
	dup	@mx[10].s,@KL[5]
	dup	@mx[11].s,$tmpw1
	orr	@mx[12].d,$zctr.d,$zctr.d
	lsr	$tmp0,@K[6],#32
	dup	@mx[13].s,$tmpw0
	lsr	$tmp1,@K[7],#32
	dup	@mx[14].s,@KL[7]
	dup	@mx[15].s,$tmpw1
___
}

sub SVE2_LOAD_STATES() {
$code.=<<___;
	lsr	$tmp0,@K[0],#32
	dup	@mx[0].s,@KL[0]
	dup	$bak0.s,@KL[0]
	dup	@mx[1].s,$tmpw0
	dup	$bak1.s,$tmpw0
	lsr	$tmp1,@K[1],#32
	dup	@mx[2].s,@KL[1]
	dup	$bak2.s,@KL[1]
	dup	@mx[3].s,$tmpw1
	dup	$bak3.s,$tmpw1
	lsr	$tmp0,@K[2],#32
	dup	@mx[4].s,@KL[2]
	dup	$bak4.s,@KL[2]
	dup	@mx[5].s,$tmpw0
	dup	$bak5.s,$tmpw0
	lsr	$tmp1,@K[3],#32
	dup	@mx[6].s,@KL[3]
	dup	$bak6.s,@KL[3]
	dup	@mx[7].s,$tmpw1
	dup	$bak7.s,$tmpw1
	lsr	$tmp0,@K[4],#32
	dup	@mx[8].s,@KL[4]
	dup	$bak8.s,@KL[4]
	dup	@mx[9].s,$tmpw0
	dup	$bak9.s,$tmpw0
	lsr	$tmp1,@K[5],#32
	dup	@mx[10].s,@KL[5]
	dup	$bak10.s,@KL[5]
	dup	@mx[11].s,$tmpw1
	dup	$bak11.s,$tmpw1
	orr	@mx[12].d,$zctr.d,$zctr.d
	lsr	$tmp0,@K[6],#32
	dup	@mx[13].s,$tmpw0
	dup	$bak13.s,$tmpw0
	lsr	$tmp1,@K[7],#32
	dup	@mx[14].s,@KL[7]
	dup	$bak14.s,@KL[7]
	dup	@mx[15].s,$tmpw1
	dup	$bak15.s,$tmpw1
___
}

sub sve_handle_blocks() {
$code.=<<___;
	cbz	$sve2flag,.sve_inner
___
	&SVE2_LOAD_STATES();
	&SVE2_INNER_BLOCK();
	&SVE2_ADD_STATES();
$code.=<<___;
	b	.fini_inner
.sve_inner:
___
	&SVE_LOAD_STATES();
	&SVE_INNER_BLOCK();
	&SVE_ADD_STATES();
$code.=<<___;
.fini_inner:
___
	&SVE_TRANSFORMS();
}

sub chacha20_process() {
$code.=<<___;
.align	5
.Loop:
	cmp	$blocks,$veclen
	b.lt	.Lexit
___
	&sve_handle_blocks();
$code.=<<___;
	subs	$blocks,$blocks,$veclen
	b.gt	.Loop
.Lexit:
___
}

{{{
$code.=<<___;
#include "arm_arch.h"

.arch   armv8-a

.extern	OPENSSL_armcap_P
.hidden	OPENSSL_armcap_P

.text
.align	5
.Lchacha20_consts:
.quad	0x3320646e61707865,0x6b20657479622d32		// endian-neutral
.Lrot8:
	.word 0x02010003,0x04040404,0x02010003,0x04040404
.globl	ChaCha20_ctr32_sve
.type	ChaCha20_ctr32_sve,%function
.align	5
ChaCha20_ctr32_sve:
	AARCH64_VALID_CALL_TARGET
	cntw	$veclen, ALL, MUL #1
	lsr	$blocks,$len,#6
	cmp	$blocks,$veclen
	b.lt	.Lreturn
	mov	$sve2flag,0
	adrp	$tmp,OPENSSL_armcap_P
	ldr	$tmpw,[$tmp,#:lo12:OPENSSL_armcap_P]
	tst	$tmpw,#ARMV8_SVE2
	b.eq	1f
	mov	$sve2flag,1
	b	2f
1:
	cmp	$veclen,4
	b.le	.Lreturn
	adr	$tmp,.Lrot8
	ldp	$tmpw0,$tmpw1,[$tmp]
	index	$rot8.s,$tmpw0,$tmpw1
2:
	stp	d8,d9,[sp,-96]!
	stp	d10,d11,[sp,16]
	stp	d12,d13,[sp,32]
	stp	d14,d15,[sp,48]
	stp	x19,x20,[sp,64]
	stp	x21,x22,[sp,80]
	adr	$tmp,.Lchacha20_consts
	ldp	@K[0],@K[1],[$tmp]
	ldp	@K[2],@K[3],[$key]
	ldp	@K[4],@K[5],[$key, 16]
	ldp	@K[6],@K[7],[$ctr]
	ldr	$wctr,[$ctr]
	index	$zctr.s,$wctr,1
	ptrues	p0.s,ALL
#ifdef	__AARCH64EB__
	ror	@K[2],@K[2],#32
	ror	@K[3],@K[3],#32
	ror	@K[4],@K[4],#32
	ror	@K[5],@K[5],#32
	ror	@K[6],@K[6],#32
	ror	@K[7],@K[7],#32
#endif
___
	&chacha20_process();
$code.=<<___;
	ldp	d10,d11,[sp,16]
	ldp	d12,d13,[sp,32]
	ldp	d14,d15,[sp,48]
	ldp	x19,x20,[sp,64]
	ldp	x21,x22,[sp,80]
	ldp	d8,d9,[sp],96
	str	$wctr,[$ctr]
	and	$len,$len,#63
	add	$len,$len,$blocks,lsl #6
.Lreturn:
	ret
.size	ChaCha20_ctr32_sve,.-ChaCha20_ctr32_sve
___

}}}

########################################
{
my  %opcode_unpred = (
	"movprfx"      => 0x0420BC00,
	"eor"          => 0x04a03000,
	"add"          => 0x04200000,
	"orr"          => 0x04603000,
	"lsl"          => 0x04209C00,
	"lsr"          => 0x04209400,
	"incw"         => 0x04B0C000,
	"xar"          => 0x04203400,
	"zip1"         => 0x05206000,
	"zip2"         => 0x05206400,
	"uzp1"         => 0x05206800,
	"uzp2"         => 0x05206C00,
	"index"        => 0x04204C00,
	"mov"          => 0x05203800,
	"dup"          => 0x05203800,
	"cntw"         => 0x04A0E000,
	"tbl"          => 0x05203000);

my  %opcode_imm_unpred = (
	"dup"          => 0x2538C000,
	"index"        => 0x04204400);

my %opcode_scalar_pred = (
	"mov"          => 0x0528A000,
	"cpy"          => 0x0528A000,
	"st4w"         => 0xE5606000,
	"st1w"         => 0xE5004000,
	"ld1w"         => 0xA5404000);

my %opcode_gather_pred = (
	"ld1w"         => 0x85204000);

my  %opcode_pred = (
	"eor"          => 0x04190000,
	"add"          => 0x04000000,
	"orr"          => 0x04180000,
	"whilelo"      => 0x25200C00,
	"whilelt"      => 0x25200400,
	"cntp"         => 0x25208000,
	"addvl"        => 0x04205000,
	"lsl"          => 0x04038000,
	"lsr"          => 0x04018000,
	"sel"          => 0x0520C000,
	"mov"          => 0x0520C000,
	"ptrue"        => 0x2518E000,
	"pfalse"       => 0x2518E400,
	"ptrues"       => 0x2519E000,
	"pnext"        => 0x2519C400,
	"ld4w"         => 0xA560E000,
	"st4w"         => 0xE570E000,
	"st1w"         => 0xE500E000,
	"ld1w"         => 0xA540A000,
	"ld1rw"        => 0x8540C000,
	"revh"         => 0x05258000);

my  %tsize = (
	'b'          => 0,
	'h'          => 1,
	's'          => 2,
	'd'          => 3);

my %sf = (
	"w"          => 0,
	"x"          => 1);

my %pattern = (
	"POW2"       => 0,
	"VL1"        => 1,
	"VL2"        => 2,
	"VL3"        => 3,
	"VL4"        => 4,
	"VL5"        => 5,
	"VL6"        => 6,
	"VL7"        => 7,
	"VL8"        => 8,
	"VL16"       => 9,
	"VL32"       => 10,
	"VL64"       => 11,
	"VL128"      => 12,
	"VL256"      => 13,
	"MUL4"       => 29,
	"MUL3"       => 30,
	"ALL"        => 31);

sub create_verifier {
	my $filename="./compile_sve.sh";

$scripts = <<___;
#! /bin/bash
set -e
CROSS_COMPILE=\${CROSS_COMPILE:-'aarch64-none-linux-gnu-'}

[ -z "\$1" ] && exit 1
ARCH=`uname -p | xargs echo -n`

# need gcc-10 and above to compile SVE code
# change this according to your system during debugging
if [ \$ARCH == 'aarch64' ]; then
	CC=gcc-11
	OBJDUMP=objdump
else
	CC=\${CROSS_COMPILE}gcc
	OBJDUMP=\${CROSS_COMPILE}objdump
fi
TMPFILE=/tmp/\$\$
cat > \$TMPFILE.c << EOF
extern __attribute__((noinline, section("disasm_output"))) void dummy_func()
{
	asm("\$@\\t\\n");
}
int main(int argc, char *argv[])
{
}
EOF
\$CC -march=armv8.2-a+sve+sve2 -o \$TMPFILE.out \$TMPFILE.c
\$OBJDUMP -d \$TMPFILE.out | awk -F"\\n" -v RS="\\n\\n" '\$1 ~ /dummy_func/' | awk 'FNR == 2 {printf "%s",\$2}'
rm \$TMPFILE.c \$TMPFILE.out
___
	open(FH, '>', $filename) or die $!;
	print FH $scripts;
	close(FH);
	system("chmod a+x ./compile_sve.sh");
}

sub compile_sve {
	return `./compile_sve.sh '@_'`
}

sub verify_inst {
	my ($code,$inst)=@_;
	my $hexcode = (sprintf "%08x", $code);

	if ($debug_encoder == 1) {
		my $expect=&compile_sve($inst);
		if ($expect ne $hexcode) {
			return (sprintf "%s // Encode Error! expect [%s] actual [%s]", $inst, $expect, $hexcode);
		}
	}
	return (sprintf ".inst\t0x%s\t//%s", $hexcode, $inst);
}

sub reg_code {
	my $code = shift;

	if ($code == "zr") {
		return "31";
	}
	return $code;
}

sub encode_size_imm() {
	my ($mnemonic, $isize, $const)=@_;
	my $esize = (8<<$tsize{$isize});
	my $tsize_imm = $esize + $const;

	if ($mnemonic eq "lsr" || $mnemonic eq "xar") {
		$tsize_imm = 2*$esize - $const;
	}
	return (($tsize_imm>>5)<<22)|(($tsize_imm&0x1f)<<16);
}

sub encode_shift_pred() {
	my ($mnemonic, $isize, $const)=@_;
	my $esize = (8<<$tsize{$isize});
	my $tsize_imm = $esize + $const;

	if ($mnemonic eq "lsr") {
		$tsize_imm = 2*$esize - $const;
	}
	return (($tsize_imm>>5)<<22)|(($tsize_imm&0x1f)<<5);
}

sub sve_unpred {
	my ($mnemonic,$arg)=@_;
	my $inst = (sprintf "%s %s", $mnemonic,$arg);

	if ($arg =~ m/z([0-9]+)\.([bhsd]),\s*\{\s*z([0-9]+)\.[bhsd].*\},\s*z([0-9]+)\.[bhsd].*/o) {
		return &verify_inst($opcode_unpred{$mnemonic}|$1|($3<<5)|($tsize{$2}<<22)|($4<<16),
					$inst)
	} elsif ($arg =~ m/z([0-9]+)\.([bhsd]),\s*([zwx][0-9]+.*)/o) {
       		my $regd = $1;
		my $isize = $2;
		my $regs=$3;

		if (($mnemonic eq "lsl") || ($mnemonic eq "lsr")) {
			if ($regs =~ m/z([0-9]+)[^,]*(?:,\s*#?([0-9]+))?/o
				&& ((8<<$tsize{$isize}) > $2)) {
				return &verify_inst($opcode_unpred{$mnemonic}|$regd|($1<<5)|&encode_size_imm($mnemonic,$isize,$2),
					$inst);
			}
		} elsif($regs =~ m/[wx]([0-9]+),\s*[wx]([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$regd|($tsize{$isize}<<22)|($1<<5)|($2<<16), $inst);
		} elsif ($regs =~ m/[wx]([0-9]+),\s*#?([0-9]+)/o) {
			return &verify_inst($opcode_imm_unpred{$mnemonic}|$regd|($tsize{$isize}<<22)|($1<<5)|($2<<16), $inst);
		} elsif ($regs =~ m/[wx]([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$regd|($tsize{$isize}<<22)|($1<<5), $inst);
		} else {
			my $encoded_size = 0;
			if (($mnemonic eq "add") || ($mnemonic =~ /zip./) || ($mnemonic =~ /uzp./) ) {
				$encoded_size = ($tsize{$isize}<<22);
			}
			if ($regs =~ m/z([0-9]+)\.[bhsd],\s*z([0-9]+)\.[bhsd],\s*([0-9]+)/o &&
				$1 == $regd) {
				return &verify_inst($opcode_unpred{$mnemonic}|$regd|($2<<5)|&encode_size_imm($mnemonic,$isize,$3), $inst);
			} elsif ($regs =~ m/z([0-9]+)\.[bhsd],\s*z([0-9]+)\.[bhsd]/o) {
				return &verify_inst($opcode_unpred{$mnemonic}|$regd|$encoded_size|($1<<5)|($2<<16), $inst);
			}
		}
	} elsif ($arg =~ m/z([0-9]+)\.([bhsd]),\s*#?([0-9]+)/o) {
		return &verify_inst($opcode_imm_unpred{$mnemonic}|$1|($3<<5)|($tsize{$2}<<22),
					$inst)
	}
	sprintf "%s // fail to parse", $inst;
}

sub sve_pred {
	my ($mnemonic,,$arg)=@_;
	my $inst = (sprintf "%s %s", $mnemonic,$arg);

	if ($arg =~ m/\{\s*z([0-9]+)\.([bhsd]).*\},\s*p([0-9])+(\/z)?,\s*\[(\s*[xs].*)\]/o) {
		my $zt = $1;
		my $size = $tsize{$2};
		my $pg = $3;
		my $addr = $5;
		my $xn = 31;

		if ($addr =~ m/x([0-9]+)\s*/o) {
			$xn = $1;
		}

		if ($mnemonic =~m/ld1r[bhwd]/o) {
			$size = 0;
		}
		if ($addr =~ m/\w+\s*,\s*x([0-9]+),.*/o) {
			return &verify_inst($opcode_scalar_pred{$mnemonic}|($size<<21)|$zt|($pg<<10)|($1<<16)|($xn<<5),$inst);
		} elsif ($addr =~ m/\w+\s*,\s*z([0-9]+)\.s,\s*([US]\w+)/o) {
			my $xs = ($2 eq "SXTW") ? 1 : 0;
			return &verify_inst($opcode_gather_pred{$mnemonic}|($xs<<22)|$zt|($pg<<10)|($1<<16)|($xn<<5),$inst);
		} elsif($addr =~ m/\w+\s*,\s*#?([0-9]+)/o) {
			return &verify_inst($opcode_pred{$mnemonic}|($size<<21)|$zt|($pg<<10)|($1<<16)|($xn<<5),$inst);
		} else {
			return &verify_inst($opcode_pred{$mnemonic}|($size<<21)|$zt|($pg<<10)|($xn<<5),$inst);
		}
	} elsif ($arg =~ m/z([0-9]+)\.([bhsd]),\s*p([0-9]+)\/([mz]),\s*([zwx][0-9]+.*)/o) {
		my $regd = $1;
		my $isize = $2;
		my $pg = $3;
		my $mod = $4;
		my $regs = $5;

		if (($mnemonic eq "lsl") || ($mnemonic eq "lsr")) {
			if ($regs =~ m/z([0-9]+)[^,]*(?:,\s*#?([0-9]+))?/o
				&& $regd == $1
				&& $mode == 'm'
				&& ((8<<$tsize{$isize}) > $2)) {
				return &verify_inst($opcode_pred{$mnemonic}|$regd|($pg<<10)|&encode_shift_pred($mnemonic,$isize,$2), $inst);
			}
		} elsif($regs =~ m/[wx]([0-9]+)/o) {
			return &verify_inst($opcode_scalar_pred{$mnemonic}|$regd|($tsize{$isize}<<22)|($pg<<10)|($1<<5), $inst);
		} elsif ($regs =~ m/z([0-9]+)[^,]*(?:,\s*z([0-9]+))?/o) {
			if ($mnemonic eq "sel") {
				return &verify_inst($opcode_pred{$mnemonic}|$regd|($tsize{$isize}<<22)|($pg<<10)|($1<<5)|($2<<16), $inst);
			} elsif ($mnemonic eq "mov") {
				return &verify_inst($opcode_pred{$mnemonic}|$regd|($tsize{$isize}<<22)|($pg<<10)|($1<<5)|($regd<<16), $inst);
			} elsif (length $2 > 0) {
				return &verify_inst($opcode_pred{$mnemonic}|$regd|($tsize{$isize}<<22)|($pg<<10)|($2<<5), $inst);
			} else {
				return &verify_inst($opcode_pred{$mnemonic}|$regd|($tsize{$isize}<<22)|($pg<<10)|($1<<5), $inst);
			}
		}
	} elsif ($arg =~ m/p([0-9]+)\.([bhsd]),\s*(\w+.*)/o) {
		my $pg = $1;
		my $isize = $2;
		my $regs = $3;

		if ($regs =~ m/([wx])(zr|[0-9]+),\s*[wx](zr|[0-9]+)/o) {
			return &verify_inst($opcode_pred{$mnemonic}|($tsize{$isize}<<22)|$pg|($sf{$1}<<12)|(&reg_code($2)<<5)|(&reg_code($3)<<16), $inst);
		} elsif ($regs =~ m/p([0-9]+),\s*p([0-9]+)\.[bhsd]/o) {
			return &verify_inst($opcode_pred{$mnemonic}|($tsize{$isize}<<22)|$pg|($1<<5), $inst);
		} else {
			return &verify_inst($opcode_pred{$mnemonic}|($tsize{$isize}<<22)|$pg|($pattern{$regs}<<5), $inst);
		}
	} elsif ($arg =~ m/p([0-9]+)\.([bhsd])/o) {
		return &verify_inst($opcode_pred{$mnemonic}|$1, $inst);
	}

	sprintf "%s // fail to parse", $inst;
}

sub sve_other {
	my ($mnemonic,$arg)=@_;
	my $inst = (sprintf "%s %s", $mnemonic,$arg);

	if ($arg =~ m/x([0-9]+)[^,]*,\s*p([0-9]+)[^,]*,\s*p([0-9]+)\.([bhsd])/o) {
		return &verify_inst($opcode_pred{$mnemonic}|($tsize{$4}<<22)|$1|($2<<10)|($3<<5), $inst);
	} elsif ($mnemonic =~ /inc[bhdw]/) {
		if ($arg =~ m/x([0-9]+)[^,]*,\s*(\w+)[^,]*,\s*MUL\s*#?([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$1|($pattern{$2}<<5)|(2<<12)|(($3 - 1)<<16), $inst);
		} elsif ($arg =~ m/z([0-9]+)[^,]*,\s*(\w+)[^,]*,\s*MUL\s*#?([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$1|($pattern{$2}<<5)|(($3 - 1)<<16), $inst);
		} elsif ($arg =~ m/x([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$1|(31<<5)|(0<<16), $inst);
		}
	} elsif ($mnemonic =~ /cnt[bhdw]/) {
		if ($arg =~ m/x([0-9]+)[^,]*,\s*(\w+)[^,]*,\s*MUL\s*#?([0-9]+)/o) {
			return &verify_inst($opcode_unpred{$mnemonic}|$1|($pattern{$2}<<5)|(($3 - 1)<<16), $inst);
		}
	} elsif ($arg =~ m/x([0-9]+)[^,]*,\s*x([0-9]+)[^,]*,\s*#?([0-9]+)/o) {
		return &verify_inst($opcode_pred{$mnemonic}|$1|($2<<16)|($3<<5), $inst);
	} elsif ($arg =~ m/z([0-9]+)[^,]*,\s*z([0-9]+)/o) {
		return &verify_inst($opcode_unpred{$mnemonic}|$1|($2<<5), $inst);
	}
	sprintf "%s // fail to parse", $inst;
}
}

open SELF,$0;
while(<SELF>) {
	next if (/^#!/);
	last if (!s/^#/\/\// and !/^$/);
	print;
}
close SELF;

if ($debug_encoder == 1) {
	&create_verifier();
}

foreach(split("\n",$code)) {
	s/\`([^\`]*)\`/eval($1)/ge;
	s/\b(\w+)\s+(z[0-9]+\.[bhsd],\s*[#zwx]?[0-9]+.*)/sve_unpred($1,$2)/ge;
	s/\b(\w+)\s+(z[0-9]+\.[bhsd],\s*\{.*\},\s*z[0-9]+.*)/sve_unpred($1,$2)/ge;
	s/\b(\w+)\s+(z[0-9]+\.[bhsd],\s*p[0-9].*)/sve_pred($1,$2)/ge;
	s/\b(\w+[1-4]r[bhwd])\s+(\{\s*z[0-9]+.*\},\s*p[0-9]+.*)/sve_pred($1,$2)/ge;
	s/\b(\w+[1-4][bhwd])\s+(\{\s*z[0-9]+.*\},\s*p[0-9]+.*)/sve_pred($1,$2)/ge;
	s/\b(\w+)\s+(p[0-9]+\.[bhsd].*)/sve_pred($1,$2)/ge;
	s/\b(movprfx|cntp|cnt[bhdw]|addvl|inc[bhdw])\s+((x|z).*)/sve_other($1,$2)/ge;
	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
