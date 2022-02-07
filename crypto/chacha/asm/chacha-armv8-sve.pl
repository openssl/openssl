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
my ($state) = ("x5");
my ($veclen_w,$veclen,$blocks) = ("w6","x6","x7");
my ($saved_outp) = ("x8");
my ($wctr, $xctr) = ("w9", "x9");
my @mx=map("z$_",(0..7,16..23));
my ($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
    $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3) = @mx;
my @xt=map("z$_",(24..31,8..11));
my ($rot8) = ("z12");
my ($zctr) = ("z13");
my ($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7,$xt8,$xt9,$xt10,$xt11)=@xt;
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
	&SVE_EOR($d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
	&SVE_REV16($d0,$d1,$d2,$d3);

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
	&SVE_EOR($d0,$a0,$d1,$a1,$d2,$a2,$d3,$a3);
	&SVE_ROT8($d0,$d1,$d2,$d3);

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
	//cbnz $sve2flag, 10f
___
	&SVE_QR_GROUP(0,0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15);
	&SVE_QR_GROUP(0,0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14);
$code.=<<___;
	// SVE 2 not enabled until hardware available
#if 0
	b 11f
10:
___
#	&SVE_QR_GROUP(1,0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15);
#	&SVE_QR_GROUP(1,0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14);
$code.=<<___;
11:
#endif
___
}

{{{
my ($dlen,$rsize,$tmp) = ("x10","x11","x12");

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
	zip1	$xt8.s,$xa.s,$xb.s
	zip2	$xt9.s,$xa.s,$xb.s
	zip1	$xt10.s,$xc.s,$xd.s
	zip2	$xt11.s,$xc.s,$xd.s
	zip1	$xa.d,$xt8.d,$xt10.d
	zip2	$xb.d,$xt8.d,$xt10.d
	zip1	$xc.d,$xt9.d,$xt11.d
	zip2	$xd.d,$xt9.d,$xt11.d
___
}

sub add_states() {
	my ($tmpw0,$tmpw1,$tmpw2,$tmpw3) = ("w10","w11","w12","w13");

$code.=<<___;
	ldp	$tmpw0,$tmpw1,[$state]
	ldp	$tmpw2,$tmpw3,[$state,#8]
	dup	$xt0.s,$tmpw0
	dup	$xt1.s,$tmpw1
	dup	$xt2.s,$tmpw2
	dup	$xt3.s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state,#16]
	ldp	$tmpw2,$tmpw3,[$state,#24]
	add	@mx[0].s,@mx[0].s,$xt0.s
	add	@mx[1].s,@mx[1].s,$xt1.s
	add	@mx[2].s,@mx[2].s,$xt2.s
	add	@mx[3].s,@mx[3].s,$xt3.s
	dup	$xt4.s,$tmpw0
	dup	$xt5.s,$tmpw1
	dup	$xt6.s,$tmpw2
	dup	$xt7.s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state,#32]
	ldp	$tmpw2,$tmpw3,[$state,#40]
	add	@mx[4].s,@mx[4].s,$xt4.s
	add	@mx[5].s,@mx[5].s,$xt5.s
	add	@mx[6].s,@mx[6].s,$xt6.s
	add	@mx[7].s,@mx[7].s,$xt7.s
	dup	$xt0.s,$tmpw0
	dup	$xt1.s,$tmpw1
	dup	$xt2.s,$tmpw2
	dup	$xt3.s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state,#48]
	ldp	$tmpw2,$tmpw3,[$state,#56]
	add	@mx[8].s,@mx[8].s,$xt0.s
	add	@mx[9].s,@mx[9].s,$xt1.s
	add	@mx[10].s,@mx[10].s,$xt2.s
	add	@mx[11].s,@mx[11].s,$xt3.s
	dup	$xt5.s,$tmpw1
	dup	$xt6.s,$tmpw2
	dup	$xt7.s,$tmpw3
	add	@mx[12].s,@mx[12].s,$zctr.s
	add	@mx[13].s,@mx[13].s,$xt5.s
	add	@mx[14].s,@mx[14].s,$xt6.s
	add	@mx[15].s,@mx[15].s,$xt7.s
___
}

sub SVE_TRANSFORMS() {
	&add_states();
	&transpose($xa0,$xb0,$xc0,$xd0);
	&transpose($xa1,$xb1,$xc1,$xd1);
	&transpose($xa2,$xb2,$xc2,$xd2);
	&transpose($xa3,$xb3,$xc3,$xd3);
	&load($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7);
	&transpose($xa0,$xa1,$xa2,$xa3);
	&transpose($xb0,$xb1,$xb2,$xb3);
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
	&load($xt0,$xt1,$xt2,$xt3,$xt4,$xt5,$xt6,$xt7);
	&transpose($xd0,$xd1,$xd2,$xd3);
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
}}}

sub SVE_LOAD_STATES() {
	my ($tmpw0,$tmpw1,$tmpw2,$tmpw3) = ("w10","w11","w12","w13");

$code.=<<___;
	// FIXME following code are not functionally necessary
	// but appear to enhance performance
#if 1
	ptrues	p2.s,ALL
	ptrues	p2.s,ALL
	ptrues	p2.s,ALL
	ptrues	p2.s,ALL
	ptrues	p2.s,ALL
	ptrues	p2.s,ALL
#endif
___
$code.=<<___;
	ldp	$tmpw0,$tmpw1,[$state]
	ldp	$tmpw2,$tmpw3,[$state,#8]
	dup	@mx[0].s,$tmpw0
	dup	@mx[1].s,$tmpw1
	dup	@mx[2].s,$tmpw2
	dup	@mx[3].s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state,#16]
	ldp	$tmpw2,$tmpw3,[$state,#24]
	dup	@mx[4].s,$tmpw0
	dup	@mx[5].s,$tmpw1
	dup	@mx[6].s,$tmpw2
	dup	@mx[7].s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state,#32]
	ldp	$tmpw2,$tmpw3,[$state,#40]
	dup	@mx[8].s,$tmpw0
	dup	@mx[9].s,$tmpw1
	dup	@mx[10].s,$tmpw2
	dup	@mx[11].s,$tmpw3
	ldp	$tmpw0,$tmpw1,[$state, #48]
	ldp	$tmpw2,$tmpw3,[$state,#56]
	mov	@mx[12].s,p0/m,$zctr.s
	dup	@mx[13].s,$tmpw1
	dup	@mx[14].s,$tmpw2
	dup	@mx[15].s,$tmpw3
___
}

sub sve_handle_blocks() {
	my ($counter) = ("x10");

	&SVE_LOAD_STATES();
$code.=<<___;
	mov	$counter,#10
.align	5
1:
___

	&SVE_INNER_BLOCK();
$code.=<<___;
	subs	$counter,$counter,1
	b.ne	1b
___
	&SVE_TRANSFORMS();
}

sub chacha20_process() {
	my ($counter) = ("x10");
	my ($tmpw) = ("w11");

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
my ($tmp,$tmpw) = ("x10", "w10");
my ($tmpw0,$tmpw1) = ("w11", "w12");
my ($ptr) = ("x13");

$code.=<<___;
#include "arm_arch.h"

.arch   armv8-a

#if 0
.extern	OPENSSL_armcap_P
.hidden	OPENSSL_armcap_P
#endif

.text
.align	5
.Lchacha20_consts:
	.word 0x61707865
	.word 0x3320646e
	.word 0x79622d32
	.word 0x6b206574
.Lrot8:
	.word 0x02010003,0x04040404,0x02010003,0x04040404
.globl	ChaCha20_ctr32_sve
.type	ChaCha20_ctr32_sve,%function
.align	5
ChaCha20_ctr32_sve:
	AARCH64_VALID_CALL_TARGET
	mov	$tmp, #64
	whilelo	p0.s,xzr,$tmp
	cntp	$veclen,p0,p0.s
	// run Neon if we only have 128-bit SVE
	// in the future, we need to check SVE2
	cmp	$veclen,4
	b.le	.Lreturn
	lsr	$blocks,$len,#6
	cmp	$blocks,$veclen
	b.lt	.Lreturn
	stp	d8,d9,[sp,-48]!
	stp	d10,d11,[sp,16]
	stp	d12,d13,[sp,32]
	sub	sp,sp,#64
	adr	$tmp,.Lchacha20_consts
	ld1	{v0.4s},[$tmp]
	adr	$tmp,.Lrot8
	ldp	$tmpw0,$tmpw1,[$tmp]
	ld1	{v1.4s,v2.4s},[$key]
	ld1	{v3.4s},[$ctr]
	ldr	$wctr,[$ctr]
	index	$zctr.s,$wctr,1
	index	$rot8.s,$tmpw0,$tmpw1
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[sp]
	mov	$state,sp
#if 0
	// SVE2 code not enabled until we have hardware
	// for verification
	mov	$sve2flag,0
	adrp	$tmp,OPENSSL_armcap_P
	ldr	$tmpw,[$tmp,#:lo12:OPENSSL_armcap_P]
	tst	$tmpw,#ARMV8_SVE2
	b.eq	1f
	mov	$sve2flag,1
1:
#endif
___
	&chacha20_process();
$code.=<<___;
	add	sp,sp,#64
	ldp	d10,d11,[sp,16]
	ldp	d12,d13,[sp,32]
	ldp	d8,d9,[sp],48
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
	} elsif ($arg =~ m/x([0-9]+)[^,]*,\s*x([0-9]+)[^,]*,\s*#?([0-9]+)/o) {
		return &verify_inst($opcode_pred{$mnemonic}|$1|($2<<16)|($3<<5), $inst);
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
	s/\b(\w+[1-4][bhwd])\s+(\{\s*z[0-9]+.*\},\s*p[0-9]+.*)/sve_pred($1,$2)/ge;
	s/\b(\w+)\s+(p[0-9]+\.[bhsd].*)/sve_pred($1,$2)/ge;
	s/\b(cntp|addvl|inc[bhdw])\s+((x|z).*)/sve_other($1,$2)/ge;
	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
