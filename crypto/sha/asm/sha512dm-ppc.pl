#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# SHA256/512 for PowerISA 3.2 using the dmsha2hash instruction.

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

if ($flavour =~ /64/) {
	$CMPLI="cmpldi";
} elsif ($flavour =~ /32/) {
	$CMPLI="cmplwi";
} else { die "nonsense $flavour"; }

$LENDIAN=($flavour=~/le/);

# Inputs are loaded as big-endian. Loading with lxvb16x does the swap for us
#  on LE, but the regular word/doubleword loads are fine on BE
$load_be_w4 = $LENDIAN ? "lxvb16x" : "lxvw4x";
$load_be_d2 = $LENDIAN ? "lxvb16x" : "lxvd2x";

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";

if ($output =~ /512/) {
	$bits=512;
	$sha2mode=1;
} else {
	$bits=256;
	$sha2mode=0;
}

$func="sha${bits}_block_dm";

$ctx="r3";
$inp="r4";
$num="r5";
$tc0="r6";
$tc16="r7";
$tc32="r8";
$tc48="r9";
$vzero="v19";

$at="dm0";
$ab="dm1";

$code=<<___;
.machine	"any"
.text

.globl	$func
.align	6
$func:
	$CMPLI	0, $num, 0
	beq		Ldone
	mtctr	$num

	dmsetdmrz	$at
	dmsetdmrz	$ab

	li	$tc0, 0
	li	$tc16, 16
	li	$tc32, 32
	li	$tc48, 48

___
$code.=<<___ if ($bits==256);
	lxvw4x	vs36, $ctx, $tc0
	lxvw4x	vs38, $ctx, $tc16
	vxor	$vzero, $vzero, $vzero

	vmrghw	v0, v4, $vzero
	vmrglw	v1, v4, $vzero
	vmrghw	v2, v6, $vzero
	vmrglw	v3, v6, $vzero
___
$code.=<<___ if ($bits==512);
	lxvd2x	vs32, $ctx, $tc0
	lxvd2x	vs33, $ctx, $tc16
	lxvd2x	vs34, $ctx, $tc32
	lxvd2x	vs35, $ctx, $tc48
___
$code.=<<___;
	dmxxinstdmr512	$at, vs32, vs34, 0

Lloop:
___
$code.=<<___ if ($bits==256);
	$load_be_w4	vs40, $inp, $tc0
	$load_be_w4	vs41, $inp, $tc16
	$load_be_w4	vs42, $inp, $tc32
	$load_be_w4	vs43, $inp, $tc48
	addi	$inp, $inp, 64
	vmrghw	v0, v8, $vzero
	vmrglw	v1, v8, $vzero
	vmrghw	v2, v9, $vzero
	vmrglw	v3, v9, $vzero
	vmrghw	v4, v10, $vzero
	vmrglw	v5, v10, $vzero
	vmrghw	v6, v11, $vzero
	vmrglw	v7, v11, $vzero
___
$code.=<<___ if ($bits==512);
	$load_be_d2	vs32, $inp, $tc0
	$load_be_d2	vs33, $inp, $tc16
	$load_be_d2	vs34, $inp, $tc32
	$load_be_d2	vs35, $inp, $tc48
	addi	$inp, $inp, 64
	$load_be_d2	vs36, $inp, $tc0
	$load_be_d2	vs37, $inp, $tc16
	$load_be_d2	vs38, $inp, $tc32
	$load_be_d2	vs39, $inp, $tc48
	addi	$inp, $inp, 64
___
$code.=<<___;
	dmxxinstdmr512	$ab, vs32, vs34, 0
	dmxxinstdmr512	$ab, vs36, vs38, 1

	dmsha2hash	$at, $ab, $sha2mode

	bdnz	Lloop

	dmxxextfdmr512	vs32, vs34, $at, 0
___
$code.=<<___ if ($bits==256);
	xxpermdi	vs36, vs32, vs33, 0
	xxpermdi	vs37, vs32, vs33, 3
	vmrgew		v4, v4, v5

	xxpermdi	vs38, vs34, vs35, 0
	xxpermdi	vs39, vs34, vs35, 3
	vmrgew		v5, v6, v7

	stxvw4x	vs36, $ctx, $tc0
	stxvw4x	vs37, $ctx, $tc16
___
$code.=<<___ if ($bits==512);
	stxvd2x	vs32, $ctx, $tc0
	stxvd2x	vs33, $ctx, $tc16
	stxvd2x	vs34, $ctx, $tc32
	stxvd2x	vs35, $ctx, $tc48
___
$code.=<<___;
Ldone:
	blr
	.long		0
	.byte		0,12,0x14,0,0,0,3,0
	.long		0
.size	$func,.-$func
___
$code.=<<___;
.asciz	"SHA${bits} for PowerISA 3.2"
.align	2
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
