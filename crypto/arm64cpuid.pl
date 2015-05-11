#!/usr/bin/env perl

$flavour = shift;
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$code.=<<___;
#include "arm_arch.h"

.text
.arch	armv8-a+crypto

.align	5
.globl	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	orr	v15.16b, v15.16b, v15.16b
	ret
.size	_armv7_neon_probe,.-_armv7_neon_probe

.globl	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
#ifdef	__APPLE__
	mrs	x0, CNTPCT_EL0
#else
	mrs	x0, CNTVCT_EL0
#endif
	ret
.size	_armv7_tick,.-_armv7_tick

.globl	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
	aese	v0.16b, v0.16b
	ret
.size	_armv8_aes_probe,.-_armv8_aes_probe

.globl	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
	sha1h	s0, s0
	ret
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.globl	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
	sha256su0	v0.4s, v0.4s
	ret
.size	_armv8_sha256_probe,.-_armv8_sha256_probe
.globl	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
	pmull	v0.1q, v0.1d, v0.1d
	ret
.size	_armv8_pmull_probe,.-_armv8_pmull_probe
___

print $code;
close STDOUT;
