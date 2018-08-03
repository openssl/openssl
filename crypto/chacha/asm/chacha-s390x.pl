#! /usr/bin/env perl
# Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# December 2015
#
# ChaCha20 for s390x.
#
# 3 times faster than compiler-generated code.

#
# August 2018
#
# Add vx code path.
#
# Copyright IBM Corp. 2018
# Author: Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use FindBin qw($Bin);
use lib "$Bin/../..";
use perlasm::s390x qw(:DEFAULT :VX AUTOLOAD LABEL INCLUDE);

my $flavour = shift;

my ($z,$SIZE_T);
if ($flavour =~ /3[12]/) {
	$z=0;	# S/390 ABI
	$SIZE_T=4;
} else {
	$z=1;	# zSeries ABI
	$SIZE_T=8;
}

my $output;
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}

my $sp="%r15";
my $stdframe=16*$SIZE_T+4*8;

my @x=map("%r$_",(0..7,"x","x","x","x",(10..13)));
my @t=map("%r$_",(8,9));
my @v=map("%v$_",(16..31));

sub ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_)=map("$_",@t);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# 'c' stores and loads in the middle, but none in the beginning
	# or end.

	alr	(@x[$a0],@x[$b0]);	# Q1
	 alr	(@x[$a1],@x[$b1]);	# Q2
	xr	(@x[$d0],@x[$a0]);
	 xr	(@x[$d1],@x[$a1]);
	rll	(@x[$d0],@x[$d0],16);
	 rll	(@x[$d1],@x[$d1],16);

	alr	($xc,@x[$d0]);
	 alr	($xc_,@x[$d1]);
	xr	(@x[$b0],$xc);
	 xr	(@x[$b1],$xc_);
	rll	(@x[$b0],@x[$b0],12);
	 rll	(@x[$b1],@x[$b1],12);

	alr	(@x[$a0],@x[$b0]);
	 alr	(@x[$a1],@x[$b1]);
	xr	(@x[$d0],@x[$a0]);
	 xr	(@x[$d1],@x[$a1]);
	rll	(@x[$d0],@x[$d0],8);
	 rll	(@x[$d1],@x[$d1],8);

	alr	($xc,@x[$d0]);
	 alr	($xc_,@x[$d1]);
	xr	(@x[$b0],$xc);
	 xr	(@x[$b1],$xc_);
	rll	(@x[$b0],@x[$b0],7);
	 rll	(@x[$b1],@x[$b1],7);

	stm	($xc,$xc_,"$stdframe+4*8+4*$c0($sp)");	# reload pair of 'c's
	lm	($xc,$xc_,"$stdframe+4*8+4*$c2($sp)");

	alr	(@x[$a2],@x[$b2]);	# Q3
	 alr	(@x[$a3],@x[$b3]);	# Q4
	xr	(@x[$d2],@x[$a2]);
	 xr	(@x[$d3],@x[$a3]);
	rll	(@x[$d2],@x[$d2],16);
	 rll	(@x[$d3],@x[$d3],16);

	alr	($xc,@x[$d2]);
	 alr	($xc_,@x[$d3]);
	xr	(@x[$b2],$xc);
	 xr	(@x[$b3],$xc_);
	rll	(@x[$b2],@x[$b2],12);
	 rll	(@x[$b3],@x[$b3],12);

	alr	(@x[$a2],@x[$b2]);
	 alr	(@x[$a3],@x[$b3]);
	xr	(@x[$d2],@x[$a2]);
	 xr	(@x[$d3],@x[$a3]);
	rll	(@x[$d2],@x[$d2],8);
	 rll	(@x[$d3],@x[$d3],8);

	alr	($xc,@x[$d2]);
	 alr	($xc_,@x[$d3]);
	xr	(@x[$b2],$xc);
	 xr	(@x[$b3],$xc_);
	rll	(@x[$b2],@x[$b2],7);
	 rll	(@x[$b3],@x[$b3],7);
}

sub VX_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));

	vaf	(@v[$a0],@v[$a0],@v[$b0]);
	vaf	(@v[$a1],@v[$a1],@v[$b1]);
	vaf	(@v[$a2],@v[$a2],@v[$b2]);
	vaf	(@v[$a3],@v[$a3],@v[$b3]);
	vx	(@v[$d0],@v[$d0],@v[$a0]);
	vx	(@v[$d1],@v[$d1],@v[$a1]);
	vx	(@v[$d2],@v[$d2],@v[$a2]);
	vx	(@v[$d3],@v[$d3],@v[$a3]);
	verllf	(@v[$d0],@v[$d0],16);
	verllf	(@v[$d1],@v[$d1],16);
	verllf	(@v[$d2],@v[$d2],16);
	verllf	(@v[$d3],@v[$d3],16);

	vaf	(@v[$c0],@v[$c0],@v[$d0]);
	vaf	(@v[$c1],@v[$c1],@v[$d1]);
	vaf	(@v[$c2],@v[$c2],@v[$d2]);
	vaf	(@v[$c3],@v[$c3],@v[$d3]);
	vx	(@v[$b0],@v[$b0],@v[$c0]);
	vx	(@v[$b1],@v[$b1],@v[$c1]);
	vx	(@v[$b2],@v[$b2],@v[$c2]);
	vx	(@v[$b3],@v[$b3],@v[$c3]);
	verllf	(@v[$b0],@v[$b0],12);
	verllf	(@v[$b1],@v[$b1],12);
	verllf	(@v[$b2],@v[$b2],12);
	verllf	(@v[$b3],@v[$b3],12);

	vaf	(@v[$a0],@v[$a0],@v[$b0]);
	vaf	(@v[$a1],@v[$a1],@v[$b1]);
	vaf	(@v[$a2],@v[$a2],@v[$b2]);
	vaf	(@v[$a3],@v[$a3],@v[$b3]);
	vx	(@v[$d0],@v[$d0],@v[$a0]);
	vx	(@v[$d1],@v[$d1],@v[$a1]);
	vx	(@v[$d2],@v[$d2],@v[$a2]);
	vx	(@v[$d3],@v[$d3],@v[$a3]);
	verllf	(@v[$d0],@v[$d0],8);
	verllf	(@v[$d1],@v[$d1],8);
	verllf	(@v[$d2],@v[$d2],8);
	verllf	(@v[$d3],@v[$d3],8);

	vaf	(@v[$c0],@v[$c0],@v[$d0]);
	vaf	(@v[$c1],@v[$c1],@v[$d1]);
	vaf	(@v[$c2],@v[$c2],@v[$d2]);
	vaf	(@v[$c3],@v[$c3],@v[$d3]);
	vx	(@v[$b0],@v[$b0],@v[$c0]);
	vx	(@v[$b1],@v[$b1],@v[$c1]);
	vx	(@v[$b2],@v[$b2],@v[$c2]);
	vx	(@v[$b3],@v[$b3],@v[$c3]);
	verllf	(@v[$b0],@v[$b0],7);
	verllf	(@v[$b1],@v[$b1],7);
	verllf	(@v[$b2],@v[$b2],7);
	verllf	(@v[$b3],@v[$b3],7);
}

PERLASM_BEGIN($output);

INCLUDE	("s390x_arch.h");
TEXT	();

################
# void ChaCha20_ctr32(unsigned char *out, const unsigned char *inp, size_t len,
#                     const unsigned int key[8], const unsigned int counter[4])
{
my ($out,$inp,$len,$key,$counter)=map("%r$_",(2..6));

# VX CODE PATH
{
my $off=$z*8*16+8;	# offset(initial state)
my $frame=$stdframe+4*16+$off;

GLOBL	("ChaCha20_ctr32");
TYPE	("ChaCha20_ctr32","\@function");
ALIGN	(32);
LABEL	("ChaCha20_ctr32");
	larl	("%r1","OPENSSL_s390xcap_P");

	lghi	("%r0",64);
&{$z?	\&cgr:\&cr}	($len,"%r0");
	jle	("_s390x_chacha_novx");

	lg	("%r0","S390X_STFLE+16(%r1)");
	tmhh	("%r0",0x4000);	# check for vector facility
	jz	("_s390x_chacha_novx");

if (!$z) {
	llgfr   ($len,$len);
	std	("%f4","16*$SIZE_T+2*8($sp)");
	std	("%f6","16*$SIZE_T+3*8($sp)");
}
&{$z?	\&stmg:\&stm}	("%r6","%r7","6*$SIZE_T($sp)");

	lghi	("%r1",-$frame);
	lgr	("%r0",$sp);
	la	($sp,"0(%r1,$sp)");	# allocate stack frame

	larl	("%r7",".Lsigma");
&{$z?	\&stg:\&st}	("%r0","0($sp)");	# backchain

	vstm	("%v8","%v15","8($sp)") if ($z);

	vlm	("%v1","%v2","0($key)");	# load key
	vl	("%v0","0(%r7)");	# load sigma constant
	vl	("%v3","0($counter)");	# load iv (counter||nonce)
	l	("%r0","0($counter)");	# load counter
	vstm	("%v0","%v3","$off($sp)");	# copy initial state to stack

	srlg	("%r1",$len,8);
	ltgr	("%r1","%r1");
	jz	(".Lvx_4x_done");

ALIGN	(16);	# process 4 64-byte blocks
LABEL	(".Lvx_4x");
	vlrepf	("%v$_",($_*4)."+$off($sp)") for (0..15);	# load initial
								#  state
	vl	("%v31","16(%r7)");
	vaf	("%v12","%v12","%v31");	# increment counter

	vlr	(@v[$_],"%v$_") for (0..15);	# copy initial state

	lhi	("%r6",10);
	j	(".Loop_vx_4x");

ALIGN	(16);
LABEL	(".Loop_vx_4x");
	VX_ROUND( 0, 4, 8,12);	# column round
	VX_ROUND( 0, 5,10,15);	# diagonal round
	brct	("%r6",".Loop_vx_4x");

	vaf	(@v[$_],@v[$_],"%v$_") for (0..15);	# state += initial
							#  state (mod 32)
	vlm	("%v6","%v7","32(%r7)");	# load vperm operands

for (0..3) {	# blocks 1,2
	vmrhf	("%v0",@v[$_*4+0],@v[$_*4+1]);	# ks = serialize(state)
	vmrhf	("%v1",@v[$_*4+2],@v[$_*4+3]);
	vperm	("%v".($_+ 8),"%v0","%v1","%v6");
	vperm	("%v".($_+12),"%v0","%v1","%v7");
}
	vlm	("%v0","%v7","0($inp)");	# load in
	vx	("%v$_","%v$_","%v".($_+8)) for (0..7);	# out = in ^ ks
	vstm	("%v0","%v7","0($out)");	# store out

	vlm	("%v6","%v7","32(%r7)");	# restore vperm operands

for (0..3) {	# blocks 2,3
	vmrlf	("%v0",@v[$_*4+0],@v[$_*4+1]);	# ks = serialize(state)
	vmrlf	("%v1",@v[$_*4+2],@v[$_*4+3]);
	vperm	("%v".($_+ 8),"%v0","%v1","%v6");
	vperm	("%v".($_+12),"%v0","%v1","%v7");
}
	vlm	("%v0","%v7","128($inp)");	# load in
	vx	("%v$_","%v$_","%v".($_+8)) for (0..7);	# out = in ^ ks
	vstm	("%v0","%v7","128($out)");	# store out

	ahi	("%r0",4);
	st	("%r0","48+$off($sp)");	# update initial state

	la	($inp,"256($inp)");
	la	($out,"256($out)");
	brctg	("%r1",".Lvx_4x");

ALIGN	(16);
LABEL	(".Lvx_4x_done");
	lghi	("%r1",0xff);
	ngr	($len,"%r1");
	jnz	(".Lvx_rem");

ALIGN	(16);
LABEL	(".Lvx_done");
	vzero	("%v$_") for (16..31);	# wipe ks and key copy
	vstm	("%v16","%v17","16+$off($sp)");
	vlm	("%v8","%v15","8($sp)") if ($z);

	la	($sp,"$frame($sp)");
&{$z?	\&lmg:\&lm}	("%r6","%r7","6*$SIZE_T($sp)");

if (!$z) {
	ld	("%f4","16*$SIZE_T+2*8($sp)");
	ld	("%f6","16*$SIZE_T+3*8($sp)");
	vzero	("%v$_") for (8..15);
}
	br	("%r14");
ALIGN	(16);
LABEL	(".Lvx_rem");
	lhi	("%r0",64);

	sr	($len,"%r0");
	brc	(2,".Lvx_rem_g64");	# cc==2?

	lghi	("%r1",-$stdframe);

	la	($counter,"48+$off($sp)");	# load updated iv
	ar	($len,"%r0");	# restore len

	lgr	("%r7",$counter);
&{$z?	\&stg:\&st}	("%r14","14*$SIZE_T+$frame($sp)");
	la	($sp,"0(%r1,$sp)");

	bras	("%r14","_s390x_chacha_novx");

	la	($sp,"$stdframe($sp)");
&{$z?	\&lg:\&l}	("%r14","14*$SIZE_T+$frame($sp)");
	lgr	($counter,"%r7");
	j	(".Lvx_done");

ALIGN	(16);
LABEL	(".Lvx_rem_g64");
	vlrepf	("%v$_",($_*4)."+$off($sp)") for (0..15);	# load initial
								#  state
	vl	("%v31","16(%r7)");
	vaf	("%v12","%v12","%v31");	# increment counter

	vlr	(@v[$_],"%v$_") for (0..15);	# state = initial state

	lhi	("%r6",10);
	j	(".Loop_vx_rem");

ALIGN	(16);
LABEL	(".Loop_vx_rem");
	VX_ROUND( 0, 4, 8,12);	# column round
	VX_ROUND( 0, 5,10,15);	# diagonal round
	brct	("%r6",".Loop_vx_rem");

	vaf	(@v[$_],@v[$_],"%v$_") for (0..15);	# state += initial
							#  state (mod 32)
	vlm	("%v6","%v7","32(%r7)");	# load vperm operands

for (0..3) {	# blocks 1,2
	vmrhf	("%v0",@v[$_*4+0],@v[$_*4+1]);	# ks = serialize(state)
	vmrhf	("%v1",@v[$_*4+2],@v[$_*4+3]);
	vperm	("%v".($_+8),"%v0","%v1","%v6");
	vperm	("%v".($_+12),"%v0","%v1","%v7");
}
	vlm	("%v0","%v3","0($inp)");	# load in
	vx	("%v$_","%v$_","%v".($_+8)) for (0..3);	# out = in ^ ks
	vstm	("%v0","%v3","0($out)");	# store out

	la	($inp,"64($inp)");
	la	($out,"64($out)");

	sr	($len,"%r0");
	brc	(4,".Lvx_tail");	# cc==4?

	vlm	("%v0","%v3","0($inp)");	# load in
	vx	("%v$_","%v$_","%v".($_+12)) for (0..3);	# out = in ^ ks
	vstm	("%v0","%v3","0($out)");	# store out
	jz	(".Lvx_done");

for (0..3) {	# blocks 3,4
	vmrlf	("%v0",@v[$_*4+0],@v[$_*4+1]);	# ks = serialize(state)
	vmrlf	("%v1",@v[$_*4+2],@v[$_*4+3]);
	vperm	("%v".($_+12),"%v0","%v1","%v6");
	vperm	("%v".($_+8),"%v0","%v1","%v7");
}
	la	($inp,"64($inp)");
	la	($out,"64($out)");

	sr	($len,"%r0");
	brc	(4,".Lvx_tail");	# cc==4?

	vlm	("%v0","%v3","0($inp)");	# load in
	vx	("%v$_","%v$_","%v".($_+12)) for (0..3);	# out = in ^ ks
	vstm	("%v0","%v3","0($out)");	# store out
	jz	(".Lvx_done");

	la	($inp,"64($inp)");
	la	($out,"64($out)");

	sr	($len,"%r0");
	vlr	("%v".($_+4),"%v$_") for (8..11);
	j	(".Lvx_tail");

ALIGN	(16);
LABEL	(".Lvx_tail");
	ar	($len,"%r0");	# restore $len
	ahi	($len,-1);

	lhi	("%r0",16);
for (0..2) {
	vll	("%v0",$len,($_*16)."($inp)");
	vx	("%v0","%v0","%v".($_+12));
	vstl	("%v0",$len,($_*16)."($out)");
	sr	($len,"%r0");
	brc	(4,".Lvx_done");	# cc==4?
}
	vll	("%v0",$len,"3*16($inp)");
	vx	("%v0","%v0","%v15");
	vstl	("%v0",$len,"3*16($out)");
	j	(".Lvx_done");
SIZE	("ChaCha20_ctr32",".-ChaCha20_ctr32");
}

# NOVX CODE PATH
{
my $frame=$stdframe+4*20;

TYPE	("_s390x_chacha_novx","\@function");
ALIGN	(32);
LABEL	("_s390x_chacha_novx");
&{$z?	\&ltgr:\&ltr}	($len,$len);	# $len==0?
	bzr	("%r14");
&{$z?	\&aghi:\&ahi}	($len,-64);
&{$z?	\&lghi:\&lhi}	("%r1",-$frame);
&{$z?	\&stmg:\&stm}	("%r6","%r15","6*$SIZE_T($sp)");
&{$z?	\&slgr:\&slr}	($out,$inp);	# difference
	la	($len,"0($inp,$len)");	# end of input minus 64
	larl	("%r7",".Lsigma");
	lgr	("%r0",$sp);
	la	($sp,"0(%r1,$sp)");
&{$z?	\&stg:\&st}	("%r0","0($sp)");

	lmg	("%r8","%r11","0($key)");	# load key
	lmg	("%r12","%r13","0($counter)");	# load counter
	lmg	("%r6","%r7","0(%r7)");	# load sigma constant

	la	("%r14","0($inp)");
&{$z?	\&stg:\&st}	($out,"$frame+3*$SIZE_T($sp)");
&{$z?	\&stg:\&st}	($len,"$frame+4*$SIZE_T($sp)");
	stmg	("%r6","%r13","$stdframe($sp)");# copy key schedule to stack
	srlg	(@x[12],"%r12",32);	# 32-bit counter value
	j	(".Loop_outer");

ALIGN	(16);
LABEL	(".Loop_outer");
	lm	(@x[0],@x[7],"$stdframe+4*0($sp)");	# load x[0]-x[7]
	lm	(@t[0],@t[1],"$stdframe+4*10($sp)");	# load x[10]-x[11]
	lm	(@x[13],@x[15],"$stdframe+4*13($sp)");	# load x[13]-x[15]
	stm	(@t[0],@t[1],"$stdframe+4*8+4*10($sp)");# offload x[10]-x[11]
	lm	(@t[0],@t[1],"$stdframe+4*8($sp)");	# load x[8]-x[9]
	st	(@x[12],"$stdframe+4*12($sp)");	# save counter
&{$z?	\&stg:\&st}	("%r14","$frame+2*$SIZE_T($sp)");# save input pointer
	lhi	("%r14",10);
	j	(".Loop");

ALIGN	(4);
LABEL	(".Loop");
	ROUND	(0, 4, 8,12);
	ROUND	(0, 5,10,15);
	brct	("%r14",".Loop");

&{$z?	\&lg:\&l}	("%r14","$frame+2*$SIZE_T($sp)");# pull input pointer
	stm	(@t[0],@t[1],"$stdframe+4*8+4*8($sp)");	# offload x[8]-x[9]
&{$z?	\&lmg:\&lm}	(@t[0],@t[1],"$frame+3*$SIZE_T($sp)");

	al	(@x[0],"$stdframe+4*0($sp)");	# accumulate key schedule
	al	(@x[1],"$stdframe+4*1($sp)");
	al	(@x[2],"$stdframe+4*2($sp)");
	al	(@x[3],"$stdframe+4*3($sp)");
	al	(@x[4],"$stdframe+4*4($sp)");
	al	(@x[5],"$stdframe+4*5($sp)");
	al	(@x[6],"$stdframe+4*6($sp)");
	al	(@x[7],"$stdframe+4*7($sp)");
	lrvr	(@x[0],@x[0]);
	lrvr	(@x[1],@x[1]);
	lrvr	(@x[2],@x[2]);
	lrvr	(@x[3],@x[3]);
	lrvr	(@x[4],@x[4]);
	lrvr	(@x[5],@x[5]);
	lrvr	(@x[6],@x[6]);
	lrvr	(@x[7],@x[7]);
	al	(@x[12],"$stdframe+4*12($sp)");
	al	(@x[13],"$stdframe+4*13($sp)");
	al	(@x[14],"$stdframe+4*14($sp)");
	al	(@x[15],"$stdframe+4*15($sp)");
	lrvr	(@x[12],@x[12]);
	lrvr	(@x[13],@x[13]);
	lrvr	(@x[14],@x[14]);
	lrvr	(@x[15],@x[15]);

	la	(@t[0],"0(@t[0],%r14)");	# reconstruct output pointer
&{$z?	\&clgr:\&clr}	("%r14",@t[1]);
	jh	(".Ltail");

	x	(@x[0],"4*0(%r14)");	# xor with input
	x	(@x[1],"4*1(%r14)");
	st	(@x[0],"4*0(@t[0])");	# store output
	x	(@x[2],"4*2(%r14)");
	st	(@x[1],"4*1(@t[0])");
	x	(@x[3],"4*3(%r14)");
	st	(@x[2],"4*2(@t[0])");
	x	(@x[4],"4*4(%r14)");
	st	(@x[3],"4*3(@t[0])");
	 lm	(@x[0],@x[3],"$stdframe+4*8+4*8($sp)");	# load x[8]-x[11]
	x	(@x[5],"4*5(%r14)");
	st	(@x[4],"4*4(@t[0])");
	x	(@x[6],"4*6(%r14)");
	 al	(@x[0],"$stdframe+4*8($sp)");
	st	(@x[5],"4*5(@t[0])");
	x	(@x[7],"4*7(%r14)");
	 al	(@x[1],"$stdframe+4*9($sp)");
	st	(@x[6],"4*6(@t[0])");
	x	(@x[12],"4*12(%r14)");
	 al	(@x[2],"$stdframe+4*10($sp)");
	st	(@x[7],"4*7(@t[0])");
	x	(@x[13],"4*13(%r14)");
	 al	(@x[3],"$stdframe+4*11($sp)");
	st	(@x[12],"4*12(@t[0])");
	x	(@x[14],"4*14(%r14)");
	st	(@x[13],"4*13(@t[0])");
	x	(@x[15],"4*15(%r14)");
	st	(@x[14],"4*14(@t[0])");
	 lrvr	(@x[0],@x[0]);
	st	(@x[15],"4*15(@t[0])");
	 lrvr	(@x[1],@x[1]);
	 lrvr	(@x[2],@x[2]);
	 lrvr	(@x[3],@x[3]);
	lhi	(@x[12],1);
	 x	(@x[0],"4*8(%r14)");
	al	(@x[12],"$stdframe+4*12($sp)");	# increment counter
	 x	(@x[1],"4*9(%r14)");
	 st	(@x[0],"4*8(@t[0])");
	 x	(@x[2],"4*10(%r14)");
	 st	(@x[1],"4*9(@t[0])");
	 x	(@x[3],"4*11(%r14)");
	 st	(@x[2],"4*10(@t[0])");
	 st	(@x[3],"4*11(@t[0])");

&{$z?	\&clgr:\&clr}	("%r14",@t[1]);	# done yet?
	la	("%r14","64(%r14)");
	jl	(".Loop_outer");

LABEL	(".Ldone");
	xgr	("%r0","%r0");
	xgr	("%r1","%r1");
	xgr	("%r2","%r2");
	xgr	("%r3","%r3");
	stmg	("%r0","%r3","$stdframe+4*4($sp)");	# wipe key copy
	stmg	("%r0","%r3","$stdframe+4*12($sp)");

&{$z?	\&lmg:\&lm}	("%r6","%r15","$frame+6*$SIZE_T($sp)");
	br	("%r14");

ALIGN	(16);
LABEL	(".Ltail");
	la	(@t[1],"64($t[1])");
	stm	(@x[0],@x[7],"$stdframe+4*0($sp)");
&{$z?	\&slgr:\&slr}	(@t[1],"%r14");
	lm	(@x[0],@x[3],"$stdframe+4*8+4*8($sp)");
&{$z?	\&lghi:\&lhi}	(@x[6],0);
	stm	(@x[12],@x[15],"$stdframe+4*12($sp)");
	al	(@x[0],"$stdframe+4*8($sp)");
	al	(@x[1],"$stdframe+4*9($sp)");
	al	(@x[2],"$stdframe+4*10($sp)");
	al	(@x[3],"$stdframe+4*11($sp)");
	lrvr	(@x[0],@x[0]);
	lrvr	(@x[1],@x[1]);
	lrvr	(@x[2],@x[2]);
	lrvr	(@x[3],@x[3]);
	stm	(@x[0],@x[3],"$stdframe+4*8($sp)");

LABEL	(".Loop_tail");
	llgc	(@x[4],"0(@x[6],%r14)");
	llgc	(@x[5],"$stdframe(@x[6],$sp)");
	xr	(@x[5],@x[4]);
	stc	(@x[5],"0(@x[6],@t[0])");
	la	(@x[6],"1(@x[6])");
	brct	(@t[1],".Loop_tail");

	j	(".Ldone");
SIZE	("_s390x_chacha_novx",".-_s390x_chacha_novx");
}
}
################

ALIGN	(64);
LABEL	(".Lsigma");
LONG	(0x61707865,0x3320646e,0x79622d32,0x6b206574);	# endian-neutral sigma
LONG	(0x00000000,0x00000001,0x00000002,0x00000003);	# vaf counter increment
LONG	(0x03020100,0x07060504,0x13121110,0x17161514);	# vperm serialization
LONG	(0x0b0a0908,0x0f0e0d0c,0x1b1a1918,0x1f1e1d1c);	# vperm serialization
ASCIZ	("\"ChaCha20 for s390x, CRYPTOGAMS by <appro\@openssl.org>\"");
ALIGN	(4);

PERLASM_END();
