#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
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
# This module implements Poly1305 hash for s390x.
#
# June 2015
#
# ~6.6/2.3 cpb on z10/z196+, >2x improvement over compiler-generated
# code. For older compiler improvement coefficient is >3x, because
# then base 2^64 and base 2^32 implementations are compared.
#
# On side note, z13 enables vector base 2^26 implementation...

#
# January 2019
#
# Add vx code path (base 2^26).
#
# Copyright IBM Corp. 2019
# Author: Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use FindBin qw($Bin);
use lib "$Bin/../..";
use perlasm::s390x qw(:DEFAULT :VX AUTOLOAD LABEL);

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

# novx code path ctx layout
# ---------------------------------
# var		value	base	off
# ---------------------------------
# u64 h[3]	hash	2^64	  0
# u32 pad[2]
# u64 r[2]	key	2^64	 32

# vx code path ctx layout
# ---------------------------------
# var		value	base	off
# ---------------------------------
# u32 acc1[5]	r^2-acc	2^26	  0
# u32 pad
# u32 acc2[5]	r-acc	2^26	 24
# u32 pad
# u32 r1[5]	r	2^26	 48
# u32 r15[5]	5*r	2^26	 68
# u32 r2[5]	r^2	2^26	 88
# u32 r25[5]	5*r^2	2^26	108
# u32 r4[5]	r^4	2^26	128
# u32 r45[5]	5*r^4	2^26	148

PERLASM_BEGIN($output);

TEXT	();

################
# static void poly1305_init(void *ctx, const unsigned char key[16])
{
my ($ctx,$key)=map("%r$_",(2..3));
my ($r0,$r1,$r2)=map("%r$_",(9,11,13));

sub MUL_RKEY {	# r*=key
my ($d0hi,$d0lo,$d1hi,$d1lo)=map("%r$_",(4..7));
my ($t0,$t1,$s1)=map("%r$_",(8,10,12));

	lg	("%r0","32($ctx)");
	lg	("%r1","40($ctx)");

	srlg	($s1,"%r1",2);
	algr	($s1,"%r1");

	lgr	($d0lo,$r0);
	lgr	($d1lo,$r1);

	mlgr	($d0hi,"%r0");
	lgr	($r1,$d1lo);
	mlgr	($d1hi,$s1);

	mlgr	($t0,"%r1");
	mlgr	($t1,"%r0");

	algr	($d0lo,$d1lo);
	lgr	($d1lo,$r2);
	alcgr	($d0hi,$d1hi);
	lghi	($d1hi,0);

	algr	($r1,$r0);
	alcgr	($t1,$t0);

	msgr	($d1lo,$s1);
	msgr	($r2,"%r0");

	algr	($r1,$d1lo);
	alcgr	($t1,$d1hi);

	algr	($r1,$d0hi);
	alcgr	($r2,$t1);

	lghi	($r0,-4);
	ngr	($r0,$r2);
	srlg	($t0,$r2,2);
	algr	($r0,$t0);
	lghi	($t1,3);
	ngr	($r2,$t1);

	algr	($r0,$d0lo);
	alcgr	($r1,$d1hi);
	alcgr	($r2,$d1hi);
}

sub ST_R5R {	# store r,5*r -> base 2^26
my @d=map("%r$_",(4..8));
my @off=@_;

	lgr	(@d[2],$r0);
	lr	("%r1",@d[2]);
	nilh	("%r1",1023);
	lgr	(@d[3],$r1);
	lr	(@d[0],"%r1");
	srlg	("%r1",@d[2],52);
	lgr	(@d[4],$r2);
	srlg	("%r0",@d[2],26);
	sll	(@d[4],24);
	lr	(@d[2],@d[3]);
	nilh	("%r0",1023);
	sll	(@d[2],12);
	lr	(@d[1],"%r0");
	&or	(@d[2],"%r1");
	srlg	("%r1",@d[3],40);
	nilh	(@d[2],1023);
	&or	(@d[4],"%r1");
	srlg	(@d[3],@d[3],14);
	nilh	(@d[4],1023);
	nilh	(@d[3],1023);

	stm	(@d[0],@d[4],"@off[0]($ctx)");
	mhi	(@d[$_],5) for (0..4);
	stm	(@d[0],@d[4],"@off[1]($ctx)");
}

GLOBL	("poly1305_init");
TYPE	("poly1305_init","\@function");
ALIGN	(16);
LABEL	("poly1305_init");
	lghi	("%r0",0);
	lghi	("%r1",-1);
	stg	("%r0","0($ctx)");	# zero hash value / acc1
	stg	("%r0","8($ctx)");
	stg	("%r0","16($ctx)");

&{$z?	\&clgr:\&clr}	($key,"%r0");
	je	(".Ldone");

	lrvg	("%r4","0($key)");	# load little-endian key
	lrvg	("%r5","8($key)");

	nihl	("%r1",0xffc0);		# 0xffffffc0ffffffff
	srlg	("%r0","%r1",4);	# 0x0ffffffc0fffffff
	srlg	("%r1","%r1",4);
	nill	("%r1",0xfffc);		# 0x0ffffffc0ffffffc

	ngr	("%r4","%r0");
	ngr	("%r5","%r1");

	stg	("%r4","32($ctx)");
	stg	("%r5","40($ctx)");

	larl	("%r1","OPENSSL_s390xcap_P");
	lg	("%r0","16(%r1)");
	tmhh	("%r0",0x4000);		# check for vector facility
	jz	(".Ldone");

	larl	("%r4","poly1305_blocks_vx");
	larl	("%r5","poly1305_emit_vx");

&{$z?	\&stmg:\&stm}	("%r6","%r13","6*$SIZE_T($sp)");
&{$z?	\&stmg:\&stm}	("%r4","%r5","4*$z+228($ctx)");

	lg	($r0,"32($ctx)");
	lg	($r1,"40($ctx)");
	lghi	($r2,0);

	ST_R5R	(48,68);	# store r,5*r

	MUL_RKEY();
	ST_R5R	(88,108);	# store r^2,5*r^2

	MUL_RKEY();
	MUL_RKEY();
	ST_R5R	(128,148);	# store r^4,5*r^4

	lghi	("%r0",0);
	stg	("%r0","24($ctx)");	# zero acc2
	stg	("%r0","32($ctx)");
	stg	("%r0","40($ctx)");

&{$z?	\&lmg:\&lm}	("%r6","%r13","6*$SIZE_T($sp)");
	lghi	("%r2",1);
	br	("%r14");

LABEL	(".Ldone");
	lghi	("%r2",0);
	br	("%r14");
SIZE	("poly1305_init",".-poly1305_init");
}

# VX CODE PATH
{
my $frame=8*16;
my @m01=map("%v$_",(0..4));
my @m23=map("%v$_",(5..9));
my @tmp=@m23;
my @acc=map("%v$_",(10..14));
my @r=map("%v$_",(15..19));
my @r5=map("%v$_",(20..24));
my $padvec="%v26";
my $mask4="%v27";
my @vperm=map("%v$_",(28..30));
my $mask="%v31";

sub REDUCE {
	vesrlg	(@tmp[0],@acc[0],26);
	vesrlg	(@tmp[3],@acc[3],26);
	vn	(@acc[0],@acc[0],$mask);
	vn	(@acc[3],@acc[3],$mask);
	vag	(@acc[1],@acc[1],@tmp[0]);	# carry 0->1
	vag	(@acc[4],@acc[4],@tmp[3]);	# carry 3->4

	vesrlg	(@tmp[1],@acc[1],26);
	vesrlg	(@tmp[4],@acc[4],26);
	vn	(@acc[1],@acc[1],$mask);
	vn	(@acc[4],@acc[4],$mask);
	veslg	(@tmp[0],@tmp[4],2);
	vag	(@tmp[4],@tmp[4],@tmp[0]);	# h[4]*=5
	vag	(@acc[2],@acc[2],@tmp[1]);	# carry 1->2
	vag	(@acc[0],@acc[0],@tmp[4]);	# carry 4->0

	vesrlg	(@tmp[2],@acc[2],26);
	vesrlg	(@tmp[0],@acc[0],26);
	vn	(@acc[2],@acc[2],$mask);
	vn	(@acc[0],@acc[0],$mask);
	vag	(@acc[3],@acc[3],@tmp[2]);	# carry 2->3
	vag	(@acc[1],@acc[1],@tmp[0]);	# carry 0->1

	vesrlg	(@tmp[3],@acc[3],26);
	vn	(@acc[3],@acc[3],$mask);
	vag	(@acc[4],@acc[4],@tmp[3]);	# carry 3->4
}

################
# static void poly1305_blocks_vx(void *ctx, const unsigned char *inp,
#                                size_t len, u32 padbit)
{
my ($ctx,$inp,$len) = map("%r$_",(2..4));
my $padbit="%r0";

GLOBL	("poly1305_blocks_vx");
TYPE	("poly1305_blocks_vx","\@function");
ALIGN	(16);
LABEL	("poly1305_blocks_vx");
if ($z) {
	aghi	($sp,-$frame);
	vstm	("%v8","%v15","0($sp)");
} else {
	std	("%f4","16*$SIZE_T+2*8($sp)");
	std	("%f6","16*$SIZE_T+3*8($sp)");
	llgfr	($len,$len);
}
	llgfr	($padbit,"%r5");
	vlef	(@acc[$_],"4*$_($ctx)",1) for (0..4);	# load acc1
	larl	("%r5",".Lconst");
	vlef	(@acc[$_],"24+4*$_($ctx)",3) for (0..4);	# load acc2
	sllg	($padbit,$padbit,24);
	vlm	(@vperm[0],$mask,"0(%r5)");	# load vperm ops, mask
	vgbm	($mask4,0x0707);
	vlvgp	($padvec,$padbit,$padbit);

	srlg	("%r1",$len,6);
	ltgr	("%r1","%r1");
	jz	(".Lvx_4x_done");

ALIGN	(16);
LABEL	(".Lvx_4x");
	vlm	("%v20","%v23","0($inp)");	# load m0,m1,m2,m3

	# m01,m23 -> base 2^26

	vperm	(@m01[0],"%v20","%v21",@vperm[0]);
	vperm	(@m23[0],"%v22","%v23",@vperm[0]);
	vperm	(@m01[2],"%v20","%v21",@vperm[1]);
	vperm	(@m23[2],"%v22","%v23",@vperm[1]);
	vperm	(@m01[4],"%v20","%v21",@vperm[2]);
	vperm	(@m23[4],"%v22","%v23",@vperm[2]);

	vesrlg	(@m01[1],@m01[0],26);
	vesrlg	(@m23[1],@m23[0],26);
	vesrlg	(@m01[3],@m01[2],30);
	vesrlg	(@m23[3],@m23[2],30);
	vesrlg	(@m01[2],@m01[2],4);
	vesrlg	(@m23[2],@m23[2],4);

	vn	(@m01[4],@m01[4],$mask4);
	vn	(@m23[4],@m23[4],$mask4);
for (0..3) {
	vn	(@m01[$_],@m01[$_],$mask);
	vn	(@m23[$_],@m23[$_],$mask);
}
	vaf	(@m01[4],@m01[4],$padvec);	# pad m01
	vaf	(@m23[4],@m23[4],$padvec);	# pad m23

	# acc = acc * r^4 + m01 * r^2 + m23

	vlrepf	(@r5[$_],"4*$_+108($ctx)") for (0..4);	# load 5*r^2
	vlrepf	(@r[$_],"4*$_+88($ctx)") for (0..4);	# load r^2

	vmalof	(@tmp[0],@m01[4],@r5[1],@m23[0]);
	vmalof	(@tmp[1],@m01[4],@r5[2],@m23[1]);
	vmalof	(@tmp[2],@m01[4],@r5[3],@m23[2]);
	vmalof	(@tmp[3],@m01[4],@r5[4],@m23[3]);
	vmalof	(@tmp[4],@m01[4],@r[0],@m23[4]);

	vmalof	(@tmp[0],@m01[3],@r5[2],@tmp[0]);
	vmalof	(@tmp[1],@m01[3],@r5[3],@tmp[1]);
	vmalof	(@tmp[2],@m01[3],@r5[4],@tmp[2]);
	vmalof	(@tmp[3],@m01[3],@r[0],@tmp[3]);
	vmalof	(@tmp[4],@m01[3],@r[1],@tmp[4]);

	vmalof	(@tmp[0],@m01[2],@r5[3],@tmp[0]);
	vmalof	(@tmp[1],@m01[2],@r5[4],@tmp[1]);
	vmalof	(@tmp[2],@m01[2],@r[0],@tmp[2]);
	vmalof	(@tmp[3],@m01[2],@r[1],@tmp[3]);
	vmalof	(@tmp[4],@m01[2],@r[2],@tmp[4]);

	vmalof	(@tmp[0],@m01[1],@r5[4],@tmp[0]);
	vmalof	(@tmp[1],@m01[1],@r[0],@tmp[1]);
	vmalof	(@tmp[2],@m01[1],@r[1],@tmp[2]);
	vmalof	(@tmp[3],@m01[1],@r[2],@tmp[3]);
	vmalof	(@tmp[4],@m01[1],@r[3],@tmp[4]);

	vmalof	(@tmp[0],@m01[0],@r[0],@tmp[0]);
	vmalof	(@tmp[1],@m01[0],@r[1],@tmp[1]);
	vmalof	(@tmp[2],@m01[0],@r[2],@tmp[2]);
	vmalof	(@tmp[3],@m01[0],@r[3],@tmp[3]);
	vmalof	(@tmp[4],@m01[0],@r[4],@tmp[4]);

	vlrepf	(@r5[$_],"4*$_+148($ctx)") for (0..4);	# load 5*r^4
	vlrepf	(@r[$_],"4*$_+128($ctx)") for (0..4);	# load r^4

	vmalof	(@tmp[0],@acc[4],@r5[1],@tmp[0]);
	vmalof	(@tmp[1],@acc[4],@r5[2],@tmp[1]);
	vmalof	(@tmp[2],@acc[4],@r5[3],@tmp[2]);
	vmalof	(@tmp[3],@acc[4],@r5[4],@tmp[3]);
	vmalof	(@tmp[4],@acc[4],@r[0],@tmp[4]);

	vmalof	(@tmp[0],@acc[3],@r5[2],@tmp[0]);
	vmalof	(@tmp[1],@acc[3],@r5[3],@tmp[1]);
	vmalof	(@tmp[2],@acc[3],@r5[4],@tmp[2]);
	vmalof	(@tmp[3],@acc[3],@r[0],@tmp[3]);
	vmalof	(@tmp[4],@acc[3],@r[1],@tmp[4]);

	vmalof	(@tmp[0],@acc[2],@r5[3],@tmp[0]);
	vmalof	(@tmp[1],@acc[2],@r5[4],@tmp[1]);
	vmalof	(@tmp[2],@acc[2],@r[0],@tmp[2]);
	vmalof	(@tmp[3],@acc[2],@r[1],@tmp[3]);
	vmalof	(@tmp[4],@acc[2],@r[2],@tmp[4]);

	vmalof	(@tmp[0],@acc[1],@r5[4],@tmp[0]);
	vmalof	(@tmp[1],@acc[1],@r[0],@tmp[1]);
	vmalof	(@tmp[2],@acc[1],@r[1],@tmp[2]);
	vmalof	(@tmp[3],@acc[1],@r[2],@tmp[3]);
	vmalof	(@tmp[4],@acc[1],@r[3],@tmp[4]);

	vmalof	(@acc[1],@acc[0],@r[1],@tmp[1]);
	vmalof	(@acc[2],@acc[0],@r[2],@tmp[2]);
	vmalof	(@acc[3],@acc[0],@r[3],@tmp[3]);
	vmalof	(@acc[4],@acc[0],@r[4],@tmp[4]);
	vmalof	(@acc[0],@acc[0],@r[0],@tmp[0]);

	REDUCE	();

	la	($inp,"64($inp)");
	brctg	("%r1",".Lvx_4x");

ALIGN	(16);
LABEL	(".Lvx_4x_done");
	tml	($len,32);
	jz	(".Lvx_2x_done");

	vlm	("%v20","%v21","0($inp)");	# load m0,m1

	# m01 -> base 2^26

	vperm	(@m01[0],"%v20","%v21",@vperm[0]);
	vperm	(@m01[2],"%v20","%v21",@vperm[1]);
	vperm	(@m01[4],"%v20","%v21",@vperm[2]);

	vesrlg	(@m01[1],@m01[0],26);
	vesrlg	(@m01[3],@m01[2],30);
	vesrlg	(@m01[2],@m01[2],4);

	vn	(@m01[4],@m01[4],$mask4);
	vn	(@m01[$_],@m01[$_],$mask) for (0..3);

	vaf	(@m01[4],@m01[4],$padvec);	# pad m01

	# acc = acc * r^2+ m01

	vlrepf	(@r5[$_],"4*$_+108($ctx)") for (0..4);	# load 5*r^2
	vlrepf	(@r[$_],"4*$_+88($ctx)") for (0..4);	# load r^2

	vmalof	(@tmp[0],@acc[4],@r5[1],@m01[0]);
	vmalof	(@tmp[1],@acc[4],@r5[2],@m01[1]);
	vmalof	(@tmp[2],@acc[4],@r5[3],@m01[2]);
	vmalof	(@tmp[3],@acc[4],@r5[4],@m01[3]);
	vmalof	(@tmp[4],@acc[4],@r[0],@m01[4]);

	vmalof	(@tmp[0],@acc[3],@r5[2],@tmp[0]);
	vmalof	(@tmp[1],@acc[3],@r5[3],@tmp[1]);
	vmalof	(@tmp[2],@acc[3],@r5[4],@tmp[2]);
	vmalof	(@tmp[3],@acc[3],@r[0],@tmp[3]);
	vmalof	(@tmp[4],@acc[3],@r[1],@tmp[4]);

	vmalof	(@tmp[0],@acc[2],@r5[3],@tmp[0]);
	vmalof	(@tmp[1],@acc[2],@r5[4],@tmp[1]);
	vmalof	(@tmp[2],@acc[2],@r[0],@tmp[2]);
	vmalof	(@tmp[3],@acc[2],@r[1],@tmp[3]);
	vmalof	(@tmp[4],@acc[2],@r[2],@tmp[4]);

	vmalof	(@tmp[0],@acc[1],@r5[4],@tmp[0]);
	vmalof	(@tmp[1],@acc[1],@r[0],@tmp[1]);
	vmalof	(@tmp[2],@acc[1],@r[1],@tmp[2]);
	vmalof	(@tmp[3],@acc[1],@r[2],@tmp[3]);
	vmalof	(@tmp[4],@acc[1],@r[3],@tmp[4]);

	vmalof	(@acc[1],@acc[0],@r[1],@tmp[1]);
	vmalof	(@acc[2],@acc[0],@r[2],@tmp[2]);
	vmalof	(@acc[3],@acc[0],@r[3],@tmp[3]);
	vmalof	(@acc[4],@acc[0],@r[4],@tmp[4]);
	vmalof	(@acc[0],@acc[0],@r[0],@tmp[0]);

	REDUCE	();

	la	($inp,"32($inp)");

ALIGN	(16);
LABEL	(".Lvx_2x_done");
	tml	($len,16);
	jz	(".Lvx_done");

	vleig	($padvec,0,0);

	vzero	("%v20");
	vl	("%v21","0($inp)");	# load m0

	# m0 -> base 2^26

	vperm	(@m01[0],"%v20","%v21",@vperm[0]);
	vperm	(@m01[2],"%v20","%v21",@vperm[1]);
	vperm	(@m01[4],"%v20","%v21",@vperm[2]);

	vesrlg	(@m01[1],@m01[0],26);
	vesrlg	(@m01[3],@m01[2],30);
	vesrlg	(@m01[2],@m01[2],4);

	vn	(@m01[4],@m01[4],$mask4);
	vn	(@m01[$_],@m01[$_],$mask) for (0..3);

	vaf	(@m01[4],@m01[4],$padvec);	# pad m0

	# acc = acc * r + m01

	vlrepf	(@r5[$_],"4*$_+68($ctx)") for (0..4);	# load 5*r
	vlrepf	(@r[$_],"4*$_+48($ctx)") for (0..4);	# load r

	vmalof	(@tmp[0],@acc[4],@r5[1],@m01[0]);
	vmalof	(@tmp[1],@acc[4],@r5[2],@m01[1]);
	vmalof	(@tmp[2],@acc[4],@r5[3],@m01[2]);
	vmalof	(@tmp[3],@acc[4],@r5[4],@m01[3]);
	vmalof	(@tmp[4],@acc[4],@r[0],@m01[4]);

	vmalof	(@tmp[0],@acc[3],@r5[2],@tmp[0]);
	vmalof	(@tmp[1],@acc[3],@r5[3],@tmp[1]);
	vmalof	(@tmp[2],@acc[3],@r5[4],@tmp[2]);
	vmalof	(@tmp[3],@acc[3],@r[0],@tmp[3]);
	vmalof	(@tmp[4],@acc[3],@r[1],@tmp[4]);

	vmalof	(@tmp[0],@acc[2],@r5[3],@tmp[0]);
	vmalof	(@tmp[1],@acc[2],@r5[4],@tmp[1]);
	vmalof	(@tmp[2],@acc[2],@r[0],@tmp[2]);
	vmalof	(@tmp[3],@acc[2],@r[1],@tmp[3]);
	vmalof	(@tmp[4],@acc[2],@r[2],@tmp[4]);

	vmalof	(@tmp[0],@acc[1],@r5[4],@tmp[0]);
	vmalof	(@tmp[1],@acc[1],@r[0],@tmp[1]);
	vmalof	(@tmp[2],@acc[1],@r[1],@tmp[2]);
	vmalof	(@tmp[3],@acc[1],@r[2],@tmp[3]);
	vmalof	(@tmp[4],@acc[1],@r[3],@tmp[4]);

	vmalof	(@acc[1],@acc[0],@r[1],@tmp[1]);
	vmalof	(@acc[2],@acc[0],@r[2],@tmp[2]);
	vmalof	(@acc[3],@acc[0],@r[3],@tmp[3]);
	vmalof	(@acc[4],@acc[0],@r[4],@tmp[4]);
	vmalof	(@acc[0],@acc[0],@r[0],@tmp[0]);

	REDUCE	();

ALIGN	(16);
LABEL	(".Lvx_done");
	vstef	(@acc[$_],"4*$_($ctx)",1) for (0..4);	# store acc
	vstef	(@acc[$_],"24+4*$_($ctx)",3) for (0..4);

if ($z) {
	vlm	("%v8","%v15","0($sp)");
	la	($sp,"$frame($sp)");
} else {
	ld	("%f4","16*$SIZE_T+2*8($sp)");
	ld	("%f6","16*$SIZE_T+3*8($sp)");
}
	br	("%r14");
SIZE	("poly1305_blocks_vx",".-poly1305_blocks_vx");
}

################
# static void poly1305_emit_vx(void *ctx, unsigned char mac[16],
#                              const u32 nonce[4])
{
my ($ctx,$mac,$nonce) = map("%r$_",(2..4));

GLOBL	("poly1305_emit_vx");
TYPE	("poly1305_emit_vx","\@function");
ALIGN	(16);
LABEL	("poly1305_emit_vx");
if ($z) {
	aghi	($sp,-$frame);
	vstm	("%v8","%v15","0($sp)");
} else {
	std	("%f4","16*$SIZE_T+2*8($sp)");
	std	("%f6","16*$SIZE_T+3*8($sp)");
}
	larl	("%r5",".Lconst");

	vlef	(@acc[$_],"4*$_($ctx)",1) for (0..4);	# load acc1
	vlef	(@acc[$_],"24+4*$_($ctx)",3) for (0..4);	# load acc2
	vlef	(@r5[$_],"108+4*$_($ctx)",1) for (0..4);	# load 5*r^2
	vlef	(@r[$_],"88+4*$_($ctx)",1) for (0..4);	# load r^2
	vlef	(@r5[$_],"68+4*$_($ctx)",3) for (0..4);	# load 5*r
	vlef	(@r[$_],"48+4*$_($ctx)",3) for (0..4);	# load r
	vl	($mask,"48(%r5)");	# load mask

	# acc = acc1 * r^2 + acc2 * r

	vmlof	(@tmp[0],@acc[4],@r5[1]);
	vmlof	(@tmp[1],@acc[4],@r5[2]);
	vmlof	(@tmp[2],@acc[4],@r5[3]);
	vmlof	(@tmp[3],@acc[4],@r5[4]);
	vmlof	(@tmp[4],@acc[4],@r[0]);

	vmalof	(@tmp[0],@acc[3],@r5[2],@tmp[0]);
	vmalof	(@tmp[1],@acc[3],@r5[3],@tmp[1]);
	vmalof	(@tmp[2],@acc[3],@r5[4],@tmp[2]);
	vmalof	(@tmp[3],@acc[3],@r[0],@tmp[3]);
	vmalof	(@tmp[4],@acc[3],@r[1],@tmp[4]);

	vmalof	(@tmp[0],@acc[2],@r5[3],@tmp[0]);
	vmalof	(@tmp[1],@acc[2],@r5[4],@tmp[1]);
	vmalof	(@tmp[2],@acc[2],@r[0],@tmp[2]);
	vmalof	(@tmp[3],@acc[2],@r[1],@tmp[3]);
	vmalof	(@tmp[4],@acc[2],@r[2],@tmp[4]);

	vmalof	(@tmp[0],@acc[1],@r5[4],@tmp[0]);
	vmalof	(@tmp[1],@acc[1],@r[0],@tmp[1]);
	vmalof	(@tmp[2],@acc[1],@r[1],@tmp[2]);
	vmalof	(@tmp[3],@acc[1],@r[2],@tmp[3]);
	vmalof	(@tmp[4],@acc[1],@r[3],@tmp[4]);

	vmalof	(@acc[1],@acc[0],@r[1],@tmp[1]);
	vmalof	(@acc[2],@acc[0],@r[2],@tmp[2]);
	vmalof	(@acc[3],@acc[0],@r[3],@tmp[3]);
	vmalof	(@acc[4],@acc[0],@r[4],@tmp[4]);
	vmalof	(@acc[0],@acc[0],@r[0],@tmp[0]);

	vzero	("%v27");
	vsumqg	(@acc[$_],@acc[$_],"%v27") for (0..4);

	REDUCE	();

	vesrlg	(@tmp[1],@acc[1],26);
	vn	(@acc[1],@acc[1],$mask);
	vag	(@acc[2],@acc[2],@tmp[1]);	# carry 1->2

	vesrlg	(@tmp[2],@acc[2],26);
	vn	(@acc[2],@acc[2],$mask);
	vag	(@acc[3],@acc[3],@tmp[2]);	# carry 2->3

	vesrlg	(@tmp[3],@acc[3],26);
	vn	(@acc[3],@acc[3],$mask);
	vag	(@acc[4],@acc[4],@tmp[3]);	# carry 3->4

	# acc -> base 2^64
	vleib	("%v30",6*8,7);
	vleib	("%v29",13*8,7);
	vleib	("%v28",3*8,7);

	veslg	(@acc[1],@acc[1],26);
	veslg	(@acc[3],@acc[3],26);
	vo	(@acc[0],@acc[0],@acc[1]);
	vo	(@acc[2],@acc[2],@acc[3]);

	veslg	(@acc[2],@acc[2],4);
	vslb	(@acc[2],@acc[2],"%v30");	# <<52
	vo	(@acc[0],@acc[0],@acc[2]);

	vslb	(@tmp[4],@acc[4],"%v29");	# <<104
	vo	(@acc[0],@acc[0],@tmp[4]);

	vsrlb	(@acc[1],@acc[4],"%v28");	# >>24

	# acc %= 2^130-5
	vone	("%v26");
	vleig	("%v27",5,1);
	vone	("%v29");
	vleig	("%v26",-4,1);

	vaq	(@tmp[0],@acc[0],"%v27");
	vaccq	(@tmp[1],@acc[0],"%v27");

	vaq	(@tmp[1],@tmp[1],"%v26");
	vaccq	(@tmp[1],@tmp[1],@acc[1]);

	vaq	(@tmp[1],@tmp[1],"%v29");

	vn	(@tmp[2],@tmp[1],@acc[0]);
	vnc	(@tmp[3],@tmp[0],@tmp[1]);
	vo	(@acc[0],@tmp[2],@tmp[3]);

	# acc += nonce
	vl	(@vperm[0],"64(%r5)");
	vlef	(@tmp[0],"4*$_($nonce)",3-$_) for (0..3);

	vaq	(@acc[0],@acc[0],@tmp[0]);

	vperm	(@acc[0],@acc[0],@acc[0],@vperm[0]);
	vst	(@acc[0],"0($mac)");	# store mac

if ($z) {
	vlm	("%v8","%v15","0($sp)");
	la	($sp,"$frame($sp)");
} else {
	ld	("%f4","16*$SIZE_T+2*8($sp)");
	ld	("%f6","16*$SIZE_T+3*8($sp)");
}
	br	("%r14");
SIZE	("poly1305_emit_vx",".-poly1305_emit_vx");
}
}

# NOVX CODE PATH
{
################
# static void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
#                             u32 padbit)
{
my ($ctx,$inp,$len,$padbit) = map("%r$_",(2..5));

my ($d0hi,$d0lo,$d1hi,$d1lo,$t0,$h0,$t1,$h1,$h2) = map("%r$_",(6..14));
my ($r0,$r1,$s1) = map("%r$_",(0..2));
GLOBL	("poly1305_blocks");
TYPE	("poly1305_blocks","\@function");
ALIGN	(16);
LABEL	("poly1305_blocks");
$z?	srlg	($len,$len,4)	:srl	($len,4);
	lghi	("%r0",0);
&{$z?	\&clgr:\&clr}	($len,"%r0");
	je	(".Lno_data");

&{$z?	\&stmg:\&stm}	("%r6","%r14","6*$SIZE_T($sp)");

	llgfr	($padbit,$padbit);	# clear upper half, much needed with
					# non-64-bit ABI
	lg	($r0,"32($ctx)");	# load key
	lg	($r1,"40($ctx)");

	lg	($h0,"0($ctx)");	# load hash value
	lg	($h1,"8($ctx)");
	lg	($h2,"16($ctx)");

&{$z?	\&stg:\&st}	($ctx,"2*$SIZE_T($sp)");	# off-load $ctx
	srlg	($s1,$r1,2);
	algr	($s1,$r1);			# s1 = r1 + r1>>2
	j	(".Loop");

ALIGN	(16);
LABEL	(".Loop");
	lrvg	($d0lo,"0($inp)");	# load little-endian input
	lrvg	($d1lo,"8($inp)");
	la	($inp,"16($inp)");

	algr	($d0lo,$h0);		# accumulate input
	alcgr	($d1lo,$h1);

	lgr	($h0,$d0lo);
	mlgr	($d0hi,$r0);		# h0*r0	  -> $d0hi:$d0lo
	lgr	($h1,$d1lo);
	mlgr	($d1hi,$s1);		# h1*5*r1 -> $d1hi:$d1lo

	mlgr	($t0,$r1);		# h0*r1   -> $t0:$h0
	mlgr	($t1,$r0);		# h1*r0   -> $t1:$h1
	alcgr	($h2,$padbit);

	algr	($d0lo,$d1lo);
	lgr	($d1lo,$h2);
	alcgr	($d0hi,$d1hi);
	lghi	($d1hi,0);

	algr	($h1,$h0);
	alcgr	($t1,$t0);

	msgr	($d1lo,$s1);		# h2*s1
	msgr	($h2,$r0);		# h2*r0

	algr	($h1,$d1lo);
	alcgr	($t1,$d1hi);		# $d1hi is zero

	algr	($h1,$d0hi);
	alcgr	($h2,$t1);

	lghi	($h0,-4);		# final reduction step
	ngr	($h0,$h2);
	srlg	($t0,$h2,2);
	algr	($h0,$t0);
	lghi	($t1,3);
	ngr	($h2,$t1);

	algr	($h0,$d0lo);
	alcgr	($h1,$d1hi);		# $d1hi is still zero
	alcgr	($h2,$d1hi);		# $d1hi is still zero

&{$z?	\&brctg:\&brct}	($len,".Loop");

&{$z?	\&lg:\&l}	($ctx,"2*$SIZE_T($sp)");# restore $ctx

	stg	($h0,"0($ctx)");	# store hash value
	stg	($h1,"8($ctx)");
	stg	($h2,"16($ctx)");

&{$z?	\&lmg:\&lm}	("%r6","%r14","6*$SIZE_T($sp)");
LABEL	(".Lno_data");
	br	("%r14");
SIZE	("poly1305_blocks",".-poly1305_blocks");
}

################
# static void poly1305_emit(void *ctx, unsigned char mac[16],
#                           const u32 nonce[4])
{
my ($ctx,$mac,$nonce) = map("%r$_",(2..4));
my ($h0,$h1,$h2,$d0,$d1)=map("%r$_",(5..9));

GLOBL	("poly1305_emit");
TYPE	("poly1305_emit","\@function");
ALIGN	(16);
LABEL	("poly1305_emit");
&{$z?	\&stmg:\&stm}	("%r6","%r9","6*$SIZE_T($sp)");

	lg	($h0,"0($ctx)");
	lg	($h1,"8($ctx)");
	lg	($h2,"16($ctx)");

	lghi	("%r0",5);
	lghi	("%r1",0);
	lgr	($d0,$h0);
	lgr	($d1,$h1);

	algr	($h0,"%r0");		# compare to modulus
	alcgr	($h1,"%r1");
	alcgr	($h2,"%r1");

	srlg	($h2,$h2,2);		# did it borrow/carry?
	slgr	("%r1",$h2);		# 0-$h2>>2
	lg	($h2,"0($nonce)");	# load nonce
	lghi	("%r0",-1);
	lg	($ctx,"8($nonce)");
	xgr	("%r0","%r1");		# ~%r1

	ngr	($h0,"%r1");
	ngr	($d0,"%r0");
	ngr	($h1,"%r1");
	ngr	($d1,"%r0");
	ogr	($h0,$d0);
	rllg	($d0,$h2,32);		# flip nonce words
	ogr	($h1,$d1);
	rllg	($d1,$ctx,32);

	algr	($h0,$d0);		# accumulate nonce
	alcgr	($h1,$d1);

	strvg	($h0,"0($mac)");	# write little-endian result
	strvg	($h1,"8($mac)");

&{$z?	\&lmg:\&lm}	("%r6","%r9","6*$SIZE_T($sp)");
	br	("%r14");
SIZE	("poly1305_emit",".-poly1305_emit");
}
}
################

ALIGN	(128);
LABEL	(".Lconst");
LONG	(0x00060504,0x03020100,0x00161514,0x13121110);	# vperm op[m[1],m[0]]
LONG	(0x000c0b0a,0x09080706,0x001c1b1a,0x19181716);	# vperm op[m[3],m[2]]
LONG	(0x00000000,0x000f0e0d,0x00000000,0x001f1e1d);	# vperm op[  - ,m[4]]
LONG	(0x00000000,0x03ffffff,0x00000000,0x03ffffff);	# [0,2^26-1,0,2^26-1]
LONG	(0x0f0e0d0c,0x0b0a0908,0x07060504,0x03020100);	# vperm op endian
STRING	("\"Poly1305 for s390x, CRYPTOGAMS by <appro\@openssl.org>\"");

PERLASM_END();
