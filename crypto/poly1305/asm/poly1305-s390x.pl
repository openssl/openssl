#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
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

use FindBin qw($Bin);
use lib "$Bin/../..";
use perlasm::s390x qw(:DEFAULT AUTOLOAD LABEL);

$flavour = shift;

if ($flavour =~ /3[12]/) {
	$z=0;	# S/390 ABI
	$SIZE_T=4;
} else {
	$z=1;	# zSeries ABI
	$SIZE_T=8;
}

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}

$sp="%r15";

my ($ctx,$inp,$len,$padbit) = map("%r$_",(2..5));

PERLASM_BEGIN($output);

TEXT	();

GLOBL	("poly1305_init");
TYPE	("poly1305_init","\@function");
ALIGN	(16);
LABEL	("poly1305_init");
	lghi	("%r0",0);
	lghi	("%r1",-1);
	stg	("%r0","0($ctx)");	# zero hash value
	stg	("%r0","8($ctx)");
	stg	("%r0","16($ctx)");

&{$z?	\&clgr:\&clr}	($inp,"%r0");
	je	(".Lno_key");

	lrvg	("%r4","0($inp)");	# load little-endian key
	lrvg	("%r5","8($inp)");

	nihl	("%r1",0xffc0);		# 0xffffffc0ffffffff
	srlg	("%r0","%r1",4);	# 0x0ffffffc0fffffff
	srlg	("%r1","%r1",4);
	nill	("%r1",0xfffc);		# 0x0ffffffc0ffffffc

	ngr	("%r4","%r0");
	ngr	("%r5","%r1");

	stg	("%r4","32($ctx)");
	stg	("%r5","40($ctx)");

LABEL	(".Lno_key");
	lghi	("%r2",0);
	br	("%r14");
SIZE	("poly1305_init",".-poly1305_init");

{
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
{
my ($mac,$nonce)=($inp,$len);
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

STRING	("\"Poly1305 for s390x, CRYPTOGAMS by <appro\@openssl.org>\"");
}

PERLASM_END();
