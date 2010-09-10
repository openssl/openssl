#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# September 2010.

while (($output=shift) && ($output!~/^\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$Zhi="%r0";
$Zlo="%r1";

$Xi="%r2";	# argument block
$Htbl="%r3";
$inp="%r4";
$len="%r5";

$rem0="%r6";	# variables
$rem1="%r7";
$nlo="%r8";
$nhi="%r9";
$xi="%r10";
$cnt="%r11";
$tmp="%r12";
$x78="%r13";
$rem_4bit="%r14";

$sp="%r15";

$code.=<<___;
.text

.globl	gcm_gmult_4bit
.align	32
gcm_gmult_4bit:
	stmg	%r6,%r14,48($sp)

	aghi	$Xi,-1
	lghi	$len,1
	lghi	$x78,`0xf<<3`
	larl	$rem_4bit,rem_4bit

	lg	$Zlo,8+1($Xi)		# Xi
	j	.Lgmult_shortcut
.type	gcm_gmult_4bit,\@function
.size	gcm_gmult_4bit,(.-gcm_gmult_4bit)

.globl	gcm_ghash_4bit
.align	32
gcm_ghash_4bit:
	stmg	%r6,%r14,48($sp)

	aghi	$Xi,-1
	srlg	$len,$len,4
	lghi	$x78,`0xf<<3`
	larl	$rem_4bit,rem_4bit

	lg	$Zlo,8+1($Xi)		# Xi
	lg	$Zhi,0+1($Xi)
.Louter:
	xg	$Zlo,8($inp)		# Xi ^= inp 
	xg	$Zhi,0($inp)
	stg	$Zlo,8+1($Xi)
	stg	$Zhi,0+1($Xi)

.Lgmult_shortcut:
	lghi	$tmp,0xff
	srlg	$xi,$Zlo,8		# extract first two bytes
	lgr	$nhi,$Zlo
	ngr	$xi,$tmp
	ngr	$nhi,$tmp

	sllg	$nlo,$nhi,4
	nill	$nhi,0xf0
	nill	$nlo,0xf0
	lghi	$cnt,14

	lg	$Zlo,8($nlo,$Htbl)
	lg	$Zhi,0($nlo,$Htbl)

	sllg	$nlo,$xi,4
	nill	$xi,0xf0
	sllg	$rem0,$Zlo,3
	nill	$nlo,0xf0

	srlg	$Zlo,$Zlo,4
	ngr	$rem0,$x78
	sllg	$tmp,$Zhi,60
	xg	$Zlo,8($nhi,$Htbl)
	srlg	$Zhi,$Zhi,4
	xgr	$Zlo,$tmp
	xg	$Zhi,0($nhi,$Htbl)
	lgr	$nhi,$xi
	sllg	$rem1,$Zlo,3

.Lghash_inner:
	srlg	$Zlo,$Zlo,4
	ngr	$rem1,$x78
	xg	$Zlo,8($nlo,$Htbl)
	sllg	$tmp,$Zhi,60
	xg	$Zhi,0($rem0,$rem_4bit)
	xgr	$Zlo,$tmp
	srlg	$Zhi,$Zhi,4
	llgc	$xi,0($cnt,$Xi)
	sllg	$rem0,$Zlo,3
	xg	$Zhi,0($nlo,$Htbl)
	sllg	$nlo,$xi,4
	nill	$xi,0xf0
	nill	$nlo,0xf0

	srlg	$Zlo,$Zlo,4
	ngr	$rem0,$x78
	xg	$Zlo,8($nhi,$Htbl)
	sllg	$tmp,$Zhi,60
	xg	$Zhi,0($rem1,$rem_4bit)
	xgr	$Zlo,$tmp
	srlg	$Zhi,$Zhi,4
	sllg	$rem1,$Zlo,3
	xg	$Zhi,0($nhi,$Htbl)
	lgr	$nhi,$xi
	brct	$cnt,.Lghash_inner

	srlg	$Zlo,$Zlo,4
	ngr	$rem1,$x78
	xg	$Zlo,8($nlo,$Htbl)
	sllg	$tmp,$Zhi,60
	xg	$Zhi,0($rem0,$rem_4bit)
	xgr	$Zlo,$tmp
	srlg	$Zhi,$Zhi,4
	sllg	$rem0,$Zlo,3
	xg	$Zhi,0($nlo,$Htbl)

	srlg	$Zlo,$Zlo,4
	ngr	$rem0,$x78
	xg	$Zhi,0($rem1,$rem_4bit)
	sllg	$tmp,$Zhi,60
	xg	$Zlo,8($nhi,$Htbl)
	srlg	$Zhi,$Zhi,4
	xgr	$Zlo,$tmp
	xg	$Zhi,0($nhi,$Htbl)

	la	$inp,16($inp)
	xg	$Zhi,0($rem0,$rem_4bit)
	brctg	$len,.Louter

	stg	$Zlo,8+1($Xi)
	stg	$Zhi,0+1($Xi)
	lmg	%r6,%r14,48($sp)
	br	%r14
.type	gcm_ghash_4bit,\@function
.size	gcm_ghash_4bit,(.-gcm_ghash_4bit)

.align	64
rem_4bit:
	.long	`0x0000<<16`,0,`0x1C20<<16`,0,`0x3840<<16`,0,`0x2460<<16`,0
	.long	`0x7080<<16`,0,`0x6CA0<<16`,0,`0x48C0<<16`,0,`0x54E0<<16`,0
	.long	`0xE100<<16`,0,`0xFD20<<16`,0,`0xD940<<16`,0,`0xC560<<16`,0
	.long	`0x9180<<16`,0,`0x8DA0<<16`,0,`0xA9C0<<16`,0,`0xB5E0<<16`,0
.type	rem_4bit,\@object
.size	rem_4bit,(.-rem_4bit)
.string	"GHASH for s390x, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
