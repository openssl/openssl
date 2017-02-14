#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# SHA1 for C64x.
#
# November 2016
#
# This is fully-unrolled SHA1 implementation. It's 25% faster than
# one with compact loops, doesn't use in-memory ring buffer, as
# everything is accomodated in registers, and has "perfect" interrupt
# agility. Drawback is obviously the code size...

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

($CTX,$INP,$NUM) = ("A4","B4","A6");		# arguments

($A,$B,$C,$D,$E, $Arot,$F,$F0,$K) = map("A$_",(16..20, 21..24));
@V = ($A,$B,$C,$D,$E);
@X = map("B$_",(16..31));
($Actx,$Bctx,$Cctx,$Dctx,$Ectx) = map("A$_",(3,6..9));	# zaps $NUM

sub BODY_00_19 {
my ($i,$a,$b,$c,$d,$e) = @_;
my $j = ($i+1)&15;

$code.=<<___				if ($i<14);
	ROTL	$a,5,$Arot		;; $i
||	AND	$c,$b,$F
||	ANDN	$d,$b,$F0
||	ADD	$K,$e,$e		; E+=K
||	 LDNW	*${INP}++,@X[$i+2]
	OR	$F0,$F,$F		; F_00_19(B,C,D)
||	ROTL	$b,30,$b
||	 SWAP2	@X[$i+1],@X[$i+1]
||	ADD	@X[$i],$e,$e		; E+=X[i]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 SWAP4	@X[$i+1],@X[$i+1]
	ADD	$F,$e,$e		; E+=F_00_19(B,C,D)
___
$code.=<<___				if ($i==14);
	ROTL	$a,5,$Arot		;; $i
||	AND	$c,$b,$F
||	ANDN	$d,$b,$F0
||	ADD	$K,$e,$e		; E+=K
	OR	$F0,$F,$F		; F_00_19(B,C,D)
||	ROTL	$b,30,$b
||	ADD	@X[$i],$e,$e		; E+=X[i]
||	 SWAP2	@X[$i+1],@X[$i+1]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 SWAP4	@X[$i+1],@X[$i+1]
	ADD	$F,$e,$e		; E+=F_00_19(B,C,D)
___
$code.=<<___				if ($i==15);
||	 XOR	@X[($j+2)&15],@X[$j],@X[$j]
	ROTL	$a,5,$Arot		;; $i
||	AND	$c,$b,$F
||	ANDN	$d,$b,$F0
||	ADD	$K,$e,$e		; E+=K
||	 XOR	@X[($j+8)&15],@X[$j],@X[$j]
	OR	$F0,$F,$F		; F_00_19(B,C,D)
||	ROTL	$b,30,$b
||	ADD	@X[$i],$e,$e		; E+=X[i]
||	 XOR	@X[($j+13)&15],@X[$j],@X[$j]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 ROTL	@X[$j],1,@X[$j]
	ADD	$F,$e,$e		; E+=F_00_19(B,C,D)
___
$code.=<<___				if ($i>15);
||	 XOR	@X[($j+2)&15],@X[$j],@X[$j]
	ROTL	$a,5,$Arot		;; $i
||	AND	$c,$b,$F
||	ANDN	$d,$b,$F0
||	ADD	$K,$e,$e		; E+=K
||	 XOR	@X[($j+8)&15],@X[$j],@X[$j]
	OR	$F0,$F,$F		; F_00_19(B,C,D)
||	ROTL	$b,30,$b
||	ADD	@X[$i&15],$e,$e		; E+=X[i]
||	 XOR	@X[($j+13)&15],@X[$j],@X[$j]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 ROTL	@X[$j],1,@X[$j]
	ADD	$F,$e,$e		; E+=F_00_19(B,C,D)
___
}

sub BODY_20_39 {
my ($i,$a,$b,$c,$d,$e) = @_;
my $j = ($i+1)&15;

$code.=<<___				if ($i<79);
||	 XOR	@X[($j+2)&15],@X[$j],@X[$j]
	ROTL	$a,5,$Arot		;; $i
||	XOR	$c,$b,$F
||	ADD	$K,$e,$e		; E+=K
||	 XOR	@X[($j+8)&15],@X[$j],@X[$j]
	XOR	$d,$F,$F		; F_20_39(B,C,D)
||	ROTL	$b,30,$b
||	ADD	@X[$i&15],$e,$e		; E+=X[i]
||	 XOR	@X[($j+13)&15],@X[$j],@X[$j]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 ROTL	@X[$j],1,@X[$j]
	ADD	$F,$e,$e		; E+=F_20_39(B,C,D)
___
$code.=<<___				if ($i==79);
|| [A0]	B	loop?
|| [A0]	LDNW	*${INP}++,@X[0]		; pre-fetch input
	ROTL	$a,5,$Arot		;; $i
||	XOR	$c,$b,$F
||	ADD	$K,$e,$e		; E+=K
|| [A0]	LDNW	*${INP}++,@X[1]
	XOR	$d,$F,$F		; F_20_39(B,C,D)
||	ROTL	$b,30,$b
||	ADD	@X[$i&15],$e,$e		; E+=X[i]
	ADD	$Arot,$e,$e		; E+=rot(A,5)
	ADD	$F,$e,$e		; E+=F_20_39(B,C,D)
||	ADD	$Bctx,$a,$a		; accumulate context
||	ADD	$Cctx,$b,$b
	ADD	$Dctx,$c,$c
||	ADD	$Ectx,$d,$d
||	ADD	$Actx,$e,$e
;;===== branch to loop? is taken here
___
}

sub BODY_40_59 {
my ($i,$a,$b,$c,$d,$e) = @_;
my $j = ($i+1)&15;

$code.=<<___;
||	 XOR	@X[($j+2)&15],@X[$j],@X[$j]
	ROTL	$a,5,$Arot		;; $i
||	AND	$c,$b,$F
||	AND	$d,$b,$F0
||	ADD	$K,$e,$e		; E+=K
||	 XOR	@X[($j+8)&15],@X[$j],@X[$j]
	XOR	$F0,$F,$F
||	AND	$c,$d,$F0
||	ROTL	$b,30,$b
||	 XOR	@X[($j+13)&15],@X[$j],@X[$j]
||	ADD	@X[$i&15],$e,$e		; E+=X[i]
	XOR	$F0,$F,$F		; F_40_59(B,C,D)
||	ADD	$Arot,$e,$e		; E+=rot(A,5)
||	 ROTL	@X[$j],1,@X[$j]
	ADD	$F,$e,$e		; E+=F_20_39(B,C,D)
___
}

$code=<<___;
	.text

	.if	.ASSEMBLER_VERSION<7000000
	.asg	0,__TI_EABI__
	.endif
	.if	__TI_EABI__
	.asg	sha1_block_data_order,_sha1_block_data_order
	.endif

	.asg	B3,RA
	.asg	A15,FP
	.asg	B15,SP

	.if	.BIG_ENDIAN
	.asg	MV,SWAP2
	.asg	MV,SWAP4
	.endif

	.global	_sha1_block_data_order
_sha1_block_data_order:
	.asmfunc
	MV	$NUM,A0			; reassign $NUM
  [!A0]	BNOP	RA			; if ($NUM==0) return;
|| [A0]	LDW	*${CTX}[0],$A		; load A-E...
   [A0]	LDW	*${CTX}[1],$B
   [A0]	LDW	*${CTX}[2],$C
   [A0]	LDW	*${CTX}[3],$D
   [A0]	LDW	*${CTX}[4],$E
   [A0]	LDNW	*${INP}++,@X[0]		; pre-fetch input
   [A0]	LDNW	*${INP}++,@X[1]
	NOP	3

loop?:
	SUB	A0,1,A0
||	MV	$A,$Actx
||	MVD	$B,$Bctx
||	SWAP2	@X[0],@X[0]
||	MVKL	0x5a827999,$K
	MVKH	0x5a827999,$K		; K_00_19
||	MV	$C,$Cctx
||	MV	$D,$Dctx
||	MVD	$E,$Ectx
||	SWAP4	@X[0],@X[0]
___
for ($i=0;$i<20;$i++)	{ &BODY_00_19($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
||	MVKL	0x6ed9eba1,$K
	MVKH	0x6ed9eba1,$K		; K_20_39
___
for (;$i<40;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
||	MVKL	0x8f1bbcdc,$K
	MVKH	0x8f1bbcdc,$K		; K_40_59
___
for (;$i<60;$i++)	{ &BODY_40_59($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
||	MVKL	0xca62c1d6,$K
	MVKH	0xca62c1d6,$K		; K_60_79
___
for (;$i<80;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	BNOP	RA			; return
	STW	$A,*${CTX}[0]		; emit A-E...
	STW	$B,*${CTX}[1]
	STW	$C,*${CTX}[2]
	STW	$D,*${CTX}[3]
	STW	$E,*${CTX}[4]
	.endasmfunc

	.sect	.const
	.cstring "SHA1 block transform for C64x, CRYPTOGAMS by <appro\@openssl.org>"
	.align	4
___

print $code;
close STDOUT;
