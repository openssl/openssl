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
# If compared to compiler-generated code with similar characteristics,
# i.e. compiled with OPENSSL_SMALL_FOOTPRINT and utilizing SPLOOPs,
# this implementation is 25% smaller and >2x faster. In absolute terms
# performance is (quite impressive) ~6.5 cycles per processed byte.
# Unlike its predecessor, sha1-c64xplus module, this module has worse
# interrupt agility. While original added up to 5 cycles delay to
# response to interrupt, this module adds up to 100. Fully unrolled
# implementation doesn't add any delay and even 25% faster, but is
# almost 5x larger...
#
# !!! Note that this module uses AMR, which means that all interrupt
# service routines are expected to preserve it and for own well-being
# zero it upon entry.

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

($CTX,$INP,$NUM) = ("A4","B4","A6");		# arguments

($A,$B,$C,$D,$E, $Arot,$F,$F0,$T,$K) = map("A$_",(16..20, 21..25));
($X0,$X2,$X8,$X13) = ("A26","B26","A27","B27");
($TX0,$TX1,$TX2,$TX3) = map("B$_",(28..31));
($XPA,$XPB) = ("A5","B5");			# X circular buffer
($Actx,$Bctx,$Cctx,$Dctx,$Ectx) = map("A$_",(3,6..9));	# zaps $NUM

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
	.asmfunc stack_usage(64)
	MV	$NUM,A0			; reassign $NUM
||	MVK	-64,B0
  [!A0]	BNOP	RA			; if ($NUM==0) return;
|| [A0]	STW	FP,*SP--[16]		; save frame pointer and alloca(64)
|| [A0]	MV	SP,FP
   [A0]	LDW	*${CTX}[0],$A		; load A-E...
|| [A0]	AND	B0,SP,SP		; align stack at 64 bytes
   [A0]	LDW	*${CTX}[1],$B
|| [A0]	SUBAW	SP,2,SP			; reserve two words above buffer
   [A0]	LDW	*${CTX}[2],$C
|| [A0]	MVK	0x00404,B0
   [A0]	LDW	*${CTX}[3],$D
|| [A0]	MVKH	0x50000,B0		; 0x050404, 64 bytes for $XP[AB]
   [A0]	LDW	*${CTX}[4],$E
|| [A0]	MVC	B0,AMR			; setup circular addressing
	LDNW	*${INP}++,$TX1		; pre-fetch input
	NOP	1

loop?:
	MVKL	0x5a827999,$K
||	ADDAW	SP,2,$XPB
||	SUB	A0,1,A0
	MVKH	0x5a827999,$K		; K_00_19
||	MV	$A,$Actx
||	MV	$B,$Bctx
;;==================================================
	B	body_00_13?		; BODY_00_13
||	MVK	11,B0
||	MV	$XPB,$XPA
||	MV	$C,$Cctx
||	MV	$D,$Dctx
||	MVD	$E,$Ectx

body_00_13?:
	ROTL	$A,5,$Arot
||	AND	$C,$B,$F
||	ANDN	$D,$B,$F0
||	ADD	$K,$E,$T		; T=E+K

	XOR	$F0,$F,$F		; F_00_19(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C
||	SWAP2	$TX1,$TX2
||	LDNW	*${INP}++,$TX1

	ADD	$F,$T,$T		; T+=F_00_19(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	SWAP4	$TX2,$TX3		; byte swap

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A

	ADD	$TX3,$T,$A		; A=T+Xi
||	STW	$TX3,*${XPB}++
||	BDEC	body_00_13?,B0
;;==================================================
	ROTL	$A,5,$Arot		; BODY_14
||	AND	$C,$B,$F
||	ANDN	$D,$B,$F0
||	ADD	$K,$E,$T		; T=E+K

	XOR	$F0,$F,$F		; F_00_19(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C
||	SWAP2	$TX1,$TX2
||	LDNW	*${INP}++,$TX1

	ADD	$F,$T,$T		; T+=F_00_19(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	SWAP4	$TX2,$TX2		; byte swap
||	LDW	*${XPA}++,$X0		; fetches from X ring buffer are
||	LDW	*${XPB}[4],$X2		; 2 iterations ahead

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A
||	LDW	*${XPA}[7],$X8
||	MV	$TX3,$X13		; ||	LDW	*${XPB}[15],$X13
||	MV	$TX2,$TX3

	ADD	$TX2,$T,$A		; A=T+Xi
||	STW	$TX2,*${XPB}++
;;==================================================
	ROTL	$A,5,$Arot		; BODY_15
||	AND	$C,$B,$F
||	ANDN	$D,$B,$F0
||	ADD	$K,$E,$T		; T=E+K

	XOR	$F0,$F,$F		; F_00_19(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C
||	SWAP2	$TX1,$TX2

	ADD	$F,$T,$T		; T+=F_00_19(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	SWAP4	$TX2,$TX2		; byte swap
||	XOR	$X0,$X2,$TX0		; Xupdate XORs are 1 iteration ahead
||	LDW	*${XPA}++,$X0
||	LDW	*${XPB}[4],$X2

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A
||	XOR	$X8,$X13,$TX1
||	LDW	*${XPA}[7],$X8
||	MV	$TX3,$X13		; ||	LDW	*${XPB}[15],$X13
||	MV	$TX2,$TX3

	ADD	$TX2,$T,$A		; A=T+Xi
||	STW	$TX2,*${XPB}++
||	XOR	$TX0,$TX1,$TX1
;;==================================================
||	B	body_16_19?		; BODY_16_19
||	MVK	1,B0

body_16_19?:
	ROTL	$A,5,$Arot
||	AND	$C,$B,$F
||	ANDN	$D,$B,$F0
||	ADD	$K,$E,$T		; T=E+K
||	ROTL	$TX1,1,$TX2		; Xupdate output

	XOR	$F0,$F,$F		; F_00_19(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C

	ADD	$F,$T,$T		; T+=F_00_19(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	XOR	$X0,$X2,$TX0
||	LDW	*${XPA}++,$X0
||	LDW	*${XPB}[4],$X2

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A
||	XOR	$X8,$X13,$TX1
||	LDW	*${XPA}[7],$X8
||	MV	$TX3,$X13		; ||	LDW	*${XPB}[15],$X13
||	MV	$TX2,$TX3

	ADD	$TX2,$T,$A		; A=T+Xi
||	STW	$TX2,*${XPB}++
||	XOR	$TX0,$TX1,$TX1
||	BDEC	body_16_19?,B0

	MVKL	0x6ed9eba1,$K
||	MVK	17,B0
	MVKH	0x6ed9eba1,$K		; K_20_39
___
sub BODY_20_39 {
my $label = shift;
$code.=<<___;
;;==================================================
||	B	$label			; BODY_20_39

$label:
	ROTL	$A,5,$Arot
||	XOR	$B,$C,$F
||	ADD	$K,$E,$T		; T=E+K
||	ROTL	$TX1,1,$TX2		; Xupdate output

	XOR	$D,$F,$F		; F_20_39(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C

	ADD	$F,$T,$T		; T+=F_20_39(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	XOR	$X0,$X2,$TX0
||	LDW	*${XPA}++,$X0
||	LDW	*${XPB}[4],$X2

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A
||	XOR	$X8,$X13,$TX1
||	LDW	*${XPA}[7],$X8
||	MV	$TX3,$X13		; ||	LDW	*${XPB}[15],$X13
||	MV	$TX2,$TX3

	ADD	$TX2,$T,$A		; A=T+Xi
||	STW	$TX2,*${XPB}++		; last one is redundant
||	XOR	$TX0,$TX1,$TX1
||	BDEC	$label,B0
___
}	&BODY_20_39("body_20_39?");
$code.=<<___;
;;==================================================
	MVKL	0x8f1bbcdc,$K
||	MVK	17,B0
	MVKH	0x8f1bbcdc,$K		; K_40_59
||	B	body_40_59?		; BODY_40_59
||	AND	$B,$C,$F
||	AND	$B,$D,$F0

body_40_59?:
	ROTL	$A,5,$Arot
||	XOR	$F0,$F,$F
||	AND	$C,$D,$F0
||	ADD	$K,$E,$T		; T=E+K
||	ROTL	$TX1,1,$TX2		; Xupdate output

	XOR	$F0,$F,$F		; F_40_59(B,C,D)
||	MV	$D,$E			; E=D
||	MV	$C,$D			; D=C

	ADD	$F,$T,$T		; T+=F_40_59(B,C,D)
||	ROTL	$B,30,$C		; C=ROL(B,30)
||	XOR	$X0,$X2,$TX0
||	LDW	*${XPA}++,$X0
||	LDW	*${XPB}[4],$X2

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	MV	$A,$B			; B=A
||	XOR	$X8,$X13,$TX1
||	LDW	*${XPA}[7],$X8
||	MV	$TX3,$X13		; ||	LDW	*${XPB}[15],$X13
||	MV	$TX2,$TX3

	ADD	$TX2,$T,$A		; A=T+Xi
||	STW	$TX2,*${XPB}++
||	XOR	$TX0,$TX1,$TX1
||	AND	$B,$C,$F
||	AND	$B,$D,$F0
||	BDEC	body_40_59?,B0

	MVKL	0xca62c1d6,$K
||	MVK	16,B0
	MVKH	0xca62c1d6,$K		; K_60_79
___
	&BODY_20_39("body_60_78?");	# BODY_60_78
$code.=<<___;
;;==================================================
   [A0]	B	loop?
||	ROTL	$A,5,$Arot		; BODY_79
||	XOR	$B,$C,$F
||	ROTL	$TX1,1,$TX2		; Xupdate output

   [A0]	LDNW	*${INP}++,$TX1		; pre-fetch input
||	ADD	$K,$E,$T		; T=E+K
||	XOR	$D,$F,$F		; F_20_39(B,C,D)

	ADD	$F,$T,$T		; T+=F_20_39(B,C,D)
||	ADD	$Ectx,$D,$E		; E=D,E+=Ectx
||	ADD	$Dctx,$C,$D		; D=C,D+=Dctx
||	ROTL	$B,30,$C		; C=ROL(B,30)

	ADD	$Arot,$T,$T		; T+=ROL(A,5)
||	ADD	$Bctx,$A,$B		; B=A,B+=Bctx

	ADD	$TX2,$T,$A		; A=T+Xi

	ADD	$Actx,$A,$A		; A+=Actx
||	ADD	$Cctx,$C,$C		; C+=Cctx
;; end of loop?

	BNOP	RA			; return
||	MV	FP,SP			; restore stack pointer
||	LDW	*FP[0],FP		; restore frame pointer
	STW	$A,*${CTX}[0]		; emit A-E...
||	MVK	0,B0
	STW	$B,*${CTX}[1]
||	MVC	B0,AMR			; clear AMR
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
