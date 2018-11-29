;; Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
;;
;; Licensed under the OpenSSL license (the "License").  You may not use
;; this file except in compliance with the License.  You can obtain a copy
;; in the file LICENSE in the source distribution or at
;; https://www.openssl.org/source/license.html
;;
;; ====================================================================
;; Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
;; project. The module is dual licensed under OpenSSL and CRYPTOGAMS
;; licenses depending on where you obtain it. For further details see
;; https://github.com/dot-asm/cryptogams/.
;; ====================================================================

	.text

	.if	.ASSEMBLER_VERSION<7000000
	.asg	0,__TI_EABI__
	.endif
	.if	__TI_EABI__
	.asg	bn_div_3_words,_bn_div_3_words
	.endif

	.asg	B3,RA
	.asg	A4,ARG0
	.asg	A4,Q			; RET
	.asg	B4,Dlo			; ARG1
	.asg	A6,Dhi			; ARG2
	.asg	B5,Dhi_
	.asg	B2,Rlo
	.asg	A2,Rhi

	.global	_bn_div_3_words
_bn_div_3_words:
	.asmfunc
	.if	.TMS320C6400_PLUS
	SUB	ARG0,4,B0
||	MVK	32,B1
	LDW	*B0,Rlo
||	LDW	*ARG0,Rhi
||	MVC	B1,ILC
	NOP	4

	SPLOOP	3
||	MV	Dhi,Dhi_
||	MVK	0,Q			; Q = 0
	SUBU	Rlo,Dlo,B1:B0		; R - D
||	SUBU	Rhi,Dhi,A1:A0
||	SHRU	Dhi_:Dlo,1,Dhi_:Dlo	; D >>= 1
||	SHRU	Dhi,1,Dhi
   [B1]	SUB	A1:A0,1,A1:A0
||      ADD	Q,Q,Q			; Q <<= 1
  [!A1]	MV	B0,Rlo			; choose between R and R - D
||[!A1]	MV	A0,Rhi
||[!A1]	OR	Q,1,Q
||	MV	Dhi,Dhi_
	SPKERNEL
	.else
	;; C64x, i.e. without plus, doesn't have SPLOOP, and as result
	;; below loop can postpone interrupts by up to 96 cycles. 
	.asg	B6,Dhi			; re-assign
	SUB	ARG0,4,B0
	LDW	*B0,Rlo
||	LDW	*ARG0,Rhi

	MVK	30,A3
	BDEC	loop?,A3

	MV	Dhi,Dhi_
||	MVK	0,Q			; Q = 0
||	NOP	2
loop?:
	BDEC	loop?,A3
||	SUBU	Rlo,Dlo,B1:B0		; R - D
||	SUBU	Rhi,Dhi_,A1:A0
||	MV	Dhi_,Dhi
||	SHRU	Dhi_:Dlo,1,Dhi_:Dlo	; D >>= 1
   [B1]	SUB	A1:A0,1,A1:A0
||	SHRU	Dhi,1,Dhi_
||      ADD	Q,Q,Q			; Q <<= 1
  [!A1]	MV	B0,Rlo			; choose between R and R - D
||[!A1]	MV	A0,Rhi
||[!A1]	OR	Q,1,Q
	.endif

	BNOP	RA,1
	SUBU	Rlo,Dlo,B1:B0
||	SUBU	Rhi,Dhi_,A1:A0
   [B1]	SUB	A1:A0,1,A1:A0
||	SHR	Q,31,A2			; top bit -> mask
||	ADD	Q,Q,Q			; Q <<= 1
  [!A1]	OR	Q,1,Q
	OR	Q,A2,Q			; if overflow, return all ones
	.endasmfunc
