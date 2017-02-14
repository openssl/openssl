#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$code.=<<___;
	.text

	.if	.ASSEMBLER_VERSION<7000000
	.asg	0,__TI_EABI__
	.endif
	.if	__TI_EABI__
	.asg	OPENSSL_rdtsc,_OPENSSL_rdtsc
	.asg	OPENSSL_cleanse,_OPENSSL_cleanse
	.asg	CRYPTO_memcmp,_CRYPTO_memcmp
	.asg	OPENSSL_atomic_add,_OPENSSL_atomic_add
	.asg	OPENSSL_wipe_cpu,_OPENSSL_wipe_cpu
	.asg	OPENSSL_instrument_bus,_OPENSSL_instrument_bus
	.asg	OPENSSL_instrument_bus2,_OPENSSL_instrument_bus2
	.endif

	.asg	B3,RA
	.asg	0x01AC0000,TIMER_BASE	; Timer 2

	.global	_OPENSSL_rdtsc
_OPENSSL_rdtsc:
	.asmfunc
	MVKL	TIMER_BASE,A5
	MVKH	TIMER_BASE,A5
	LDW	*A5[0],A2	; load CTL
	LDW	*A5[2],A4	; load CTN
	NOP	2
	.if	.BIG_ENDIAN
	MVK	0x2c0,A7	; internal clock source, don't hold, go
||	MVK	-1,A6		; maximum period
	.else
	MVK	0x2c0,A6	; internal clock source, don't hold, go
||	MVK	-1,A7		; maximum period
	.endif
  [!A2]	STDW	A7:A6,*A5[0]	; fire it up
||	BNOP	RA,5
	.endasmfunc

	.global	_OPENSSL_cleanse
_OPENSSL_cleanse:
	.asmfunc
	ZERO	A3:A2
||	ZERO	B2
||	SHRU	B4,3,B0		; is length >= 8
||	ADD	1,A4,B6
  [!B0]	BNOP	RA
|| [B0]	SUB	B0,1,B2
||	ZERO	A1
||	ZERO	B1
   [B2]	BDEC	cleanse_loop?,B2
||[!B0]	CMPLT	0,B4,A1
||[!B0]	CMPLT	1,B4,B1
||	ZERO	B5
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B2]	BDEC	cleanse_loop?,B2
||[!B0]	CMPLT	2,B4,A1
||[!B0]	CMPLT	3,B4,B1
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B2]	BDEC	cleanse_loop?,B2
||[!B0]	CMPLT	4,B4,A1
||[!B0]	CMPLT	5,B4,B1
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B2]	BDEC	cleanse_loop?,B2
||[!B0]	CMPLT	6,B4,A1
   [A1]	STB	A2,*A4++[2]
|| [B2]	BDEC	cleanse_loop?,B2

cleanse_loop?:
	STNDW	A3:A2,*A4++
||	SUB	B4,8,B4
|| [B2]	BDEC	cleanse_loop?,B2

	MV	B4,B0		; remaining bytes
||	ADD	1,A4,B6
||	BNOP	RA
   [B0]	CMPLT	0,B0,A1
|| [B0]	CMPLT	1,B0,B1
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B0]	CMPLT	2,B0,A1
|| [B0]	CMPLT	3,B0,B1
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B0]	CMPLT	4,B0,A1
|| [B0]	CMPLT	5,B0,B1
   [A1]	STB	A2,*A4++[2]
|| [B1] STB	B5,*B6++[2]
|| [B0]	CMPLT	6,B0,A1
   [A1]	STB	A2,*A4++[2]
	.endasmfunc

	.if	0
	.global	_CRYPTO_memcmp
_CRYPTO_memcmp:
	.asmfunc
	MV	A6,B0
  [!B0]	BNOP	RA
||[!B0]	ZERO	A4
|| [B0]	ZERO	A1:A0
   [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0
   [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0
   [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0
   [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0
   [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0
	XOR	A5,B5,A1
|| [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0

memcmp_loop?:
	OR	A1,A0,A0
||	XOR	A5,B5,A1
|| [B0]	LDBU	*A4++,A5
|| [B0]	LDBU	*B4++,B5
|| [B0]	BDEC	memcmp_loop?,B0

	BNOP	RA,3
	ZERO	A4
  [A0]	MVK	1,A4
	.endasmfunc
	.endif

	.global	_OPENSSL_atomic_add
_OPENSSL_atomic_add:
	.asmfunc
	BNOP	atomic_store?	; pre-C64x+ systems are uni-processor, it's
||	LDW	*A4,B5		; enough to hold interrupts off through
				; the load-update-store cycle to achieve
				; atomicity
	NOP
	BNOP	RA,3		; and this branch stretches even over store
	ADD	B4,B5,B5
atomic_store?:
	STW	B5,*A4
||	MV	B5,A4
	.endasmfunc

	.global	_OPENSSL_wipe_cpu
_OPENSSL_wipe_cpu:
	.asmfunc
	ZERO	A0
||	ZERO	B0
||	ZERO	A1
||	ZERO	B1
	ZERO	A3:A2
||	MVD	B0,B2
||	ZERO	A4
||	ZERO	B4
||	ZERO	A5
||	ZERO	B5
||	BNOP	RA
	ZERO	A7:A6
||	ZERO	B7:B6
||	ZERO	A8
||	ZERO	B8
||	ZERO	A9
||	ZERO	B9
	ZERO	A17:A16
||	ZERO	B17:B16
||	ZERO	A18
||	ZERO	B18
||	ZERO	A19
||	ZERO	B19
	ZERO	A21:A20
||	ZERO	B21:B20
||	ZERO	A22
||	ZERO	B22
||	ZERO	A23
||	ZERO	B23
	ZERO	A25:A24
||	ZERO	B25:B24
||	ZERO	A26
||	ZERO	B26
||	ZERO	A27
||	ZERO	B27
	ZERO	A29:A28
||	ZERO	B29:B28
||	ZERO	A30
||	ZERO	B30
||	ZERO	A31
||	ZERO	B31
	.endasmfunc

CLFLUSH	.macro	CONTROL,ADDR,LEN
	B	passthrough?
||	STW	ADDR,*CONTROL[0]
	STW	LEN,*CONTROL[1]
spinlock?:
	LDW	*CONTROL[1],A0
	NOP	3
passthrough?:
	NOP
  [A0]	BNOP	spinlock?,5
	.endm

	.global	_OPENSSL_instrument_bus
_OPENSSL_instrument_bus:
	.asmfunc
	MV	B4,B0			; reassign sizeof(output)
||	MV	A4,B4			; reassign output
||	MVK	0x00004030,A3
||	MVKL	TIMER_BASE,B16
	MV	B0,A4			; return value
||	MVK	1,A1
||	MVKH	0x01840000,A3		; L1DWIBAR
||	MVKH	TIMER_BASE,B16
	LDW	*B16[2],B8		; collect 1st tick
||	MVK	0x00004010,A5
	NOP	4
	MV	B8,B9			; lasttick = tick
||	MVK	0,B7			; lastdiff = 0
||	MVKH	0x01840000,A5		; L2WIBAR
	CLFLUSH	A3,B4,A1		; write-back and invalidate L1D line
	CLFLUSH	A5,B4,A1		; write-back and invalidate L2 line
	LDW	*B4,B5
	NOP	4
	ADD	B7,B5,B5
	STW	B5,*B4
bus_loop1?:
	LDW	*B16[2],B8
|| [B0]	SUB	B0,1,B0
	NOP	4
	SUB	B8,B9,B7		; lastdiff = tick - lasttick
||	MV	B8,B9			; lasttick = tick
	CLFLUSH	A3,B4,A1		; write-back and invalidate L1D line
	CLFLUSH	A5,B4,A1		; write-back and invalidate L2 line
	LDW	*B4,B5
	NOP	4
	ADD	B7,B5,B5
	STW	B5,*B4			; [!B1] is removed to flatten samples
||	ADDK	4,B4
|| [B0]	BNOP	bus_loop1?,5

	BNOP	RA,5
	.endasmfunc

	.global	_OPENSSL_instrument_bus2
_OPENSSL_instrument_bus2:
	.asmfunc
	MV	A6,B0			; reassign max
||	MV	B4,A6			; reassing sizeof(output)
||	MVK	0x00004030,A3
||	MVKL	TIMER_BASE,B16
	MV	A4,B4			; reassign output
||	MVK	0,A4			; return value
||	MVK	1,A1
||	MVKH	0x01840000,A3		; L1DWIBAR
||	MVKH	TIMER_BASE,B16

	LDW	*B16[2],B8		; collect 1st tick
||	MVK	0x00004010,A5
	NOP	4
	MV	B8,B9			; lasttick = tick
||	MVK	0,B7			; lastdiff = 0
||	MVKH	0x01840000,A5		; L2WIBAR
	CLFLUSH	A3,B4,A1		; write-back and invalidate L1D line
	CLFLUSH	A5,B4,A1		; write-back and invalidate L2 line
	LDW	*B4,B5
	NOP	4
	ADD	B7,B5,B5
	STW	B5,*B4

	LDW	*B16[2],B8		; collect 1st diff
	NOP	4
	SUB	B8,B9,B7		; lastdiff = tick - lasttick
||	MV	B8,B9			; lasttick = tick
||	SUB	B0,1,B0
bus_loop2?:
	CLFLUSH	A3,B4,A1		; write-back and invalidate L1D line
	CLFLUSH	A5,B4,A1		; write-back and invalidate L2 line
	LDW	*B4,B5
	NOP	4
	ADD	B7,B5,B5
	STW	B5,*B4			; [!B1] is removed to flatten samples
||[!B0]	BNOP	bus_loop2_done?,2
||	SUB	B0,1,B0
	LDW	*B16[2],B8
	NOP	4
	SUB	B8,B9,B8
||	MV	B8,B9
	CMPEQ	B8,B7,B2
||	MV	B8,B7
  [!B2]	ADDAW	B4,1,B4
||[!B2]	ADDK	1,A4
	CMPEQ	A4,A6,A2
  [!A2]	BNOP	bus_loop2?,5

bus_loop2_done?:
	BNOP	RA,5
	.endasmfunc

	.if	__TI_EABI__
	.sect	".init_array"
	.else
	.sect	".pinit"
	.endif
	.align	4
	.long	_OPENSSL_rdtsc		; auto-start timer
___

print $code;
close STDOUT;
