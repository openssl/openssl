	.SPACE $PRIVATE$
	.SUBSPA $DATA$,QUAD=1,ALIGN=8,ACCESS=31
	.SUBSPA $BSS$,QUAD=1,ALIGN=8,ACCESS=31,ZERO,SORT=82
	.SPACE $TEXT$
	.SUBSPA $LIT$,QUAD=0,ALIGN=8,ACCESS=44
	.SUBSPA $CODE$,QUAD=0,ALIGN=8,ACCESS=44,CODE_ONLY
	.IMPORT $global$,DATA
	.IMPORT $$dyncall,MILLICODE
; gcc_compiled.:
	.SPACE $TEXT$
	.SUBSPA $CODE$

	.align 4
	.EXPORT bn_mul_add_words,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,ARGW3=GR,RTNVAL=GR
bn_mul_add_words
	.PROC
	.CALLINFO FRAME=64,CALLS,SAVE_RP,ENTRY_GR=4
	.ENTRY
	stw %r2,-20(0,%r30)
	stwm %r4,64(0,%r30)
	copy %r24,%r31
	stw %r3,-60(0,%r30)
	ldi 0,%r20
	ldo 12(%r26),%r2
	stw %r23,-16(0,%r30)
	copy %r25,%r3
	ldo 12(%r3),%r1
	fldws -16(0,%r30),%fr8L
L$0010
	copy %r20,%r25
	ldi 0,%r24
	fldws 0(0,%r3),%fr9L
	ldw 0(0,%r26),%r19
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r19,%r23
	ldw -16(0,%r30),%r28
	ldw -12(0,%r30),%r29
	ldi 0,%r22
	add %r23,%r29,%r29
	addc %r22,%r28,%r28
	add %r25,%r29,%r29
	addc %r24,%r28,%r28
	copy %r28,%r21
	ldi 0,%r20
	copy %r21,%r20
	addib,= -1,%r31,L$0011
	stw %r29,0(0,%r26)
	copy %r20,%r25
	ldi 0,%r24
	fldws -8(0,%r1),%fr9L
	ldw -8(0,%r2),%r19
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r19,%r23
	ldw -16(0,%r30),%r28
	ldw -12(0,%r30),%r29
	ldi 0,%r22
	add %r23,%r29,%r29
	addc %r22,%r28,%r28
	add %r25,%r29,%r29
	addc %r24,%r28,%r28
	copy %r28,%r21
	ldi 0,%r20
	copy %r21,%r20
	addib,= -1,%r31,L$0011
	stw %r29,-8(0,%r2)
	copy %r20,%r25
	ldi 0,%r24
	fldws -4(0,%r1),%fr9L
	ldw -4(0,%r2),%r19
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r19,%r23
	ldw -16(0,%r30),%r28
	ldw -12(0,%r30),%r29
	ldi 0,%r22
	add %r23,%r29,%r29
	addc %r22,%r28,%r28
	add %r25,%r29,%r29
	addc %r24,%r28,%r28
	copy %r28,%r21
	ldi 0,%r20
	copy %r21,%r20
	addib,= -1,%r31,L$0011
	stw %r29,-4(0,%r2)
	copy %r20,%r25
	ldi 0,%r24
	fldws 0(0,%r1),%fr9L
	ldw 0(0,%r2),%r19
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r19,%r23
	ldw -16(0,%r30),%r28
	ldw -12(0,%r30),%r29
	ldi 0,%r22
	add %r23,%r29,%r29
	addc %r22,%r28,%r28
	add %r25,%r29,%r29
	addc %r24,%r28,%r28
	copy %r28,%r21
	ldi 0,%r20
	copy %r21,%r20
	addib,= -1,%r31,L$0011
	stw %r29,0(0,%r2)
	ldo 16(%r1),%r1
	ldo 16(%r3),%r3
	ldo 16(%r2),%r2
	bl L$0010,0
	ldo 16(%r26),%r26
L$0011
	copy %r20,%r28
	ldw -84(0,%r30),%r2
	ldw -60(0,%r30),%r3
	bv 0(%r2)
	ldwm -64(0,%r30),%r4
	.EXIT
	.PROCEND
	.align 4
	.EXPORT bn_mul_words,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,ARGW3=GR,RTNVAL=GR
bn_mul_words
	.PROC
	.CALLINFO FRAME=64,CALLS,SAVE_RP,ENTRY_GR=3
	.ENTRY
	stw %r2,-20(0,%r30)
	copy %r25,%r2
	stwm %r4,64(0,%r30)
	copy %r24,%r19
	ldi 0,%r28
	stw %r23,-16(0,%r30)
	ldo 12(%r26),%r31
	ldo 12(%r2),%r29
	fldws -16(0,%r30),%fr8L
L$0026
	fldws 0(0,%r2),%fr9L
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r28,%r21
	ldi 0,%r20
	ldw -16(0,%r30),%r24
	ldw -12(0,%r30),%r25
	add %r21,%r25,%r25
	addc %r20,%r24,%r24
	copy %r24,%r23
	ldi 0,%r22
	copy %r23,%r28
	addib,= -1,%r19,L$0027
	stw %r25,0(0,%r26)
	fldws -8(0,%r29),%fr9L
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r28,%r21
	ldi 0,%r20
	ldw -16(0,%r30),%r24
	ldw -12(0,%r30),%r25
	add %r21,%r25,%r25
	addc %r20,%r24,%r24
	copy %r24,%r23
	ldi 0,%r22
	copy %r23,%r28
	addib,= -1,%r19,L$0027
	stw %r25,-8(0,%r31)
	fldws -4(0,%r29),%fr9L
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r28,%r21
	ldi 0,%r20
	ldw -16(0,%r30),%r24
	ldw -12(0,%r30),%r25
	add %r21,%r25,%r25
	addc %r20,%r24,%r24
	copy %r24,%r23
	ldi 0,%r22
	copy %r23,%r28
	addib,= -1,%r19,L$0027
	stw %r25,-4(0,%r31)
	fldws 0(0,%r29),%fr9L
	xmpyu %fr8L,%fr9L,%fr9
	fstds %fr9,-16(0,%r30)
	copy %r28,%r21
	ldi 0,%r20
	ldw -16(0,%r30),%r24
	ldw -12(0,%r30),%r25
	add %r21,%r25,%r25
	addc %r20,%r24,%r24
	copy %r24,%r23
	ldi 0,%r22
	copy %r23,%r28
	addib,= -1,%r19,L$0027
	stw %r25,0(0,%r31)
	ldo 16(%r29),%r29
	ldo 16(%r2),%r2
	ldo 16(%r31),%r31
	bl L$0026,0
	ldo 16(%r26),%r26
L$0027
	ldw -84(0,%r30),%r2
	bv 0(%r2)
	ldwm -64(0,%r30),%r4
	.EXIT
	.PROCEND
	.align 4
	.EXPORT bn_sqr_words,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR
bn_sqr_words
	.PROC
	.CALLINFO FRAME=0,NO_CALLS
	.ENTRY
	ldo 28(%r26),%r19
	ldo 12(%r25),%r28
L$0042
	fldws 0(0,%r25),%fr8L
	fldws 0(0,%r25),%fr8R
	xmpyu %fr8L,%fr8R,%fr8
	fstds %fr8,-16(0,%r30)
	ldw -16(0,%r30),%r22
	ldw -12(0,%r30),%r23
	stw %r23,0(0,%r26)
	copy %r22,%r21
	ldi 0,%r20
	addib,= -1,%r24,L$0049
	stw %r21,-24(0,%r19)
	fldws -8(0,%r28),%fr8L
	fldws -8(0,%r28),%fr8R
	xmpyu %fr8L,%fr8R,%fr8
	fstds %fr8,-16(0,%r30)
	ldw -16(0,%r30),%r22
	ldw -12(0,%r30),%r23
	stw %r23,-20(0,%r19)
	copy %r22,%r21
	ldi 0,%r20
	addib,= -1,%r24,L$0049
	stw %r21,-16(0,%r19)
	fldws -4(0,%r28),%fr8L
	fldws -4(0,%r28),%fr8R
	xmpyu %fr8L,%fr8R,%fr8
	fstds %fr8,-16(0,%r30)
	ldw -16(0,%r30),%r22
	ldw -12(0,%r30),%r23
	stw %r23,-12(0,%r19)
	copy %r22,%r21
	ldi 0,%r20
	addib,= -1,%r24,L$0049
	stw %r21,-8(0,%r19)
	fldws 0(0,%r28),%fr8L
	fldws 0(0,%r28),%fr8R
	xmpyu %fr8L,%fr8R,%fr8
	fstds %fr8,-16(0,%r30)
	ldw -16(0,%r30),%r22
	ldw -12(0,%r30),%r23
	stw %r23,-4(0,%r19)
	copy %r22,%r21
	ldi 0,%r20
	addib,= -1,%r24,L$0049
	stw %r21,0(0,%r19)
	ldo 16(%r28),%r28
	ldo 16(%r25),%r25
	ldo 32(%r19),%r19
	bl L$0042,0
	ldo 32(%r26),%r26
L$0049
	bv,n 0(%r2)
	.EXIT
	.PROCEND
	.IMPORT BN_num_bits_word,CODE
	.IMPORT fprintf,CODE
	.IMPORT __iob,DATA
	.SPACE $TEXT$
	.SUBSPA $LIT$

	.align 4
L$C0000
	.STRING "Division would overflow (%d)\x0a\x00"
	.IMPORT abort,CODE
	.SPACE $TEXT$
	.SUBSPA $CODE$

	.align 4
	.EXPORT bn_div64,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR
bn_div64
	.PROC
	.CALLINFO FRAME=128,CALLS,SAVE_RP,ENTRY_GR=8
	.ENTRY
	stw %r2,-20(0,%r30)
	stwm %r8,128(0,%r30)
	stw %r7,-124(0,%r30)
	stw %r4,-112(0,%r30)
	stw %r3,-108(0,%r30)
	copy %r26,%r3
	copy %r25,%r4
	stw %r6,-120(0,%r30)
	ldi 0,%r7
	stw %r5,-116(0,%r30)
	movb,<> %r24,%r5,L$0051
	ldi 2,%r6
	bl L$0068,0
	ldi -1,%r28
L$0051
	.CALL ARGW0=GR
	bl BN_num_bits_word,%r2
	copy %r5,%r26
	copy %r28,%r24
	ldi 32,%r19
	comb,= %r19,%r24,L$0052
	subi 31,%r24,%r19
	mtsar %r19
	zvdepi 1,32,%r19
	comb,>>= %r19,%r3,L$0052
	addil LR'__iob-$global$+32,%r27
	ldo RR'__iob-$global$+32(%r1),%r26
	ldil LR'L$C0000,%r25
	.CALL ARGW0=GR,ARGW1=GR,ARGW2=GR
	bl fprintf,%r2
	ldo RR'L$C0000(%r25),%r25
	.CALL 
	bl abort,%r2
	nop
L$0052
	comb,>> %r5,%r3,L$0053
	subi 32,%r24,%r24
	sub %r3,%r5,%r3
L$0053
	comib,= 0,%r24,L$0054
	subi 31,%r24,%r19
	mtsar %r19
	zvdep %r5,32,%r5
	zvdep %r3,32,%r21
	subi 32,%r24,%r20
	mtsar %r20
	vshd 0,%r4,%r20
	or %r21,%r20,%r3
	mtsar %r19
	zvdep %r4,32,%r4
L$0054
	extru %r5,15,16,%r23
	extru %r5,31,16,%r28
L$0055
	extru %r3,15,16,%r19
	comb,<> %r23,%r19,L$0058
	copy %r3,%r26
	bl L$0059,0
	zdepi -1,31,16,%r29
L$0058
	.IMPORT $$divU,MILLICODE
	bl $$divU,%r31
	copy %r23,%r25
L$0059
	stw %r29,-16(0,%r30)
	fldws -16(0,%r30),%fr10L
	stw %r28,-16(0,%r30)
	fldws -16(0,%r30),%fr10R
	stw %r23,-16(0,%r30)
	xmpyu %fr10L,%fr10R,%fr8
	fldws -16(0,%r30),%fr10R
	fstws %fr8R,-16(0,%r30)
	xmpyu %fr10L,%fr10R,%fr9
	ldw -16(0,%r30),%r8
	fstws %fr9R,-16(0,%r30)
	copy %r8,%r22
	ldw -16(0,%r30),%r8
	extru %r4,15,16,%r24
	copy %r8,%r21
L$0060
	sub %r3,%r21,%r20
	copy %r20,%r19
	depi 0,31,16,%r19
	comib,<> 0,%r19,L$0061
	zdep %r20,15,16,%r19
	addl %r19,%r24,%r19
	comb,>>= %r19,%r22,L$0061
	sub %r22,%r28,%r22
	sub %r21,%r23,%r21
	bl L$0060,0
	ldo -1(%r29),%r29
L$0061
	stw %r29,-16(0,%r30)
	fldws -16(0,%r30),%fr10L
	stw %r28,-16(0,%r30)
	fldws -16(0,%r30),%fr10R
	xmpyu %fr10L,%fr10R,%fr8
	fstws %fr8R,-16(0,%r30)
	ldw -16(0,%r30),%r8
	stw %r23,-16(0,%r30)
	fldws -16(0,%r30),%fr10R
	copy %r8,%r19
	xmpyu %fr10L,%fr10R,%fr8
	fstws %fr8R,-16(0,%r30)
	extru %r19,15,16,%r20
	ldw -16(0,%r30),%r8
	zdep %r19,15,16,%r19
	addl %r8,%r20,%r20
	comclr,<<= %r19,%r4,0
	addi 1,%r20,%r20
	comb,<<= %r20,%r3,L$0066
	sub %r4,%r19,%r4
	addl %r3,%r5,%r3
	ldo -1(%r29),%r29
L$0066
	addib,= -1,%r6,L$0056
	sub %r3,%r20,%r3
	zdep %r29,15,16,%r7
	shd %r3,%r4,16,%r3
	bl L$0055,0
	zdep %r4,15,16,%r4
L$0056
	or %r7,%r29,%r28
L$0068
	ldw -148(0,%r30),%r2
	ldw -124(0,%r30),%r7
	ldw -120(0,%r30),%r6
	ldw -116(0,%r30),%r5
	ldw -112(0,%r30),%r4
	ldw -108(0,%r30),%r3
	bv 0(%r2)
	ldwm -128(0,%r30),%r8
	.EXIT
	.PROCEND
