;	Static Name Aliases
;
	TITLE   bn_mulw.c
	.386
F_TEXT	SEGMENT  WORD USE16 PUBLIC 'CODE'
F_TEXT	ENDS
_DATA	SEGMENT  WORD USE16 PUBLIC 'DATA'
_DATA	ENDS
CONST	SEGMENT  WORD USE16 PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT  WORD USE16 PUBLIC 'BSS'
_BSS	ENDS
DGROUP	GROUP	CONST, _BSS, _DATA
	ASSUME DS: DGROUP, SS: DGROUP
F_TEXT      SEGMENT
	ASSUME	CS: F_TEXT
	PUBLIC	_bn_mul_add_words
_bn_mul_add_words	PROC FAR
; Line 58
	push	bp
	push	bx
	push	esi
	push	di
	push	ds
	push	es
	mov	bp,sp
;	w = 28
;	num = 26
;	ap = 22
;	rp = 18
	xor	esi,esi			;c=0;
	mov	di,WORD PTR [bp+18]	; load r
	mov	ds,WORD PTR [bp+20]	; load r
	mov	bx,WORD PTR [bp+22]	; load a
	mov	es,WORD PTR [bp+24]	; load a
	mov	ecx,DWORD PTR [bp+28]	; load w
	mov	bp,WORD PTR [bp+26]	; load num
	shr	bp,1	; div count by 4 and do groups of 4
	shr	bp,1
	je	$L555

$L546:
	mov	eax,ecx
	mul	DWORD PTR es:[bx]	; w* *a
	add	eax,DWORD PTR ds:[di]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di],eax
	mov	esi,edx
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+4]	; w* *a
	add	eax,DWORD PTR ds:[di+4]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+4],eax
	mov	esi,edx
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+8]	; w* *a
	add	eax,DWORD PTR ds:[di+8]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+8],eax
	mov	esi,edx
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+12]	; w* *a
	add	eax,DWORD PTR ds:[di+12]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+12],eax
	mov	esi,edx
	;
	add	bx,16
	add	di,16
	;
	dec	bp
	je	$L555
	jmp	$L546
;
;
$L555:
	mov	bp,sp
	mov	bp,WORD PTR [bp+26]	; load num
	and	bp,3
	dec	bp
	js	$L547

	mov	eax,ecx
	mul	DWORD PTR es:[bx]	; w* *a
	add	eax,DWORD PTR ds:[di]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di],eax
	mov	esi,edx
	dec	bp
	js	$L547			; Note that we are now testing for -1
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+4]	; w* *a
	add	eax,DWORD PTR ds:[di+4]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+4],eax
	mov	esi,edx
	dec	bp
	js	$L547
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+8]	; w* *a
	add	eax,DWORD PTR ds:[di+8]	; + *r
	adc	edx,0
	adc	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+8],eax
	mov	esi,edx
$L547:
	mov	eax,esi
	mov	edx,esi
	shr	edx,16
	pop	es
	pop	ds
	pop	di
	pop	esi
	pop	bx
	pop	bp
	ret	
	nop	
_bn_mul_add_words	ENDP

	PUBLIC	_bn_mul_words
_bn_mul_words	PROC FAR
; Line 76
	push	bp
	push	bx
	push	esi
	push	di
	push	ds
	push	es
	xor	esi,esi
	mov	bp,sp
	mov	di,WORD PTR [bp+18]	; r
	mov	ds,WORD PTR [bp+20]
	mov	bx,WORD PTR [bp+22]	; a
	mov	es,WORD PTR [bp+24]
	mov	ecx,DWORD PTR [bp+28]	; w
	mov	bp,WORD PTR [bp+26]	; num 

$FC743:
	mov	eax,ecx
	mul	DWORD PTR es:[bx]
	add	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di],eax
	mov	esi,edx
	dec	bp
	je	$L764
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+4]
	add	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+4],eax
	mov	esi,edx
	dec	bp
	je	$L764
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+8]
	add	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+8],eax
	mov	esi,edx
	dec	bp
	je	$L764
	;
	mov	eax,ecx
	mul	DWORD PTR es:[bx+12]
	add	eax,esi
	adc	edx,0
	mov	DWORD PTR ds:[di+12],eax
	mov	esi,edx
	dec	bp
	je	$L764
	;
	add	bx,16
	add	di,16
	jmp	$FC743
	nop
$L764:
	mov	eax,esi
	mov	edx,esi
	shr	edx,16
	pop	es
	pop	ds
	pop	di
	pop	esi
	pop	bx
	pop	bp
	ret	
	nop	
_bn_mul_words	ENDP
	PUBLIC	_bn_sqr_words
_bn_sqr_words	PROC FAR
; Line 92
	push	bp
	push	bx
	push	si
	push	di
	push	ds
	push	es
	mov	bp,sp
	mov	si,WORD PTR [bp+16]
	mov	ds,WORD PTR [bp+18]
	mov	di,WORD PTR [bp+20]
	mov	es,WORD PTR [bp+22]
	mov	bx,WORD PTR [bp+24]

	mov	bp,bx	; save a memory lookup later
	shr	bx,1	; div count by 4 and do groups of 4
	shr	bx,1
	je	$L666

$L765:
	mov	eax,DWORD PTR es:[di]
	mul	eax
	mov	DWORD PTR ds:[si],eax
	mov	DWORD PTR ds:[si+4],edx
	;
	mov	eax,DWORD PTR es:[di+4]
	mul	eax
	mov	DWORD PTR ds:[si+8],eax
	mov	DWORD PTR ds:[si+12],edx
	;
	mov	eax,DWORD PTR es:[di+8]
	mul	eax
	mov	DWORD PTR ds:[si+16],eax
	mov	DWORD PTR ds:[si+20],edx
	;
	mov	eax,DWORD PTR es:[di+12]
	mul	eax
	mov	DWORD PTR ds:[si+24],eax
	mov	DWORD PTR ds:[si+28],edx
	;
	add	di,16
	add	si,32
	dec	bx
	je	$L666
	jmp	$L765
$L666:
	and	bp,3
	dec	bp	; The copied value of bx (num)
	js	$L645
	;
	mov	eax,DWORD PTR es:[di]
	mul	eax
	mov	DWORD PTR ds:[si],eax
	mov	DWORD PTR ds:[si+4],edx
	dec	bp
	js	$L645
	;
	mov	eax,DWORD PTR es:[di+4]
	mul	eax
	mov	DWORD PTR ds:[si+8],eax
	mov	DWORD PTR ds:[si+12],edx
	dec	bp
	js	$L645
	;
	mov	eax,DWORD PTR es:[di+8]
	mul	eax
	mov	DWORD PTR ds:[si+16],eax
	mov	DWORD PTR ds:[si+20],edx
$L645:
	pop	es
	pop	ds
	pop	di
	pop	si
	pop	bx
	pop	bp
	ret	
_bn_sqr_words	ENDP

	PUBLIC	_bn_div64
_bn_div64	PROC FAR
	push	bp
	mov	bp,sp
	mov	edx, DWORD PTR [bp+6]
	mov	eax, DWORD PTR [bp+10]
	div	DWORD PTR [bp+14]
	mov	edx,eax
	shr	edx,16
	pop	bp
	ret	
_bn_div64	ENDP

	PUBLIC	_bn_add_words
_bn_add_words	PROC FAR
; Line 58
	push	bp
	push	bx
	push	esi
	push	di
	push	ds
	push	es
	mov	bp,sp
;	w = 28
;	num = 26
;	ap = 22
;	rp = 18
	xor	esi,esi			;c=0;
	mov	si,WORD PTR [bp+22]	; load a
	mov	es,WORD PTR [bp+24]	; load a
	mov	di,WORD PTR [bp+26]	; load b
	mov	ds,WORD PTR [bp+28]	; load b

	mov	dx,WORD PTR [bp+30]	; load num
	dec	dx
	js	$L547
	xor	ecx,ecx

$L5477:
	xor	ebx,ebx
	mov	eax,DWORD PTR es:[si]	; *a
	add	eax,ecx
	adc	ebx,0
	add	si,4			; a++
	add	eax,DWORD PTR ds:[di]	; + *b
	mov	ecx,ebx
	adc	ecx,0
	add	di,4
	mov	bx,WORD PTR [bp+18]
	mov	ds,WORD PTR [bp+20]
	mov	DWORD PTR ds:[bx],eax
	add	bx,4
	mov	ds,WORD PTR [bp+28]
	mov	WORD PTR [bp+18],bx
	dec	dx
	js	$L547			; Note that we are now testing for -1
	jmp	$L5477
	;
$L547:
	mov	eax,ecx
	mov	edx,ecx
	shr	edx,16
	pop	es
	pop	ds
	pop	di
	pop	esi
	pop	bx
	pop	bp
	ret	
	nop	
_bn_add_words	ENDP
F_TEXT	ENDS
END
