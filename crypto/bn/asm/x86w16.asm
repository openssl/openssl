;	Static Name Aliases
;
	TITLE   bn_mulw.c
	.8087
F_TEXT	SEGMENT  WORD PUBLIC 'CODE'
F_TEXT	ENDS
_DATA	SEGMENT  WORD PUBLIC 'DATA'
_DATA	ENDS
CONST	SEGMENT  WORD PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT  WORD PUBLIC 'BSS'
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
	push	si
	push	di
	push	ds
	push	es
	mov	bp,sp
;	w = 26
;	num = 24
;	ap = 20
;	rp = 16
	xor	si,si			;c=0;
	mov	di,WORD PTR [bp+16]	; load r
	mov	ds,WORD PTR [bp+18]	; load r
	mov	bx,WORD PTR [bp+20]	; load a
	mov	es,WORD PTR [bp+22]	; load a
	mov	cx,WORD PTR [bp+26]	; load w
	mov	bp,WORD PTR [bp+24]	; load num

	shr	bp,1	; div count by 4 and do groups of 4
	shr	bp,1
	je	$L555

$L546:
	mov	ax,cx
	mul	WORD PTR es:[bx]	; w* *a
	add	ax,WORD PTR ds:[di]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di],ax
	mov	si,dx
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+2]	; w* *a
	add	ax,WORD PTR ds:[di+2]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+2],ax
	mov	si,dx
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+4]	; w* *a
	add	ax,WORD PTR ds:[di+4]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+4],ax
	mov	si,dx
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+6]	; w* *a
	add	ax,WORD PTR ds:[di+6]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+6],ax
	mov	si,dx
	;
	add	bx,8
	add	di,8
	;
	dec	bp
	je	$L555
	jmp	$L546
;
;
$L555:
	mov	bp,sp
	mov	bp,WORD PTR [bp+24]	; load num
	and	bp,3
	dec	bp
	js	$L547

	mov	ax,cx
	mul	WORD PTR es:[bx]	; w* *a
	add	ax,WORD PTR ds:[di]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di],ax
	mov	si,dx
	dec	bp
	js	$L547			; Note that we are now testing for -1
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+2]	; w* *a
	add	ax,WORD PTR ds:[di+2]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+2],ax
	mov	si,dx
	dec	bp
	js	$L547
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+4]	; w* *a
	add	ax,WORD PTR ds:[di+4]	; + *r
	adc	dx,0
	adc	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+4],ax
	mov	si,dx
$L547:
	mov	ax,si
	pop	es
	pop	ds
	pop	di
	pop	si
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
	push	si
	push	di
	push	ds
	push	es
	xor	si,si
	mov	bp,sp
	mov	di,WORD PTR [bp+16]	; r
	mov	ds,WORD PTR [bp+18]
	mov	bx,WORD PTR [bp+20]	; a
	mov	es,WORD PTR [bp+22]
	mov	cx,WORD PTR [bp+26]	; w
	mov	bp,WORD PTR [bp+24]	; num 
$FC743:
	mov	ax,cx
	mul	WORD PTR es:[bx]
	add	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di],ax
	mov	si,dx
	dec	bp
	je	$L764
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+2]
	add	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+2],ax
	mov	si,dx
	dec	bp
	je	$L764
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+4]
	add	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+4],ax
	mov	si,dx
	dec	bp
	je	$L764
	;
	mov	ax,cx
	mul	WORD PTR es:[bx+6]
	add	ax,si
	adc	dx,0
	mov	WORD PTR ds:[di+6],ax
	mov	si,dx
	dec	bp
	je	$L764
	;
	add	bx,8
	add	di,8
	jmp	$FC743
	nop
$L764:
	mov	ax,si
	pop	es
	pop	ds
	pop	di
	pop	si
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
	mov	ax,WORD PTR es:[di]
	mul	ax
	mov	WORD PTR ds:[si],ax
	mov	WORD PTR ds:[si+2],dx
	;
	mov	ax,WORD PTR es:[di+2]
	mul	ax
	mov	WORD PTR ds:[si+4],ax
	mov	WORD PTR ds:[si+6],dx
	;
	mov	ax,WORD PTR es:[di+4]
	mul	ax
	mov	WORD PTR ds:[si+8],ax
	mov	WORD PTR ds:[si+10],dx
	;
	mov	ax,WORD PTR es:[di+6]
	mul	ax
	mov	WORD PTR ds:[si+12],ax
	mov	WORD PTR ds:[si+14],dx
	;
	add	di,8
	add	si,16
	dec	bx
	je	$L666
	jmp	$L765
$L666:
	and	bp,3
	dec	bp	; The copied value of bx (num)
	js	$L645
	;
	mov	ax,WORD PTR es:[di]
	mul	ax
	mov	WORD PTR ds:[si],ax
	mov	WORD PTR ds:[si+2],dx
	dec	bp
	js	$L645
	;
	mov	ax,WORD PTR es:[di+2]
	mul	ax
	mov	WORD PTR ds:[si+4],ax
	mov	WORD PTR ds:[si+6],dx
	dec	bp
	js	$L645
	;
	mov	ax,WORD PTR es:[di+4]
	mul	ax
	mov	WORD PTR ds:[si+8],ax
	mov	WORD PTR ds:[si+10],dx
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
	mov	dx, WORD PTR [bp+6]
	mov	ax, WORD PTR [bp+8]
	div	WORD PTR [bp+10]
	pop	bp
	ret	
_bn_div64	ENDP
F_TEXT	ENDS
END
