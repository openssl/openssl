	TITLE	bn_mulw.c
	.386P
.model FLAT
PUBLIC	_bn_mul_add_word
_TEXT	SEGMENT
; File bn_mulw.c
_bn_mul_add_word PROC NEAR
	push	ebp
	push	ebx
	push	esi
	push	edi
	mov	edi,DWORD PTR 20[esp]   ; r
	mov	ebx,DWORD PTR 24[esp]	; a
	mov	ecx,DWORD PTR 32[esp]	; w
	xor	esi,esi			; c=0

	mov	ebp,DWORD PTR 28[esp]	; num
	shr	ebp,2			; num/4
	jz	$L666

$L546:
	; Round one
	mov	eax,DWORD PTR [ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR [edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR [edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow

	; Round two
	mov	eax,DWORD PTR 4[ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR 4[edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR 4[edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow

	; Round three
	mov	eax,DWORD PTR 8[ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR 8[edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR 8[edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow

	; Round four
	mov	eax,DWORD PTR 12[ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR 12[edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR 12[edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow

	add	ebx,16
	add	edi,16

	dec	ebp
	jz	$L666
	jmp	$L546
$L666:
	mov	ebp,DWORD PTR 28[esp]	; num
	and	ebp,3			; num%4
	jz	$L547

	; Round one
	mov	eax,DWORD PTR [ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR [edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR [edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow
	dec	ebp
	jz	$L547
	; Round two
	mov	eax,DWORD PTR 4[ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR 4[edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR 4[edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow
	dec	ebp
	jz	$L547
	; Round three
	mov	eax,DWORD PTR 8[ebx]	; edx:eax = *a * w
	mul	ecx
	add	eax,DWORD PTR 8[edi]	; *r+=ax
	adc	edx,0
	add	eax,esi			; edx:eax += c
	adc	edx,0
	mov	DWORD PTR 8[edi],eax	; *r+=ax
	mov	esi,edx			; c = overflow

$L547:
	mov	eax,esi
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_bn_mul_add_word ENDP
_TEXT	ENDS
PUBLIC	_bn_mul_word
_TEXT	SEGMENT
_bn_mul_word PROC NEAR
	push	ebp
	push	ebx
	push	esi
	push	edi

	mov	edi,DWORD PTR 20[esp]	; r
	mov	ebx,DWORD PTR 24[esp]	; a
	mov	ebp,DWORD PTR 28[esp]	; num
	mov	ecx,DWORD PTR 32[esp]	; w
	xor	esi,esi			; c=0

	shr	ebp,2			; num/4
	jz	$L266

$L593:
	; Round one
	mov	eax,DWORD PTR [ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR [edi],eax	; *r=eax
	mov	esi,edx			; c=edx
	; Round two
	mov	eax,DWORD PTR 4[ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR 4[edi],eax	; *r=eax
	mov	esi,edx			; c=edx
	; Round three
	mov	eax,DWORD PTR 8[ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR 8[edi],eax	; *r=eax
	mov	esi,edx			; c=edx
	; Round four
	mov	eax,DWORD PTR 12[ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR 12[edi],eax	; *r=eax
	mov	esi,edx			; c=edx

	add	ebx,16
	add	edi,16

	dec	ebp
	jz	$L266
	jmp	$L593
$L266:
	mov	ebp,DWORD PTR 28[esp]	; num
	and	ebp,3	
	jz	$L601

	; Round one
	mov	eax,DWORD PTR [ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR [edi],eax	; *r=eax
	mov	esi,edx			; c=edx
	dec	ebp
	jz	$L601
	; Round two
	mov	eax,DWORD PTR 4[ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR 4[edi],eax	; *r=eax
	mov	esi,edx			; c=edx
	dec	ebp
	jz	$L601
	; Round three
	mov	eax,DWORD PTR 8[ebx]	; edx:eax= w * *a 
	mul	ecx
	add	eax,esi			; edx:eax+=c
	adc	edx,0
	mov	DWORD PTR 8[edi],eax	; *r=eax
	mov	esi,edx			; c=edx

$L601:
	mov	eax,esi
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_bn_mul_word ENDP
_TEXT	ENDS
PUBLIC	_bn_sqr_words
_TEXT	SEGMENT
_bn_sqr_words PROC NEAR
	push	ebx
	push	esi
	push	edi
	mov	esi,DWORD PTR 16[esp]	; r
	mov	edi,DWORD PTR 20[esp]	; a
	mov	ebx,DWORD PTR 24[esp]	; num
	
	shr	ebx,2			; num/4
	jz	$L111
$L640:
	; Round 1
	mov	eax, DWORD PTR [edi]
	mul	eax			; *a * *a
	mov	DWORD PTR [esi],eax
	mov	DWORD PTR 4[esi],edx
	; Round 2
	mov	eax, DWORD PTR 4[edi]
	mul	eax			; *a * *a
	mov	DWORD PTR 8[esi],eax
	mov	DWORD PTR 12[esi],edx
	; Round 3
	mov	eax, DWORD PTR 8[edi]
	mul	eax			; *a * *a
	mov	DWORD PTR 16[esi],eax
	mov	DWORD PTR 20[esi],edx
	; Round 4
	mov	eax, DWORD PTR 12[edi]
	mul	eax			; *a * *a
	mov	DWORD PTR 24[esi],eax
	mov	DWORD PTR 28[esi],edx

	add	edi,16
	add	esi,32

	dec	ebx
	jz	$L111
	jmp	$L640
$L111:
	mov	ebx,DWORD PTR 24[esp]	; num
	and	ebx,3			; num%3
	jz	$L645

	; Round 1
	mov	eax, DWORD PTR [edi]
	mul	eax			; *a * *a
	mov	DWORD PTR [esi],eax
	mov	DWORD PTR 4[esi],edx
	dec	ebx
	jz	$L645
	; Round 2
	mov	eax, DWORD PTR 4[edi]
	mul	eax			; *a * *a
	mov	DWORD PTR 8[esi],eax
	mov	DWORD PTR 12[esi],edx
	dec	ebx
	jz	$L645
	; Round 3
	mov	eax, DWORD PTR 8[edi]
	mul	eax			; *a * *a
	mov	DWORD PTR 16[esi],eax
	mov	DWORD PTR 20[esi],edx

$L645:
	pop	edi
	pop	esi
	pop	ebx
	ret
_bn_sqr_words ENDP
_TEXT	ENDS
PUBLIC	_bn_div64
_TEXT	SEGMENT
_bn_div64 PROC NEAR
	mov	edx, DWORD PTR 4[esp]
	mov	eax, DWORD PTR 8[esp]
	div	DWORD PTR 12[esp]
	ret
_bn_div64 ENDP
_TEXT	ENDS
END
