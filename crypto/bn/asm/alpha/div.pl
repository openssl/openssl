#!/usr/local/bin/perl

sub bn_div_words
	{
	local($data)=<<'EOF';
 #
 # What follows was taken directly from the C compiler with a few
 # hacks to redo the lables.
 #
.text
        .set noreorder
	.set volatile
	.align 3
	.globl bn_div_words
	.ent bn_div_words
bn_div_words
	ldgp $29,0($27)
bn_div_words.ng:
	lda $30,-48($30)
	.frame $30,48,$26,0
	stq $26,0($30)
	stq $9,8($30)
	stq $10,16($30)
	stq $11,24($30)
	stq $12,32($30)
	stq $13,40($30)
	.mask 0x4003e00,-48
	.prologue 1
	bis $16,$16,$9
	bis $17,$17,$10
	bis $18,$18,$11
	bis $31,$31,$13
	bis $31,2,$12
	bne $11,$9119
	lda $0,-1
	br $31,$9136
	.align 4
$9119:
	bis $11,$11,$16
	jsr $26,BN_num_bits_word
	ldgp $29,0($26)
	subq $0,64,$1
	beq $1,$9120
	bis $31,1,$1
	sll $1,$0,$1
	cmpule $9,$1,$1
	bne $1,$9120
 #	lda $16,_IO_stderr_
 #	lda $17,$C32
 #	bis $0,$0,$18
 #	jsr $26,fprintf
 #	ldgp $29,0($26)
	jsr $26,abort
	ldgp $29,0($26)
	.align 4
$9120:
	bis $31,64,$3
	cmpult $9,$11,$2
	subq $3,$0,$1
	addl $1,$31,$0
	subq $9,$11,$1
	cmoveq $2,$1,$9
	beq $0,$9122
	zapnot $0,15,$2
	subq $3,$0,$1
	sll $11,$2,$11
	sll $9,$2,$3
	srl $10,$1,$1
	sll $10,$2,$10
	bis $3,$1,$9
$9122:
	srl $11,32,$5
	zapnot $11,15,$6
	lda $7,-1
	.align 5
$9123:
	srl $9,32,$1
	subq $1,$5,$1
	bne $1,$9126
	zapnot $7,15,$27
	br $31,$9127
	.align 4
$9126:
	bis $9,$9,$24
	bis $5,$5,$25
	divqu $24,$25,$27
$9127:
	srl $10,32,$4
	.align 5
$9128:
	mulq $27,$5,$1
	subq $9,$1,$3
	zapnot $3,240,$1
	bne $1,$9129
	mulq $6,$27,$2
	sll $3,32,$1
	addq $1,$4,$1
	cmpule $2,$1,$2
	bne $2,$9129
	subq $27,1,$27
	br $31,$9128
	.align 4
$9129:
	mulq $27,$6,$1
	mulq $27,$5,$4
	srl $1,32,$3
	sll $1,32,$1
	addq $4,$3,$4
	cmpult $10,$1,$2
	subq $10,$1,$10
	addq $2,$4,$2
	cmpult $9,$2,$1
	bis $2,$2,$4
	beq $1,$9134
	addq $9,$11,$9
	subq $27,1,$27
$9134:
	subl $12,1,$12
	subq $9,$4,$9
	beq $12,$9124
	sll $27,32,$13
	sll $9,32,$2
	srl $10,32,$1
	sll $10,32,$10
	bis $2,$1,$9
	br $31,$9123
	.align 4
$9124:
	bis $13,$27,$0
$9136:
	ldq $26,0($30)
	ldq $9,8($30)
	ldq $10,16($30)
	ldq $11,24($30)
	ldq $12,32($30)
	ldq $13,40($30)
	addq $30,48,$30
	ret $31,($26),1
	.end bn_div_words
EOF
	&asm_add($data);
	}

1;
