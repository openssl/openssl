 # DEC Alpha assember
 # The bn_div64 is actually gcc output but the other parts are hand done.
 # Thanks to tzeruch@ceddec.com for sending me the gcc output for
 # bn_div64.
	.file	1 "bn_mulw.c"
	.set noat
gcc2_compiled.:
__gnu_compiled_c:
	.text
	.align 3
	.globl bn_mul_add_words
	.ent bn_mul_add_words
bn_mul_add_words:
bn_mul_add_words..ng:
	.frame $30,0,$26,0
	.prologue 0
	subq $18,2,$25	# num=-2
	bis $31,$31,$0
	blt $25,$42
	.align 5
$142:
	subq $18,2,$18	# num-=2
	subq $25,2,$25	# num-=2

	ldq $1,0($17)	# a[0]
	ldq $2,8($17)	# a[1]

	mulq $19,$1,$3	# a[0]*w low part	r3
 	umulh $19,$1,$1 # a[0]*w high part	r1
	mulq $19,$2,$4	# a[1]*w low part	r4
 	umulh $19,$2,$2 # a[1]*w high part	r2

	ldq $22,0($16)	# r[0]			r22
	ldq $23,8($16)	# r[1]			r23

	addq $3,$22,$3	# a0 low part + r[0]	
	addq $4,$23,$4	# a1 low part + r[1]	
	cmpult $3,$22,$5 # overflow?
	cmpult $4,$23,$6 # overflow?
	addq $5,$1,$1	# high part + overflow 
	addq $6,$2,$2	# high part + overflow 

	addq $3,$0,$3	# add c
	cmpult $3,$0,$5 # overflow?
	stq $3,0($16)
	addq $5,$1,$0	# c=high part + overflow 

	addq $4,$0,$4	# add c
	cmpult $4,$0,$5 # overflow?
	stq $4,8($16)
	addq $5,$2,$0	# c=high part + overflow 

	ble $18,$43

 	addq $16,16,$16
 	addq $17,16,$17
	blt $25,$42

 	br $31,$142
$42:
	ldq $1,0($17)	# a[0]
 	umulh $19,$1,$3 # a[0]*w high part
	mulq $19,$1,$1	# a[0]*w low part
	ldq $2,0($16)	# r[0]
	addq $1,$2,$1	# low part + r[0]
	cmpult $1,$2,$4 # overflow?
	addq $4,$3,$3	# high part + overflow 
	addq $1,$0,$1	# add c
	cmpult $1,$0,$4 # overflow?
	addq $4,$3,$0	# c=high part + overflow 
	stq $1,0($16)

	.align 4
$43:
	ret $31,($26),1
	.end bn_mul_add_words
	.align 3
	.globl bn_mul_words
	.ent bn_mul_words
bn_mul_words:
bn_mul_words..ng:
	.frame $30,0,$26,0
	.prologue 0
	subq $18,2,$25	# num=-2
	bis $31,$31,$0
	blt $25,$242
	.align 5
$342:
	subq $18,2,$18	# num-=2
	subq $25,2,$25	# num-=2

	ldq $1,0($17)	# a[0]
	ldq $2,8($17)	# a[1]

	mulq $19,$1,$3	# a[0]*w low part	r3
 	umulh $19,$1,$1 # a[0]*w high part	r1
	mulq $19,$2,$4	# a[1]*w low part	r4
 	umulh $19,$2,$2 # a[1]*w high part	r2

	addq $3,$0,$3	# add c
	cmpult $3,$0,$5 # overflow?
	stq $3,0($16)
	addq $5,$1,$0	# c=high part + overflow 

	addq $4,$0,$4	# add c
	cmpult $4,$0,$5 # overflow?
	stq $4,8($16)
	addq $5,$2,$0	# c=high part + overflow 

	ble $18,$243

 	addq $16,16,$16
 	addq $17,16,$17
	blt $25,$242

 	br $31,$342
$242:
	ldq $1,0($17)	# a[0]
 	umulh $19,$1,$3 # a[0]*w high part
	mulq $19,$1,$1	# a[0]*w low part
	addq $1,$0,$1	# add c
	cmpult $1,$0,$4 # overflow?
	addq $4,$3,$0	# c=high part + overflow 
	stq $1,0($16)
$243:
	ret $31,($26),1
	.end bn_mul_words
	.align 3
	.globl bn_sqr_words
	.ent bn_sqr_words
bn_sqr_words:
bn_sqr_words..ng:
	.frame $30,0,$26,0
	.prologue 0
	
	subq $18,2,$25	# num=-2
	blt $25,$442
	.align 5
$542:
	subq $18,2,$18	# num-=2
	subq $25,2,$25	# num-=2

	ldq $1,0($17)	# a[0]
	ldq $4,8($17)	# a[1]

	mulq $1,$1,$2	# a[0]*w low part	r2
 	umulh $1,$1,$3 # a[0]*w high part	r3
	mulq $4,$4,$5	# a[1]*w low part	r5
 	umulh $4,$4,$6 # a[1]*w high part	r6

	stq $2,0($16)	# r[0]
	stq $3,8($16)	# r[1]
	stq $5,16($16)	# r[3]
	stq $6,24($16)	# r[4]

	ble $18,$443

 	addq $16,32,$16
 	addq $17,16,$17
	blt $25,$442
 	br $31,$542

$442:
	ldq $1,0($17)   # a[0]
	mulq $1,$1,$2   # a[0]*w low part       r2
        umulh $1,$1,$3  # a[0]*w high part       r3
	stq $2,0($16)   # r[0]
        stq $3,8($16)   # r[1]

	.align 4
$443:
	ret $31,($26),1
	.end bn_sqr_words

	.align 3
	.globl bn_add_words
	.ent bn_add_words
bn_add_words:
bn_add_words..ng:
	.frame $30,0,$26,0
	.prologue 0

	bis	$31,$31,$8	# carry = 0
	ble	$19,$900
$901:
	ldq	$0,0($17)	# a[0]
	ldq	$1,0($18)	# a[1]

	addq	$0,$1,$3	# c=a+b;
	 addq	$17,8,$17	# a++

	cmpult	$3,$1,$7	# did we overflow?
	 addq	$18,8,$18	# b++

	addq	$8,$3,$3	# c+=carry

	cmpult	$3,$8,$8	# did we overflow?
	 stq	$3,($16)	# r[0]=c

	addq	$7,$8,$8	# add into overflow
	 subq	$19,1,$19	# loop--

	addq	$16,8,$16	# r++
	 bgt	$19,$901
$900:
	bis	$8,$8,$0	# return carry
	ret $31,($26),1
	.end bn_add_words

 #
 # What follows was taken directly from the C compiler with a few
 # hacks to redo the lables.
 #
.text
	.align 3
	.globl bn_div64
	.ent bn_div64
bn_div64:
	ldgp $29,0($27)
bn_div64..ng:
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
	bne $11,$119
	lda $0,-1
	br $31,$136
	.align 4
$119:
	bis $11,$11,$16
	jsr $26,BN_num_bits_word
	ldgp $29,0($26)
	subq $0,64,$1
	beq $1,$120
	bis $31,1,$1
	sll $1,$0,$1
	cmpule $9,$1,$1
	bne $1,$120
 #	lda $16,_IO_stderr_
 #	lda $17,$C32
 #	bis $0,$0,$18
 #	jsr $26,fprintf
 #	ldgp $29,0($26)
	jsr $26,abort
	ldgp $29,0($26)
	.align 4
$120:
	bis $31,64,$3
	cmpult $9,$11,$2
	subq $3,$0,$1
	addl $1,$31,$0
	subq $9,$11,$1
	cmoveq $2,$1,$9
	beq $0,$122
	zapnot $0,15,$2
	subq $3,$0,$1
	sll $11,$2,$11
	sll $9,$2,$3
	srl $10,$1,$1
	sll $10,$2,$10
	bis $3,$1,$9
$122:
	srl $11,32,$5
	zapnot $11,15,$6
	lda $7,-1
	.align 5
$123:
	srl $9,32,$1
	subq $1,$5,$1
	bne $1,$126
	zapnot $7,15,$27
	br $31,$127
	.align 4
$126:
	bis $9,$9,$24
	bis $5,$5,$25
	divqu $24,$25,$27
$127:
	srl $10,32,$4
	.align 5
$128:
	mulq $27,$5,$1
	subq $9,$1,$3
	zapnot $3,240,$1
	bne $1,$129
	mulq $6,$27,$2
	sll $3,32,$1
	addq $1,$4,$1
	cmpule $2,$1,$2
	bne $2,$129
	subq $27,1,$27
	br $31,$128
	.align 4
$129:
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
	beq $1,$134
	addq $9,$11,$9
	subq $27,1,$27
$134:
	subl $12,1,$12
	subq $9,$4,$9
	beq $12,$124
	sll $27,32,$13
	sll $9,32,$2
	srl $10,32,$1
	sll $10,32,$10
	bis $2,$1,$9
	br $31,$123
	.align 4
$124:
	bis $13,$27,$0
$136:
	ldq $26,0($30)
	ldq $9,8($30)
	ldq $10,16($30)
	ldq $11,24($30)
	ldq $12,32($30)
	ldq $13,40($30)
	addq $30,48,$30
	ret $31,($26),1
	.end bn_div64
	.ident	"GCC: (GNU) 2.7.2.1"


