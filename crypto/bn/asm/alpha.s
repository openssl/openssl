 # DEC Alpha assember
 # The bn_div_words is actually gcc output but the other parts are hand done.
 # Thanks to tzeruch@ceddec.com for sending me the gcc output for
 # bn_div_words.
 # I've gone back and re-done most of routines.
 # The key thing to remeber for the 164 CPU is that while a
 # multiply operation takes 8 cycles, another one can only be issued
 # after 4 cycles have elapsed.  I've done modification to help
 # improve this.  Also, normally, a ld instruction will not be available
 # for about 3 cycles.
	.file	1 "bn_asm.c"
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
	.align 5
	subq	$18,4,$18
	bis	$31,$31,$0
	blt	$18,$43		# if we are -1, -2, -3 or -4 goto tail code
	ldq	$20,0($17)	# 1 1
	ldq	$1,0($16)	# 1 1
	.align 3
$42:
	mulq	$20,$19,$5	# 1 2 1	######
	ldq	$21,8($17)	# 2 1
	ldq	$2,8($16)	# 2 1
	umulh	$20,$19,$20	# 1 2	######
	ldq	$27,16($17)	# 3 1
	ldq	$3,16($16)	# 3 1
	mulq	$21,$19,$6	# 2 2 1	######
	 ldq	$28,24($17)	# 4 1
	addq	$1,$5,$1	# 1 2 2
	 ldq	$4,24($16)	# 4 1
	umulh	$21,$19,$21	# 2 2	######
	 cmpult	$1,$5,$22	# 1 2 3 1
	addq	$20,$22,$20	# 1 3 1
	 addq	$1,$0,$1	# 1 2 3 1
	mulq	$27,$19,$7	# 3 2 1	######
	 cmpult	$1,$0,$0	# 1 2 3 2
	addq	$2,$6,$2	# 2 2 2
	 addq	$20,$0,$0	# 1 3 2 
	cmpult	$2,$6,$23	# 2 2 3 1
	 addq	$21,$23,$21	# 2 3 1
	umulh	$27,$19,$27	# 3 2	######
	 addq	$2,$0,$2	# 2 2 3 1
	cmpult	$2,$0,$0	# 2 2 3 2
	 subq	$18,4,$18
	mulq	$28,$19,$8	# 4 2 1	######
	 addq	$21,$0,$0	# 2 3 2 
	addq	$3,$7,$3	# 3 2 2
	 addq	$16,32,$16
	cmpult	$3,$7,$24	# 3 2 3 1
	 stq	$1,-32($16)	# 1 2 4
	umulh	$28,$19,$28	# 4 2	######
	 addq	$27,$24,$27	# 3 3 1
	addq	$3,$0,$3	# 3 2 3 1
	 stq	$2,-24($16)	# 2 2 4
	cmpult	$3,$0,$0	# 3 2 3 2
	 stq	$3,-16($16)	# 3 2 4
	addq	$4,$8,$4	# 4 2 2
	 addq	$27,$0,$0	# 3 3 2 
	cmpult	$4,$8,$25	# 4 2 3 1
	 addq	$17,32,$17
	addq	$28,$25,$28	# 4 3 1
	 addq	$4,$0,$4	# 4 2 3 1
	cmpult	$4,$0,$0	# 4 2 3 2
	 stq	$4,-8($16)	# 4 2 4
	addq	$28,$0,$0	# 4 3 2 
	 blt	$18,$43

	ldq	$20,0($17)	# 1 1
	ldq	$1,0($16)	# 1 1

	br	$42

	.align 4
$45:
	ldq	$20,0($17)	# 4 1
	ldq	$1,0($16)	# 4 1
	mulq	$20,$19,$5	# 4 2 1
	subq	$18,1,$18
	addq	$16,8,$16
	addq	$17,8,$17
	umulh	$20,$19,$20	# 4 2
	addq	$1,$5,$1	# 4 2 2
	cmpult	$1,$5,$22	# 4 2 3 1
	addq	$20,$22,$20	# 4 3 1
	addq	$1,$0,$1	# 4 2 3 1
	cmpult	$1,$0,$0	# 4 2 3 2
	addq	$20,$0,$0	# 4 3 2 
	stq	$1,-8($16)	# 4 2 4
	bgt	$18,$45
	ret	$31,($26),1	# else exit

	.align 4
$43:
	addq	$18,4,$18
	bgt	$18,$45		# goto tail code
	ret	$31,($26),1	# else exit

	.end bn_mul_add_words
	.align 3
	.globl bn_mul_words
	.ent bn_mul_words
bn_mul_words:
bn_mul_words..ng:
	.frame $30,0,$26,0
	.prologue 0
	.align 5
	subq	$18,4,$18
	bis	$31,$31,$0
	blt	$18,$143	# if we are -1, -2, -3 or -4 goto tail code
	ldq	$20,0($17)	# 1 1
	.align 3
$142:

	mulq	$20,$19,$5	# 1 2 1	#####
	 ldq	$21,8($17)	# 2 1
	 ldq	$27,16($17)	# 3 1
	umulh	$20,$19,$20	# 1 2	#####
	 ldq	$28,24($17)	# 4 1
	mulq	$21,$19,$6	# 2 2 1	#####
	 addq	$5,$0,$5	# 1 2 3 1
	subq	$18,4,$18
	 cmpult	$5,$0,$0	# 1 2 3 2
	umulh	$21,$19,$21	# 2 2	#####
	 addq	$20,$0,$0	# 1 3 2 
	addq	$17,32,$17
	 addq	$6,$0,$6	# 2 2 3 1
	mulq	$27,$19,$7	# 3 2 1	#####
	 cmpult	$6,$0,$0	# 2 2 3 2
	addq	$21,$0,$0	# 2 3 2 
	 addq	$16,32,$16
	umulh	$27,$19,$27	# 3 2	#####
	 stq	$5,-32($16)	# 1 2 4
	mulq	$28,$19,$8	# 4 2 1	#####
	 addq	$7,$0,$7	# 3 2 3 1
	stq	$6,-24($16)	# 2 2 4
	 cmpult	$7,$0,$0	# 3 2 3 2
	umulh	$28,$19,$28	# 4 2	#####
	 addq	$27,$0,$0	# 3 3 2 
	stq	$7,-16($16)	# 3 2 4
	 addq	$8,$0,$8	# 4 2 3 1
	cmpult	$8,$0,$0	# 4 2 3 2

	addq	$28,$0,$0	# 4 3 2 

	stq	$8,-8($16)	# 4 2 4

	blt	$18,$143

	ldq	$20,0($17)	# 1 1

	br	$142

	.align 4
$145:
	ldq	$20,0($17)	# 4 1
	mulq	$20,$19,$5	# 4 2 1
	subq	$18,1,$18
	umulh	$20,$19,$20	# 4 2
	addq	$5,$0,$5	# 4 2 3 1
	 addq	$16,8,$16
	cmpult	$5,$0,$0	# 4 2 3 2
	 addq	$17,8,$17
	addq	$20,$0,$0	# 4 3 2 
	stq	$5,-8($16)	# 4 2 4

	bgt	$18,$145
	ret	$31,($26),1	# else exit

	.align 4
$143:
	addq	$18,4,$18
	bgt	$18,$145	# goto tail code
	ret	$31,($26),1	# else exit

	.end bn_mul_words
	.align 3
	.globl bn_sqr_words
	.ent bn_sqr_words
bn_sqr_words:
bn_sqr_words..ng:
	.frame $30,0,$26,0
	.prologue 0

	subq	$18,4,$18
	blt	$18,$543	# if we are -1, -2, -3 or -4 goto tail code
	ldq	$20,0($17)	# 1 1
	.align 3
$542:
	mulq	$20,$20,$5		######
	 ldq	$21,8($17)	# 1 1
	subq	$18,4
 	umulh	$20,$20,$1		######
	ldq	$27,16($17)	# 1 1
	mulq	$21,$21,$6		######
	ldq	$28,24($17)	# 1 1
	stq	$5,0($16)	# r[0]
 	umulh	$21,$21,$2		######
	stq	$1,8($16)	# r[1]
	mulq	$27,$27,$7		######
	stq	$6,16($16)	# r[0]
 	umulh	$27,$27,$3		######
	stq	$2,24($16)	# r[1]
	mulq	$28,$28,$8		######
	stq	$7,32($16)	# r[0]
 	umulh	$28,$28,$4		######
	stq	$3,40($16)	# r[1]

 	addq	$16,64,$16
 	addq	$17,32,$17
	stq	$8,-16($16)	# r[0]
	stq	$4,-8($16)	# r[1]

	blt	$18,$543
	ldq	$20,0($17)	# 1 1
 	br 	$542

$442:
	ldq	$20,0($17)   # a[0]
	mulq	$20,$20,$5  # a[0]*w low part       r2
	addq	$16,16,$16
	addq	$17,8,$17
	subq	$18,1,$18
        umulh	$20,$20,$1  # a[0]*w high part       r3
	stq	$5,-16($16)   # r[0]
        stq	$1,-8($16)   # r[1]

	bgt	$18,$442
	ret	$31,($26),1	# else exit

	.align 4
$543:
	addq	$18,4,$18
	bgt	$18,$442	# goto tail code
	ret	$31,($26),1	# else exit
	.end bn_sqr_words

	.align 3
	.globl bn_add_words
	.ent bn_add_words
bn_add_words:
bn_add_words..ng:
	.frame $30,0,$26,0
	.prologue 0

	subq	$19,4,$19
	bis	$31,$31,$0	# carry = 0
	blt	$19,$900
	ldq	$5,0($17)	# a[0]
	ldq	$1,0($18)	# b[1]
	.align 3
$901:
	addq	$1,$5,$1	# r=a+b;
	 ldq	$6,8($17)	# a[1]
	cmpult	$1,$5,$22	# did we overflow?
	 ldq	$2,8($18)	# b[1]
	addq	$1,$0,$1	# c+= overflow
	 ldq	$7,16($17)	# a[2]
	cmpult	$1,$0,$0	# overflow?
	 ldq	$3,16($18)	# b[2]
	addq	$0,$22,$0
	 ldq	$8,24($17)	# a[3]
	addq	$2,$6,$2	# r=a+b;
	 ldq	$4,24($18)	# b[3]
	cmpult	$2,$6,$23	# did we overflow?
	 addq	$3,$7,$3	# r=a+b;
	addq	$2,$0,$2	# c+= overflow
	 cmpult	$3,$7,$24	# did we overflow?
	cmpult	$2,$0,$0	# overflow?
	 addq	$4,$8,$4	# r=a+b;
	addq	$0,$23,$0
	 cmpult	$4,$8,$25	# did we overflow?
	addq	$3,$0,$3	# c+= overflow
	 stq	$1,0($16)	# r[0]=c
	cmpult	$3,$0,$0	# overflow?
	 stq	$2,8($16)	# r[1]=c
	addq	$0,$24,$0
	 stq	$3,16($16)	# r[2]=c
	addq	$4,$0,$4	# c+= overflow
	 subq	$19,4,$19	# loop--
	cmpult	$4,$0,$0	# overflow?
	 addq	$17,32,$17	# a++
	addq	$0,$25,$0
	 stq	$4,24($16)	# r[3]=c
	addq	$18,32,$18	# b++
	 addq	$16,32,$16	# r++

	blt	$19,$900
	 ldq	$5,0($17)	# a[0]
	ldq	$1,0($18)	# b[1]
	 br	$901
	.align 4
$945:
	ldq	$5,0($17)	# a[0]
	 ldq	$1,0($18)	# b[1]
	addq	$1,$5,$1	# r=a+b;
	 subq	$19,1,$19	# loop--
	addq	$1,$0,$1	# c+= overflow
	 addq	$17,8,$17	# a++
	cmpult	$1,$5,$22	# did we overflow?
	 cmpult	$1,$0,$0	# overflow?
	addq	$18,8,$18	# b++
	 stq	$1,0($16)	# r[0]=c
	addq	$0,$22,$0
	 addq	$16,8,$16	# r++

	bgt	$19,$945
	ret	$31,($26),1	# else exit

$900:
	addq	$19,4,$19
	bgt	$19,$945	# goto tail code
	ret	$31,($26),1	# else exit
	.end bn_add_words

 #
 # What follows was taken directly from the C compiler with a few
 # hacks to redo the lables.
 #
.text
	.align 3
	.globl bn_div_words
	.ent bn_div_words
bn_div_words:
	ldgp $29,0($27)
bn_div_words..ng:
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
	.end bn_div_words

	.set noat
	.text
	.align 3
	.globl bn_sub_words
	.ent bn_sub_words
bn_sub_words:
bn_sub_words..ng:
	.frame $30,0,$26,0
	.prologue 0

	subq	$19,	4,	$19
	bis	$31,	$31,	$0
	blt	$19,	$100
	ldq	$1,	0($17)
	ldq	$2,	0($18)
$101:
	ldq	$3,	8($17)
	cmpult	$1,	$2,	$4
	ldq	$5,	8($18)
	subq	$1,	$2,	$1
	ldq	$6,	16($17)
	cmpult	$1,	$0,	$2
	ldq	$7,	16($18)
	subq	$1,	$0,	$23
	ldq	$8,	24($17)
	addq	$2,	$4,	$0
	cmpult	$3,	$5,	$24
	subq	$3,	$5,	$3
	ldq	$22,	24($18)
	cmpult	$3,	$0,	$5
	subq	$3,	$0,	$25
	addq	$5,	$24,	$0
	cmpult	$6,	$7,	$27
	subq	$6,	$7,	$6
	stq	$23,	0($16)
	cmpult	$6,	$0,	$7
	subq	$6,	$0,	$28
	addq	$7,	$27,	$0
	cmpult	$8,	$22,	$21
	subq	$8,	$22,	$8
	stq	$25,	8($16)
	cmpult	$8,	$0,	$22
	subq	$8,	$0,	$20
	addq	$22,	$21,	$0
	stq	$28,	16($16)
	subq	$19,	4,	$19
	stq	$20,	24($16)
	addq	$17,	32,	$17
	addq	$18,	32,	$18
	addq	$16,	32,	$16
	blt	$19,	$100
	ldq	$1,	0($17)
	ldq	$2,	0($18)
	br	$101
$102:
	ldq	$1,	0($17)
	ldq	$2,	0($18)
	cmpult	$1,	$2,	$27
	subq	$1,	$2,	$1
	cmpult	$1,	$0,	$2
	subq	$1,	$0,	$1
	stq	$1,	0($16)
	addq	$2,	$27,	$0
	addq	$17,	8,	$17
	addq	$18,	8,	$18
	addq	$16,	8,	$16
	subq	$19,	1,	$19
	bgt	$19,	$102
	ret	$31,($26),1
$100:
	addq	$19,	4,	$19
	bgt	$19,	$102
$103:
	ret	$31,($26),1
	.end bn_sub_words
	.text
	.align 3
	.globl bn_mul_comba4
	.ent bn_mul_comba4
bn_mul_comba4:
bn_mul_comba4..ng:
	.frame $30,0,$26,0
	.prologue 0

	ldq	$0,	0($17)
	ldq	$1,	0($18)
	ldq	$2,	8($17)
	ldq	$3,	8($18)
	ldq	$4,	16($17)
	ldq	$5,	16($18)
	ldq	$6,	24($17)
	ldq	$7,	24($18)
	bis	$31,	$31,	$23
	mulq	$0,	$1,	$8
	umulh	$0,	$1,	$22
	stq	$8,	0($16)
	bis	$31,	$31,	$8
	mulq	$0,	$3,	$24
	umulh	$0,	$3,	$25
	addq	$22,	$24,	$22
	cmpult	$22,	$24,	$27
	addq	$27,	$25,	$25
	addq	$23,	$25,	$23
	cmpult	$23,	$25,	$28
	addq	$8,	$28,	$8
	mulq	$2,	$1,	$21
	umulh	$2,	$1,	$20
	addq	$22,	$21,	$22
	cmpult	$22,	$21,	$19
	addq	$19,	$20,	$20
	addq	$23,	$20,	$23
	cmpult	$23,	$20,	$17
	addq	$8,	$17,	$8
	stq	$22,	8($16)
	bis	$31,	$31,	$22
	mulq	$2,	$3,	$18
	umulh	$2,	$3,	$24
	addq	$23,	$18,	$23
	cmpult	$23,	$18,	$27
	addq	$27,	$24,	$24
	addq	$8,	$24,	$8
	cmpult	$8,	$24,	$25
	addq	$22,	$25,	$22
	mulq	$0,	$5,	$28
	umulh	$0,	$5,	$21
	addq	$23,	$28,	$23
	cmpult	$23,	$28,	$19
	addq	$19,	$21,	$21
	addq	$8,	$21,	$8
	cmpult	$8,	$21,	$20
	addq	$22,	$20,	$22
	mulq	$4,	$1,	$17
	umulh	$4,	$1,	$18
	addq	$23,	$17,	$23
	cmpult	$23,	$17,	$27
	addq	$27,	$18,	$18
	addq	$8,	$18,	$8
	cmpult	$8,	$18,	$24
	addq	$22,	$24,	$22
	stq	$23,	16($16)
	bis	$31,	$31,	$23
	mulq	$0,	$7,	$25
	umulh	$0,	$7,	$28
	addq	$8,	$25,	$8
	cmpult	$8,	$25,	$19
	addq	$19,	$28,	$28
	addq	$22,	$28,	$22
	cmpult	$22,	$28,	$21
	addq	$23,	$21,	$23
	mulq	$2,	$5,	$20
	umulh	$2,	$5,	$17
	addq	$8,	$20,	$8
	cmpult	$8,	$20,	$27
	addq	$27,	$17,	$17
	addq	$22,	$17,	$22
	cmpult	$22,	$17,	$18
	addq	$23,	$18,	$23
	mulq	$4,	$3,	$24
	umulh	$4,	$3,	$25
	addq	$8,	$24,	$8
	cmpult	$8,	$24,	$19
	addq	$19,	$25,	$25
	addq	$22,	$25,	$22
	cmpult	$22,	$25,	$28
	addq	$23,	$28,	$23
	mulq	$6,	$1,	$21
	umulh	$6,	$1,	$0
	addq	$8,	$21,	$8
	cmpult	$8,	$21,	$20
	addq	$20,	$0,	$0
	addq	$22,	$0,	$22
	cmpult	$22,	$0,	$27
	addq	$23,	$27,	$23
	stq	$8,	24($16)
	bis	$31,	$31,	$8
	mulq	$2,	$7,	$17
	umulh	$2,	$7,	$18
	addq	$22,	$17,	$22
	cmpult	$22,	$17,	$24
	addq	$24,	$18,	$18
	addq	$23,	$18,	$23
	cmpult	$23,	$18,	$19
	addq	$8,	$19,	$8
	mulq	$4,	$5,	$25
	umulh	$4,	$5,	$28
	addq	$22,	$25,	$22
	cmpult	$22,	$25,	$21
	addq	$21,	$28,	$28
	addq	$23,	$28,	$23
	cmpult	$23,	$28,	$20
	addq	$8,	$20,	$8
	mulq	$6,	$3,	$0
	umulh	$6,	$3,	$27
	addq	$22,	$0,	$22
	cmpult	$22,	$0,	$1
	addq	$1,	$27,	$27
	addq	$23,	$27,	$23
	cmpult	$23,	$27,	$17
	addq	$8,	$17,	$8
	stq	$22,	32($16)
	bis	$31,	$31,	$22
	mulq	$4,	$7,	$24
	umulh	$4,	$7,	$18
	addq	$23,	$24,	$23
	cmpult	$23,	$24,	$19
	addq	$19,	$18,	$18
	addq	$8,	$18,	$8
	cmpult	$8,	$18,	$2
	addq	$22,	$2,	$22
	mulq	$6,	$5,	$25
	umulh	$6,	$5,	$21
	addq	$23,	$25,	$23
	cmpult	$23,	$25,	$28
	addq	$28,	$21,	$21
	addq	$8,	$21,	$8
	cmpult	$8,	$21,	$20
	addq	$22,	$20,	$22
	stq	$23,	40($16)
	bis	$31,	$31,	$23
	mulq	$6,	$7,	$0
	umulh	$6,	$7,	$1
	addq	$8,	$0,	$8
	cmpult	$8,	$0,	$27
	addq	$27,	$1,	$1
	addq	$22,	$1,	$22
	cmpult	$22,	$1,	$17
	addq	$23,	$17,	$23
	stq	$8,	48($16)
	stq	$22,	56($16)
	ret	$31,($26),1
	.end bn_mul_comba4
	.text
	.align 3
	.globl bn_mul_comba8
	.ent bn_mul_comba8
bn_mul_comba8:
bn_mul_comba8..ng:
	.frame $30,0,$26,0
	.prologue 0
	ldq	$1,	0($17)
	ldq	$2,	0($18)
	zapnot	$1,	15,	$7
	srl	$2,	32,	$8
	mulq	$8,	$7,	$22
	srl	$1,	32,	$6
	zapnot	$2,	15,	$5
	mulq	$5,	$6,	$4
	mulq	$7,	$5,	$24
	addq	$22,	$4,	$22
	cmpult	$22,	$4,	$1
	mulq	$6,	$8,	$3
	beq	$1,	$173
	bis	$31,	1,	$1
	sll	$1,	32,	$1
	addq	$3,	$1,	$3
$173:
	sll	$22,	32,	$4
	addq	$24,	$4,	$24
	stq	$24,	0($16)
	ldq	$2,	0($17)
	ldq	$1,	8($18)
	zapnot	$2,	15,	$7
	srl	$1,	32,	$8
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$2,	32,	$6
	mulq	$5,	$6,	$23
	mulq	$6,	$8,	$6
	srl	$22,	32,	$1
	cmpult	$24,	$4,	$2
	addq	$3,	$1,	$3
	addq	$2,	$3,	$22
	addq	$25,	$23,	$25
	cmpult	$25,	$23,	$1
	bis	$31,	1,	$2
	beq	$1,	$177
	sll	$2,	32,	$1
	addq	$6,	$1,	$6
$177:
	sll	$25,	32,	$23
	ldq	$1,	0($18)
	addq	$0,	$23,	$0
	bis	$0,	$0,	$7
	ldq	$3,	8($17)
	addq	$22,	$7,	$22
	srl	$1,	32,	$8
	cmpult	$22,	$7,	$4
	zapnot	$3,	15,	$7
	mulq	$8,	$7,	$28
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$25,	32,	$1
	cmpult	$0,	$23,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$4,	$6,	$24
	srl	$3,	32,	$6
	mulq	$5,	$6,	$2
	mulq	$6,	$8,	$6
	addq	$28,	$2,	$28
	cmpult	$28,	$2,	$1
	bis	$31,	1,	$2
	beq	$1,	$181
	sll	$2,	32,	$1
	addq	$6,	$1,	$6
$181:
	sll	$28,	32,	$2
	addq	$21,	$2,	$21
	bis	$21,	$21,	$7
	addq	$22,	$7,	$22
	stq	$22,	8($16)
	ldq	$3,	16($17)
	ldq	$1,	0($18)
	cmpult	$22,	$7,	$4
	zapnot	$3,	15,	$7
	srl	$1,	32,	$8
	mulq	$8,	$7,	$22
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$20
	srl	$28,	32,	$1
	cmpult	$21,	$2,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$4,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$23
	srl	$3,	32,	$6
	mulq	$5,	$6,	$2
	mulq	$6,	$8,	$6
	addq	$22,	$2,	$22
	cmpult	$22,	$2,	$1
	bis	$31,	1,	$2
	beq	$1,	$185
	sll	$2,	32,	$1
	addq	$6,	$1,	$6
$185:
	sll	$22,	32,	$2
	ldq	$1,	8($18)
	addq	$20,	$2,	$20
	bis	$20,	$20,	$7
	ldq	$4,	8($17)
	addq	$24,	$7,	$24
	srl	$1,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$22,	32,	$1
	cmpult	$20,	$2,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$22
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$21
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$189
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$189:
	sll	$25,	32,	$5
	ldq	$2,	16($18)
	addq	$0,	$5,	$0
	bis	$0,	$0,	$7
	ldq	$4,	0($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$0,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$193
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$193:
	sll	$28,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$24,	$7,	$24
	stq	$24,	16($16)
	ldq	$4,	0($17)
	ldq	$5,	24($18)
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$24
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$0,	$24,	$0
	cmpult	$0,	$24,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$197
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$197:
	sll	$0,	32,	$24
	ldq	$1,	16($18)
	addq	$2,	$24,	$2
	bis	$2,	$2,	$7
	ldq	$4,	8($17)
	addq	$23,	$7,	$23
	srl	$1,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$0,	32,	$1
	cmpult	$2,	$24,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$24
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$20
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$201
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$201:
	sll	$25,	32,	$5
	ldq	$2,	8($18)
	addq	$21,	$5,	$21
	bis	$21,	$21,	$7
	ldq	$4,	16($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$21,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$205
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$205:
	sll	$28,	32,	$25
	ldq	$2,	0($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$209
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$209:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$23,	$7,	$23
	stq	$23,	24($16)
	ldq	$4,	32($17)
	ldq	$5,	0($18)
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$23
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$28,	$23,	$28
	cmpult	$28,	$23,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$213
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$213:
	sll	$28,	32,	$23
	ldq	$1,	8($18)
	addq	$2,	$23,	$2
	bis	$2,	$2,	$7
	ldq	$4,	24($17)
	addq	$22,	$7,	$22
	srl	$1,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$23,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$23
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$21
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$217
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$217:
	sll	$25,	32,	$5
	ldq	$2,	16($18)
	addq	$0,	$5,	$0
	bis	$0,	$0,	$7
	ldq	$4,	16($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$0,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$221
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$221:
	sll	$28,	32,	$25
	ldq	$2,	24($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	8($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$225
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$225:
	sll	$0,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	0($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$229
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$229:
	sll	$28,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$22,	$7,	$22
	stq	$22,	32($16)
	ldq	$4,	0($17)
	ldq	$5,	40($18)
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$22
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$0,	$22,	$0
	cmpult	$0,	$22,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$233
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$233:
	sll	$0,	32,	$22
	ldq	$1,	32($18)
	addq	$2,	$22,	$2
	bis	$2,	$2,	$7
	ldq	$4,	8($17)
	addq	$24,	$7,	$24
	srl	$1,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$0,	32,	$1
	cmpult	$2,	$22,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$22
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$20
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$237
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$237:
	sll	$25,	32,	$5
	ldq	$2,	24($18)
	addq	$21,	$5,	$21
	bis	$21,	$21,	$7
	ldq	$4,	16($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$21,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$241
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$241:
	sll	$28,	32,	$25
	ldq	$2,	16($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$245
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$245:
	sll	$0,	32,	$25
	ldq	$2,	8($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	32($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$249
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$249:
	sll	$28,	32,	$25
	ldq	$2,	0($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	40($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$253
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$253:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$24,	$7,	$24
	stq	$24,	40($16)
	ldq	$4,	48($17)
	ldq	$5,	0($18)
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$24
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$28,	$24,	$28
	cmpult	$28,	$24,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$257
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$257:
	sll	$28,	32,	$24
	ldq	$1,	8($18)
	addq	$2,	$24,	$2
	bis	$2,	$2,	$7
	ldq	$4,	40($17)
	addq	$23,	$7,	$23
	srl	$1,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$24,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$24
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$21
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$261
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$261:
	sll	$25,	32,	$5
	ldq	$2,	16($18)
	addq	$0,	$5,	$0
	bis	$0,	$0,	$7
	ldq	$4,	32($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$0,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$265
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$265:
	sll	$28,	32,	$25
	ldq	$2,	24($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$269
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$269:
	sll	$0,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	16($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$273
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$273:
	sll	$28,	32,	$25
	ldq	$2,	40($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	8($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$277
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$277:
	sll	$0,	32,	$25
	ldq	$2,	48($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	0($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$281
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$281:
	sll	$28,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$23,	$7,	$23
	stq	$23,	48($16)
	ldq	$4,	0($17)
	ldq	$5,	56($18)
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$23
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$0,	$23,	$0
	cmpult	$0,	$23,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$285
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$285:
	sll	$0,	32,	$23
	ldq	$1,	48($18)
	addq	$2,	$23,	$2
	bis	$2,	$2,	$7
	ldq	$4,	8($17)
	addq	$22,	$7,	$22
	srl	$1,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$0,	32,	$1
	cmpult	$2,	$23,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$23
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$20
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$289
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$289:
	sll	$25,	32,	$5
	ldq	$2,	40($18)
	addq	$21,	$5,	$21
	bis	$21,	$21,	$7
	ldq	$4,	16($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$21,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$293
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$293:
	sll	$28,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$297
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$297:
	sll	$0,	32,	$25
	ldq	$2,	24($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	32($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$301
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$301:
	sll	$28,	32,	$25
	ldq	$2,	16($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	40($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$305
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$305:
	sll	$0,	32,	$25
	ldq	$2,	8($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	48($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$309
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$309:
	sll	$28,	32,	$25
	ldq	$2,	0($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	56($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$313
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$313:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$22,	$7,	$22
	stq	$22,	56($16)
	ldq	$4,	56($17)
	ldq	$5,	8($18)
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$22
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$28,	$22,	$28
	cmpult	$28,	$22,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$317
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$317:
	sll	$28,	32,	$22
	ldq	$1,	16($18)
	addq	$2,	$22,	$2
	bis	$2,	$2,	$7
	ldq	$4,	48($17)
	addq	$24,	$7,	$24
	srl	$1,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$22,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$22
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$21
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$321
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$321:
	sll	$25,	32,	$5
	ldq	$2,	24($18)
	addq	$0,	$5,	$0
	bis	$0,	$0,	$7
	ldq	$4,	40($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$0,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$325
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$325:
	sll	$28,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	32($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$329
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$329:
	sll	$0,	32,	$25
	ldq	$2,	40($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$333
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$333:
	sll	$28,	32,	$25
	ldq	$2,	48($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	16($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$337
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$337:
	sll	$0,	32,	$25
	ldq	$2,	56($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	8($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$341
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$341:
	sll	$28,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$24,	$7,	$24
	stq	$24,	64($16)
	ldq	$4,	16($17)
	ldq	$5,	56($18)
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$24
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$0,	$24,	$0
	cmpult	$0,	$24,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$345
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$345:
	sll	$0,	32,	$24
	ldq	$1,	48($18)
	addq	$2,	$24,	$2
	bis	$2,	$2,	$7
	ldq	$4,	24($17)
	addq	$23,	$7,	$23
	srl	$1,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$0,	32,	$1
	cmpult	$2,	$24,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$24
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$20
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$349
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$349:
	sll	$25,	32,	$5
	ldq	$2,	40($18)
	addq	$21,	$5,	$21
	bis	$21,	$21,	$7
	ldq	$4,	32($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$21,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$353
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$353:
	sll	$28,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	40($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$357
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$357:
	sll	$0,	32,	$25
	ldq	$2,	24($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	48($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$361
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$361:
	sll	$28,	32,	$25
	ldq	$2,	16($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	56($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$365
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$365:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$23,	$7,	$23
	stq	$23,	72($16)
	ldq	$4,	56($17)
	ldq	$5,	24($18)
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$23
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$28,	$23,	$28
	cmpult	$28,	$23,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$369
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$369:
	sll	$28,	32,	$23
	ldq	$1,	32($18)
	addq	$2,	$23,	$2
	bis	$2,	$2,	$7
	ldq	$4,	48($17)
	addq	$22,	$7,	$22
	srl	$1,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$23,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$23
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$21
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$373
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$373:
	sll	$25,	32,	$5
	ldq	$2,	40($18)
	addq	$0,	$5,	$0
	bis	$0,	$0,	$7
	ldq	$4,	40($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$0,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$377
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$377:
	sll	$28,	32,	$25
	ldq	$2,	48($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	32($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$23,	$23
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$381
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$381:
	sll	$0,	32,	$25
	ldq	$2,	56($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	24($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$385
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$385:
	sll	$28,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$22,	$7,	$22
	stq	$22,	80($16)
	ldq	$4,	32($17)
	ldq	$5,	56($18)
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$22
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$0,	$22,	$0
	cmpult	$0,	$22,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$389
	sll	$21,	32,	$1
	addq	$6,	$1,	$6
$389:
	sll	$0,	32,	$22
	ldq	$1,	48($18)
	addq	$2,	$22,	$2
	bis	$2,	$2,	$7
	ldq	$4,	40($17)
	addq	$24,	$7,	$24
	srl	$1,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$25
	zapnot	$1,	15,	$5
	mulq	$7,	$5,	$21
	srl	$0,	32,	$1
	cmpult	$2,	$22,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$22
	srl	$4,	32,	$6
	mulq	$5,	$6,	$5
	bis	$31,	1,	$20
	addq	$25,	$5,	$25
	cmpult	$25,	$5,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$393
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$393:
	sll	$25,	32,	$5
	ldq	$2,	40($18)
	addq	$21,	$5,	$21
	bis	$21,	$21,	$7
	ldq	$4,	48($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$25,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$21,	$5,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$397
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$397:
	sll	$28,	32,	$25
	ldq	$2,	32($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	56($17)
	addq	$24,	$7,	$24
	srl	$2,	32,	$8
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$21
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$22,	$22
	addq	$21,	$25,	$21
	cmpult	$21,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$401
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$401:
	sll	$21,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$24,	$7,	$24
	stq	$24,	88($16)
	ldq	$4,	56($17)
	ldq	$5,	40($18)
	cmpult	$24,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$0
	srl	$21,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$23,	$6,	$23
	cmpult	$23,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$24
	mulq	$7,	$5,	$5
	addq	$1,	$22,	$22
	addq	$0,	$24,	$0
	cmpult	$0,	$24,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$405
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$405:
	sll	$0,	32,	$24
	ldq	$2,	48($18)
	addq	$5,	$24,	$5
	bis	$5,	$5,	$7
	ldq	$4,	48($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$24,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$24
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$5
	addq	$28,	$25,	$28
	cmpult	$28,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$409
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$409:
	sll	$28,	32,	$25
	ldq	$2,	56($18)
	addq	$5,	$25,	$5
	bis	$5,	$5,	$7
	ldq	$4,	40($17)
	addq	$23,	$7,	$23
	srl	$2,	32,	$8
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$25,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$1,	$24,	$24
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$413
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$413:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$23,	$7,	$23
	stq	$23,	96($16)
	ldq	$4,	48($17)
	ldq	$5,	56($18)
	cmpult	$23,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$22,	$6,	$22
	cmpult	$22,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$23
	mulq	$7,	$5,	$5
	addq	$1,	$24,	$24
	addq	$28,	$23,	$28
	cmpult	$28,	$23,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$417
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$417:
	sll	$28,	32,	$23
	ldq	$2,	48($18)
	addq	$5,	$23,	$5
	bis	$5,	$5,	$7
	ldq	$4,	56($17)
	addq	$22,	$7,	$22
	srl	$2,	32,	$8
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	mulq	$8,	$7,	$0
	srl	$28,	32,	$1
	addq	$6,	$1,	$6
	cmpult	$5,	$23,	$1
	zapnot	$2,	15,	$5
	addq	$1,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$23
	srl	$4,	32,	$6
	mulq	$5,	$6,	$25
	mulq	$7,	$5,	$2
	addq	$0,	$25,	$0
	cmpult	$0,	$25,	$1
	mulq	$6,	$8,	$6
	beq	$1,	$421
	sll	$20,	32,	$1
	addq	$6,	$1,	$6
$421:
	sll	$0,	32,	$25
	addq	$2,	$25,	$2
	bis	$2,	$2,	$7
	addq	$22,	$7,	$22
	stq	$22,	104($16)
	ldq	$4,	56($17)
	ldq	$5,	56($18)
	cmpult	$22,	$7,	$3
	zapnot	$4,	15,	$7
	srl	$5,	32,	$8
	mulq	$8,	$7,	$28
	srl	$0,	32,	$1
	cmpult	$2,	$25,	$2
	addq	$6,	$1,	$6
	addq	$2,	$6,	$6
	addq	$3,	$6,	$6
	addq	$24,	$6,	$24
	cmpult	$24,	$6,	$1
	srl	$4,	32,	$6
	zapnot	$5,	15,	$5
	mulq	$5,	$6,	$22
	mulq	$7,	$5,	$2
	addq	$1,	$23,	$23
	addq	$28,	$22,	$28
	cmpult	$28,	$22,	$1
	mulq	$6,	$8,	$3
	beq	$1,	$425
	sll	$20,	32,	$1
	addq	$3,	$1,	$3
$425:
	sll	$28,	32,	$22
	srl	$28,	32,	$1
	addq	$2,	$22,	$2
	addq	$3,	$1,	$3
	bis	$2,	$2,	$7
	addq	$24,	$7,	$24
	cmpult	$7,	$22,	$1
	cmpult	$24,	$7,	$2
	addq	$1,	$3,	$6
	addq	$2,	$6,	$6
	stq	$24,	112($16)
	addq	$23,	$6,	$23
	stq	$23,	120($16)
	ret	$31,	($26),	1
	.end bn_mul_comba8
	.text
	.align 3
	.globl bn_sqr_comba4
	.ent bn_sqr_comba4
bn_sqr_comba4:
bn_sqr_comba4..ng:
	.frame $30,0,$26,0
	.prologue 0

	ldq	$0,	0($17)
	ldq	$1,	8($17)
	ldq	$2,	16($17)
	ldq	$3,	24($17)
	bis	$31,	$31,	$6
	mulq	$0,	$0,	$4
	umulh	$0,	$0,	$5
	stq	$4,	0($16)
	bis	$31,	$31,	$4
	mulq	$0,	$1,	$7
	umulh	$0,	$1,	$8
	cmplt	$7,	$31,	$22
	cmplt	$8,	$31,	$23
	addq	$7,	$7,	$7
	addq	$8,	$8,	$8
	addq	$8,	$22,	$8
	addq	$4,	$23,	$4
	addq	$5,	$7,	$5
	addq	$6,	$8,	$6
	cmpult	$5,	$7,	$24
	cmpult	$6,	$8,	$25
	addq	$6,	$24,	$6
	addq	$4,	$25,	$4
	stq	$5,	8($16)
	bis	$31,	$31,	$5
	mulq	$1,	$1,	$27
	umulh	$1,	$1,	$28
	addq	$6,	$27,	$6
	addq	$4,	$28,	$4
	cmpult	$6,	$27,	$21
	cmpult	$4,	$28,	$20
	addq	$4,	$21,	$4
	addq	$5,	$20,	$5
	mulq	$2,	$0,	$19
	umulh	$2,	$0,	$18
	cmplt	$19,	$31,	$17
	cmplt	$18,	$31,	$22
	addq	$19,	$19,	$19
	addq	$18,	$18,	$18
	addq	$18,	$17,	$18
	addq	$5,	$22,	$5
	addq	$6,	$19,	$6
	addq	$4,	$18,	$4
	cmpult	$6,	$19,	$23
	cmpult	$4,	$18,	$7
	addq	$4,	$23,	$4
	addq	$5,	$7,	$5
	stq	$6,	16($16)
	bis	$31,	$31,	$6
	mulq	$3,	$0,	$8
	umulh	$3,	$0,	$24
	cmplt	$8,	$31,	$25
	cmplt	$24,	$31,	$27
	addq	$8,	$8,	$8
	addq	$24,	$24,	$24
	addq	$24,	$25,	$24
	addq	$6,	$27,	$6
	addq	$4,	$8,	$4
	addq	$5,	$24,	$5
	cmpult	$4,	$8,	$28
	cmpult	$5,	$24,	$21
	addq	$5,	$28,	$5
	addq	$6,	$21,	$6
	mulq	$2,	$1,	$20
	umulh	$2,	$1,	$17
	cmplt	$20,	$31,	$22
	cmplt	$17,	$31,	$19
	addq	$20,	$20,	$20
	addq	$17,	$17,	$17
	addq	$17,	$22,	$17
	addq	$6,	$19,	$6
	addq	$4,	$20,	$4
	addq	$5,	$17,	$5
	cmpult	$4,	$20,	$18
	cmpult	$5,	$17,	$23
	addq	$5,	$18,	$5
	addq	$6,	$23,	$6
	stq	$4,	24($16)
	bis	$31,	$31,	$4
	mulq	$2,	$2,	$7
	umulh	$2,	$2,	$25
	addq	$5,	$7,	$5
	addq	$6,	$25,	$6
	cmpult	$5,	$7,	$27
	cmpult	$6,	$25,	$8
	addq	$6,	$27,	$6
	addq	$4,	$8,	$4
	mulq	$3,	$1,	$24
	umulh	$3,	$1,	$28
	cmplt	$24,	$31,	$21
	cmplt	$28,	$31,	$22
	addq	$24,	$24,	$24
	addq	$28,	$28,	$28
	addq	$28,	$21,	$28
	addq	$4,	$22,	$4
	addq	$5,	$24,	$5
	addq	$6,	$28,	$6
	cmpult	$5,	$24,	$19
	cmpult	$6,	$28,	$20
	addq	$6,	$19,	$6
	addq	$4,	$20,	$4
	stq	$5,	32($16)
	bis	$31,	$31,	$5
	mulq	$3,	$2,	$17
	umulh	$3,	$2,	$18
	cmplt	$17,	$31,	$23
	cmplt	$18,	$31,	$7
	addq	$17,	$17,	$17
	addq	$18,	$18,	$18
	addq	$18,	$23,	$18
	addq	$5,	$7,	$5
	addq	$6,	$17,	$6
	addq	$4,	$18,	$4
	cmpult	$6,	$17,	$25
	cmpult	$4,	$18,	$27
	addq	$4,	$25,	$4
	addq	$5,	$27,	$5
	stq	$6,	40($16)
	bis	$31,	$31,	$6
	mulq	$3,	$3,	$8
	umulh	$3,	$3,	$21
	addq	$4,	$8,	$4
	addq	$5,	$21,	$5
	cmpult	$4,	$8,	$22
	cmpult	$5,	$21,	$24
	addq	$5,	$22,	$5
	addq	$6,	$24,	$6
	stq	$4,	48($16)
	stq	$5,	56($16)
	ret	$31,($26),1
	.end bn_sqr_comba4
	.text
	.align 3
	.globl bn_sqr_comba8
	.ent bn_sqr_comba8
bn_sqr_comba8:
bn_sqr_comba8..ng:
	.frame $30,0,$26,0
	.prologue 0

	ldq	$0,	0($17)
	ldq	$1,	8($17)
	ldq	$2,	16($17)
	ldq	$3,	24($17)
	ldq	$4,	32($17)
	ldq	$5,	40($17)
	ldq	$6,	48($17)
	ldq	$7,	56($17)
	bis	$31,	$31,	$23
	mulq	$0,	$0,	$8
	umulh	$0,	$0,	$22
	stq	$8,	0($16)
	bis	$31,	$31,	$8
	mulq	$1,	$0,	$24
	umulh	$1,	$0,	$25
	cmplt	$24,	$31,	$27
	cmplt	$25,	$31,	$28
	addq	$24,	$24,	$24
	addq	$25,	$25,	$25
	addq	$25,	$27,	$25
	addq	$8,	$28,	$8
	addq	$22,	$24,	$22
	addq	$23,	$25,	$23
	cmpult	$22,	$24,	$21
	cmpult	$23,	$25,	$20
	addq	$23,	$21,	$23
	addq	$8,	$20,	$8
	stq	$22,	8($16)
	bis	$31,	$31,	$22
	mulq	$1,	$1,	$19
	umulh	$1,	$1,	$18
	addq	$23,	$19,	$23
	addq	$8,	$18,	$8
	cmpult	$23,	$19,	$17
	cmpult	$8,	$18,	$27
	addq	$8,	$17,	$8
	addq	$22,	$27,	$22
	mulq	$2,	$0,	$28
	umulh	$2,	$0,	$24
	cmplt	$28,	$31,	$25
	cmplt	$24,	$31,	$21
	addq	$28,	$28,	$28
	addq	$24,	$24,	$24
	addq	$24,	$25,	$24
	addq	$22,	$21,	$22
	addq	$23,	$28,	$23
	addq	$8,	$24,	$8
	cmpult	$23,	$28,	$20
	cmpult	$8,	$24,	$19
	addq	$8,	$20,	$8
	addq	$22,	$19,	$22
	stq	$23,	16($16)
	bis	$31,	$31,	$23
	mulq	$2,	$1,	$18
	umulh	$2,	$1,	$17
	cmplt	$18,	$31,	$27
	cmplt	$17,	$31,	$25
	addq	$18,	$18,	$18
	addq	$17,	$17,	$17
	addq	$17,	$27,	$17
	addq	$23,	$25,	$23
	addq	$8,	$18,	$8
	addq	$22,	$17,	$22
	cmpult	$8,	$18,	$21
	cmpult	$22,	$17,	$28
	addq	$22,	$21,	$22
	addq	$23,	$28,	$23
	mulq	$3,	$0,	$24
	umulh	$3,	$0,	$20
	cmplt	$24,	$31,	$19
	cmplt	$20,	$31,	$27
	addq	$24,	$24,	$24
	addq	$20,	$20,	$20
	addq	$20,	$19,	$20
	addq	$23,	$27,	$23
	addq	$8,	$24,	$8
	addq	$22,	$20,	$22
	cmpult	$8,	$24,	$25
	cmpult	$22,	$20,	$18
	addq	$22,	$25,	$22
	addq	$23,	$18,	$23
	stq	$8,	24($16)
	bis	$31,	$31,	$8
	mulq	$2,	$2,	$17
	umulh	$2,	$2,	$21
	addq	$22,	$17,	$22
	addq	$23,	$21,	$23
	cmpult	$22,	$17,	$28
	cmpult	$23,	$21,	$19
	addq	$23,	$28,	$23
	addq	$8,	$19,	$8
	mulq	$3,	$1,	$27
	umulh	$3,	$1,	$24
	cmplt	$27,	$31,	$20
	cmplt	$24,	$31,	$25
	addq	$27,	$27,	$27
	addq	$24,	$24,	$24
	addq	$24,	$20,	$24
	addq	$8,	$25,	$8
	addq	$22,	$27,	$22
	addq	$23,	$24,	$23
	cmpult	$22,	$27,	$18
	cmpult	$23,	$24,	$17
	addq	$23,	$18,	$23
	addq	$8,	$17,	$8
	mulq	$4,	$0,	$21
	umulh	$4,	$0,	$28
	cmplt	$21,	$31,	$19
	cmplt	$28,	$31,	$20
	addq	$21,	$21,	$21
	addq	$28,	$28,	$28
	addq	$28,	$19,	$28
	addq	$8,	$20,	$8
	addq	$22,	$21,	$22
	addq	$23,	$28,	$23
	cmpult	$22,	$21,	$25
	cmpult	$23,	$28,	$27
	addq	$23,	$25,	$23
	addq	$8,	$27,	$8
	stq	$22,	32($16)
	bis	$31,	$31,	$22
	mulq	$3,	$2,	$24
	umulh	$3,	$2,	$18
	cmplt	$24,	$31,	$17
	cmplt	$18,	$31,	$19
	addq	$24,	$24,	$24
	addq	$18,	$18,	$18
	addq	$18,	$17,	$18
	addq	$22,	$19,	$22
	addq	$23,	$24,	$23
	addq	$8,	$18,	$8
	cmpult	$23,	$24,	$20
	cmpult	$8,	$18,	$21
	addq	$8,	$20,	$8
	addq	$22,	$21,	$22
	mulq	$4,	$1,	$28
	umulh	$4,	$1,	$25
	cmplt	$28,	$31,	$27
	cmplt	$25,	$31,	$17
	addq	$28,	$28,	$28
	addq	$25,	$25,	$25
	addq	$25,	$27,	$25
	addq	$22,	$17,	$22
	addq	$23,	$28,	$23
	addq	$8,	$25,	$8
	cmpult	$23,	$28,	$19
	cmpult	$8,	$25,	$24
	addq	$8,	$19,	$8
	addq	$22,	$24,	$22
	mulq	$5,	$0,	$18
	umulh	$5,	$0,	$20
	cmplt	$18,	$31,	$21
	cmplt	$20,	$31,	$27
	addq	$18,	$18,	$18
	addq	$20,	$20,	$20
	addq	$20,	$21,	$20
	addq	$22,	$27,	$22
	addq	$23,	$18,	$23
	addq	$8,	$20,	$8
	cmpult	$23,	$18,	$17
	cmpult	$8,	$20,	$28
	addq	$8,	$17,	$8
	addq	$22,	$28,	$22
	stq	$23,	40($16)
	bis	$31,	$31,	$23
	mulq	$3,	$3,	$25
	umulh	$3,	$3,	$19
	addq	$8,	$25,	$8
	addq	$22,	$19,	$22
	cmpult	$8,	$25,	$24
	cmpult	$22,	$19,	$21
	addq	$22,	$24,	$22
	addq	$23,	$21,	$23
	mulq	$4,	$2,	$27
	umulh	$4,	$2,	$18
	cmplt	$27,	$31,	$20
	cmplt	$18,	$31,	$17
	addq	$27,	$27,	$27
	addq	$18,	$18,	$18
	addq	$18,	$20,	$18
	addq	$23,	$17,	$23
	addq	$8,	$27,	$8
	addq	$22,	$18,	$22
	cmpult	$8,	$27,	$28
	cmpult	$22,	$18,	$25
	addq	$22,	$28,	$22
	addq	$23,	$25,	$23
	mulq	$5,	$1,	$19
	umulh	$5,	$1,	$24
	cmplt	$19,	$31,	$21
	cmplt	$24,	$31,	$20
	addq	$19,	$19,	$19
	addq	$24,	$24,	$24
	addq	$24,	$21,	$24
	addq	$23,	$20,	$23
	addq	$8,	$19,	$8
	addq	$22,	$24,	$22
	cmpult	$8,	$19,	$17
	cmpult	$22,	$24,	$27
	addq	$22,	$17,	$22
	addq	$23,	$27,	$23
	mulq	$6,	$0,	$18
	umulh	$6,	$0,	$28
	cmplt	$18,	$31,	$25
	cmplt	$28,	$31,	$21
	addq	$18,	$18,	$18
	addq	$28,	$28,	$28
	addq	$28,	$25,	$28
	addq	$23,	$21,	$23
	addq	$8,	$18,	$8
	addq	$22,	$28,	$22
	cmpult	$8,	$18,	$20
	cmpult	$22,	$28,	$19
	addq	$22,	$20,	$22
	addq	$23,	$19,	$23
	stq	$8,	48($16)
	bis	$31,	$31,	$8
	mulq	$4,	$3,	$24
	umulh	$4,	$3,	$17
	cmplt	$24,	$31,	$27
	cmplt	$17,	$31,	$25
	addq	$24,	$24,	$24
	addq	$17,	$17,	$17
	addq	$17,	$27,	$17
	addq	$8,	$25,	$8
	addq	$22,	$24,	$22
	addq	$23,	$17,	$23
	cmpult	$22,	$24,	$21
	cmpult	$23,	$17,	$18
	addq	$23,	$21,	$23
	addq	$8,	$18,	$8
	mulq	$5,	$2,	$28
	umulh	$5,	$2,	$20
	cmplt	$28,	$31,	$19
	cmplt	$20,	$31,	$27
	addq	$28,	$28,	$28
	addq	$20,	$20,	$20
	addq	$20,	$19,	$20
	addq	$8,	$27,	$8
	addq	$22,	$28,	$22
	addq	$23,	$20,	$23
	cmpult	$22,	$28,	$25
	cmpult	$23,	$20,	$24
	addq	$23,	$25,	$23
	addq	$8,	$24,	$8
	mulq	$6,	$1,	$17
	umulh	$6,	$1,	$21
	cmplt	$17,	$31,	$18
	cmplt	$21,	$31,	$19
	addq	$17,	$17,	$17
	addq	$21,	$21,	$21
	addq	$21,	$18,	$21
	addq	$8,	$19,	$8
	addq	$22,	$17,	$22
	addq	$23,	$21,	$23
	cmpult	$22,	$17,	$27
	cmpult	$23,	$21,	$28
	addq	$23,	$27,	$23
	addq	$8,	$28,	$8
	mulq	$7,	$0,	$20
	umulh	$7,	$0,	$25
	cmplt	$20,	$31,	$24
	cmplt	$25,	$31,	$18
	addq	$20,	$20,	$20
	addq	$25,	$25,	$25
	addq	$25,	$24,	$25
	addq	$8,	$18,	$8
	addq	$22,	$20,	$22
	addq	$23,	$25,	$23
	cmpult	$22,	$20,	$19
	cmpult	$23,	$25,	$17
	addq	$23,	$19,	$23
	addq	$8,	$17,	$8
	stq	$22,	56($16)
	bis	$31,	$31,	$22
	mulq	$4,	$4,	$21
	umulh	$4,	$4,	$27
	addq	$23,	$21,	$23
	addq	$8,	$27,	$8
	cmpult	$23,	$21,	$28
	cmpult	$8,	$27,	$24
	addq	$8,	$28,	$8
	addq	$22,	$24,	$22
	mulq	$5,	$3,	$18
	umulh	$5,	$3,	$20
	cmplt	$18,	$31,	$25
	cmplt	$20,	$31,	$19
	addq	$18,	$18,	$18
	addq	$20,	$20,	$20
	addq	$20,	$25,	$20
	addq	$22,	$19,	$22
	addq	$23,	$18,	$23
	addq	$8,	$20,	$8
	cmpult	$23,	$18,	$17
	cmpult	$8,	$20,	$21
	addq	$8,	$17,	$8
	addq	$22,	$21,	$22
	mulq	$6,	$2,	$27
	umulh	$6,	$2,	$28
	cmplt	$27,	$31,	$24
	cmplt	$28,	$31,	$25
	addq	$27,	$27,	$27
	addq	$28,	$28,	$28
	addq	$28,	$24,	$28
	addq	$22,	$25,	$22
	addq	$23,	$27,	$23
	addq	$8,	$28,	$8
	cmpult	$23,	$27,	$19
	cmpult	$8,	$28,	$18
	addq	$8,	$19,	$8
	addq	$22,	$18,	$22
	mulq	$7,	$1,	$20
	umulh	$7,	$1,	$17
	cmplt	$20,	$31,	$21
	cmplt	$17,	$31,	$24
	addq	$20,	$20,	$20
	addq	$17,	$17,	$17
	addq	$17,	$21,	$17
	addq	$22,	$24,	$22
	addq	$23,	$20,	$23
	addq	$8,	$17,	$8
	cmpult	$23,	$20,	$25
	cmpult	$8,	$17,	$27
	addq	$8,	$25,	$8
	addq	$22,	$27,	$22
	stq	$23,	64($16)
	bis	$31,	$31,	$23
	mulq	$5,	$4,	$28
	umulh	$5,	$4,	$19
	cmplt	$28,	$31,	$18
	cmplt	$19,	$31,	$21
	addq	$28,	$28,	$28
	addq	$19,	$19,	$19
	addq	$19,	$18,	$19
	addq	$23,	$21,	$23
	addq	$8,	$28,	$8
	addq	$22,	$19,	$22
	cmpult	$8,	$28,	$24
	cmpult	$22,	$19,	$20
	addq	$22,	$24,	$22
	addq	$23,	$20,	$23
	mulq	$6,	$3,	$17
	umulh	$6,	$3,	$25
	cmplt	$17,	$31,	$27
	cmplt	$25,	$31,	$18
	addq	$17,	$17,	$17
	addq	$25,	$25,	$25
	addq	$25,	$27,	$25
	addq	$23,	$18,	$23
	addq	$8,	$17,	$8
	addq	$22,	$25,	$22
	cmpult	$8,	$17,	$21
	cmpult	$22,	$25,	$28
	addq	$22,	$21,	$22
	addq	$23,	$28,	$23
	mulq	$7,	$2,	$19
	umulh	$7,	$2,	$24
	cmplt	$19,	$31,	$20
	cmplt	$24,	$31,	$27
	addq	$19,	$19,	$19
	addq	$24,	$24,	$24
	addq	$24,	$20,	$24
	addq	$23,	$27,	$23
	addq	$8,	$19,	$8
	addq	$22,	$24,	$22
	cmpult	$8,	$19,	$18
	cmpult	$22,	$24,	$17
	addq	$22,	$18,	$22
	addq	$23,	$17,	$23
	stq	$8,	72($16)
	bis	$31,	$31,	$8
	mulq	$5,	$5,	$25
	umulh	$5,	$5,	$21
	addq	$22,	$25,	$22
	addq	$23,	$21,	$23
	cmpult	$22,	$25,	$28
	cmpult	$23,	$21,	$20
	addq	$23,	$28,	$23
	addq	$8,	$20,	$8
	mulq	$6,	$4,	$27
	umulh	$6,	$4,	$19
	cmplt	$27,	$31,	$24
	cmplt	$19,	$31,	$18
	addq	$27,	$27,	$27
	addq	$19,	$19,	$19
	addq	$19,	$24,	$19
	addq	$8,	$18,	$8
	addq	$22,	$27,	$22
	addq	$23,	$19,	$23
	cmpult	$22,	$27,	$17
	cmpult	$23,	$19,	$25
	addq	$23,	$17,	$23
	addq	$8,	$25,	$8
	mulq	$7,	$3,	$21
	umulh	$7,	$3,	$28
	cmplt	$21,	$31,	$20
	cmplt	$28,	$31,	$24
	addq	$21,	$21,	$21
	addq	$28,	$28,	$28
	addq	$28,	$20,	$28
	addq	$8,	$24,	$8
	addq	$22,	$21,	$22
	addq	$23,	$28,	$23
	cmpult	$22,	$21,	$18
	cmpult	$23,	$28,	$27
	addq	$23,	$18,	$23
	addq	$8,	$27,	$8
	stq	$22,	80($16)
	bis	$31,	$31,	$22
	mulq	$6,	$5,	$19
	umulh	$6,	$5,	$17
	cmplt	$19,	$31,	$25
	cmplt	$17,	$31,	$20
	addq	$19,	$19,	$19
	addq	$17,	$17,	$17
	addq	$17,	$25,	$17
	addq	$22,	$20,	$22
	addq	$23,	$19,	$23
	addq	$8,	$17,	$8
	cmpult	$23,	$19,	$24
	cmpult	$8,	$17,	$21
	addq	$8,	$24,	$8
	addq	$22,	$21,	$22
	mulq	$7,	$4,	$28
	umulh	$7,	$4,	$18
	cmplt	$28,	$31,	$27
	cmplt	$18,	$31,	$25
	addq	$28,	$28,	$28
	addq	$18,	$18,	$18
	addq	$18,	$27,	$18
	addq	$22,	$25,	$22
	addq	$23,	$28,	$23
	addq	$8,	$18,	$8
	cmpult	$23,	$28,	$20
	cmpult	$8,	$18,	$19
	addq	$8,	$20,	$8
	addq	$22,	$19,	$22
	stq	$23,	88($16)
	bis	$31,	$31,	$23
	mulq	$6,	$6,	$17
	umulh	$6,	$6,	$24
	addq	$8,	$17,	$8
	addq	$22,	$24,	$22
	cmpult	$8,	$17,	$21
	cmpult	$22,	$24,	$27
	addq	$22,	$21,	$22
	addq	$23,	$27,	$23
	mulq	$7,	$5,	$25
	umulh	$7,	$5,	$28
	cmplt	$25,	$31,	$18
	cmplt	$28,	$31,	$20
	addq	$25,	$25,	$25
	addq	$28,	$28,	$28
	addq	$28,	$18,	$28
	addq	$23,	$20,	$23
	addq	$8,	$25,	$8
	addq	$22,	$28,	$22
	cmpult	$8,	$25,	$19
	cmpult	$22,	$28,	$17
	addq	$22,	$19,	$22
	addq	$23,	$17,	$23
	stq	$8,	96($16)
	bis	$31,	$31,	$8
	mulq	$7,	$6,	$24
	umulh	$7,	$6,	$21
	cmplt	$24,	$31,	$27
	cmplt	$21,	$31,	$18
	addq	$24,	$24,	$24
	addq	$21,	$21,	$21
	addq	$21,	$27,	$21
	addq	$8,	$18,	$8
	addq	$22,	$24,	$22
	addq	$23,	$21,	$23
	cmpult	$22,	$24,	$20
	cmpult	$23,	$21,	$25
	addq	$23,	$20,	$23
	addq	$8,	$25,	$8
	stq	$22,	104($16)
	bis	$31,	$31,	$22
	mulq	$7,	$7,	$28
	umulh	$7,	$7,	$19
	addq	$23,	$28,	$23
	addq	$8,	$19,	$8
	cmpult	$23,	$28,	$17
	cmpult	$8,	$19,	$27
	addq	$8,	$17,	$8
	addq	$22,	$27,	$22
	stq	$23,	112($16)
	stq	$8,	120($16)
	ret	$31,($26),1
	.end bn_sqr_comba8
