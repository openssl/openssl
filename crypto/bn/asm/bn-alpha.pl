#!/usr/local/bin/perl
# I have this in perl so I can use more usefull register names and then convert
# them into alpha registers.
#

$d=&data();
$d =~ s/CC/0/g;
$d =~ s/R1/1/g;
$d =~ s/R2/2/g;
$d =~ s/R3/3/g;
$d =~ s/R4/4/g;
$d =~ s/L1/5/g;
$d =~ s/L2/6/g;
$d =~ s/L3/7/g;
$d =~ s/L4/8/g;
$d =~ s/O1/22/g;
$d =~ s/O2/23/g;
$d =~ s/O3/24/g;
$d =~ s/O4/25/g;
$d =~ s/A1/20/g;
$d =~ s/A2/21/g;
$d =~ s/A3/27/g;
$d =~ s/A4/28/g;
if (0){
}

print $d;

sub data
	{
	local($data)=<<'EOF';

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
	bis	$31,$31,$CC
	blt	$18,$43		# if we are -1, -2, -3 or -4 goto tail code
	ldq	$A1,0($17)	# 1 1
	ldq	$R1,0($16)	# 1 1
	.align 3
$42:
	mulq	$A1,$19,$L1	# 1 2 1	######
	ldq	$A2,8($17)	# 2 1
	ldq	$R2,8($16)	# 2 1
	umulh	$A1,$19,$A1	# 1 2	######
	ldq	$A3,16($17)	# 3 1
	ldq	$R3,16($16)	# 3 1
	mulq	$A2,$19,$L2	# 2 2 1	######
	 ldq	$A4,24($17)	# 4 1
	addq	$R1,$L1,$R1	# 1 2 2
	 ldq	$R4,24($16)	# 4 1
	umulh	$A2,$19,$A2	# 2 2	######
	 cmpult	$R1,$L1,$O1	# 1 2 3 1
	addq	$A1,$O1,$A1	# 1 3 1
	 addq	$R1,$CC,$R1	# 1 2 3 1
	mulq	$A3,$19,$L3	# 3 2 1	######
	 cmpult	$R1,$CC,$CC	# 1 2 3 2
	addq	$R2,$L2,$R2	# 2 2 2
	 addq	$A1,$CC,$CC	# 1 3 2 
	cmpult	$R2,$L2,$O2	# 2 2 3 1
	 addq	$A2,$O2,$A2	# 2 3 1
	umulh	$A3,$19,$A3	# 3 2	######
	 addq	$R2,$CC,$R2	# 2 2 3 1
	cmpult	$R2,$CC,$CC	# 2 2 3 2
	 subq	$18,4,$18
	mulq	$A4,$19,$L4	# 4 2 1	######
	 addq	$A2,$CC,$CC	# 2 3 2 
	addq	$R3,$L3,$R3	# 3 2 2
	 addq	$16,32,$16
	cmpult	$R3,$L3,$O3	# 3 2 3 1
	 stq	$R1,-32($16)	# 1 2 4
	umulh	$A4,$19,$A4	# 4 2	######
	 addq	$A3,$O3,$A3	# 3 3 1
	addq	$R3,$CC,$R3	# 3 2 3 1
	 stq	$R2,-24($16)	# 2 2 4
	cmpult	$R3,$CC,$CC	# 3 2 3 2
	 stq	$R3,-16($16)	# 3 2 4
	addq	$R4,$L4,$R4	# 4 2 2
	 addq	$A3,$CC,$CC	# 3 3 2 
	cmpult	$R4,$L4,$O4	# 4 2 3 1
	 addq	$17,32,$17
	addq	$A4,$O4,$A4	# 4 3 1
	 addq	$R4,$CC,$R4	# 4 2 3 1
	cmpult	$R4,$CC,$CC	# 4 2 3 2
	 stq	$R4,-8($16)	# 4 2 4
	addq	$A4,$CC,$CC	# 4 3 2 
	 blt	$18,$43

	ldq	$A1,0($17)	# 1 1
	ldq	$R1,0($16)	# 1 1

	br	$42

	.align 4
$45:
	ldq	$A1,0($17)	# 4 1
	ldq	$R1,0($16)	# 4 1
	mulq	$A1,$19,$L1	# 4 2 1
	subq	$18,1,$18
	addq	$16,8,$16
	addq	$17,8,$17
	umulh	$A1,$19,$A1	# 4 2
	addq	$R1,$L1,$R1	# 4 2 2
	cmpult	$R1,$L1,$O1	# 4 2 3 1
	addq	$A1,$O1,$A1	# 4 3 1
	addq	$R1,$CC,$R1	# 4 2 3 1
	cmpult	$R1,$CC,$CC	# 4 2 3 2
	addq	$A1,$CC,$CC	# 4 3 2 
	stq	$R1,-8($16)	# 4 2 4
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
	bis	$31,$31,$CC
	blt	$18,$143	# if we are -1, -2, -3 or -4 goto tail code
	ldq	$A1,0($17)	# 1 1
	.align 3
$142:

	mulq	$A1,$19,$L1	# 1 2 1	#####
	 ldq	$A2,8($17)	# 2 1
	 ldq	$A3,16($17)	# 3 1
	umulh	$A1,$19,$A1	# 1 2	#####
	 ldq	$A4,24($17)	# 4 1
	mulq	$A2,$19,$L2	# 2 2 1	#####
	 addq	$L1,$CC,$L1	# 1 2 3 1
	subq	$18,4,$18
	 cmpult	$L1,$CC,$CC	# 1 2 3 2
	umulh	$A2,$19,$A2	# 2 2	#####
	 addq	$A1,$CC,$CC	# 1 3 2 
	addq	$17,32,$17
	 addq	$L2,$CC,$L2	# 2 2 3 1
	mulq	$A3,$19,$L3	# 3 2 1	#####
	 cmpult	$L2,$CC,$CC	# 2 2 3 2
	addq	$A2,$CC,$CC	# 2 3 2 
	 addq	$16,32,$16
	umulh	$A3,$19,$A3	# 3 2	#####
	 stq	$L1,-32($16)	# 1 2 4
	mulq	$A4,$19,$L4	# 4 2 1	#####
	 addq	$L3,$CC,$L3	# 3 2 3 1
	stq	$L2,-24($16)	# 2 2 4
	 cmpult	$L3,$CC,$CC	# 3 2 3 2
	umulh	$A4,$19,$A4	# 4 2	#####
	 addq	$A3,$CC,$CC	# 3 3 2 
	stq	$L3,-16($16)	# 3 2 4
	 addq	$L4,$CC,$L4	# 4 2 3 1
	cmpult	$L4,$CC,$CC	# 4 2 3 2

	addq	$A4,$CC,$CC	# 4 3 2 

	stq	$L4,-8($16)	# 4 2 4

	blt	$18,$143

	ldq	$A1,0($17)	# 1 1

	br	$142

	.align 4
$145:
	ldq	$A1,0($17)	# 4 1
	mulq	$A1,$19,$L1	# 4 2 1
	subq	$18,1,$18
	umulh	$A1,$19,$A1	# 4 2
	addq	$L1,$CC,$L1	# 4 2 3 1
	 addq	$16,8,$16
	cmpult	$L1,$CC,$CC	# 4 2 3 2
	 addq	$17,8,$17
	addq	$A1,$CC,$CC	# 4 3 2 
	stq	$L1,-8($16)	# 4 2 4

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
	ldq	$A1,0($17)	# 1 1
	.align 3
$542:
	mulq	$A1,$A1,$L1		######
	 ldq	$A2,8($17)	# 1 1
	subq	$18,4
 	umulh	$A1,$A1,$R1		######
	ldq	$A3,16($17)	# 1 1
	mulq	$A2,$A2,$L2		######
	ldq	$A4,24($17)	# 1 1
	stq	$L1,0($16)	# r[0]
 	umulh	$A2,$A2,$R2		######
	stq	$R1,8($16)	# r[1]
	mulq	$A3,$A3,$L3		######
	stq	$L2,16($16)	# r[0]
 	umulh	$A3,$A3,$R3		######
	stq	$R2,24($16)	# r[1]
	mulq	$A4,$A4,$L4		######
	stq	$L3,32($16)	# r[0]
 	umulh	$A4,$A4,$R4		######
	stq	$R3,40($16)	# r[1]

 	addq	$16,64,$16
 	addq	$17,32,$17
	stq	$L4,-16($16)	# r[0]
	stq	$R4,-8($16)	# r[1]

	blt	$18,$543
	ldq	$A1,0($17)	# 1 1
 	br 	$542

$442:
	ldq	$A1,0($17)   # a[0]
	mulq	$A1,$A1,$L1  # a[0]*w low part       r2
	addq	$16,16,$16
	addq	$17,8,$17
	subq	$18,1,$18
        umulh	$A1,$A1,$R1  # a[0]*w high part       r3
	stq	$L1,-16($16)   # r[0]
        stq	$R1,-8($16)   # r[1]

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
	bis	$31,$31,$CC	# carry = 0
	blt	$19,$900
	ldq	$L1,0($17)	# a[0]
	ldq	$R1,0($18)	# b[1]
	.align 3
$901:
	addq	$R1,$L1,$R1	# r=a+b;
	 ldq	$L2,8($17)	# a[1]
	cmpult	$R1,$L1,$O1	# did we overflow?
	 ldq	$R2,8($18)	# b[1]
	addq	$R1,$CC,$R1	# c+= overflow
	 ldq	$L3,16($17)	# a[2]
	cmpult	$R1,$CC,$CC	# overflow?
	 ldq	$R3,16($18)	# b[2]
	addq	$CC,$O1,$CC
	 ldq	$L4,24($17)	# a[3]
	addq	$R2,$L2,$R2	# r=a+b;
	 ldq	$R4,24($18)	# b[3]
	cmpult	$R2,$L2,$O2	# did we overflow?
	 addq	$R3,$L3,$R3	# r=a+b;
	addq	$R2,$CC,$R2	# c+= overflow
	 cmpult	$R3,$L3,$O3	# did we overflow?
	cmpult	$R2,$CC,$CC	# overflow?
	 addq	$R4,$L4,$R4	# r=a+b;
	addq	$CC,$O2,$CC
	 cmpult	$R4,$L4,$O4	# did we overflow?
	addq	$R3,$CC,$R3	# c+= overflow
	 stq	$R1,0($16)	# r[0]=c
	cmpult	$R3,$CC,$CC	# overflow?
	 stq	$R2,8($16)	# r[1]=c
	addq	$CC,$O3,$CC
	 stq	$R3,16($16)	# r[2]=c
	addq	$R4,$CC,$R4	# c+= overflow
	 subq	$19,4,$19	# loop--
	cmpult	$R4,$CC,$CC	# overflow?
	 addq	$17,32,$17	# a++
	addq	$CC,$O4,$CC
	 stq	$R4,24($16)	# r[3]=c
	addq	$18,32,$18	# b++
	 addq	$16,32,$16	# r++

	blt	$19,$900
	 ldq	$L1,0($17)	# a[0]
	ldq	$R1,0($18)	# b[1]
	 br	$901
	.align 4
$945:
	ldq	$L1,0($17)	# a[0]
	 ldq	$R1,0($18)	# b[1]
	addq	$R1,$L1,$R1	# r=a+b;
	 subq	$19,1,$19	# loop--
	addq	$R1,$CC,$R1	# c+= overflow
	 addq	$17,8,$17	# a++
	cmpult	$R1,$L1,$O1	# did we overflow?
	 cmpult	$R1,$CC,$CC	# overflow?
	addq	$18,8,$18	# b++
	 stq	$R1,0($16)	# r[0]=c
	addq	$CC,$O1,$CC
	 addq	$16,8,$16	# r++

	bgt	$19,$945
	ret	$31,($26),1	# else exit

$900:
	addq	$19,4,$19
	bgt	$19,$945	# goto tail code
	ret	$31,($26),1	# else exit
	.end bn_add_words

	.align 3
	.globl bn_sub_words
	.ent bn_sub_words
bn_sub_words:
bn_sub_words..ng:
	.frame $30,0,$26,0
	.prologue 0

	subq	$19,4,$19
	bis	$31,$31,$CC	# carry = 0
 br	$800
	blt	$19,$800
	ldq	$L1,0($17)	# a[0]
	ldq	$R1,0($18)	# b[1]
	.align 3
$801:
	addq	$R1,$L1,$R1	# r=a+b;
	 ldq	$L2,8($17)	# a[1]
	cmpult	$R1,$L1,$O1	# did we overflow?
	 ldq	$R2,8($18)	# b[1]
	addq	$R1,$CC,$R1	# c+= overflow
	 ldq	$L3,16($17)	# a[2]
	cmpult	$R1,$CC,$CC	# overflow?
	 ldq	$R3,16($18)	# b[2]
	addq	$CC,$O1,$CC
	 ldq	$L4,24($17)	# a[3]
	addq	$R2,$L2,$R2	# r=a+b;
	 ldq	$R4,24($18)	# b[3]
	cmpult	$R2,$L2,$O2	# did we overflow?
	 addq	$R3,$L3,$R3	# r=a+b;
	addq	$R2,$CC,$R2	# c+= overflow
	 cmpult	$R3,$L3,$O3	# did we overflow?
	cmpult	$R2,$CC,$CC	# overflow?
	 addq	$R4,$L4,$R4	# r=a+b;
	addq	$CC,$O2,$CC
	 cmpult	$R4,$L4,$O4	# did we overflow?
	addq	$R3,$CC,$R3	# c+= overflow
	 stq	$R1,0($16)	# r[0]=c
	cmpult	$R3,$CC,$CC	# overflow?
	 stq	$R2,8($16)	# r[1]=c
	addq	$CC,$O3,$CC
	 stq	$R3,16($16)	# r[2]=c
	addq	$R4,$CC,$R4	# c+= overflow
	 subq	$19,4,$19	# loop--
	cmpult	$R4,$CC,$CC	# overflow?
	 addq	$17,32,$17	# a++
	addq	$CC,$O4,$CC
	 stq	$R4,24($16)	# r[3]=c
	addq	$18,32,$18	# b++
	 addq	$16,32,$16	# r++

	blt	$19,$800
	 ldq	$L1,0($17)	# a[0]
	ldq	$R1,0($18)	# b[1]
	 br	$801
	.align 4
$845:
	ldq	$L1,0($17)	# a[0]
	 ldq	$R1,0($18)	# b[1]
	cmpult	$L1,$R1,$O1	# will we borrow?
	 subq	$L1,$R1,$R1	# r=a-b;
	subq	$19,1,$19	# loop--
	 cmpult  $R1,$CC,$O2	# will we borrow?
	subq	$R1,$CC,$R1	# c+= overflow
	 addq	$17,8,$17	# a++
	addq	$18,8,$18	# b++
	 stq	$R1,0($16)	# r[0]=c
	addq	$O2,$O1,$CC
	 addq	$16,8,$16	# r++

	bgt	$19,$845
	ret	$31,($26),1	# else exit

$800:
	addq	$19,4,$19
	bgt	$19,$845	# goto tail code
	ret	$31,($26),1	# else exit
	.end bn_sub_words

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
EOF
	return($data);
	}

