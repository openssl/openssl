	.file	1 "../bn_mulw.c"
	.set	nobopt
	.option pic2

 # GNU C 2.6.3 [AL 1.1, MM 40] SGI running IRIX 5.0 compiled by GNU C

 # Cc1 defaults:
 # -mabicalls

 # Cc1 arguments (-G value = 0, Cpu = 3000, ISA = 1):
 # -quiet -dumpbase -O2 -o

gcc2_compiled.:
__gnu_compiled_c:
	.rdata

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x34,0x39,0x20
	.byte	0x24,0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x33,0x34,0x20
	.byte	0x24,0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x35,0x20,0x24
	.byte	0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x38,0x20,0x24
	.byte	0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x32,0x33,0x20
	.byte	0x24,0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x37,0x38,0x20
	.byte	0x24,0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x33,0x2e,0x37,0x30,0x20
	.byte	0x24,0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x32,0x20,0x24
	.byte	0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x34,0x20,0x24
	.byte	0x0

	.byte	0x24,0x52,0x65,0x76,0x69,0x73,0x69,0x6f
	.byte	0x6e,0x3a,0x20,0x31,0x2e,0x38,0x20,0x24
	.byte	0x0
	.text
	.align	2
	.globl	bn_mul_add_words
	.ent	bn_mul_add_words
bn_mul_add_words:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, extra= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	move	$12,$4
	move	$14,$5
	move	$9,$6
	move	$13,$7
	move	$8,$0
	addu	$10,$12,12
	addu	$11,$14,12
$L2:
	lw	$6,0($14)
	#nop
	multu	$13,$6
	mfhi	$6
	mflo	$7
	#nop
	move	$5,$8
	move	$4,$0
	lw	$3,0($12)
	addu	$9,$9,-1
	move	$2,$0
	addu	$7,$7,$3
	sltu	$8,$7,$3
	addu	$6,$6,$2
	addu	$6,$6,$8
	addu	$7,$7,$5
	sltu	$2,$7,$5
	addu	$6,$6,$4
	addu	$6,$6,$2
	srl	$3,$6,0
	move	$2,$0
	move	$8,$3
	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L3
	sw	$7,0($12)
	.set	macro
	.set	reorder

	lw	$6,-8($11)
	#nop
	multu	$13,$6
	mfhi	$6
	mflo	$7
	#nop
	move	$5,$8
	move	$4,$0
	lw	$3,-8($10)
	addu	$9,$9,-1
	move	$2,$0
	addu	$7,$7,$3
	sltu	$8,$7,$3
	addu	$6,$6,$2
	addu	$6,$6,$8
	addu	$7,$7,$5
	sltu	$2,$7,$5
	addu	$6,$6,$4
	addu	$6,$6,$2
	srl	$3,$6,0
	move	$2,$0
	move	$8,$3
	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L3
	sw	$7,-8($10)
	.set	macro
	.set	reorder

	lw	$6,-4($11)
	#nop
	multu	$13,$6
	mfhi	$6
	mflo	$7
	#nop
	move	$5,$8
	move	$4,$0
	lw	$3,-4($10)
	addu	$9,$9,-1
	move	$2,$0
	addu	$7,$7,$3
	sltu	$8,$7,$3
	addu	$6,$6,$2
	addu	$6,$6,$8
	addu	$7,$7,$5
	sltu	$2,$7,$5
	addu	$6,$6,$4
	addu	$6,$6,$2
	srl	$3,$6,0
	move	$2,$0
	move	$8,$3
	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L3
	sw	$7,-4($10)
	.set	macro
	.set	reorder

	lw	$6,0($11)
	#nop
	multu	$13,$6
	mfhi	$6
	mflo	$7
	#nop
	move	$5,$8
	move	$4,$0
	lw	$3,0($10)
	addu	$9,$9,-1
	move	$2,$0
	addu	$7,$7,$3
	sltu	$8,$7,$3
	addu	$6,$6,$2
	addu	$6,$6,$8
	addu	$7,$7,$5
	sltu	$2,$7,$5
	addu	$6,$6,$4
	addu	$6,$6,$2
	srl	$3,$6,0
	move	$2,$0
	move	$8,$3
	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L3
	sw	$7,0($10)
	.set	macro
	.set	reorder

	addu	$11,$11,16
	addu	$14,$14,16
	addu	$10,$10,16
	.set	noreorder
	.set	nomacro
	j	$L2
	addu	$12,$12,16
	.set	macro
	.set	reorder

$L3:
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$8
	.set	macro
	.set	reorder

	.end	bn_mul_add_words
	.align	2
	.globl	bn_mul_words
	.ent	bn_mul_words
bn_mul_words:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, extra= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	move	$11,$4
	move	$12,$5
	move	$8,$6
	move	$6,$0
	addu	$10,$11,12
	addu	$9,$12,12
$L10:
	lw	$4,0($12)
	#nop
	multu	$7,$4
	mfhi	$4
	mflo	$5
	#nop
	move	$3,$6
	move	$2,$0
	addu	$8,$8,-1
	addu	$5,$5,$3
	sltu	$6,$5,$3
	addu	$4,$4,$2
	addu	$4,$4,$6
	srl	$3,$4,0
	move	$2,$0
	move	$6,$3
	.set	noreorder
	.set	nomacro
	beq	$8,$0,$L11
	sw	$5,0($11)
	.set	macro
	.set	reorder

	lw	$4,-8($9)
	#nop
	multu	$7,$4
	mfhi	$4
	mflo	$5
	#nop
	move	$3,$6
	move	$2,$0
	addu	$8,$8,-1
	addu	$5,$5,$3
	sltu	$6,$5,$3
	addu	$4,$4,$2
	addu	$4,$4,$6
	srl	$3,$4,0
	move	$2,$0
	move	$6,$3
	.set	noreorder
	.set	nomacro
	beq	$8,$0,$L11
	sw	$5,-8($10)
	.set	macro
	.set	reorder

	lw	$4,-4($9)
	#nop
	multu	$7,$4
	mfhi	$4
	mflo	$5
	#nop
	move	$3,$6
	move	$2,$0
	addu	$8,$8,-1
	addu	$5,$5,$3
	sltu	$6,$5,$3
	addu	$4,$4,$2
	addu	$4,$4,$6
	srl	$3,$4,0
	move	$2,$0
	move	$6,$3
	.set	noreorder
	.set	nomacro
	beq	$8,$0,$L11
	sw	$5,-4($10)
	.set	macro
	.set	reorder

	lw	$4,0($9)
	#nop
	multu	$7,$4
	mfhi	$4
	mflo	$5
	#nop
	move	$3,$6
	move	$2,$0
	addu	$8,$8,-1
	addu	$5,$5,$3
	sltu	$6,$5,$3
	addu	$4,$4,$2
	addu	$4,$4,$6
	srl	$3,$4,0
	move	$2,$0
	move	$6,$3
	.set	noreorder
	.set	nomacro
	beq	$8,$0,$L11
	sw	$5,0($10)
	.set	macro
	.set	reorder

	addu	$9,$9,16
	addu	$12,$12,16
	addu	$10,$10,16
	.set	noreorder
	.set	nomacro
	j	$L10
	addu	$11,$11,16
	.set	macro
	.set	reorder

$L11:
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$6
	.set	macro
	.set	reorder

	.end	bn_mul_words
	.align	2
	.globl	bn_sqr_words
	.ent	bn_sqr_words
bn_sqr_words:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, extra= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	move	$9,$4
	addu	$7,$9,28
	addu	$8,$5,12
$L18:
	lw	$2,0($5)
	#nop
	multu	$2,$2
	mfhi	$2
	mflo	$3
	#nop
	addu	$6,$6,-1
	sw	$3,0($9)
	srl	$3,$2,0
	move	$2,$0
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L19
	sw	$3,-24($7)
	.set	macro
	.set	reorder

	lw	$2,-8($8)
	#nop
	multu	$2,$2
	mfhi	$2
	mflo	$3
	#nop
	addu	$6,$6,-1
	sw	$3,-20($7)
	srl	$3,$2,0
	move	$2,$0
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L19
	sw	$3,-16($7)
	.set	macro
	.set	reorder

	lw	$2,-4($8)
	#nop
	multu	$2,$2
	mfhi	$2
	mflo	$3
	#nop
	addu	$6,$6,-1
	sw	$3,-12($7)
	srl	$3,$2,0
	move	$2,$0
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L19
	sw	$3,-8($7)
	.set	macro
	.set	reorder

	lw	$2,0($8)
	#nop
	multu	$2,$2
	mfhi	$2
	mflo	$3
	#nop
	addu	$6,$6,-1
	sw	$3,-4($7)
	srl	$3,$2,0
	move	$2,$0
	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L19
	sw	$3,0($7)
	.set	macro
	.set	reorder

	addu	$8,$8,16
	addu	$5,$5,16
	addu	$7,$7,32
	.set	noreorder
	.set	nomacro
	j	$L18
	addu	$9,$9,32
	.set	macro
	.set	reorder

$L19:
	j	$31
	.end	bn_sqr_words
	.rdata
	.align	2
$LC0:

	.byte	0x44,0x69,0x76,0x69,0x73,0x69,0x6f,0x6e
	.byte	0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x6f
	.byte	0x76,0x65,0x72,0x66,0x6c,0x6f,0x77,0xa
	.byte	0x0
	.text
	.align	2
	.globl	bn_div64
	.ent	bn_div64
bn_div64:
	.frame	$sp,56,$31		# vars= 0, regs= 7/0, args= 16, extra= 8
	.mask	0x901f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	subu	$sp,$sp,56
	.cprestore 16
	sw	$16,24($sp)
	move	$16,$4
	sw	$17,28($sp)
	move	$17,$5
	sw	$18,32($sp)
	move	$18,$6
	sw	$20,40($sp)
	move	$20,$0
	sw	$19,36($sp)
	li	$19,0x00000002		# 2
	sw	$31,48($sp)
	.set	noreorder
	.set	nomacro
	bne	$18,$0,$L26
	sw	$28,44($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L43
	li	$2,-1			# 0xffffffff
	.set	macro
	.set	reorder

$L26:
	move	$4,$18
	jal	BN_num_bits_word
	move	$4,$2
	li	$2,0x00000020		# 32
	.set	noreorder
	.set	nomacro
	beq	$4,$2,$L27
	li	$2,0x00000001		# 1
	.set	macro
	.set	reorder

	sll	$2,$2,$4
	sltu	$2,$2,$16
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L44
	li	$5,0x00000020		# 32
	.set	macro
	.set	reorder

	la	$4,__iob+32
	la	$5,$LC0
	jal	fprintf
	jal	abort
$L27:
	li	$5,0x00000020		# 32
$L44:
	sltu	$2,$16,$18
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L28
	subu	$4,$5,$4
	.set	macro
	.set	reorder

	subu	$16,$16,$18
$L28:
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L29
	li	$10,-65536			# 0xffff0000
	.set	macro
	.set	reorder

	sll	$18,$18,$4
	sll	$3,$16,$4
	subu	$2,$5,$4
	srl	$2,$17,$2
	or	$16,$3,$2
	sll	$17,$17,$4
$L29:
	srl	$7,$18,16
	andi	$9,$18,0xffff
$L30:
	srl	$2,$16,16
	.set	noreorder
	.set	nomacro
	beq	$2,$7,$L34
	li	$6,0x0000ffff		# 65535
	.set	macro
	.set	reorder

	divu	$6,$16,$7
$L34:
	mult	$6,$9
	mflo	$5
	#nop
	#nop
	mult	$6,$7
	and	$2,$17,$10
	srl	$8,$2,16
	mflo	$4
$L35:
	subu	$3,$16,$4
	and	$2,$3,$10
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L36
	sll	$2,$3,16
	.set	macro
	.set	reorder

	addu	$2,$2,$8
	sltu	$2,$2,$5
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L36
	subu	$5,$5,$9
	.set	macro
	.set	reorder

	subu	$4,$4,$7
	.set	noreorder
	.set	nomacro
	j	$L35
	addu	$6,$6,-1
	.set	macro
	.set	reorder

$L36:
	mult	$6,$7
	mflo	$5
	#nop
	#nop
	mult	$6,$9
	mflo	$4
	#nop
	#nop
	srl	$3,$4,16
	sll	$2,$4,16
	and	$4,$2,$10
	sltu	$2,$17,$4
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L40
	addu	$5,$5,$3
	.set	macro
	.set	reorder

	addu	$5,$5,1
$L40:
	sltu	$2,$16,$5
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L41
	subu	$17,$17,$4
	.set	macro
	.set	reorder

	addu	$16,$16,$18
	addu	$6,$6,-1
$L41:
	addu	$19,$19,-1
	.set	noreorder
	.set	nomacro
	beq	$19,$0,$L31
	subu	$16,$16,$5
	.set	macro
	.set	reorder

	sll	$20,$6,16
	sll	$3,$16,16
	srl	$2,$17,16
	or	$16,$3,$2
	.set	noreorder
	.set	nomacro
	j	$L30
	sll	$17,$17,16
	.set	macro
	.set	reorder

$L31:
	or	$2,$20,$6
$L43:
	lw	$31,48($sp)
	lw	$20,40($sp)
	lw	$19,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	addu	$sp,$sp,56
	j	$31
	.end	bn_div64

	.globl abort .text
	.globl fprintf .text
	.globl BN_num_bits_word .text
