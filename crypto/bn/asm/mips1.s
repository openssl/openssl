/* This assember is for R2000/R3000 machines, or higher ones that do
 * no want to do any 64 bit arithmatic.
 * Make sure that the SSLeay bignum library is compiled with 
 * THIRTY_TWO_BIT set.
 * This must either be compiled with the system CC, or, if you use GNU gas,
 * cc -E mips1.s|gas -o mips1.o
 */
	.set	reorder
	.set	noat

#define R1	$1
#define CC	$2
#define	R2	$3
#define R3	$8
#define R4	$9
#define L1	$10
#define L2 	$11
#define L3	$12
#define L4 	$13
#define H1 	$14
#define H2	$15
#define H3	$24
#define H4	$25

#define P1	$4
#define P2	$5
#define P3	$6
#define P4	$7

	.align	2
	.ent	bn_mul_add_words
	.globl	bn_mul_add_words
.text
bn_mul_add_words:
	.frame	$sp,0,$31
	.mask	0x00000000,0
	.fmask	0x00000000,0

	#blt	P3,4,$lab34
	
	subu	R1,P3,4
	move	CC,$0
	bltz	R1,$lab34
$lab2:	
	lw	R1,0(P1)
	 lw	L1,0(P2)
	lw	R2,4(P1)
	 lw	L2,4(P2)
	lw	R3,8(P1)
	 lw	L3,8(P2)
	lw	R4,12(P1)
	 lw	L4,12(P2)
	multu	L1,P4
	 addu	R1,R1,CC
	mflo	L1
	 sltu	CC,R1,CC
	addu	R1,R1,L1
	 mfhi	H1
	sltu	L1,R1,L1
	 sw	R1,0(P1)
	addu	CC,CC,L1
	 multu	L2,P4
	addu	CC,H1,CC
	mflo	L2
	 addu	R2,R2,CC
	sltu	CC,R2,CC
	 mfhi	H2
	addu	R2,R2,L2
	 addu	P2,P2,16
	sltu	L2,R2,L2
	 sw	R2,4(P1)
	addu	CC,CC,L2
	 multu	L3,P4
	addu	CC,H2,CC
	mflo	L3
	 addu	R3,R3,CC
	sltu	CC,R3,CC
	 mfhi	H3
	addu	R3,R3,L3
	 addu	P1,P1,16
	sltu	L3,R3,L3
	 sw	R3,-8(P1)
	addu	CC,CC,L3
	 multu	L4,P4
	addu	CC,H3,CC
	mflo	L4
	 addu	R4,R4,CC
	sltu	CC,R4,CC
	 mfhi	H4
	addu	R4,R4,L4
	 subu	P3,P3,4
	sltu	L4,R4,L4
	addu	CC,CC,L4
	addu	CC,H4,CC

	subu	R1,P3,4
	sw	R4,-4(P1)	# delay slot
	bgez	R1,$lab2

	bleu	P3,0,$lab3
	.align	2
$lab33: 
	lw	L1,0(P2)
	 lw	R1,0(P1)
	multu	L1,P4
	 addu	R1,R1,CC
	sltu	CC,R1,CC
	 addu	P1,P1,4
	mflo	L1
	 mfhi	H1
	addu	R1,R1,L1
	 addu	P2,P2,4
	sltu	L1,R1,L1
	 subu	P3,P3,1
	addu	CC,CC,L1
	 sw	R1,-4(P1)
	addu	CC,H1,CC
	 bgtz	P3,$lab33
	j	$31
	.align	2
$lab3:
	j	$31
	.align	2
$lab34:
	bgt	P3,0,$lab33
	j	$31
	.end	bn_mul_add_words

	.align	2
	# Program Unit: bn_mul_words
	.ent	bn_mul_words
	.globl	bn_mul_words
.text
bn_mul_words:
	.frame	$sp,0,$31
	.mask	0x00000000,0
	.fmask	0x00000000,0
	
	subu	P3,P3,4
	move	CC,$0
	bltz	P3,$lab45
$lab44:	
	lw	L1,0(P2)
	 lw	L2,4(P2)
	lw	L3,8(P2)
	 lw	L4,12(P2)
	multu	L1,P4
	 subu	P3,P3,4
	mflo	L1
	 mfhi	H1
	addu	L1,L1,CC
	 multu	L2,P4
	sltu	CC,L1,CC
	 sw	L1,0(P1)
	addu	CC,H1,CC
	 mflo	L2
	mfhi	H2
	 addu	L2,L2,CC
	multu	L3,P4
	 sltu	CC,L2,CC
	sw	L2,4(P1)
	 addu	CC,H2,CC
	mflo	L3
	 mfhi	H3
	addu	L3,L3,CC
	 multu	L4,P4
	sltu	CC,L3,CC
	 sw	L3,8(P1)
	addu	CC,H3,CC
	 mflo	L4
	mfhi	H4
	 addu	L4,L4,CC
	addu	P1,P1,16
	 sltu	CC,L4,CC
	addu	P2,P2,16
	 addu	CC,H4,CC
	sw	L4,-4(P1)

	bgez	P3,$lab44
	b	$lab45
$lab46:
	lw	L1,0(P2)
	 addu	P1,P1,4
	multu	L1,P4
	 addu	P2,P2,4
	mflo	L1
	 mfhi	H1
	addu	L1,L1,CC
	 subu	P3,P3,1
	sltu	CC,L1,CC
	 sw	L1,-4(P1)
	addu	CC,H1,CC
	 bgtz	P3,$lab46
	j	$31
$lab45:
	addu	P3,P3,4
	bgtz	P3,$lab46
	j	$31
	.align	2
	.end	bn_mul_words

	# Program Unit: bn_sqr_words
	.ent	bn_sqr_words
	.globl	bn_sqr_words
.text
bn_sqr_words:
	.frame	$sp,0,$31
	.mask	0x00000000,0
	.fmask	0x00000000,0
	
	subu	P3,P3,4
	bltz	P3,$lab55
$lab54:
	lw	L1,0(P2)
	 lw	L2,4(P2)
	lw	L3,8(P2)
	 lw	L4,12(P2)

	multu	L1,L1
	 subu	P3,P3,4
	mflo	L1
	 mfhi	H1
	sw	L1,0(P1)
	 sw	H1,4(P1)

	multu	L2,L2
	 addu	P1,P1,32
	mflo	L2
	 mfhi	H2
	sw	L2,-24(P1)
	 sw	H2,-20(P1)

	multu	L3,L3
	 addu	P2,P2,16
	mflo	L3
	 mfhi	H3
	sw	L3,-16(P1)
	 sw	H3,-12(P1)

	multu	L4,L4

	mflo	L4
	 mfhi	H4
	sw	L4,-8(P1)
	 sw	H4,-4(P1)

	bgtz	P3,$lab54
	b	$lab55
$lab56:	
	lw	L1,0(P2)
	addu	P1,P1,8
	multu	L1,L1
	addu	P2,P2,4
	subu	P3,P3,1
	mflo	L1
	mfhi	H1
	sw	L1,-8(P1)
	sw	H1,-4(P1)

	bgtz	P3,$lab56
	j	$31
$lab55:
	addu	P3,P3,4
	bgtz	P3,$lab56
	j	$31
	.align	2
	.end	bn_sqr_words

	# Program Unit: bn_add_words
	.ent	bn_add_words
	.globl	bn_add_words
.text
bn_add_words: 	 # 0x590
	.frame	$sp,0,$31
	.mask	0x00000000,0
	.fmask	0x00000000,0
	
	subu	P4,P4,4
	move	CC,$0
	bltz	P4,$lab65
$lab64:	
	lw	L1,0(P2)
	lw	R1,0(P3)
	lw	L2,4(P2)
	lw	R2,4(P3)

	addu	L1,L1,CC
	 lw	L3,8(P2)
	sltu	CC,L1,CC
	 addu	L1,L1,R1
	sltu	R1,L1,R1
	 lw	R3,8(P3)
	addu	CC,CC,R1
	 lw	L4,12(P2)

	addu	L2,L2,CC
	 lw	R4,12(P3)
	sltu	CC,L2,CC
	 addu	L2,L2,R2
	sltu	R2,L2,R2
	 sw	L1,0(P1)
	addu	CC,CC,R2
	 addu	P1,P1,16
	addu	L3,L3,CC
	 sw	L2,-12(P1)
 
	sltu	CC,L3,CC
	 addu	L3,L3,R3
	sltu	R3,L3,R3
	 addu	P2,P2,16
	addu	CC,CC,R3

	addu	L4,L4,CC
	 addu	P3,P3,16
	sltu	CC,L4,CC
	 addu	L4,L4,R4
	subu	P4,P4,4
	 sltu	R4,L4,R4
	sw	L3,-8(P1)
	 addu	CC,CC,R4
	sw	L4,-4(P1)

	bgtz	P4,$lab64
	b	$lab65
$lab66:
	lw	L1,0(P2)
	 lw	R1,0(P3)
	addu	L1,L1,CC
	 addu	P1,P1,4
	sltu	CC,L1,CC
	 addu	P2,P2,4
	addu	P3,P3,4
	 addu	L1,L1,R1
	subu	P4,P4,1
	 sltu	R1,L1,R1
	sw	L1,-4(P1)
	 addu	CC,CC,R1

	bgtz	P4,$lab66
	j	$31
$lab65:
	addu	P4,P4,4
	bgtz	P4,$lab66
	j	$31
	.end	bn_add_words

	# Program Unit: bn_div64
	.set	at
	.set	reorder
	.text	
	.align	2
	.globl	bn_div64
 # 321		{
	.ent	bn_div64 2
bn_div64:
	subu	$sp, 64
	sw	$31, 56($sp)
	sw	$16, 48($sp)
	.mask	0x80010000, -56
	.frame	$sp, 64, $31
	move	$9, $4
	move	$12, $5
	move	$16, $6
 # 322		BN_ULONG dh,dl,q,ret=0,th,tl,t;
	move	$31, $0
 # 323		int i,count=2;
	li	$13, 2
 # 324	
 # 325		if (d == 0) return(BN_MASK2);
	bne	$16, 0, $80
	li	$2, -1
	b	$93
$80:
 # 326	
 # 327		i=BN_num_bits_word(d);
	move	$4, $16
	sw	$31, 16($sp)
	sw	$9, 24($sp)
	sw	$12, 32($sp)
	sw	$13, 40($sp)
	.livereg	0x800ff0e,0xfff
	jal	BN_num_bits_word
	li	$4, 32
	lw	$31, 16($sp)
	lw	$9, 24($sp)
	lw	$12, 32($sp)
	lw	$13, 40($sp)
	move	$3, $2
 # 328		if ((i != BN_BITS2) && (h > (BN_ULONG)1<<i))
	beq	$2, $4, $81
	li	$14, 1
	sll	$15, $14, $2
	bleu	$9, $15, $81
 # 329			{
 # 330	#if !defined(NO_STDIO) && !defined(WIN16)
 # 331			fprintf(stderr,"Division would overflow (%d)\n",i);
 # 332	#endif
 # 333			abort();
	sw	$3, 8($sp)
	sw	$9, 24($sp)
	sw	$12, 32($sp)
	sw	$13, 40($sp)
	sw	$31, 26($sp)
	.livereg	0xff0e,0xfff
	jal	abort
	lw	$3, 8($sp)
	li	$4, 32
	lw	$9, 24($sp)
	lw	$12, 32($sp)
	lw	$13, 40($sp)
	lw	$31, 26($sp)
 # 334			}
$81:
 # 335		i=BN_BITS2-i;
	subu	$3, $4, $3
 # 336		if (h >= d) h-=d;
	bltu	$9, $16, $82
	subu	$9, $9, $16
$82:
 # 337	
 # 338		if (i)
	beq	$3, 0, $83
 # 339			{
 # 340			d<<=i;
	sll	$16, $16, $3
 # 341			h=(h<<i)|(l>>(BN_BITS2-i));
	sll	$24, $9, $3
	subu	$25, $4, $3
	srl	$14, $12, $25
	or	$9, $24, $14
 # 342			l<<=i;
	sll	$12, $12, $3
 # 343			}
$83:
 # 344		dh=(d&BN_MASK2h)>>BN_BITS4;
 # 345		dl=(d&BN_MASK2l);
	and	$8, $16, -65536
	srl	$8, $8, 16
	and	$10, $16, 65535
	li	$6, -65536
$84:
 # 346		for (;;)
 # 347			{
 # 348			if ((h>>BN_BITS4) == dh)
	srl	$15, $9, 16
	bne	$8, $15, $85
 # 349				q=BN_MASK2l;
	li	$5, 65535
	b	$86
$85:
 # 350			else
 # 351				q=h/dh;
	divu	$5, $9, $8
$86:
 # 352	
 # 353			for (;;)
 # 354				{
 # 355				t=(h-q*dh);
	mul	$4, $5, $8
	subu	$2, $9, $4
	move	$3, $2
 # 356				if ((t&BN_MASK2h) ||
 # 357					((dl*q) <= (
 # 358						(t<<BN_BITS4)+
 # 359						((l&BN_MASK2h)>>BN_BITS4))))
	and	$25, $2, $6
	bne	$25, $0, $87
	mul	$24, $10, $5
	sll	$14, $3, 16
	and	$15, $12, $6
	srl	$25, $15, 16
	addu	$15, $14, $25
	bgtu	$24, $15, $88
$87:
 # 360					break;
	mul	$3, $10, $5
	b	$89
$88:
 # 361				q--;
	addu	$5, $5, -1
 # 362				}
	b	$86
$89:
 # 363			th=q*dh;
 # 364			tl=q*dl;
 # 365			t=(tl>>BN_BITS4);
 # 366			tl=(tl<<BN_BITS4)&BN_MASK2h;
	sll	$14, $3, 16
	and	$2, $14, $6
	move	$11, $2
 # 367			th+=t;
	srl	$25, $3, 16
	addu	$7, $4, $25
 # 368	
 # 369			if (l < tl) th++;
	bgeu	$12, $2, $90
	addu	$7, $7, 1
$90:
 # 370			l-=tl;
	subu	$12, $12, $11
 # 371			if (h < th)
	bgeu	$9, $7, $91
 # 372				{
 # 373				h+=d;
	addu	$9, $9, $16
 # 374				q--;
	addu	$5, $5, -1
 # 375				}
$91:
 # 376			h-=th;
	subu	$9, $9, $7
 # 377	
 # 378			if (--count == 0) break;
	addu	$13, $13, -1
	beq	$13, 0, $92
 # 379	
 # 380			ret=q<<BN_BITS4;
	sll	$31, $5, 16
 # 381			h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
	sll	$24, $9, 16
	srl	$15, $12, 16
	or	$9, $24, $15
 # 382			l=(l&BN_MASK2l)<<BN_BITS4;
	and	$12, $12, 65535
	sll	$12, $12, 16
 # 383			}
	b	$84
$92:
 # 384		ret|=q;
	or	$31, $31, $5
 # 385		return(ret);
	move	$2, $31
$93:
	lw	$16, 48($sp)
	lw	$31, 56($sp)
	addu	$sp, 64
	j	$31
	.end	bn_div64

