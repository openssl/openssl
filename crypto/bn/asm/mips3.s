/* This assember is for R4000 and above machines.  It takes advantage
 * of the 64 bit registers present on these CPUs.
 * Make sure that the SSLeay bignum library is compiled with
 * SIXTY_FOUR_BIT set and BN_LLONG undefined.
 * This must either be compiled with the system CC, or, if you use GNU gas,
 * cc -E mips3.s|gas -o mips3.o
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
	ld	R1,0(P1)
	 ld	L1,0(P2)
	ld	R2,8(P1)
	 ld	L2,8(P2)
	ld	R3,16(P1)
	 ld	L3,16(P2)
	ld	R4,24(P1)
	 ld	L4,24(P2)
	dmultu	L1,P4
	 daddu	R1,R1,CC
	mflo	L1
	 sltu	CC,R1,CC
	daddu	R1,R1,L1
	 mfhi	H1
	sltu	L1,R1,L1
	 sd	R1,0(P1)
	daddu	CC,CC,L1
	 dmultu	L2,P4
	daddu	CC,H1,CC
	mflo	L2
	 daddu	R2,R2,CC
	sltu	CC,R2,CC
	 mfhi	H2
	daddu	R2,R2,L2
	 daddu	P2,P2,32
	sltu	L2,R2,L2
	 sd	R2,8(P1)
	daddu	CC,CC,L2
	 dmultu	L3,P4
	daddu	CC,H2,CC
	mflo	L3
	 daddu	R3,R3,CC
	sltu	CC,R3,CC
	 mfhi	H3
	daddu	R3,R3,L3
	 daddu	P1,P1,32
	sltu	L3,R3,L3
	 sd	R3,-16(P1)
	daddu	CC,CC,L3
	 dmultu	L4,P4
	daddu	CC,H3,CC
	mflo	L4
	 daddu	R4,R4,CC
	sltu	CC,R4,CC
	 mfhi	H4
	daddu	R4,R4,L4
	 subu	P3,P3,4
	sltu	L4,R4,L4
	daddu	CC,CC,L4
	daddu	CC,H4,CC

	subu	R1,P3,4
	sd	R4,-8(P1)	# delay slot
	bgez	R1,$lab2

	bleu	P3,0,$lab3
	.align	2
$lab33: 
	ld	L1,0(P2)
	 ld	R1,0(P1)
	dmultu	L1,P4
	 daddu	R1,R1,CC
	sltu	CC,R1,CC
	 daddu	P1,P1,8
	mflo	L1
	 mfhi	H1
	daddu	R1,R1,L1
	 daddu	P2,P2,8
	sltu	L1,R1,L1
	 subu	P3,P3,1
	daddu	CC,CC,L1
	 sd	R1,-8(P1)
	daddu	CC,H1,CC
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
	ld	L1,0(P2)
	 ld	L2,8(P2)
	ld	L3,16(P2)
	 ld	L4,24(P2)
	dmultu	L1,P4
	 subu	P3,P3,4
	mflo	L1
	 mfhi	H1
	daddu	L1,L1,CC
	 dmultu	L2,P4
	sltu	CC,L1,CC
	 sd	L1,0(P1)
	daddu	CC,H1,CC
	 mflo	L2
	mfhi	H2
	 daddu	L2,L2,CC
	dmultu	L3,P4
	 sltu	CC,L2,CC
	sd	L2,8(P1)
	 daddu	CC,H2,CC
	mflo	L3
	 mfhi	H3
	daddu	L3,L3,CC
	 dmultu	L4,P4
	sltu	CC,L3,CC
	 sd	L3,16(P1)
	daddu	CC,H3,CC
	 mflo	L4
	mfhi	H4
	 daddu	L4,L4,CC
	daddu	P1,P1,32
	 sltu	CC,L4,CC
	daddu	P2,P2,32
	 daddu	CC,H4,CC
	sd	L4,-8(P1)

	bgez	P3,$lab44
	b	$lab45
$lab46:
	ld	L1,0(P2)
	 daddu	P1,P1,8
	dmultu	L1,P4
	 daddu	P2,P2,8
	mflo	L1
	 mfhi	H1
	daddu	L1,L1,CC
	 subu	P3,P3,1
	sltu	CC,L1,CC
	 sd	L1,-8(P1)
	daddu	CC,H1,CC
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
 b $lab55
	bltz	P3,$lab55
$lab54:
	ld	L1,0(P2)
	 ld	L2,8(P2)
	ld	L3,16(P2)
	 ld	L4,24(P2)

	dmultu	L1,L1
	 subu	P3,P3,4
	mflo	L1
	 mfhi	H1
	sd	L1,0(P1)
	 sd	H1,8(P1)

	dmultu	L2,L2
	 daddu	P1,P1,32
	mflo	L2
	 mfhi	H2
	sd	L2,-48(P1)
	 sd	H2,-40(P1)

	dmultu	L3,L3
	 daddu	P2,P2,32
	mflo	L3
	 mfhi	H3
	sd	L3,-32(P1)
	 sd	H3,-24(P1)

	dmultu	L4,L4

	mflo	L4
	 mfhi	H4
	sd	L4,-16(P1)
	 sd	H4,-8(P1)

	bgtz	P3,$lab54
	b	$lab55
$lab56:	
	ld	L1,0(P2)
	daddu	P1,P1,16
	dmultu	L1,L1
	daddu	P2,P2,8
	subu	P3,P3,1
	mflo	L1
	mfhi	H1
	sd	L1,-16(P1)
	sd	H1,-8(P1)

	bgtz	P3,$lab56
	j	$31
$lab55:
	daddu	P3,P3,4
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
	ld	L1,0(P2)
	ld	R1,0(P3)
	ld	L2,8(P2)
	ld	R2,8(P3)

	daddu	L1,L1,CC
	 ld	L3,16(P2)
	sltu	CC,L1,CC
	 daddu	L1,L1,R1
	sltu	R1,L1,R1
	 ld	R3,16(P3)
	daddu	CC,CC,R1
	 ld	L4,24(P2)

	daddu	L2,L2,CC
	 ld	R4,24(P3)
	sltu	CC,L2,CC
	 daddu	L2,L2,R2
	sltu	R2,L2,R2
	 sd	L1,0(P1)
	daddu	CC,CC,R2
	 daddu	P1,P1,32
	daddu	L3,L3,CC
	 sd	L2,-24(P1)

	sltu	CC,L3,CC
	 daddu	L3,L3,R3
	sltu	R3,L3,R3
	 daddu	P2,P2,32
	daddu	CC,CC,R3

	daddu	L4,L4,CC
	 daddu	P3,P3,32
	sltu	CC,L4,CC
	 daddu	L4,L4,R4
	sltu	R4,L4,R4
	 subu	P4,P4,4
	sd	L3,-16(P1)
	 daddu	CC,CC,R4
	sd	L4,-8(P1)

	bgtz	P4,$lab64
	b	$lab65
$lab66:
	ld	L1,0(P2)
	 ld	R1,0(P3)
	daddu	L1,L1,CC
	 daddu	P1,P1,8
	sltu	CC,L1,CC
	 daddu	P2,P2,8
	daddu	P3,P3,8
	 daddu	L1,L1,R1
	subu	P4,P4,1
	 sltu	R1,L1,R1
	sd	L1,-8(P1)
	 daddu	CC,CC,R1

	bgtz	P4,$lab66
	j	$31
$lab65:
	addu	P4,P4,4
	bgtz	P4,$lab66
	j	$31
	.end	bn_add_words

#if 1
	# Program Unit: bn_div64
	.set	at
	.set	reorder
	.text	
	.align	2
	.globl	bn_div64
 # 321		{
	.ent	bn_div64
bn_div64:
	dsubu	$sp, 64
	sd	$31, 56($sp)
	sd	$16, 48($sp)
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
	dli	$2, -1
	b	$93
$80:
 # 326	
 # 327		i=BN_num_bits_word(d);
	move	$4, $16
	sd	$31, 16($sp)
	sd	$9, 24($sp)
	sd	$12, 32($sp)
	sd	$13, 40($sp)
	.livereg	0x800ff0e,0xfff
	jal	BN_num_bits_word
	dli	$4, 64
	ld	$31, 16($sp)
	ld	$9, 24($sp)
	ld	$12, 32($sp)
	ld	$13, 40($sp)
	move	$3, $2
 # 328		if ((i != BN_BITS2) && (h > (BN_ULONG)1<<i))
	beq	$2, $4, $81
	dli	$14, 1
	dsll	$15, $14, $2
	bleu	$9, $15, $81
 # 329			{
 # 330	#if !defined(NO_STDIO) && !defined(WIN16)
 # 331			fprintf(stderr,"Division would overflow (%d)\n",i);
 # 332	#endif
 # 333			abort();
	sd	$3, 8($sp)
	sd	$31, 16($sp)
	sd	$9, 24($sp)
	sd	$12, 32($sp)
	sd	$13, 40($sp)
	.livereg	0xff0e,0xfff
	jal	abort
	dli	$4, 64
	ld	$3, 8($sp)
	ld	$31, 16($sp)
	ld	$9, 24($sp)
	ld	$12, 32($sp)
	ld	$13, 40($sp)
 # 334			}
$81:
 # 335		i=BN_BITS2-i;
	dsubu	$3, $4, $3
 # 336		if (h >= d) h-=d;
	bltu	$9, $16, $82
	dsubu	$9, $9, $16
$82:
 # 337	
 # 338		if (i)
	beq	$3, 0, $83
 # 339			{
 # 340			d<<=i;
	dsll	$16, $16, $3
 # 341			h=(h<<i)|(l>>(BN_BITS2-i));
	dsll	$24, $9, $3
	dsubu	$25, $4, $3
	dsrl	$14, $12, $25
	or	$9, $24, $14
 # 342			l<<=i;
	dsll	$12, $12, $3
 # 343			}
$83:
 # 344		dh=(d&BN_MASK2h)>>BN_BITS4;
 # 345		dl=(d&BN_MASK2l);
	and	$8, $16,0xFFFFFFFF00000000
	dsrl	$8, $8, 32
	# dli	$10,0xFFFFFFFF # Is this needed?
	# and	$10, $16, $10
	dsll	$10, $16, 32
	dsrl	$10, $10, 32
	dli	$6,0xFFFFFFFF00000000
$84:
 # 346		for (;;)
 # 347			{
 # 348			if ((h>>BN_BITS4) == dh)
	dsrl	$15, $9, 32
	bne	$8, $15, $85
 # 349				q=BN_MASK2l;
	dli	$5, 0xFFFFFFFF
	b	$86
$85:
 # 350			else
 # 351				q=h/dh;
	ddivu	$5, $9, $8
$86:
 # 352	
 # 353			for (;;)
 # 354				{
 # 355				t=(h-q*dh);
	dmul	$4, $5, $8
	dsubu	$2, $9, $4
	move	$3, $2
 # 356				if ((t&BN_MASK2h) ||
 # 357					((dl*q) <= (
 # 358						(t<<BN_BITS4)+
 # 359						((l&BN_MASK2h)>>BN_BITS4))))
	and	$25, $2, $6
	bne	$25, $0, $87
	dmul	$24, $10, $5
	dsll	$14, $3, 32
	and	$15, $12, $6
	dsrl	$25, $15, 32
	daddu	$15, $14, $25
	bgtu	$24, $15, $88
$87:
 # 360					break;
	dmul	$3, $10, $5
	b	$89
$88:
 # 361				q--;
	daddu	$5, $5, -1
 # 362				}
	b	$86
$89:
 # 363			th=q*dh;
 # 364			tl=q*dl;
 # 365			t=(tl>>BN_BITS4);
 # 366			tl=(tl<<BN_BITS4)&BN_MASK2h;
	dsll	$14, $3, 32
	and	$2, $14, $6
	move	$11, $2
 # 367			th+=t;
	dsrl	$25, $3, 32
	daddu	$7, $4, $25
 # 368	
 # 369			if (l < tl) th++;
	bgeu	$12, $2, $90
	daddu	$7, $7, 1
$90:
 # 370			l-=tl;
	dsubu	$12, $12, $11
 # 371			if (h < th)
	bgeu	$9, $7, $91
 # 372				{
 # 373				h+=d;
	daddu	$9, $9, $16
 # 374				q--;
	daddu	$5, $5, -1
 # 375				}
$91:
 # 376			h-=th;
	dsubu	$9, $9, $7
 # 377	
 # 378			if (--count == 0) break;
	addu	$13, $13, -1
	beq	$13, 0, $92
 # 379	
 # 380			ret=q<<BN_BITS4;
	dsll	$31, $5, 32
 # 381			h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
	dsll	$24, $9, 32
	dsrl	$15, $12, 32
	or	$9, $24, $15
 # 382			l=(l&BN_MASK2l)<<BN_BITS4;
	and	$12, $12, 0xFFFFFFFF
	dsll	$12, $12, 32
 # 383			}
	b	$84
$92:
 # 384		ret|=q;
	or	$31, $31, $5
 # 385		return(ret);
	move	$2, $31
$93:
	ld	$16, 48($sp)
	ld	$31, 56($sp)
	daddu	$sp, 64
	j	$31
	.end	bn_div64
#endif
