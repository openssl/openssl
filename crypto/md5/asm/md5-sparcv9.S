.ident	"md5-sparcv9.S, Version 1.0"
.ident	"SPARC V9 ISA artwork by Andy Polyakov <appro@fy.chalmers.se>"
.file	"md5-sparcv9.S"

/*
 * ====================================================================
 * Copyright (c) 1999 Andy Polyakov <appro@fy.chalmers.se>.
 *
 * Rights for redistribution and usage in source and binary forms are
 * granted as long as above copyright notices are retained. Warranty
 * of any kind is (of course:-) disclaimed.
 * ====================================================================
 */

/*
 * This is my modest contribution to OpenSSL project (see
 * http://www.openssl.org/ for more information about it) and is an
 * assembler implementation of MD5 block hash function. I've hand-coded
 * this for the sole reason to reach UltraSPARC-specific "load in
 * little-endian byte order" instruction. This gives up to 15%
 * performance improvement for cases when input message is aligned at
 * 32 bits boundary. The module was tested under both 32 *and* 64 bit
 * kernels. For updates see http://fy.chalmers.se/~appro/hpe/.
 *
 * To compile with SC4.x/SC5.x:
 *
 *	cc -xarch=v[9|8plus] -DULTRASPARC -DMD5_BLOCK_DATA_ORDER \
 *		-c md5-sparcv9.S
 *
 * and with gcc:
 *
 *	gcc -mcpu=ultrasparc -DULTRASPARC -DMD5_BLOCK_DATA_ORDER \
 *		-c md5-sparcv9.S
 *
 * or if above fails (it does if you have gas):
 *
 *	gcc -E -DULTRASPARC -DMD5_BLOCK_DATA_ORDER md5_block.sparc.S | \
 *		as -xarch=v8plus /dev/fd/0 -o md5-sparcv9.o
 */

#define	A	%o0
#define B	%o1
#define	C	%o2
#define	D	%o3
#define	T1	%o4
#define	T2	%o5

#define	R0	%l0
#define	R1	%l1
#define	R2	%l2
#define	R3	%l3
#define	R4	%l4
#define	R5	%l5
#define	R6	%l6
#define	R7	%l7
#define	R8	%i3
#define	R9	%i4
#define	R10	%i5
#define	R11	%g1
#define R12	%g2
#define	R13	%g3
#define RX	%g4

#define Aptr	%i0+0
#define Bptr	%i0+4
#define Cptr	%i0+8
#define Dptr	%i0+12

#define Aval	R5	/* those not used at the end of the last round */
#define Bval	R6
#define Cval	R7
#define Dval	R8

#if defined(MD5_BLOCK_DATA_ORDER)
# if defined(ULTRASPARC)
#  define	LOAD			lda
#  define	X(i)			[%i1+i*4]%asi
#  define	md5_block		md5_block_asm_data_order_aligned
#  define	ASI_PRIMARY_LITTLE	0x88
# else
#  error "MD5_BLOCK_DATA_ORDER is supported only on UltraSPARC!"
# endif
#else
# define	LOAD			ld
# define	X(i)			[%i1+i*4]
# define	md5_block		md5_block_asm_host_order
#endif

.section        ".text",#alloc,#execinstr

#if defined(__SUNPRO_C) && defined(__sparcv9)
  /* They've said -xarch=v9 at command line */
  .register	%g2,#scratch
  .register	%g3,#scratch
# define	FRAME	-192
#elif defined(__GNUC__) && defined(__arch64__)
  /* They've said -m64 at command line */
  .register     %g2,#scratch
  .register     %g3,#scratch
# define        FRAME   -192
#else
# define	FRAME	-96
#endif

.align  32

.global md5_block
md5_block:
	save	%sp,FRAME,%sp

	ld	[Dptr],D
	ld	[Cptr],C
	ld	[Bptr],B
	ld	[Aptr],A
#ifdef ASI_PRIMARY_LITTLE
	rd	%asi,%o7	! How dare I? Well, I just do:-)
	wr	%g0,ASI_PRIMARY_LITTLE,%asi
#endif
	LOAD	X(0),R0

.Lmd5_block_loop:

!!!!!!!!Round 0

	xor	C,D,T1
	sethi	%hi(0xd76aa478),T2
	and	T1,B,T1
	or	T2,%lo(0xd76aa478),T2	!=
	xor	T1,D,T1
	add	T1,R0,T1
	LOAD	X(1),R1
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,7,T2
	srl	A,32-7,A
	or	A,T2,A			!=
	 xor	 B,C,T1
	add	A,B,A

	sethi	%hi(0xe8c7b756),T2
	and	T1,A,T1			!=
	or	T2,%lo(0xe8c7b756),T2
	xor	T1,C,T1
	LOAD	X(2),R2
	add	T1,R1,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,12,T2
	srl	D,32-12,D		!=
	or	D,T2,D
	 xor	 A,B,T1
	add	D,A,D

	sethi	%hi(0x242070db),T2	!=
	and	T1,D,T1
	or	T2,%lo(0x242070db),T2
	xor	T1,B,T1
	add	T1,R2,T1		!=
	LOAD	X(3),R3
	add	T1,T2,T1
	add	C,T1,C
	sll	C,17,T2			!=
	srl	C,32-17,C
	or	C,T2,C
	 xor	 D,A,T1
	add	C,D,C			!=

	sethi	%hi(0xc1bdceee),T2
	and	T1,C,T1
	or	T2,%lo(0xc1bdceee),T2
	xor	T1,A,T1			!=
	add	T1,R3,T1
	LOAD	X(4),R4
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,22,T2
	srl	B,32-22,B
	or	B,T2,B
	 xor	 C,D,T1			!=
	add	B,C,B

	sethi	%hi(0xf57c0faf),T2
	and	T1,B,T1
	or	T2,%lo(0xf57c0faf),T2	!=
	xor	T1,D,T1
	add	T1,R4,T1
	LOAD	X(5),R5
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,7,T2
	srl	A,32-7,A
	or	A,T2,A			!=
	 xor	 B,C,T1
	add	A,B,A

	sethi	%hi(0x4787c62a),T2
	and	T1,A,T1			!=
	or	T2,%lo(0x4787c62a),T2
	xor	T1,C,T1
	LOAD	X(6),R6
	add	T1,R5,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,12,T2
	srl	D,32-12,D		!=
	or	D,T2,D
	 xor	 A,B,T1
	add	D,A,D

	sethi	%hi(0xa8304613),T2	!=
	and	T1,D,T1
	or	T2,%lo(0xa8304613),T2
	xor	T1,B,T1
	add	T1,R6,T1		!=
	LOAD	X(7),R7
	add	T1,T2,T1
	add	C,T1,C
	sll	C,17,T2			!=
	srl	C,32-17,C
	or	C,T2,C
	 xor	 D,A,T1
	add	C,D,C			!=

	sethi	%hi(0xfd469501),T2
	and	T1,C,T1
	or	T2,%lo(0xfd469501),T2
	xor	T1,A,T1			!=
	add	T1,R7,T1
	LOAD	X(8),R8
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,22,T2
	srl	B,32-22,B
	or	B,T2,B
	 xor	 C,D,T1			!=
	add	B,C,B

	sethi	%hi(0x698098d8),T2
	and	T1,B,T1
	or	T2,%lo(0x698098d8),T2	!=
	xor	T1,D,T1
	add	T1,R8,T1
	LOAD	X(9),R9
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,7,T2
	srl	A,32-7,A
	or	A,T2,A			!=
	 xor	 B,C,T1
	add	A,B,A

	sethi	%hi(0x8b44f7af),T2
	and	T1,A,T1			!=
	or	T2,%lo(0x8b44f7af),T2
	xor	T1,C,T1
	LOAD	X(10),R10
	add	T1,R9,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,12,T2
	srl	D,32-12,D		!=
	or	D,T2,D
	 xor	 A,B,T1
	add	D,A,D

	sethi	%hi(0xffff5bb1),T2	!=
	and	T1,D,T1
	or	T2,%lo(0xffff5bb1),T2
	xor	T1,B,T1
	add	T1,R10,T1		!=
	LOAD	X(11),R11
	add	T1,T2,T1
	add	C,T1,C
	sll	C,17,T2			!=
	srl	C,32-17,C
	or	C,T2,C
	 xor	 D,A,T1
	add	C,D,C			!=

	sethi	%hi(0x895cd7be),T2
	and	T1,C,T1
	or	T2,%lo(0x895cd7be),T2
	xor	T1,A,T1			!=
	add	T1,R11,T1
	LOAD	X(12),R12
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,22,T2
	srl	B,32-22,B
	or	B,T2,B
	 xor	 C,D,T1			!=
	add	B,C,B

	sethi	%hi(0x6b901122),T2
	and	T1,B,T1
	or	T2,%lo(0x6b901122),T2	!=
	xor	T1,D,T1
	add	T1,R12,T1
	LOAD	X(13),R13
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,7,T2
	srl	A,32-7,A
	or	A,T2,A			!=
	 xor	 B,C,T1
	add	A,B,A

	sethi	%hi(0xfd987193),T2
	and	T1,A,T1			!=
	or	T2,%lo(0xfd987193),T2
	xor	T1,C,T1
	LOAD	X(14),RX
	add	T1,R13,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,12,T2
	srl	D,32-12,D		!=
	or	D,T2,D
	 xor	 A,B,T1
	add	D,A,D

	sethi	%hi(0xa679438e),T2	!=
	and	T1,D,T1
	or	T2,%lo(0xa679438e),T2
	xor	T1,B,T1
	add	T1,RX,T1		!=
	LOAD	X(15),RX
	add	T1,T2,T1
	add	C,T1,C
	sll	C,17,T2			!=
	srl	C,32-17,C
	or	C,T2,C
	 xor	 D,A,T1
	add	C,D,C			!=

	sethi	%hi(0x49b40821),T2
	and	T1,C,T1
	or	T2,%lo(0x49b40821),T2
	xor	T1,A,T1			!=
	add	T1,RX,T1
	!pre-LOADed	X(1),R1
	add	T1,T2,T1
	add	B,T1,B
	sll	B,22,T2			!=
	srl	B,32-22,B
	or	B,T2,B
	add	B,C,B

!!!!!!!!Round 1

	xor	B,C,T1			!=
	sethi	%hi(0xf61e2562),T2
	and	T1,D,T1
	or	T2,%lo(0xf61e2562),T2
	xor	T1,C,T1			!=
	add	T1,R1,T1
	!pre-LOADed	X(6),R6
	add	T1,T2,T1
	add	A,T1,A
	sll	A,5,T2			!=
	srl	A,32-5,A
	or	A,T2,A
	add	A,B,A

	xor	A,B,T1			!=
	sethi	%hi(0xc040b340),T2
	and	T1,C,T1
	or	T2,%lo(0xc040b340),T2
	xor	T1,B,T1			!=
	add	T1,R6,T1
	!pre-LOADed	X(11),R11
	add	T1,T2,T1
	add	D,T1,D
	sll	D,9,T2			!=
	srl	D,32-9,D
	or	D,T2,D
	add	D,A,D

	xor	D,A,T1			!=
	sethi	%hi(0x265e5a51),T2
	and	T1,B,T1
	or	T2,%lo(0x265e5a51),T2
	xor	T1,A,T1			!=
	add	T1,R11,T1
	!pre-LOADed	X(0),R0
	add	T1,T2,T1
	add	C,T1,C
	sll	C,14,T2			!=
	srl	C,32-14,C
	or	C,T2,C
	add	C,D,C

	xor	C,D,T1			!=
	sethi	%hi(0xe9b6c7aa),T2
	and	T1,A,T1
	or	T2,%lo(0xe9b6c7aa),T2
	xor	T1,D,T1			!=
	add	T1,R0,T1
	!pre-LOADed	X(5),R5
	add	T1,T2,T1
	add	B,T1,B
	sll	B,20,T2			!=
	srl	B,32-20,B
	or	B,T2,B
	add	B,C,B

	xor	B,C,T1			!=
	sethi	%hi(0xd62f105d),T2
	and	T1,D,T1
	or	T2,%lo(0xd62f105d),T2
	xor	T1,C,T1			!=
	add	T1,R5,T1
	!pre-LOADed	X(10),R10
	add	T1,T2,T1
	add	A,T1,A
	sll	A,5,T2			!=
	srl	A,32-5,A
	or	A,T2,A
	add	A,B,A

	xor	A,B,T1			!=
	sethi	%hi(0x02441453),T2
	and	T1,C,T1
	or	T2,%lo(0x02441453),T2
	xor	T1,B,T1			!=
	add	T1,R10,T1
	LOAD	X(15),RX
	add	T1,T2,T1
	add	D,T1,D			!=
	sll	D,9,T2
	srl	D,32-9,D
	or	D,T2,D
	add	D,A,D			!=

	xor	D,A,T1
	sethi	%hi(0xd8a1e681),T2
	and	T1,B,T1
	or	T2,%lo(0xd8a1e681),T2	!=
	xor	T1,A,T1
	add	T1,RX,T1
	!pre-LOADed	X(4),R4
	add	T1,T2,T1
	add	C,T1,C			!=
	sll	C,14,T2
	srl	C,32-14,C
	or	C,T2,C
	add	C,D,C			!=

	xor	C,D,T1
	sethi	%hi(0xe7d3fbc8),T2
	and	T1,A,T1
	or	T2,%lo(0xe7d3fbc8),T2	!=
	xor	T1,D,T1
	add	T1,R4,T1
	!pre-LOADed	X(9),R9
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,20,T2
	srl	B,32-20,B
	or	B,T2,B
	add	B,C,B			!=

	xor	B,C,T1
	sethi	%hi(0x21e1cde6),T2
	and	T1,D,T1
	or	T2,%lo(0x21e1cde6),T2	!=
	xor	T1,C,T1
	add	T1,R9,T1
	LOAD	X(14),RX
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,5,T2
	srl	A,32-5,A
	or	A,T2,A			!=
	add	A,B,A

	xor	A,B,T1
	sethi	%hi(0xc33707d6),T2
	and	T1,C,T1			!=
	or	T2,%lo(0xc33707d6),T2
	xor	T1,B,T1
	add	T1,RX,T1
	!pre-LOADed	X(3),R3
	add	T1,T2,T1		!=
	add	D,T1,D
	sll	D,9,T2
	srl	D,32-9,D
	or	D,T2,D			!=
	add	D,A,D

	xor	D,A,T1
	sethi	%hi(0xf4d50d87),T2
	and	T1,B,T1			!=
	or	T2,%lo(0xf4d50d87),T2
	xor	T1,A,T1
	add	T1,R3,T1
	!pre-LOADed	X(8),R8
	add	T1,T2,T1		!=
	add	C,T1,C
	sll	C,14,T2
	srl	C,32-14,C
	or	C,T2,C			!=
	add	C,D,C

	xor	C,D,T1
	sethi	%hi(0x455a14ed),T2
	and	T1,A,T1			!=
	or	T2,%lo(0x455a14ed),T2
	xor	T1,D,T1
	add	T1,R8,T1
	!pre-LOADed	X(13),R13
	add	T1,T2,T1		!=
	add	B,T1,B
	sll	B,20,T2
	srl	B,32-20,B
	or	B,T2,B			!=
	add	B,C,B

	xor	B,C,T1
	sethi	%hi(0xa9e3e905),T2
	and	T1,D,T1			!=
	or	T2,%lo(0xa9e3e905),T2
	xor	T1,C,T1
	add	T1,R13,T1
	!pre-LOADed	X(2),R2
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,5,T2
	srl	A,32-5,A
	or	A,T2,A			!=
	add	A,B,A

	xor	A,B,T1
	sethi	%hi(0xfcefa3f8),T2
	and	T1,C,T1			!=
	or	T2,%lo(0xfcefa3f8),T2
	xor	T1,B,T1
	add	T1,R2,T1
	!pre-LOADed	X(7),R7
	add	T1,T2,T1		!=
	add	D,T1,D
	sll	D,9,T2
	srl	D,32-9,D
	or	D,T2,D			!=
	add	D,A,D

	xor	D,A,T1
	sethi	%hi(0x676f02d9),T2
	and	T1,B,T1			!=
	or	T2,%lo(0x676f02d9),T2
	xor	T1,A,T1
	add	T1,R7,T1
	!pre-LOADed	X(12),R12
	add	T1,T2,T1		!=
	add	C,T1,C
	sll	C,14,T2
	srl	C,32-14,C
	or	C,T2,C			!=
	add	C,D,C

	xor	C,D,T1
	sethi	%hi(0x8d2a4c8a),T2
	and	T1,A,T1			!=
	or	T2,%lo(0x8d2a4c8a),T2
	xor	T1,D,T1
	add	T1,R12,T1
	!pre-LOADed	X(5),R5
	add	T1,T2,T1		!=
	add	B,T1,B
	sll	B,20,T2
	srl	B,32-20,B
	or	B,T2,B			!=
	add	B,C,B

!!!!!!!!Round 2

	xor	B,C,T1
	sethi	%hi(0xfffa3942),T2
	xor	T1,D,T1			!=
	or	T2,%lo(0xfffa3942),T2
	add	T1,R5,T1
	!pre-LOADed	X(8),R8
	add	T1,T2,T1
	add	A,T1,A			!=
	sll	A,4,T2
	srl	A,32-4,A
	or	A,T2,A
	add	A,B,A			!=

	xor	A,B,T1
	sethi	%hi(0x8771f681),T2
	xor	T1,C,T1
	or	T2,%lo(0x8771f681),T2	!=
	add	T1,R8,T1
	!pre-LOADed	X(11),R11
	add	T1,T2,T1
	add	D,T1,D
	sll	D,11,T2			!=
	srl	D,32-11,D
	or	D,T2,D
	add	D,A,D

	xor	D,A,T1			!=
	sethi	%hi(0x6d9d6122),T2
	xor	T1,B,T1
	or	T2,%lo(0x6d9d6122),T2
	add	T1,R11,T1		!=
	LOAD	X(14),RX
	add	T1,T2,T1
	add	C,T1,C
	sll	C,16,T2			!=
	srl	C,32-16,C
	or	C,T2,C
	add	C,D,C

	xor	C,D,T1			!=
	sethi	%hi(0xfde5380c),T2
	xor	T1,A,T1
	or	T2,%lo(0xfde5380c),T2
	add	T1,RX,T1		!=
	!pre-LOADed	X(1),R1
	add	T1,T2,T1
	add	B,T1,B
	sll	B,23,T2
	srl	B,32-23,B		!=
	or	B,T2,B
	add	B,C,B

	xor	B,C,T1
	sethi	%hi(0xa4beea44),T2	!=
	xor	T1,D,T1
	or	T2,%lo(0xa4beea44),T2
	add	T1,R1,T1
	!pre-LOADed	X(4),R4
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,4,T2
	srl	A,32-4,A
	or	A,T2,A			!=
	add	A,B,A

	xor	A,B,T1
	sethi	%hi(0x4bdecfa9),T2
	xor	T1,C,T1			!=
	or	T2,%lo(0x4bdecfa9),T2
	add	T1,R4,T1
	!pre-LOADed	X(7),R7
	add	T1,T2,T1
	add	D,T1,D			!=
	sll	D,11,T2
	srl	D,32-11,D
	or	D,T2,D
	add	D,A,D			!=

	xor	D,A,T1
	sethi	%hi(0xf6bb4b60),T2
	xor	T1,B,T1
	or	T2,%lo(0xf6bb4b60),T2	!=
	add	T1,R7,T1
	!pre-LOADed	X(10),R10
	add	T1,T2,T1
	add	C,T1,C
	sll	C,16,T2			!=
	srl	C,32-16,C
	or	C,T2,C
	add	C,D,C

	xor	C,D,T1			!=
	sethi	%hi(0xbebfbc70),T2
	xor	T1,A,T1
	or	T2,%lo(0xbebfbc70),T2
	add	T1,R10,T1		!=
	!pre-LOADed	X(13),R13
	add	T1,T2,T1
	add	B,T1,B
	sll	B,23,T2
	srl	B,32-23,B		!=
	or	B,T2,B
	add	B,C,B

	xor	B,C,T1
	sethi	%hi(0x289b7ec6),T2	!=
	xor	T1,D,T1
	or	T2,%lo(0x289b7ec6),T2
	add	T1,R13,T1
	!pre-LOADed	X(0),R0
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,4,T2
	srl	A,32-4,A
	or	A,T2,A			!=
	add	A,B,A

	xor	A,B,T1
	sethi	%hi(0xeaa127fa),T2
	xor	T1,C,T1			!=
	or	T2,%lo(0xeaa127fa),T2
	add	T1,R0,T1
	!pre-LOADed	X(3),R3
	add	T1,T2,T1
	add	D,T1,D			!=
	sll	D,11,T2
	srl	D,32-11,D
	or	D,T2,D
	add	D,A,D			!=

	xor	D,A,T1
	sethi	%hi(0xd4ef3085),T2
	xor	T1,B,T1
	or	T2,%lo(0xd4ef3085),T2	!=
	add	T1,R3,T1
	!pre-LOADed	X(6),R6
	add	T1,T2,T1
	add	C,T1,C
	sll	C,16,T2			!=
	srl	C,32-16,C
	or	C,T2,C
	add	C,D,C

	xor	C,D,T1			!=
	sethi	%hi(0x04881d05),T2
	xor	T1,A,T1
	or	T2,%lo(0x04881d05),T2
	add	T1,R6,T1		!=
	!pre-LOADed	X(9),R9
	add	T1,T2,T1
	add	B,T1,B
	sll	B,23,T2
	srl	B,32-23,B		!=
	or	B,T2,B
	add	B,C,B

	xor	B,C,T1
	sethi	%hi(0xd9d4d039),T2	!=
	xor	T1,D,T1
	or	T2,%lo(0xd9d4d039),T2
	add	T1,R9,T1
	!pre-LOADed	X(12),R12
	add	T1,T2,T1		!=
	add	A,T1,A
	sll	A,4,T2
	srl	A,32-4,A
	or	A,T2,A			!=
	add	A,B,A

	xor	A,B,T1
	sethi	%hi(0xe6db99e5),T2
	xor	T1,C,T1			!=
	or	T2,%lo(0xe6db99e5),T2
	add	T1,R12,T1
	LOAD	X(15),RX
	add	T1,T2,T1		!=
	add	D,T1,D
	sll	D,11,T2
	srl	D,32-11,D
	or	D,T2,D			!=
	add	D,A,D

	xor	D,A,T1
	sethi	%hi(0x1fa27cf8),T2
	xor	T1,B,T1			!=
	or	T2,%lo(0x1fa27cf8),T2
	add	T1,RX,T1
	!pre-LOADed	X(2),R2
	add	T1,T2,T1
	add	C,T1,C			!=
	sll	C,16,T2
	srl	C,32-16,C
	or	C,T2,C
	add	C,D,C			!=

	xor	C,D,T1
	sethi	%hi(0xc4ac5665),T2
	xor	T1,A,T1
	or	T2,%lo(0xc4ac5665),T2	!=
	add	T1,R2,T1
	!pre-LOADed	X(0),R0
	add	T1,T2,T1
	add	B,T1,B
	sll	B,23,T2			!=
	srl	B,32-23,B
	or	B,T2,B
	add	B,C,B

!!!!!!!!Round 3

	orn	B,D,T1			!=
	sethi	%hi(0xf4292244),T2
	xor	T1,C,T1
	or	T2,%lo(0xf4292244),T2
	add	T1,R0,T1		!=
	!pre-LOADed	X(7),R7
	add	T1,T2,T1
	add	A,T1,A
	sll	A,6,T2
	srl	A,32-6,A		!=
	or	A,T2,A
	add	A,B,A

	orn	A,C,T1
	sethi	%hi(0x432aff97),T2	!=
	xor	T1,B,T1
	or	T2,%lo(0x432aff97),T2
	LOAD	X(14),RX
	add	T1,R7,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,10,T2
	srl	D,32-10,D		!=
	or	D,T2,D
	add	D,A,D

	orn	D,B,T1
	sethi	%hi(0xab9423a7),T2	!=
	xor	T1,A,T1
	or	T2,%lo(0xab9423a7),T2
	add	T1,RX,T1
	!pre-LOADed	X(5),R5
	add	T1,T2,T1		!=
	add	C,T1,C
	sll	C,15,T2
	srl	C,32-15,C
	or	C,T2,C			!=
	add	C,D,C

	orn	C,A,T1
	sethi	%hi(0xfc93a039),T2
	xor	T1,D,T1			!=
	or	T2,%lo(0xfc93a039),T2
	add	T1,R5,T1
	!pre-LOADed	X(12),R12
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,21,T2
	srl	B,32-21,B
	or	B,T2,B
	add	B,C,B			!=

	orn	B,D,T1
	sethi	%hi(0x655b59c3),T2
	xor	T1,C,T1
	or	T2,%lo(0x655b59c3),T2	!=
	add	T1,R12,T1
	!pre-LOADed	X(3),R3
	add	T1,T2,T1
	add	A,T1,A
	sll	A,6,T2			!=
	srl	A,32-6,A
	or	A,T2,A
	add	A,B,A

	orn	A,C,T1			!=
	sethi	%hi(0x8f0ccc92),T2
	xor	T1,B,T1
	or	T2,%lo(0x8f0ccc92),T2
	add	T1,R3,T1		!=
	!pre-LOADed	X(10),R10
	add	T1,T2,T1
	add	D,T1,D
	sll	D,10,T2
	srl	D,32-10,D		!=
	or	D,T2,D
	add	D,A,D

	orn	D,B,T1
	sethi	%hi(0xffeff47d),T2	!=
	xor	T1,A,T1
	or	T2,%lo(0xffeff47d),T2
	add	T1,R10,T1
	!pre-LOADed	X(1),R1
	add	T1,T2,T1		!=
	add	C,T1,C
	sll	C,15,T2
	srl	C,32-15,C
	or	C,T2,C			!=
	add	C,D,C

	orn	C,A,T1
	sethi	%hi(0x85845dd1),T2
	xor	T1,D,T1			!=
	or	T2,%lo(0x85845dd1),T2
	add	T1,R1,T1
	!pre-LOADed	X(8),R8
	add	T1,T2,T1
	add	B,T1,B			!=
	sll	B,21,T2
	srl	B,32-21,B
	or	B,T2,B
	add	B,C,B			!=

	orn	B,D,T1
	sethi	%hi(0x6fa87e4f),T2
	xor	T1,C,T1
	or	T2,%lo(0x6fa87e4f),T2	!=
	add	T1,R8,T1
	LOAD	X(15),RX
	add	T1,T2,T1
	add	A,T1,A			!=
	sll	A,6,T2
	srl	A,32-6,A
	or	A,T2,A
	add	A,B,A			!=

	orn	A,C,T1
	sethi	%hi(0xfe2ce6e0),T2
	xor	T1,B,T1
	or	T2,%lo(0xfe2ce6e0),T2	!=
	add	T1,RX,T1
	!pre-LOADed	X(6),R6
	add	T1,T2,T1
	add	D,T1,D
	sll	D,10,T2			!=
	srl	D,32-10,D
	or	D,T2,D
	add	D,A,D

	orn	D,B,T1			!=
	sethi	%hi(0xa3014314),T2
	xor	T1,A,T1
	or	T2,%lo(0xa3014314),T2
	add	T1,R6,T1		!=
	!pre-LOADed	X(13),R13
	add	T1,T2,T1
	add	C,T1,C
	sll	C,15,T2
	srl	C,32-15,C		!=
	or	C,T2,C
	add	C,D,C

	orn	C,A,T1
	sethi	%hi(0x4e0811a1),T2	!=
	xor	T1,D,T1
	or	T2,%lo(0x4e0811a1),T2
	!pre-LOADed	X(4),R4
	 ld	 [Aptr],Aval
	add	T1,R13,T1		!=
	add	T1,T2,T1
	add	B,T1,B
	sll	B,21,T2
	srl	B,32-21,B		!=
	or	B,T2,B
	add	B,C,B

	orn	B,D,T1
	sethi	%hi(0xf7537e82),T2	!=
	xor	T1,C,T1
	or	T2,%lo(0xf7537e82),T2
	!pre-LOADed	X(11),R11
	 ld	 [Dptr],Dval
	add	T1,R4,T1		!=
	add	T1,T2,T1
	add	A,T1,A
	sll	A,6,T2
	srl	A,32-6,A		!=
	or	A,T2,A
	add	A,B,A

	orn	A,C,T1
	sethi	%hi(0xbd3af235),T2	!=
	xor	T1,B,T1
	or	T2,%lo(0xbd3af235),T2
	!pre-LOADed	X(2),R2
	 ld	 [Cptr],Cval
	add	T1,R11,T1		!=
	add	T1,T2,T1
	add	D,T1,D
	sll	D,10,T2
	srl	D,32-10,D		!=
	or	D,T2,D
	add	D,A,D

	orn	D,B,T1
	sethi	%hi(0x2ad7d2bb),T2	!=
	xor	T1,A,T1
	or	T2,%lo(0x2ad7d2bb),T2
	!pre-LOADed	X(9),R9
	 ld	 [Bptr],Bval
	add	T1,R2,T1		!=
	 add	 Aval,A,Aval
	add	T1,T2,T1
	 st	 Aval,[Aptr]
	add	C,T1,C			!=
	sll	C,15,T2
	 add	 Dval,D,Dval
	srl	C,32-15,C
	or	C,T2,C			!=
	 st	 Dval,[Dptr]
	add	C,D,C

	orn	C,A,T1
	sethi	%hi(0xeb86d391),T2	!=
	xor	T1,D,T1
	or	T2,%lo(0xeb86d391),T2
	add	T1,R9,T1
	!pre-LOADed	X(0),R0
	 mov	 Aval,A			!=
	add	T1,T2,T1
	 mov	 Dval,D
	add	B,T1,B
	sll	B,21,T2			!=
	 add	 Cval,C,Cval
	srl	B,32-21,B
	 st	 Cval,[Cptr]
	or	B,T2,B			!=
	add	B,C,B

	deccc	%i2
	mov	Cval,C
	add	B,Bval,B		!=
	inc	64,%i1
	nop
	st	B,[Bptr]
	nop				!=

#ifdef	ULTRASPARC
	bg,a,pt	%icc,.Lmd5_block_loop
#else
	bg,a	.Lmd5_block_loop
#endif
	LOAD	X(0),R0

#ifdef ASI_PRIMARY_LITTLE
	wr	%g0,%o7,%asi
#endif
	ret
	restore	%g0,0,%o0

.type	md5_block,#function
.size	md5_block,(.-md5_block)
