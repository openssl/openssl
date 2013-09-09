/* ====================================================================
 * Copyright (c) 2011-2013 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/* This implementation is by Ted Krovetz and was submitted to SUPERCOP and
 * marked as public domain. It was been altered to allow for non-aligned inputs
 * and to allow the block counter to be passed in specifically. */

#include <string.h>
#include <stdint.h>
#include <openssl/opensslconf.h>

#if !defined(OPENSSL_NO_CHACHA)

#include <openssl/chacha.h>

#ifndef CHACHA_RNDS
#define CHACHA_RNDS 20    /* 8 (high speed), 20 (conservative), 12 (middle) */
#endif

/* Architecture-neutral way to specify 16-byte vector of ints              */
typedef unsigned vec __attribute__ ((vector_size (16)));

/* This implementation is designed for Neon, SSE and AltiVec machines. The
 * following specify how to do certain vector operations efficiently on
 * each architecture, using intrinsics.
 * This implementation supports parallel processing of multiple blocks,
 * including potentially using general-purpose registers.
 */
#if __ARM_NEON__
#include <arm_neon.h>
#define GPR_TOO   1
#define VBPI      2
#define ONE       (vec)vsetq_lane_u32(1,vdupq_n_u32(0),0)
#define LOAD(m)   (vec)(*((vec*)(m)))
#define STORE(m,r) (*((vec*)(m))) = (r)
#define ROTV1(x)  (vec)vextq_u32((uint32x4_t)x,(uint32x4_t)x,1)
#define ROTV2(x)  (vec)vextq_u32((uint32x4_t)x,(uint32x4_t)x,2)
#define ROTV3(x)  (vec)vextq_u32((uint32x4_t)x,(uint32x4_t)x,3)
#define ROTW16(x) (vec)vrev32q_u16((uint16x8_t)x)
#if __clang__
#define ROTW7(x)  (x << ((vec){ 7, 7, 7, 7})) ^ (x >> ((vec){25,25,25,25}))
#define ROTW8(x)  (x << ((vec){ 8, 8, 8, 8})) ^ (x >> ((vec){24,24,24,24}))
#define ROTW12(x) (x << ((vec){12,12,12,12})) ^ (x >> ((vec){20,20,20,20}))
#else
#define ROTW7(x)  (vec)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,7),(uint32x4_t)x,25)
#define ROTW8(x)  (vec)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,8),(uint32x4_t)x,24)
#define ROTW12(x) (vec)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,12),(uint32x4_t)x,20)
#endif
#elif __SSE2__
#include <emmintrin.h>
#define GPR_TOO   0
#if __clang__
#define VBPI      4
#else
#define VBPI      3
#endif
#define ONE       (vec)_mm_set_epi32(0,0,0,1)
#define LOAD(m)   (vec)_mm_loadu_si128((__m128i*)(m))
#define STORE(m,r) _mm_storeu_si128((__m128i*)(m), (__m128i) (r))
#define ROTV1(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(0,3,2,1))
#define ROTV2(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(1,0,3,2))
#define ROTV3(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(2,1,0,3))
#define ROTW7(x)  (vec)(_mm_slli_epi32((__m128i)x, 7) ^ _mm_srli_epi32((__m128i)x,25))
#define ROTW12(x) (vec)(_mm_slli_epi32((__m128i)x,12) ^ _mm_srli_epi32((__m128i)x,20))
#if __SSSE3__
#include <tmmintrin.h>
#define ROTW8(x)  (vec)_mm_shuffle_epi8((__m128i)x,_mm_set_epi8(14,13,12,15,10,9,8,11,6,5,4,7,2,1,0,3))
#define ROTW16(x) (vec)_mm_shuffle_epi8((__m128i)x,_mm_set_epi8(13,12,15,14,9,8,11,10,5,4,7,6,1,0,3,2))
#else
#define ROTW8(x)  (vec)(_mm_slli_epi32((__m128i)x, 8) ^ _mm_srli_epi32((__m128i)x,24))
#define ROTW16(x) (vec)(_mm_slli_epi32((__m128i)x,16) ^ _mm_srli_epi32((__m128i)x,16))
#endif
#else
#error -- Implementation supports only machines with neon or SSE2
#endif

#ifndef REVV_BE
#define REVV_BE(x)  (x)
#endif

#ifndef REVW_BE
#define REVW_BE(x)  (x)
#endif

#define BPI      (VBPI + GPR_TOO)  /* Blocks computed per loop iteration   */

#define DQROUND_VECTORS(a,b,c,d)                \
    a += b; d ^= a; d = ROTW16(d);              \
    c += d; b ^= c; b = ROTW12(b);              \
    a += b; d ^= a; d = ROTW8(d);               \
    c += d; b ^= c; b = ROTW7(b);               \
    b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);  \
    a += b; d ^= a; d = ROTW16(d);              \
    c += d; b ^= c; b = ROTW12(b);              \
    a += b; d ^= a; d = ROTW8(d);               \
    c += d; b ^= c; b = ROTW7(b);               \
    b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);

#define QROUND_WORDS(a,b,c,d) \
  a = a+b; d ^= a; d = d<<16 | d>>16; \
  c = c+d; b ^= c; b = b<<12 | b>>20; \
  a = a+b; d ^= a; d = d<< 8 | d>>24; \
  c = c+d; b ^= c; b = b<< 7 | b>>25;

#define WRITE_XOR(in, op, d, v0, v1, v2, v3)                   \
	STORE(op + d + 0, LOAD(in + d + 0) ^ REVV_BE(v0));      \
	STORE(op + d + 4, LOAD(in + d + 4) ^ REVV_BE(v1));      \
	STORE(op + d + 8, LOAD(in + d + 8) ^ REVV_BE(v2));      \
	STORE(op + d +12, LOAD(in + d +12) ^ REVV_BE(v3));

void CRYPTO_chacha_20(
	unsigned char *out,
	const unsigned char *in,
	size_t inlen,
	const unsigned char key[32],
	const unsigned char nonce[8],
	size_t counter)
	{
	unsigned iters, i, *op=(unsigned *)out, *ip=(unsigned *)in, *kp;
#if defined(__ARM_NEON__)
	unsigned *np;
#endif
	vec s0, s1, s2, s3;
#if !defined(__ARM_NEON__) && !defined(__SSE2__)
	__attribute__ ((aligned (16))) unsigned key[8], nonce[4];
#endif
	__attribute__ ((aligned (16))) unsigned chacha_const[] =
		{0x61707865,0x3320646E,0x79622D32,0x6B206574};
#if defined(__ARM_NEON__) || defined(__SSE2__)
	kp = (unsigned *)key;
#else
	((vec *)key)[0] = REVV_BE(((vec *)key)[0]);
	((vec *)key)[1] = REVV_BE(((vec *)key)[1]);
	nonce[0] = REVW_BE(((unsigned *)nonce)[0]);
	nonce[1] = REVW_BE(((unsigned *)nonce)[1]);
	nonce[2] = REVW_BE(((unsigned *)nonce)[2]);
	nonce[3] = REVW_BE(((unsigned *)nonce)[3]);
	kp = (unsigned *)key;
	np = (unsigned *)nonce;
#endif
#if defined(__ARM_NEON__)
	np = (unsigned*) nonce;
#endif
	s0 = LOAD(chacha_const);
	s1 = LOAD(&((vec*)kp)[0]);
	s2 = LOAD(&((vec*)kp)[1]);
	s3 = (vec){
		counter & 0xffffffff,
#if __ARM_NEON__
		0,  /* can't right-shift 32 bits on a 32-bit system. */
#else
		counter >> 32,
#endif
		((uint32_t*)nonce)[0],
		((uint32_t*)nonce)[1]
	};

	for (iters = 0; iters < inlen/(BPI*64); iters++)
		{
#if GPR_TOO
		register unsigned x0, x1, x2, x3, x4, x5, x6, x7, x8,
				  x9, x10, x11, x12, x13, x14, x15;
#endif
#if VBPI > 2
		vec v8,v9,v10,v11;
#endif
#if VBPI > 3
		vec v12,v13,v14,v15;
#endif

		vec v0,v1,v2,v3,v4,v5,v6,v7;
		v4 = v0 = s0; v5 = v1 = s1; v6 = v2 = s2; v3 = s3;
		v7 = v3 + ONE;
#if VBPI > 2
		v8 = v4; v9 = v5; v10 = v6;
		v11 =  v7 + ONE;
#endif
#if VBPI > 3
		v12 = v8; v13 = v9; v14 = v10;
		v15 = v11 + ONE;
#endif
#if GPR_TOO
		x0 = chacha_const[0]; x1 = chacha_const[1];
		x2 = chacha_const[2]; x3 = chacha_const[3];
		x4 = kp[0]; x5 = kp[1]; x6  = kp[2]; x7  = kp[3];
		x8 = kp[4]; x9 = kp[5]; x10 = kp[6]; x11 = kp[7];
		x12 = counter+BPI*iters+(BPI-1); x13 = 0;
		x14 = np[0]; x15 = np[1];
#endif
		for (i = CHACHA_RNDS/2; i; i--)
			{
			DQROUND_VECTORS(v0,v1,v2,v3)
			DQROUND_VECTORS(v4,v5,v6,v7)
#if VBPI > 2
			DQROUND_VECTORS(v8,v9,v10,v11)
#endif
#if VBPI > 3
			DQROUND_VECTORS(v12,v13,v14,v15)
#endif
#if GPR_TOO
			QROUND_WORDS( x0, x4, x8,x12)
			QROUND_WORDS( x1, x5, x9,x13)
			QROUND_WORDS( x2, x6,x10,x14)
			QROUND_WORDS( x3, x7,x11,x15)
			QROUND_WORDS( x0, x5,x10,x15)
			QROUND_WORDS( x1, x6,x11,x12)
			QROUND_WORDS( x2, x7, x8,x13)
			QROUND_WORDS( x3, x4, x9,x14)
#endif
			}

		WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
		s3 += ONE;
		WRITE_XOR(ip, op, 16, v4+s0, v5+s1, v6+s2, v7+s3)
		s3 += ONE;
#if VBPI > 2
		WRITE_XOR(ip, op, 32, v8+s0, v9+s1, v10+s2, v11+s3)
		s3 += ONE;
#endif
#if VBPI > 3
		WRITE_XOR(ip, op, 48, v12+s0, v13+s1, v14+s2, v15+s3)
		s3 += ONE;
#endif
		ip += VBPI*16;
		op += VBPI*16;
#if GPR_TOO
		op[0]  = REVW_BE(REVW_BE(ip[0])  ^ (x0  + chacha_const[0]));
		op[1]  = REVW_BE(REVW_BE(ip[1])  ^ (x1  + chacha_const[1]));
		op[2]  = REVW_BE(REVW_BE(ip[2])  ^ (x2  + chacha_const[2]));
		op[3]  = REVW_BE(REVW_BE(ip[3])  ^ (x3  + chacha_const[3]));
		op[4]  = REVW_BE(REVW_BE(ip[4])  ^ (x4  + kp[0]));
		op[5]  = REVW_BE(REVW_BE(ip[5])  ^ (x5  + kp[1]));
		op[6]  = REVW_BE(REVW_BE(ip[6])  ^ (x6  + kp[2]));
		op[7]  = REVW_BE(REVW_BE(ip[7])  ^ (x7  + kp[3]));
		op[8]  = REVW_BE(REVW_BE(ip[8])  ^ (x8  + kp[4]));
		op[9]  = REVW_BE(REVW_BE(ip[9])  ^ (x9  + kp[5]));
		op[10] = REVW_BE(REVW_BE(ip[10]) ^ (x10 + kp[6]));
		op[11] = REVW_BE(REVW_BE(ip[11]) ^ (x11 + kp[7]));
		op[12] = REVW_BE(REVW_BE(ip[12]) ^ (x12 + BPI*iters+(BPI-1)));
		op[13] = REVW_BE(REVW_BE(ip[13]) ^ (x13));
		op[14] = REVW_BE(REVW_BE(ip[14]) ^ (x14 + np[0]));
		op[15] = REVW_BE(REVW_BE(ip[15]) ^ (x15 + np[1]));
		s3 += ONE;
		ip += 16;
		op += 16;
#endif
		}

	for (iters = inlen%(BPI*64)/64; iters != 0; iters--)
		{
		vec v0 = s0, v1 = s1, v2 = s2, v3 = s3;
		for (i = CHACHA_RNDS/2; i; i--)
			{
			DQROUND_VECTORS(v0,v1,v2,v3);
			}
		WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
		s3 += ONE;
		ip += 16;
		op += 16;
		}

	inlen = inlen % 64;
	if (inlen)
		{
		__attribute__ ((aligned (16))) vec buf[4];
		vec v0,v1,v2,v3;
		v0 = s0; v1 = s1; v2 = s2; v3 = s3;
		for (i = CHACHA_RNDS/2; i; i--)
			{
			DQROUND_VECTORS(v0,v1,v2,v3);
			}

		if (inlen >= 16)
			{
			STORE(op + 0, LOAD(ip + 0) ^ REVV_BE(v0 + s0));
			if (inlen >= 32)
				{
				STORE(op + 4, LOAD(ip + 4) ^ REVV_BE(v1 + s1));
				if (inlen >= 48)
					{
					STORE(op + 8, LOAD(ip +  8) ^
						      REVV_BE(v2 + s2));
					buf[3] = REVV_BE(v3 + s3);
					}
				else
					buf[2] = REVV_BE(v2 + s2);
				}
			else
				buf[1] = REVV_BE(v1 + s1);
			}
		else
			buf[0] = REVV_BE(v0 + s0);

		for (i=inlen & ~15; i<inlen; i++)
			((char *)op)[i] = ((char *)ip)[i] ^ ((char *)buf)[i];
		}
	}

#endif  /* !OPENSSL_NO_CHACHA */
