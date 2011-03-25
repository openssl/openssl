/* crypto/ec/ecp_nistp224.c */
/*
 * Written by Emilia Kasper (Google) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2000-2010 The OpenSSL Project.  All rights reserved.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * A 64-bit implementation of the NIST P-224 elliptic curve point multiplication
 *
 * Inspired by Daniel J. Bernstein's public domain nistp224 implementation
 * and Adam Langley's public domain 64-bit C implementation of curve25519
 */
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC_NISTP224_64_GCC_128
#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include "ec_lcl.h"

#if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
  /* even with gcc, the typedef won't work for 32-bit platforms */
  typedef __uint128_t uint128_t; /* nonstandard; implemented by gcc on 64-bit platforms */
#else
  #error "Need GCC 3.1 or later to define type uint128_t"
#endif

typedef uint8_t u8;


/******************************************************************************/
/*		    INTERNAL REPRESENTATION OF FIELD ELEMENTS
 *
 * Field elements are represented as a_0 + 2^56*a_1 + 2^112*a_2 + 2^168*a_3
 * where each slice a_i is a 64-bit word, i.e., a field element is an fslice
 * array a with 4 elements, where a[i] = a_i.
 * Outputs from multiplications are represented as unreduced polynomials
 * b_0 + 2^56*b_1 + 2^112*b_2 + 2^168*b_3 + 2^224*b_4 + 2^280*b_5 + 2^336*b_6
 * where each b_i is a 128-bit word. We ensure that inputs to each field
 * multiplication satisfy a_i < 2^60, so outputs satisfy b_i < 4*2^60*2^60,
 * and fit into a 128-bit word without overflow. The coefficients are then
 * again partially reduced to a_i < 2^57. We only reduce to the unique minimal
 * representation at the end of the computation.
 *
 */

typedef uint64_t fslice;

/* Field element represented as a byte arrary.
 * 28*8 = 224 bits is also the group order size for the elliptic curve.  */
typedef u8 felem_bytearray[28];

static const felem_bytearray nistp224_curve_params[5] = {
	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* p */
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},
	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* a */
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE},
	{0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,    /* b */
	 0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
	 0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4},
	{0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,    /* x */
	 0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
	 0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21},
	{0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,    /* y */
	 0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
	 0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34}
};

/* Precomputed multiples of the standard generator
 * b_0*G + b_1*2^56*G + b_2*2^112*G + b_3*2^168*G for
 * (b_3, b_2, b_1, b_0) in [0,15], i.e., gmul[0] = point_at_infinity,
 * gmul[1] = G, gmul[2] = 2^56*G, gmul[3] = 2^56*G + G, etc.
 * Points are given in Jacobian projective coordinates: words 0-3 represent the
 * X-coordinate (slice a_0 is word 0, etc.), words 4-7 represent the
 * Y-coordinate and words 8-11 represent the Z-coordinate. */
static const fslice gmul[16][3][4] = {
	{{0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000},
	 {0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000},
	 {0x00000000000000, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x3280d6115c1d21, 0xc1d356c2112234, 0x7f321390b94a03, 0xb70e0cbd6bb4bf},
	 {0xd5819985007e34, 0x75a05a07476444, 0xfb4c22dfe6cd43, 0xbd376388b5f723},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xfd9675666ebbe9, 0xbca7664d40ce5e, 0x2242df8d8a2a43, 0x1f49bbb0f99bc5},
	 {0x29e0b892dc9c43, 0xece8608436e662, 0xdc858f185310d0, 0x9812dd4eb8d321},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x6d3e678d5d8eb8, 0x559eed1cb362f1, 0x16e9a3bbce8a3f, 0xeedcccd8c2a748},
	 {0xf19f90ed50266d, 0xabf2b4bf65f9df, 0x313865468fafec, 0x5cb379ba910a17},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x0641966cab26e3, 0x91fb2991fab0a0, 0xefec27a4e13a0b, 0x0499aa8a5f8ebe},
	 {0x7510407766af5d, 0x84d929610d5450, 0x81d77aae82f706, 0x6916f6d4338c5b},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xea95ac3b1f15c6, 0x086000905e82d4, 0xdd323ae4d1c8b1, 0x932b56be7685a3},
	 {0x9ef93dea25dbbf, 0x41665960f390f0, 0xfdec76dbe2a8a7, 0x523e80f019062a},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x822fdd26732c73, 0xa01c83531b5d0f, 0x363f37347c1ba4, 0xc391b45c84725c},
	 {0xbbd5e1b2d6ad24, 0xddfbcde19dfaec, 0xc393da7e222a7f, 0x1efb7890ede244},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x4c9e90ca217da1, 0xd11beca79159bb, 0xff8d33c2c98b7c, 0x2610b39409f849},
	 {0x44d1352ac64da0, 0xcdbb7b2c46b4fb, 0x966c079b753c89, 0xfe67e4e820b112},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xe28cae2df5312d, 0xc71b61d16f5c6e, 0x79b7619a3e7c4c, 0x05c73240899b47},
	 {0x9f7f6382c73e3a, 0x18615165c56bda, 0x641fab2116fd56, 0x72855882b08394},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x0469182f161c09, 0x74a98ca8d00fb5, 0xb89da93489a3e0, 0x41c98768fb0c1d},
	 {0xe5ea05fb32da81, 0x3dce9ffbca6855, 0x1cfe2d3fbf59e6, 0x0e5e03408738a7},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xdab22b2333e87f, 0x4430137a5dd2f6, 0xe03ab9f738beb8, 0xcb0c5d0dc34f24},
	 {0x764a7df0c8fda5, 0x185ba5c3fa2044, 0x9281d688bcbe50, 0xc40331df893881},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xb89530796f0f60, 0xade92bd26909a3, 0x1a0c83fb4884da, 0x1765bf22a5a984},
	 {0x772a9ee75db09e, 0x23bc6c67cec16f, 0x4c1edba8b14e2f, 0xe2a215d9611369},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x571e509fb5efb3, 0xade88696410552, 0xc8ae85fada74fe, 0x6c7e4be83bbde3},
	 {0xff9f51160f4652, 0xb47ce2495a6539, 0xa2946c53b582f4, 0x286d2db3ee9a60},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x40bbd5081a44af, 0x0995183b13926c, 0xbcefba6f47f6d0, 0x215619e9cc0057},
	 {0x8bc94d3b0df45e, 0xf11c54a3694f6f, 0x8631b93cdfe8b5, 0xe7e3f4b0982db9},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0xb17048ab3e1c7b, 0xac38f36ff8a1d8, 0x1c29819435d2c6, 0xc813132f4c07e9},
	 {0x2891425503b11f, 0x08781030579fea, 0xf5426ba5cc9674, 0x1e28ebf18562bc},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}},
	{{0x9f31997cc864eb, 0x06cd91d28b5e4c, 0xff17036691a973, 0xf1aef351497c58},
	 {0xdd1f2d600564ff, 0xdead073b1402db, 0x74a684435bd693, 0xeea7471f962558},
	 {0x00000000000001, 0x00000000000000, 0x00000000000000, 0x00000000000000}}
};

/* Precomputation for the group generator. */
typedef struct {
	fslice g_pre_comp[16][3][4];
	int references;
} NISTP224_PRE_COMP;

const EC_METHOD *EC_GFp_nistp224_method(void)
	{
	static const EC_METHOD ret = {
		NID_X9_62_prime_field,
		ec_GFp_nistp224_group_init,
		ec_GFp_simple_group_finish,
		ec_GFp_simple_group_clear_finish,
		ec_GFp_nist_group_copy,
		ec_GFp_nistp224_group_set_curve,
		ec_GFp_simple_group_get_curve,
		ec_GFp_simple_group_get_degree,
		ec_GFp_simple_group_check_discriminant,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		ec_GFp_simple_point_set_affine_coordinates,
		ec_GFp_nistp224_point_get_affine_coordinates,
		ec_GFp_simple_set_compressed_coordinates,
		ec_GFp_simple_point2oct,
		ec_GFp_simple_oct2point,
		ec_GFp_simple_add,
		ec_GFp_simple_dbl,
		ec_GFp_simple_invert,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_simple_is_on_curve,
		ec_GFp_simple_cmp,
		ec_GFp_simple_make_affine,
		ec_GFp_simple_points_make_affine,
		ec_GFp_nistp224_points_mul,
		ec_GFp_nistp224_precompute_mult,
		ec_GFp_nistp224_have_precompute_mult,
		ec_GFp_nist_field_mul,
		ec_GFp_nist_field_sqr,
		0 /* field_div */,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
	}

/* Helper functions to convert field elements to/from internal representation */
static void bin28_to_felem(fslice out[4], const u8 in[28])
	{
	out[0] = *((const uint64_t *)(in)) & 0x00ffffffffffffff;
	out[1] = (*((const uint64_t *)(in+7))) & 0x00ffffffffffffff;
	out[2] = (*((const uint64_t *)(in+14))) & 0x00ffffffffffffff;
	out[3] = (*((const uint64_t *)(in+21))) & 0x00ffffffffffffff;
	}

static void felem_to_bin28(u8 out[28], const fslice in[4])
	{
	unsigned i;
	for (i = 0; i < 7; ++i)
		{
		out[i]	  = in[0]>>(8*i);
		out[i+7]  = in[1]>>(8*i);
		out[i+14] = in[2]>>(8*i);
		out[i+21] = in[3]>>(8*i);
		}
	}

/* To preserve endianness when using BN_bn2bin and BN_bin2bn */
static void flip_endian(u8 *out, const u8 *in, unsigned len)
	{
	unsigned i;
	for (i = 0; i < len; ++i)
		out[i] = in[len-1-i];
	}

/* From OpenSSL BIGNUM to internal representation */
static int BN_to_felem(fslice out[4], const BIGNUM *bn)
	{
        felem_bytearray b_in;
	felem_bytearray b_out;
	unsigned num_bytes;

	/* BN_bn2bin eats leading zeroes */
	memset(b_out, 0, sizeof b_out);
	num_bytes = BN_num_bytes(bn);
	if (num_bytes > sizeof b_out)
		{
		ECerr(EC_F_BN_TO_FELEM, EC_R_BIGNUM_OUT_OF_RANGE);
		return 0;
		}
	if (BN_is_negative(bn))
		{
		ECerr(EC_F_BN_TO_FELEM, EC_R_BIGNUM_OUT_OF_RANGE);
		return 0;
		}
	num_bytes = BN_bn2bin(bn, b_in);
	flip_endian(b_out, b_in, num_bytes);
	bin28_to_felem(out, b_out);
	return 1;
	}

/* From internal representation to OpenSSL BIGNUM */
static BIGNUM *felem_to_BN(BIGNUM *out, const fslice in[4])
	{
	felem_bytearray b_in, b_out;
	felem_to_bin28(b_in, in);
	flip_endian(b_out, b_in, sizeof b_out);
	return BN_bin2bn(b_out, sizeof b_out, out);
	}

/******************************************************************************/
/*				FIELD OPERATIONS
 *
 * Field operations, using the internal representation of field elements.
 * NB! These operations are specific to our point multiplication and cannot be
 * expected to be correct in general - e.g., multiplication with a large scalar
 * will cause an overflow.
 *
 */

/* Sum two field elements: out += in */
static void felem_sum64(fslice out[4], const fslice in[4])
	{
	out[0] += in[0];
	out[1] += in[1];
	out[2] += in[2];
	out[3] += in[3];
	}

/* Subtract field elements: out -= in */
/* Assumes in[i] < 2^57 */
static void felem_diff64(fslice out[4], const fslice in[4])
	{
	static const uint64_t two58p2 = (((uint64_t) 1) << 58) + (((uint64_t) 1) << 2);
	static const uint64_t two58m2 = (((uint64_t) 1) << 58) - (((uint64_t) 1) << 2);
	static const uint64_t two58m42m2 = (((uint64_t) 1) << 58) -
	    (((uint64_t) 1) << 42) - (((uint64_t) 1) << 2);

	/* Add 0 mod 2^224-2^96+1 to ensure out > in */
	out[0] += two58p2;
	out[1] += two58m42m2;
	out[2] += two58m2;
	out[3] += two58m2;

	out[0] -= in[0];
	out[1] -= in[1];
	out[2] -= in[2];
	out[3] -= in[3];
	}

/* Subtract in unreduced 128-bit mode: out128 -= in128 */
/* Assumes in[i] < 2^119 */
static void felem_diff128(uint128_t out[7], const uint128_t in[4])
	{
	static const uint128_t two120 = ((uint128_t) 1) << 120;
	static const uint128_t two120m64 = (((uint128_t) 1) << 120) -
		(((uint128_t) 1) << 64);
	static const uint128_t two120m104m64 = (((uint128_t) 1) << 120) -
		(((uint128_t) 1) << 104) - (((uint128_t) 1) << 64);

	/* Add 0 mod 2^224-2^96+1 to ensure out > in */
	out[0] += two120;
	out[1] += two120m64;
	out[2] += two120m64;
	out[3] += two120;
	out[4] += two120m104m64;
	out[5] += two120m64;
	out[6] += two120m64;

	out[0] -= in[0];
	out[1] -= in[1];
	out[2] -= in[2];
	out[3] -= in[3];
	out[4] -= in[4];
	out[5] -= in[5];
	out[6] -= in[6];
	}

/* Subtract in mixed mode: out128 -= in64 */
/* in[i] < 2^63 */
static void felem_diff_128_64(uint128_t out[7], const fslice in[4])
	{
	static const uint128_t two64p8 = (((uint128_t) 1) << 64) +
		(((uint128_t) 1) << 8);
	static const uint128_t two64m8 = (((uint128_t) 1) << 64) -
		(((uint128_t) 1) << 8);
	static const uint128_t two64m48m8 = (((uint128_t) 1) << 64) -
		(((uint128_t) 1) << 48) - (((uint128_t) 1) << 8);

	/* Add 0 mod 2^224-2^96+1 to ensure out > in */
	out[0] += two64p8;
	out[1] += two64m48m8;
	out[2] += two64m8;
	out[3] += two64m8;

	out[0] -= in[0];
	out[1] -= in[1];
	out[2] -= in[2];
	out[3] -= in[3];
	}

/* Multiply a field element by a scalar: out64 = out64 * scalar
 * The scalars we actually use are small, so results fit without overflow */
static void felem_scalar64(fslice out[4], const fslice scalar)
	{
	out[0] *= scalar;
	out[1] *= scalar;
	out[2] *= scalar;
	out[3] *= scalar;
	}

/* Multiply an unreduced field element by a scalar: out128 = out128 * scalar
 * The scalars we actually use are small, so results fit without overflow */
static void felem_scalar128(uint128_t out[7], const uint128_t scalar)
	{
	out[0] *= scalar;
	out[1] *= scalar;
	out[2] *= scalar;
	out[3] *= scalar;
	out[4] *= scalar;
	out[5] *= scalar;
	out[6] *= scalar;
	}

/* Square a field element: out = in^2 */
static void felem_square(uint128_t out[7], const fslice in[4])
	{
	out[0] = ((uint128_t) in[0]) * in[0];
	out[1] = ((uint128_t) in[0]) * in[1] * 2;
	out[2] = ((uint128_t) in[0]) * in[2] * 2 + ((uint128_t) in[1]) * in[1];
	out[3] = ((uint128_t) in[0]) * in[3] * 2 +
		((uint128_t) in[1]) * in[2] * 2;
	out[4] = ((uint128_t) in[1]) * in[3] * 2 + ((uint128_t) in[2]) * in[2];
	out[5] = ((uint128_t) in[2]) * in[3] * 2;
	out[6] = ((uint128_t) in[3]) * in[3];
	}

/* Multiply two field elements: out = in1 * in2 */
static void felem_mul(uint128_t out[7], const fslice in1[4], const fslice in2[4])
	{
	out[0] = ((uint128_t) in1[0]) * in2[0];
	out[1] = ((uint128_t) in1[0]) * in2[1] + ((uint128_t) in1[1]) * in2[0];
	out[2] = ((uint128_t) in1[0]) * in2[2] + ((uint128_t) in1[1]) * in2[1] +
		((uint128_t) in1[2]) * in2[0];
	out[3] = ((uint128_t) in1[0]) * in2[3] + ((uint128_t) in1[1]) * in2[2] +
		((uint128_t) in1[2]) * in2[1] + ((uint128_t) in1[3]) * in2[0];
	out[4] = ((uint128_t) in1[1]) * in2[3] + ((uint128_t) in1[2]) * in2[2] +
		((uint128_t) in1[3]) * in2[1];
	out[5] = ((uint128_t) in1[2]) * in2[3] + ((uint128_t) in1[3]) * in2[2];
	out[6] = ((uint128_t) in1[3]) * in2[3];
	}

/* Reduce 128-bit coefficients to 64-bit coefficients. Requires in[i] < 2^126,
 * ensures out[0] < 2^56, out[1] < 2^56, out[2] < 2^56, out[3] < 2^57 */
static void felem_reduce(fslice out[4], const uint128_t in[7])
	{
	static const uint128_t two127p15 = (((uint128_t) 1) << 127) +
		(((uint128_t) 1) << 15);
	static const uint128_t two127m71 = (((uint128_t) 1) << 127) -
		(((uint128_t) 1) << 71);
	static const uint128_t two127m71m55 = (((uint128_t) 1) << 127) -
		(((uint128_t) 1) << 71) - (((uint128_t) 1) << 55);
	uint128_t output[5];

	/* Add 0 mod 2^224-2^96+1 to ensure all differences are positive */
	output[0] = in[0] + two127p15;
	output[1] = in[1] + two127m71m55;
	output[2] = in[2] + two127m71;
	output[3] = in[3];
	output[4] = in[4];

	/* Eliminate in[4], in[5], in[6] */
	output[4] += in[6] >> 16;
	output[3] += (in[6]&0xffff) << 40;
	output[2] -= in[6];

	output[3] += in[5] >> 16;
	output[2] += (in[5]&0xffff) << 40;
	output[1] -= in[5];

	output[2] += output[4] >> 16;
	output[1] += (output[4]&0xffff) << 40;
	output[0] -= output[4];
	output[4] = 0;

	/* Carry 2 -> 3 -> 4 */
	output[3] += output[2] >> 56;
	output[2] &= 0x00ffffffffffffff;

	output[4] += output[3] >> 56;
	output[3] &= 0x00ffffffffffffff;

	/* Now output[2] < 2^56, output[3] < 2^56 */

	/* Eliminate output[4] */
	output[2] += output[4] >> 16;
	output[1] += (output[4]&0xffff) << 40;
	output[0] -= output[4];

	/* Carry 0 -> 1 -> 2 -> 3 */
	output[1] += output[0] >> 56;
	out[0] = output[0] & 0x00ffffffffffffff;

	output[2] += output[1] >> 56;
	out[1] = output[1] & 0x00ffffffffffffff;
	output[3] += output[2] >> 56;
	out[2] = output[2] & 0x00ffffffffffffff;

	/* out[0] < 2^56, out[1] < 2^56, out[2] < 2^56,
	 * out[3] < 2^57 (due to final carry) */
	out[3] = output[3];
	}

/* Reduce to unique minimal representation */
static void felem_contract(fslice out[4], const fslice in[4])
	{
	static const int64_t two56 = ((uint64_t) 1) << 56;
	/* 0 <= in < 2^225 */
	/* if in > 2^224 , reduce in = in - 2^224 + 2^96 - 1 */
	int64_t tmp[4], a;
	tmp[0] = (int64_t) in[0] - (in[3] >> 56);
	tmp[1] = (int64_t) in[1] + ((in[3] >> 16) & 0x0000010000000000);
	tmp[2] = (int64_t) in[2];
	tmp[3] = (int64_t) in[3] & 0x00ffffffffffffff;

	/* eliminate negative coefficients */
	a = tmp[0] >> 63;
	tmp[0] += two56 & a;
	tmp[1] -= 1 & a;

	a = tmp[1] >> 63;
	tmp[1] += two56 & a;
	tmp[2] -= 1 & a;

	a = tmp[2] >> 63;
	tmp[2] += two56 & a;
	tmp[3] -= 1 & a;

	a = tmp[3] >> 63;
	tmp[3] += two56 & a;
	tmp[0] += 1 & a;
	tmp[1] -= (1 & a) << 40;

	/* carry 1 -> 2 -> 3 */
	tmp[2] += tmp[1] >> 56;
	tmp[1] &= 0x00ffffffffffffff;

	tmp[3] += tmp[2] >> 56;
	tmp[2] &= 0x00ffffffffffffff;

	/* 0 <= in < 2^224 + 2^96 - 1 */
	/* if in > 2^224 , reduce in = in - 2^224 + 2^96 - 1 */
	tmp[0] -= (tmp[3] >> 56);
	tmp[1] += ((tmp[3] >> 16) & 0x0000010000000000);
	tmp[3] &= 0x00ffffffffffffff;

	/* eliminate negative coefficients */
	a = tmp[0] >> 63;
	tmp[0] += two56 & a;
	tmp[1] -= 1 & a;

	a = tmp[1] >> 63;
	tmp[1] += two56 & a;
	tmp[2] -= 1 & a;

	a = tmp[2] >> 63;
	tmp[2] += two56 & a;
	tmp[3] -= 1 & a;

	a = tmp[3] >> 63;
	tmp[3] += two56 & a;
	tmp[0] += 1 & a;
	tmp[1] -= (1 & a) << 40;

	/* carry 1 -> 2 -> 3 */
	tmp[2] += tmp[1] >> 56;
	tmp[1] &= 0x00ffffffffffffff;

	tmp[3] += tmp[2] >> 56;
	tmp[2] &= 0x00ffffffffffffff;

	/* Now 0 <= in < 2^224 */

	/* if in > 2^224 - 2^96, reduce */
	/* a = 0 iff in > 2^224 - 2^96, i.e.,
	 * the high 128 bits are all 1 and the lower part is non-zero */
	a = (tmp[3] + 1) | (tmp[2] + 1) |
		((tmp[1] | 0x000000ffffffffff) + 1) |
		((((tmp[1] & 0xffff) - 1) >> 63) & ((tmp[0] - 1) >> 63));
	/* turn a into an all-one mask (if a = 0) or an all-zero mask */
	a = ((a & 0x00ffffffffffffff) - 1) >> 63;
	/* subtract 2^224 - 2^96 + 1 if a is all-one*/
	tmp[3] &= a ^ 0xffffffffffffffff;
	tmp[2] &= a ^ 0xffffffffffffffff;
	tmp[1] &= (a ^ 0xffffffffffffffff) | 0x000000ffffffffff;
	tmp[0] -= 1 & a;
	/* eliminate negative coefficients: if tmp[0] is negative, tmp[1] must be
	 * non-zero, so we only need one step */
	a = tmp[0] >> 63;
	tmp[0] += two56 & a;
	tmp[1] -= 1 & a;

	out[0] = tmp[0];
	out[1] = tmp[1];
	out[2] = tmp[2];
	out[3] = tmp[3];
	}

/* Zero-check: returns 1 if input is 0, and 0 otherwise.
 * We know that field elements are reduced to in < 2^225,
 * so we only need to check three cases: 0, 2^224 - 2^96 + 1,
 * and 2^225 - 2^97 + 2 */
static fslice felem_is_zero(const fslice in[4])
	{
	fslice zero, two224m96p1, two225m97p2;

	zero = in[0] | in[1] | in[2] | in[3];
	zero = (((int64_t)(zero) - 1) >> 63) & 1;
	two224m96p1 = (in[0] ^ 1) | (in[1] ^ 0x00ffff0000000000)
		| (in[2] ^ 0x00ffffffffffffff) | (in[3] ^ 0x00ffffffffffffff);
	two224m96p1 = (((int64_t)(two224m96p1) - 1) >> 63) & 1;
	two225m97p2 = (in[0] ^ 2) | (in[1] ^ 0x00fffe0000000000)
		| (in[2] ^ 0x00ffffffffffffff) | (in[3] ^ 0x01ffffffffffffff);
	two225m97p2 = (((int64_t)(two225m97p2) - 1) >> 63) & 1;
	return (zero | two224m96p1 | two225m97p2);
	}

/* Invert a field element */
/* Computation chain copied from djb's code */
static void felem_inv(fslice out[4], const fslice in[4])
	{
	fslice ftmp[4], ftmp2[4], ftmp3[4], ftmp4[4];
	uint128_t tmp[7];
	unsigned i;

	felem_square(tmp, in); felem_reduce(ftmp, tmp);		/* 2 */
	felem_mul(tmp, in, ftmp); felem_reduce(ftmp, tmp);	/* 2^2 - 1 */
	felem_square(tmp, ftmp); felem_reduce(ftmp, tmp);	/* 2^3 - 2 */
	felem_mul(tmp, in, ftmp); felem_reduce(ftmp, tmp);	/* 2^3 - 1 */
	felem_square(tmp, ftmp); felem_reduce(ftmp2, tmp);	/* 2^4 - 2 */
	felem_square(tmp, ftmp2); felem_reduce(ftmp2, tmp);	/* 2^5 - 4 */
	felem_square(tmp, ftmp2); felem_reduce(ftmp2, tmp);	/* 2^6 - 8 */
	felem_mul(tmp, ftmp2, ftmp); felem_reduce(ftmp, tmp);	/* 2^6 - 1 */
	felem_square(tmp, ftmp); felem_reduce(ftmp2, tmp);	/* 2^7 - 2 */
	for (i = 0; i < 5; ++i)					/* 2^12 - 2^6 */
		{
		felem_square(tmp, ftmp2); felem_reduce(ftmp2, tmp);
		}
	felem_mul(tmp, ftmp2, ftmp); felem_reduce(ftmp2, tmp);	/* 2^12 - 1 */
	felem_square(tmp, ftmp2); felem_reduce(ftmp3, tmp);	/* 2^13 - 2 */
	for (i = 0; i < 11; ++i)				/* 2^24 - 2^12 */
		{
		felem_square(tmp, ftmp3); felem_reduce(ftmp3, tmp);
		}
	felem_mul(tmp, ftmp3, ftmp2); felem_reduce(ftmp2, tmp); /* 2^24 - 1 */
	felem_square(tmp, ftmp2); felem_reduce(ftmp3, tmp);	/* 2^25 - 2 */
	for (i = 0; i < 23; ++i)				/* 2^48 - 2^24 */
		{
		felem_square(tmp, ftmp3); felem_reduce(ftmp3, tmp);
		}
	felem_mul(tmp, ftmp3, ftmp2); felem_reduce(ftmp3, tmp); /* 2^48 - 1 */
	felem_square(tmp, ftmp3); felem_reduce(ftmp4, tmp);	/* 2^49 - 2 */
	for (i = 0; i < 47; ++i)				/* 2^96 - 2^48 */
		{
		felem_square(tmp, ftmp4); felem_reduce(ftmp4, tmp);
		}
	felem_mul(tmp, ftmp3, ftmp4); felem_reduce(ftmp3, tmp); /* 2^96 - 1 */
	felem_square(tmp, ftmp3); felem_reduce(ftmp4, tmp);	/* 2^97 - 2 */
	for (i = 0; i < 23; ++i)				/* 2^120 - 2^24 */
		{
		felem_square(tmp, ftmp4); felem_reduce(ftmp4, tmp);
		}
	felem_mul(tmp, ftmp2, ftmp4); felem_reduce(ftmp2, tmp); /* 2^120 - 1 */
	for (i = 0; i < 6; ++i)					/* 2^126 - 2^6 */
		{
		felem_square(tmp, ftmp2); felem_reduce(ftmp2, tmp);
		}
	felem_mul(tmp, ftmp2, ftmp); felem_reduce(ftmp, tmp);	/* 2^126 - 1 */
	felem_square(tmp, ftmp); felem_reduce(ftmp, tmp);	/* 2^127 - 2 */
	felem_mul(tmp, ftmp, in); felem_reduce(ftmp, tmp);	/* 2^127 - 1 */
	for (i = 0; i < 97; ++i)				/* 2^224 - 2^97 */
		{
		felem_square(tmp, ftmp); felem_reduce(ftmp, tmp);
		}
	felem_mul(tmp, ftmp, ftmp3); felem_reduce(out, tmp);	/* 2^224 - 2^96 - 1 */
	}

/* Copy in constant time:
 * if icopy == 1, copy in to out,
 * if icopy == 0, copy out to itself. */
static void
copy_conditional(fslice *out, const fslice *in, unsigned len, fslice icopy)
	{
	unsigned i;
	/* icopy is a (64-bit) 0 or 1, so copy is either all-zero or all-one */
	const fslice copy = -icopy;
	for (i = 0; i < len; ++i)
		{
		const fslice tmp = copy & (in[i] ^ out[i]);
		out[i] ^= tmp;
		}
	}

/* Copy in constant time:
 * if isel == 1, copy in2 to out,
 * if isel == 0, copy in1 to out. */
static void select_conditional(fslice *out, const fslice *in1, const fslice *in2,
	unsigned len, fslice isel)
	{
	unsigned i;
	/* isel is a (64-bit) 0 or 1, so sel is either all-zero or all-one */
	const fslice sel = -isel;
	for (i = 0; i < len; ++i)
		{
		const fslice tmp = sel & (in1[i] ^ in2[i]);
		out[i] = in1[i] ^ tmp;
		}
}

/******************************************************************************/
/*			 ELLIPTIC CURVE POINT OPERATIONS
 *
 * Points are represented in Jacobian projective coordinates:
 * (X, Y, Z) corresponds to the affine point (X/Z^2, Y/Z^3),
 * or to the point at infinity if Z == 0.
 *
 */

/* Double an elliptic curve point:
 * (X', Y', Z') = 2 * (X, Y, Z), where
 * X' = (3 * (X - Z^2) * (X + Z^2))^2 - 8 * X * Y^2
 * Y' = 3 * (X - Z^2) * (X + Z^2) * (4 * X * Y^2 - X') - 8 * Y^2
 * Z' = (Y + Z)^2 - Y^2 - Z^2 = 2 * Y * Z
 * Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed,
 * while x_out == y_in is not (maybe this works, but it's not tested). */
static void
point_double(fslice x_out[4], fslice y_out[4], fslice z_out[4],
	     const fslice x_in[4], const fslice y_in[4], const fslice z_in[4])
	{
	uint128_t tmp[7], tmp2[7];
	fslice delta[4];
	fslice gamma[4];
	fslice beta[4];
	fslice alpha[4];
	fslice ftmp[4], ftmp2[4];
	memcpy(ftmp, x_in, 4 * sizeof(fslice));
	memcpy(ftmp2, x_in, 4 * sizeof(fslice));

	/* delta = z^2 */
	felem_square(tmp, z_in);
	felem_reduce(delta, tmp);

	/* gamma = y^2 */
	felem_square(tmp, y_in);
	felem_reduce(gamma, tmp);

	/* beta = x*gamma */
	felem_mul(tmp, x_in, gamma);
	felem_reduce(beta, tmp);

	/* alpha = 3*(x-delta)*(x+delta) */
	felem_diff64(ftmp, delta);
	/* ftmp[i] < 2^57 + 2^58 + 2 < 2^59 */
	felem_sum64(ftmp2, delta);
	/* ftmp2[i] < 2^57 + 2^57 = 2^58 */
	felem_scalar64(ftmp2, 3);
	/* ftmp2[i] < 3 * 2^58 < 2^60 */
	felem_mul(tmp, ftmp, ftmp2);
	/* tmp[i] < 2^60 * 2^59 * 4 = 2^121 */
	felem_reduce(alpha, tmp);

	/* x' = alpha^2 - 8*beta */
	felem_square(tmp, alpha);
	/* tmp[i] < 4 * 2^57 * 2^57 = 2^116 */
	memcpy(ftmp, beta, 4 * sizeof(fslice));
	felem_scalar64(ftmp, 8);
	/* ftmp[i] < 8 * 2^57 = 2^60 */
	felem_diff_128_64(tmp, ftmp);
	/* tmp[i] < 2^116 + 2^64 + 8 < 2^117 */
	felem_reduce(x_out, tmp);

	/* z' = (y + z)^2 - gamma - delta */
	felem_sum64(delta, gamma);
	/* delta[i] < 2^57 + 2^57 = 2^58 */
	memcpy(ftmp, y_in, 4 * sizeof(fslice));
	felem_sum64(ftmp, z_in);
	/* ftmp[i] < 2^57 + 2^57 = 2^58 */
	felem_square(tmp, ftmp);
	/* tmp[i] < 4 * 2^58 * 2^58 = 2^118 */
	felem_diff_128_64(tmp, delta);
	/* tmp[i] < 2^118 + 2^64 + 8 < 2^119 */
	felem_reduce(z_out, tmp);

	/* y' = alpha*(4*beta - x') - 8*gamma^2 */
	felem_scalar64(beta, 4);
	/* beta[i] < 4 * 2^57 = 2^59 */
	felem_diff64(beta, x_out);
	/* beta[i] < 2^59 + 2^58 + 2 < 2^60 */
	felem_mul(tmp, alpha, beta);
	/* tmp[i] < 4 * 2^57 * 2^60 = 2^119 */
	felem_square(tmp2, gamma);
	/* tmp2[i] < 4 * 2^57 * 2^57 = 2^116 */
	felem_scalar128(tmp2, 8);
	/* tmp2[i] < 8 * 2^116 = 2^119 */
	felem_diff128(tmp, tmp2);
	/* tmp[i] < 2^119 + 2^120 < 2^121 */
	felem_reduce(y_out, tmp);
	}

/* Add two elliptic curve points:
 * (X_1, Y_1, Z_1) + (X_2, Y_2, Z_2) = (X_3, Y_3, Z_3), where
 * X_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1)^2 - (Z_1^2 * X_2 - Z_2^2 * X_1)^3 -
 * 2 * Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2
 * Y_3 = (Z_1^3 * Y_2 - Z_2^3 * Y_1) * (Z_2^2 * X_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^2 - X_3) -
 *        Z_2^3 * Y_1 * (Z_1^2 * X_2 - Z_2^2 * X_1)^3
 * Z_3 = (Z_1^2 * X_2 - Z_2^2 * X_1) * (Z_1 * Z_2) */

/* This function is not entirely constant-time:
 * it includes a branch for checking whether the two input points are equal,
 * (while not equal to the point at infinity).
 * This case never happens during single point multiplication,
 * so there is no timing leak for ECDH or ECDSA signing. */
static void point_add(fslice x3[4], fslice y3[4], fslice z3[4],
	const fslice x1[4], const fslice y1[4], const fslice z1[4],
	const fslice x2[4], const fslice y2[4], const fslice z2[4])
	{
	fslice ftmp[4], ftmp2[4], ftmp3[4], ftmp4[4], ftmp5[4];
	uint128_t tmp[7], tmp2[7];
	fslice z1_is_zero, z2_is_zero, x_equal, y_equal;

	/* ftmp = z1^2 */
	felem_square(tmp, z1);
	felem_reduce(ftmp, tmp);

	/* ftmp2 = z2^2 */
	felem_square(tmp, z2);
	felem_reduce(ftmp2, tmp);

	/* ftmp3 = z1^3 */
	felem_mul(tmp, ftmp, z1);
	felem_reduce(ftmp3, tmp);

	/* ftmp4 = z2^3 */
	felem_mul(tmp, ftmp2, z2);
	felem_reduce(ftmp4, tmp);

	/* ftmp3 = z1^3*y2 */
	felem_mul(tmp, ftmp3, y2);
	/* tmp[i] < 4 * 2^57 * 2^57 = 2^116 */

	/* ftmp4 = z2^3*y1 */
	felem_mul(tmp2, ftmp4, y1);
	felem_reduce(ftmp4, tmp2);

	/* ftmp3 = z1^3*y2 - z2^3*y1 */
	felem_diff_128_64(tmp, ftmp4);
	/* tmp[i] < 2^116 + 2^64 + 8 < 2^117 */
	felem_reduce(ftmp3, tmp);

	/* ftmp = z1^2*x2 */
	felem_mul(tmp, ftmp, x2);
	/* tmp[i] < 4 * 2^57 * 2^57 = 2^116 */

	/* ftmp2 =z2^2*x1 */
	felem_mul(tmp2, ftmp2, x1);
	felem_reduce(ftmp2, tmp2);

	/* ftmp = z1^2*x2 - z2^2*x1 */
	felem_diff128(tmp, tmp2);
	/* tmp[i] < 2^116 + 2^64 + 8 < 2^117 */
	felem_reduce(ftmp, tmp);

	/* the formulae are incorrect if the points are equal
	 * so we check for this and do doubling if this happens */
	x_equal = felem_is_zero(ftmp);
	y_equal = felem_is_zero(ftmp3);
	z1_is_zero = felem_is_zero(z1);
	z2_is_zero = felem_is_zero(z2);
	/* In affine coordinates, (X_1, Y_1) == (X_2, Y_2) */
	if (x_equal && y_equal && !z1_is_zero && !z2_is_zero)
		{
		point_double(x3, y3, z3, x1, y1, z1);
		return;
		}

	/* ftmp5 = z1*z2 */
	felem_mul(tmp, z1, z2);
	felem_reduce(ftmp5, tmp);

	/* z3 = (z1^2*x2 - z2^2*x1)*(z1*z2) */
	felem_mul(tmp, ftmp, ftmp5);
	felem_reduce(z3, tmp);

	/* ftmp = (z1^2*x2 - z2^2*x1)^2 */
	memcpy(ftmp5, ftmp, 4 * sizeof(fslice));
	felem_square(tmp, ftmp);
	felem_reduce(ftmp, tmp);

	/* ftmp5 = (z1^2*x2 - z2^2*x1)^3 */
	felem_mul(tmp, ftmp, ftmp5);
	felem_reduce(ftmp5, tmp);

	/* ftmp2 = z2^2*x1*(z1^2*x2 - z2^2*x1)^2 */
	felem_mul(tmp, ftmp2, ftmp);
	felem_reduce(ftmp2, tmp);

	/* ftmp4 = z2^3*y1*(z1^2*x2 - z2^2*x1)^3 */
	felem_mul(tmp, ftmp4, ftmp5);
	/* tmp[i] < 4 * 2^57 * 2^57 = 2^116 */

	/* tmp2 = (z1^3*y2 - z2^3*y1)^2 */
	felem_square(tmp2, ftmp3);
	/* tmp2[i] < 4 * 2^57 * 2^57 < 2^116 */

	/* tmp2 = (z1^3*y2 - z2^3*y1)^2 - (z1^2*x2 - z2^2*x1)^3 */
	felem_diff_128_64(tmp2, ftmp5);
	/* tmp2[i] < 2^116 + 2^64 + 8 < 2^117 */

	/* ftmp5 = 2*z2^2*x1*(z1^2*x2 - z2^2*x1)^2 */
	memcpy(ftmp5, ftmp2, 4 * sizeof(fslice));
	felem_scalar64(ftmp5, 2);
	/* ftmp5[i] < 2 * 2^57 = 2^58 */

	/* x3 = (z1^3*y2 - z2^3*y1)^2 - (z1^2*x2 - z2^2*x1)^3 -
	   2*z2^2*x1*(z1^2*x2 - z2^2*x1)^2 */
	felem_diff_128_64(tmp2, ftmp5);
	/* tmp2[i] < 2^117 + 2^64 + 8 < 2^118 */
	felem_reduce(x3, tmp2);

	/* ftmp2 = z2^2*x1*(z1^2*x2 - z2^2*x1)^2 - x3 */
	felem_diff64(ftmp2, x3);
	/* ftmp2[i] < 2^57 + 2^58 + 2 < 2^59 */

	/* tmp2 = (z1^3*y2 - z2^3*y1)*(z2^2*x1*(z1^2*x2 - z2^2*x1)^2 - x3) */
	felem_mul(tmp2, ftmp3, ftmp2);
	/* tmp2[i] < 4 * 2^57 * 2^59 = 2^118 */

	/* y3 = (z1^3*y2 - z2^3*y1)*(z2^2*x1*(z1^2*x2 - z2^2*x1)^2 - x3) -
	   z2^3*y1*(z1^2*x2 - z2^2*x1)^3 */
	felem_diff128(tmp2, tmp);
	/* tmp2[i] < 2^118 + 2^120 < 2^121 */
	felem_reduce(y3, tmp2);

	/* the result (x3, y3, z3) is incorrect if one of the inputs is the
	 * point at infinity, so we need to check for this separately */

	/* if point 1 is at infinity, copy point 2 to output, and vice versa */
	copy_conditional(x3, x2, 4, z1_is_zero);
	copy_conditional(x3, x1, 4, z2_is_zero);
	copy_conditional(y3, y2, 4, z1_is_zero);
	copy_conditional(y3, y1, 4, z2_is_zero);
	copy_conditional(z3, z2, 4, z1_is_zero);
	copy_conditional(z3, z1, 4, z2_is_zero);
	}

/* Select a point from an array of 16 precomputed point multiples,
 * in constant time: for bits = {b_0, b_1, b_2, b_3}, return the point
 * pre_comp[8*b_3 + 4*b_2 + 2*b_1 + b_0] */
static void select_point(const fslice bits[4], const fslice pre_comp[16][3][4],
	fslice out[12])
	{
	fslice tmp[5][12];
	select_conditional(tmp[0], pre_comp[7][0], pre_comp[15][0], 12, bits[3]);
	select_conditional(tmp[1], pre_comp[3][0], pre_comp[11][0], 12, bits[3]);
	select_conditional(tmp[2], tmp[1], tmp[0], 12, bits[2]);
	select_conditional(tmp[0], pre_comp[5][0], pre_comp[13][0], 12, bits[3]);
	select_conditional(tmp[1], pre_comp[1][0], pre_comp[9][0], 12, bits[3]);
	select_conditional(tmp[3], tmp[1], tmp[0], 12, bits[2]);
	select_conditional(tmp[4], tmp[3], tmp[2], 12, bits[1]);
	select_conditional(tmp[0], pre_comp[6][0], pre_comp[14][0], 12, bits[3]);
	select_conditional(tmp[1], pre_comp[2][0], pre_comp[10][0], 12, bits[3]);
	select_conditional(tmp[2], tmp[1], tmp[0], 12, bits[2]);
	select_conditional(tmp[0], pre_comp[4][0], pre_comp[12][0], 12, bits[3]);
	select_conditional(tmp[1], pre_comp[0][0], pre_comp[8][0], 12, bits[3]);
	select_conditional(tmp[3], tmp[1], tmp[0], 12, bits[2]);
	select_conditional(tmp[1], tmp[3], tmp[2], 12, bits[1]);
	select_conditional(out, tmp[1], tmp[4], 12, bits[0]);
	}

/* Interleaved point multiplication using precomputed point multiples:
 * The small point multiples 0*P, 1*P, ..., 15*P are in pre_comp[],
 * the scalars in scalars[]. If g_scalar is non-NULL, we also add this multiple
 * of the generator, using certain (large) precomputed multiples in g_pre_comp.
 * Output point (X, Y, Z) is stored in x_out, y_out, z_out */
static void batch_mul(fslice x_out[4], fslice y_out[4], fslice z_out[4],
	const felem_bytearray scalars[], const unsigned num_points, const u8 *g_scalar,
	const fslice pre_comp[][16][3][4], const fslice g_pre_comp[16][3][4])
	{
	unsigned i, j, num;
	unsigned gen_mul = (g_scalar != NULL);
	fslice nq[12], nqt[12], tmp[12];
	fslice bits[4];
	u8 byte;

	/* set nq to the point at infinity */
	memset(nq, 0, 12 * sizeof(fslice));

	/* Loop over all scalars msb-to-lsb, 4 bits at a time: for each nibble,
	 * double 4 times, then add the precomputed point multiples.
	 * If we are also adding multiples of the generator, then interleave
	 * these additions with the last 56 doublings. */
	for (i = (num_points ? 28 : 7); i > 0; --i)
		{
		for (j = 0; j < 8; ++j)
			{
			/* double once */
			point_double(nq, nq+4, nq+8, nq, nq+4, nq+8);
			/* add multiples of the generator */
			if ((gen_mul) && (i <= 7))
				{
				bits[3] = (g_scalar[i+20] >> (7-j)) & 1;
				bits[2] = (g_scalar[i+13] >> (7-j)) & 1;
				bits[1] = (g_scalar[i+6] >> (7-j)) & 1;
				bits[0] = (g_scalar[i-1] >> (7-j)) & 1;
				/* select the point to add, in constant time */
				select_point(bits, g_pre_comp, tmp);
				memcpy(nqt, nq, 12 * sizeof(fslice));
				point_add(nq, nq+4, nq+8, nqt, nqt+4, nqt+8,
					tmp, tmp+4, tmp+8);
				}
			/* do an addition after every 4 doublings */
			if (j % 4 == 3)
				{
				/* loop over all scalars */
				for (num = 0; num < num_points; ++num)
					{
					byte = scalars[num][i-1];
					bits[3] = (byte >> (10-j)) & 1;
					bits[2] = (byte >> (9-j)) & 1;
					bits[1] = (byte >> (8-j)) & 1;
					bits[0] = (byte >> (7-j)) & 1;
					/* select the point to add */
					select_point(bits,
						pre_comp[num], tmp);
					memcpy(nqt, nq, 12 * sizeof(fslice));
					point_add(nq, nq+4, nq+8, nqt, nqt+4,
						nqt+8, tmp, tmp+4, tmp+8);
					}
				}
			}
		}
	memcpy(x_out, nq, 4 * sizeof(fslice));
	memcpy(y_out, nq+4, 4 * sizeof(fslice));
	memcpy(z_out, nq+8, 4 * sizeof(fslice));
	}

/******************************************************************************/
/*		       FUNCTIONS TO MANAGE PRECOMPUTATION
 */

static NISTP224_PRE_COMP *nistp224_pre_comp_new()
	{
	NISTP224_PRE_COMP *ret = NULL;
	ret = (NISTP224_PRE_COMP *)OPENSSL_malloc(sizeof(NISTP224_PRE_COMP));
	if (!ret)
		{
		ECerr(EC_F_NISTP224_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
		return ret;
		}
	memset(ret->g_pre_comp, 0, sizeof(ret->g_pre_comp));
	ret->references = 1;
	return ret;
	}

static void *nistp224_pre_comp_dup(void *src_)
	{
	NISTP224_PRE_COMP *src = src_;

	/* no need to actually copy, these objects never change! */
	CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

	return src_;
	}

static void nistp224_pre_comp_free(void *pre_)
	{
	int i;
	NISTP224_PRE_COMP *pre = pre_;

	if (!pre)
		return;

	i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
	if (i > 0)
		return;

	OPENSSL_free(pre);
	}

static void nistp224_pre_comp_clear_free(void *pre_)
	{
	int i;
	NISTP224_PRE_COMP *pre = pre_;

	if (!pre)
		return;

	i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
	if (i > 0)
		return;

	OPENSSL_cleanse(pre, sizeof *pre);
	OPENSSL_free(pre);
	}

/******************************************************************************/
/*			   OPENSSL EC_METHOD FUNCTIONS
 */

int ec_GFp_nistp224_group_init(EC_GROUP *group)
	{
	int ret;
	ret = ec_GFp_simple_group_init(group);
	group->a_is_minus3 = 1;
	return ret;
	}

int ec_GFp_nistp224_group_set_curve(EC_GROUP *group, const BIGNUM *p,
	const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	int ret = 0;
	BN_CTX *new_ctx = NULL;
	BIGNUM *curve_p, *curve_a, *curve_b;

	if (ctx == NULL)
		if ((ctx = new_ctx = BN_CTX_new()) == NULL) return 0;
	BN_CTX_start(ctx);
	if (((curve_p = BN_CTX_get(ctx)) == NULL) ||
		((curve_a = BN_CTX_get(ctx)) == NULL) ||
		((curve_b = BN_CTX_get(ctx)) == NULL)) goto err;
	BN_bin2bn(nistp224_curve_params[0], sizeof(felem_bytearray), curve_p);
	BN_bin2bn(nistp224_curve_params[1], sizeof(felem_bytearray), curve_a);
	BN_bin2bn(nistp224_curve_params[2], sizeof(felem_bytearray), curve_b);
	if ((BN_cmp(curve_p, p)) || (BN_cmp(curve_a, a)) ||
		(BN_cmp(curve_b, b)))
		{
		ECerr(EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE,
			EC_R_WRONG_CURVE_PARAMETERS);
		goto err;
		}
	group->field_mod_func = BN_nist_mod_224;
	ret = ec_GFp_simple_group_set_curve(group, p, a, b, ctx);
err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

/* Takes the Jacobian coordinates (X, Y, Z) of a point and returns
 * (X', Y') = (X/Z^2, Y/Z^3) */
int ec_GFp_nistp224_point_get_affine_coordinates(const EC_GROUP *group,
	const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
	{
	fslice z1[4], z2[4], x_in[4], y_in[4], x_out[4], y_out[4];
	uint128_t tmp[7];

	if (EC_POINT_is_at_infinity(group, point))
		{
		ECerr(EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES,
			EC_R_POINT_AT_INFINITY);
		return 0;
		}
	if ((!BN_to_felem(x_in, &point->X)) || (!BN_to_felem(y_in, &point->Y)) ||
		(!BN_to_felem(z1, &point->Z))) return 0;
	felem_inv(z2, z1);
	felem_square(tmp, z2); felem_reduce(z1, tmp);
	felem_mul(tmp, x_in, z1); felem_reduce(x_in, tmp);
	felem_contract(x_out, x_in);
	if (x != NULL)
		{
		if (!felem_to_BN(x, x_out)) {
		ECerr(EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES,
			ERR_R_BN_LIB);
		return 0;
		}
		}
	felem_mul(tmp, z1, z2); felem_reduce(z1, tmp);
	felem_mul(tmp, y_in, z1); felem_reduce(y_in, tmp);
	felem_contract(y_out, y_in);
	if (y != NULL)
		{
		if (!felem_to_BN(y, y_out)) {
		ECerr(EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES,
			ERR_R_BN_LIB);
		return 0;
		}
		}
	return 1;
	}

/* Computes scalar*generator + \sum scalars[i]*points[i], ignoring NULL values
 * Result is stored in r (r can equal one of the inputs). */
int ec_GFp_nistp224_points_mul(const EC_GROUP *group, EC_POINT *r,
	const BIGNUM *scalar, size_t num, const EC_POINT *points[],
	const BIGNUM *scalars[], BN_CTX *ctx)
	{
	int ret = 0;
	int i, j;
	BN_CTX *new_ctx = NULL;
	BIGNUM *x, *y, *z, *tmp_scalar;
	felem_bytearray g_secret;
	felem_bytearray *secrets = NULL;
	fslice (*pre_comp)[16][3][4] = NULL;
	felem_bytearray tmp;
	unsigned num_bytes;
	int have_pre_comp = 0;
	size_t num_points = num;
	fslice x_in[4], y_in[4], z_in[4], x_out[4], y_out[4], z_out[4];
	NISTP224_PRE_COMP *pre = NULL;
	fslice (*g_pre_comp)[3][4] = NULL;
	EC_POINT *generator = NULL;
	const EC_POINT *p = NULL;
	const BIGNUM *p_scalar = NULL;

	if (ctx == NULL)
		if ((ctx = new_ctx = BN_CTX_new()) == NULL) return 0;
	BN_CTX_start(ctx);
	if (((x = BN_CTX_get(ctx)) == NULL) ||
		((y = BN_CTX_get(ctx)) == NULL) ||
		((z = BN_CTX_get(ctx)) == NULL) ||
		((tmp_scalar = BN_CTX_get(ctx)) == NULL))
		goto err;

	if (scalar != NULL)
		{
		pre = EC_EX_DATA_get_data(group->extra_data,
			nistp224_pre_comp_dup, nistp224_pre_comp_free,
			nistp224_pre_comp_clear_free);
		if (pre)
			/* we have precomputation, try to use it */
			g_pre_comp = pre->g_pre_comp;
		else
			/* try to use the standard precomputation */
			g_pre_comp = (fslice (*)[3][4]) gmul;
		generator = EC_POINT_new(group);
		if (generator == NULL)
			goto err;
		/* get the generator from precomputation */
		if (!felem_to_BN(x, g_pre_comp[1][0]) ||
			!felem_to_BN(y, g_pre_comp[1][1]) ||
			!felem_to_BN(z, g_pre_comp[1][2]))
			{
			ECerr(EC_F_EC_GFP_NISTP224_POINTS_MUL, ERR_R_BN_LIB);
			goto err;
			}
		if (!EC_POINT_set_Jprojective_coordinates_GFp(group,
				generator, x, y, z, ctx))
			goto err;
		if (0 == EC_POINT_cmp(group, generator, group->generator, ctx))
			/* precomputation matches generator */
			have_pre_comp = 1;
		else
			/* we don't have valid precomputation:
			 * treat the generator as a random point */
			num_points = num_points + 1;
		}
	secrets = OPENSSL_malloc(num_points * sizeof(felem_bytearray));
	pre_comp = OPENSSL_malloc(num_points * 16 * 3 * 4 * sizeof(fslice));

	if ((num_points) && ((secrets == NULL) || (pre_comp == NULL)))
		{
		ECerr(EC_F_EC_GFP_NISTP224_POINTS_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	/* we treat NULL scalars as 0, and NULL points as points at infinity,
	 * i.e., they contribute nothing to the linear combination */
	memset(secrets, 0, num_points * sizeof(felem_bytearray));
	memset(pre_comp, 0, num_points * 16 * 3 * 4 * sizeof(fslice));
	for (i = 0; i < num_points; ++i)
		{
		if (i == num)
			/* the generator */
			{
			p = EC_GROUP_get0_generator(group);
			p_scalar = scalar;
			}
		else
			/* the i^th point */
			{
			p = points[i];
			p_scalar = scalars[i];
			}
		if ((p_scalar != NULL) && (p != NULL))
			{
			num_bytes = BN_num_bytes(p_scalar);
			/* reduce scalar to 0 <= scalar < 2^224 */
			if ((num_bytes > sizeof(felem_bytearray)) || (BN_is_negative(p_scalar)))
				{
				/* this is an unusual input, and we don't guarantee
				 * constant-timeness */
				if (!BN_nnmod(tmp_scalar, p_scalar, &group->order, ctx))
					{
					ECerr(EC_F_EC_GFP_NISTP224_POINTS_MUL, ERR_R_BN_LIB);
					goto err;
					}
				num_bytes = BN_bn2bin(tmp_scalar, tmp);
				}
			else
				BN_bn2bin(p_scalar, tmp);
			flip_endian(secrets[i], tmp, num_bytes);
			/* precompute multiples */
			if ((!BN_to_felem(x_out, &p->X)) ||
				(!BN_to_felem(y_out, &p->Y)) ||
				(!BN_to_felem(z_out, &p->Z))) goto err;
			memcpy(pre_comp[i][1][0], x_out, 4 * sizeof(fslice));
			memcpy(pre_comp[i][1][1], y_out, 4 * sizeof(fslice));
			memcpy(pre_comp[i][1][2], z_out, 4 * sizeof(fslice));
			for (j = 1; j < 8; ++j)
				{
				point_double(pre_comp[i][2*j][0],
					pre_comp[i][2*j][1],
					pre_comp[i][2*j][2],
					pre_comp[i][j][0],
					pre_comp[i][j][1],
					pre_comp[i][j][2]);
				point_add(pre_comp[i][2*j+1][0],
					pre_comp[i][2*j+1][1],
					pre_comp[i][2*j+1][2],
					pre_comp[i][1][0],
					pre_comp[i][1][1],
					pre_comp[i][1][2],
					pre_comp[i][2*j][0],
					pre_comp[i][2*j][1],
					pre_comp[i][2*j][2]);
				}
			}
		}

	/* the scalar for the generator */
	if ((scalar != NULL) && (have_pre_comp))
		{
		memset(g_secret, 0, sizeof g_secret);
		num_bytes = BN_num_bytes(scalar);
		/* reduce scalar to 0 <= scalar < 2^224 */
		if ((num_bytes > sizeof(felem_bytearray)) || (BN_is_negative(scalar)))
			{
			/* this is an unusual input, and we don't guarantee
			 * constant-timeness */
			if (!BN_nnmod(tmp_scalar, scalar, &group->order, ctx))
				{
				ECerr(EC_F_EC_GFP_NISTP224_POINTS_MUL, ERR_R_BN_LIB);
				goto err;
				}
			num_bytes = BN_bn2bin(tmp_scalar, tmp);
			}
		else
			BN_bn2bin(scalar, tmp);
		flip_endian(g_secret, tmp, num_bytes);
		/* do the multiplication with generator precomputation*/
		batch_mul(x_out, y_out, z_out,
			(const felem_bytearray (*)) secrets, num_points,
			g_secret, (const fslice (*)[16][3][4]) pre_comp,
			(const fslice (*)[3][4]) g_pre_comp);
		}
	else
		/* do the multiplication without generator precomputation */
		batch_mul(x_out, y_out, z_out,
			(const felem_bytearray (*)) secrets, num_points,
			NULL, (const fslice (*)[16][3][4]) pre_comp, NULL);
	/* reduce the output to its unique minimal representation */
	felem_contract(x_in, x_out);
	felem_contract(y_in, y_out);
	felem_contract(z_in, z_out);
	if ((!felem_to_BN(x, x_in)) || (!felem_to_BN(y, y_in)) ||
		(!felem_to_BN(z, z_in)))
		{
		ECerr(EC_F_EC_GFP_NISTP224_POINTS_MUL, ERR_R_BN_LIB);
		goto err;
		}
	ret = EC_POINT_set_Jprojective_coordinates_GFp(group, r, x, y, z, ctx);

err:
	BN_CTX_end(ctx);
	if (generator != NULL)
		EC_POINT_free(generator);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (secrets != NULL)
		OPENSSL_free(secrets);
	if (pre_comp != NULL)
		OPENSSL_free(pre_comp);
	return ret;
	}

int ec_GFp_nistp224_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
	{
	int ret = 0;
	NISTP224_PRE_COMP *pre = NULL;
	int i, j;
	BN_CTX *new_ctx = NULL;
	BIGNUM *x, *y;
	EC_POINT *generator = NULL;

	/* throw away old precomputation */
	EC_EX_DATA_free_data(&group->extra_data, nistp224_pre_comp_dup,
		nistp224_pre_comp_free, nistp224_pre_comp_clear_free);
	if (ctx == NULL)
		if ((ctx = new_ctx = BN_CTX_new()) == NULL) return 0;
	BN_CTX_start(ctx);
	if (((x = BN_CTX_get(ctx)) == NULL) ||
		((y = BN_CTX_get(ctx)) == NULL))
		goto err;
	/* get the generator */
	if (group->generator == NULL) goto err;
	generator = EC_POINT_new(group);
	if (generator == NULL)
		goto err;
	BN_bin2bn(nistp224_curve_params[3], sizeof (felem_bytearray), x);
	BN_bin2bn(nistp224_curve_params[4], sizeof (felem_bytearray), y);
	if (!EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, ctx))
		goto err;
	if ((pre = nistp224_pre_comp_new()) == NULL)
		goto err;
	/* if the generator is the standard one, use built-in precomputation */
	if (0 == EC_POINT_cmp(group, generator, group->generator, ctx))
		{
		memcpy(pre->g_pre_comp, gmul, sizeof(pre->g_pre_comp));
		ret = 1;
		goto err;
		}
	if ((!BN_to_felem(pre->g_pre_comp[1][0], &group->generator->X)) ||
		(!BN_to_felem(pre->g_pre_comp[1][1], &group->generator->Y)) ||
		(!BN_to_felem(pre->g_pre_comp[1][2], &group->generator->Z)))
		goto err;
	/* compute 2^56*G, 2^112*G, 2^168*G */
	for (i = 1; i < 5; ++i)
		{
		point_double(pre->g_pre_comp[2*i][0], pre->g_pre_comp[2*i][1],
			pre->g_pre_comp[2*i][2], pre->g_pre_comp[i][0],
			pre->g_pre_comp[i][1], pre->g_pre_comp[i][2]);
		for (j = 0; j < 55; ++j)
			{
			point_double(pre->g_pre_comp[2*i][0],
				pre->g_pre_comp[2*i][1],
				pre->g_pre_comp[2*i][2],
				pre->g_pre_comp[2*i][0],
				pre->g_pre_comp[2*i][1],
				pre->g_pre_comp[2*i][2]);
			}
		}
	/* g_pre_comp[0] is the point at infinity */
	memset(pre->g_pre_comp[0], 0, sizeof(pre->g_pre_comp[0]));
	/* the remaining multiples */
	/* 2^56*G + 2^112*G */
	point_add(pre->g_pre_comp[6][0], pre->g_pre_comp[6][1],
		pre->g_pre_comp[6][2], pre->g_pre_comp[4][0],
		pre->g_pre_comp[4][1], pre->g_pre_comp[4][2],
		pre->g_pre_comp[2][0], pre->g_pre_comp[2][1],
		pre->g_pre_comp[2][2]);
	/* 2^56*G + 2^168*G */
	point_add(pre->g_pre_comp[10][0], pre->g_pre_comp[10][1],
		pre->g_pre_comp[10][2], pre->g_pre_comp[8][0],
		pre->g_pre_comp[8][1], pre->g_pre_comp[8][2],
		pre->g_pre_comp[2][0], pre->g_pre_comp[2][1],
		pre->g_pre_comp[2][2]);
	/* 2^112*G + 2^168*G */
	point_add(pre->g_pre_comp[12][0], pre->g_pre_comp[12][1],
		pre->g_pre_comp[12][2], pre->g_pre_comp[8][0],
		pre->g_pre_comp[8][1], pre->g_pre_comp[8][2],
		pre->g_pre_comp[4][0], pre->g_pre_comp[4][1],
		pre->g_pre_comp[4][2]);
	/* 2^56*G + 2^112*G + 2^168*G */
	point_add(pre->g_pre_comp[14][0], pre->g_pre_comp[14][1],
		pre->g_pre_comp[14][2], pre->g_pre_comp[12][0],
		pre->g_pre_comp[12][1], pre->g_pre_comp[12][2],
		pre->g_pre_comp[2][0], pre->g_pre_comp[2][1],
		pre->g_pre_comp[2][2]);
	for (i = 1; i < 8; ++i)
		{
		/* odd multiples: add G */
		point_add(pre->g_pre_comp[2*i+1][0], pre->g_pre_comp[2*i+1][1],
			pre->g_pre_comp[2*i+1][2], pre->g_pre_comp[2*i][0],
			pre->g_pre_comp[2*i][1], pre->g_pre_comp[2*i][2],
			pre->g_pre_comp[1][0], pre->g_pre_comp[1][1],
			pre->g_pre_comp[1][2]);
		}

	if (!EC_EX_DATA_set_data(&group->extra_data, pre, nistp224_pre_comp_dup,
			nistp224_pre_comp_free, nistp224_pre_comp_clear_free))
		goto err;
	ret = 1;
	pre = NULL;
 err:
	BN_CTX_end(ctx);
	if (generator != NULL)
		EC_POINT_free(generator);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (pre)
		nistp224_pre_comp_free(pre);
	return ret;
	}

int ec_GFp_nistp224_have_precompute_mult(const EC_GROUP *group)
	{
	if (EC_EX_DATA_get_data(group->extra_data, nistp224_pre_comp_dup,
			nistp224_pre_comp_free, nistp224_pre_comp_clear_free)
		!= NULL)
		return 1;
	else
		return 0;
	}

#else
static void *dummy=&dummy;
#endif
