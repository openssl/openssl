/* crypto/ec/ec.h */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#ifndef HEADER_EC_H
#define HEADER_EC_H

#include <openssl/bn.h>

#ifdef  __cplusplus
extern "C" {
#endif



typedef enum {
	/* values as defined in X9.62 (ECDSA) and elsewhere */
	POINT_CONVERSION_COMPRESSED = 2,
	POINT_CONVERSION_UNCOMPRESSED = 4,
	POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


typedef struct ec_method_st EC_METHOD;

typedef struct ec_group_st
	/*
	 EC_METHOD *meth;
	 -- field definition
	 -- curve coefficients
	 -- optional generator with associated information (order, cofactor)
	 -- optional Lim/Lee precomputation table
	*/
	EC_GROUP;

typedef struct ec_point_st EC_POINT;


/* EC_METHODs for curves over GF(p).
 * EC_GFp_simple_method provides the basis for the optimized methods.
 */
 
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
const EC_METHOD *EC_GFp_recp_method(void);
const EC_METHOD *EC_GFp_nist_method(void);


EC_GROUP *EC_GROUP_new(const EC_METHOD *);
/* We don't have types for field specifications and field elements in general.
 * Otherwise we would declare
 *     int EC_GROUP_set_curve(EC_GROUP *, .....);
 */
int EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void EC_GROUP_free(EC_GROUP *);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_copy(EC_GROUP *, const EC_GROUP*);

/* EC_GROUP_new_GFp() calls EC_GROUP_new() and EC_GROUP_set_GFp()
 * after choosing an appropriate EC_METHOD */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

int EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);

/* TODO: 'set' and 'get' functions for EC_GROUPs */


EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
 
int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int y_bit, BN_CTX *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);

int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);



/* TODO: scalar multiplication */



/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the EC functions. */

/* Function codes. */
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP		 127
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR		 100
#define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE			 101
#define EC_F_EC_GFP_SIMPLE_OCT2POINT			 102
#define EC_F_EC_GFP_SIMPLE_POINT2OCT			 103
#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP 104
#define EC_F_EC_GROUP_COPY				 105
#define EC_F_EC_GROUP_GET_EXTRA_DATA			 106
#define EC_F_EC_GROUP_NEW				 107
#define EC_F_EC_GROUP_SET_CURVE_GFP			 108
#define EC_F_EC_GROUP_SET_EXTRA_DATA			 109
#define EC_F_EC_GROUP_SET_GENERATOR			 110
#define EC_F_EC_POINT_ADD				 111
#define EC_F_EC_POINT_CMP				 123
#define EC_F_EC_POINT_COPY				 112
#define EC_F_EC_POINT_DBL				 113
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP	 114
#define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP	 124
#define EC_F_EC_POINT_IS_AT_INFINITY			 115
#define EC_F_EC_POINT_IS_ON_CURVE			 116
#define EC_F_EC_POINT_MAKE_AFFINE			 117
#define EC_F_EC_POINT_NEW				 118
#define EC_F_EC_POINT_OCT2POINT				 119
#define EC_F_EC_POINT_POINT2OCT				 120
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 121
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP	 125
#define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP	 126
#define EC_F_EC_POINT_SET_TO_INFINITY			 122

/* Reason codes. */
#define EC_R_BUFFER_TOO_SMALL				 100
#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_INVALID_ENCODING				 102
#define EC_R_INVALID_FIELD				 108
#define EC_R_INVALID_FORM				 103
#define EC_R_NO_SUCH_EXTRA_DATA				 104
#define EC_R_POINT_AT_INFINITY				 105
#define EC_R_POINT_IS_NOT_ON_CURVE			 106
#define EC_R_SLOT_FULL					 107

#ifdef  __cplusplus
}
#endif
#endif
