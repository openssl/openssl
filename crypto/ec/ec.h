/* crypto/ec/ec.h */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

#ifdef OPENSSL_NO_EC
#error EC is disabled.
#endif

#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/symhacks.h>

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
	 -- optional extra data (TODO: precomputed table for fast computation of multiples of generator)
	*/
	EC_GROUP;

typedef struct ec_point_st EC_POINT;


/* EC_METHODs for curves over GF(p).
 * EC_GFp_simple_method provides the basis for the optimized methods.
 */
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
#if 0
const EC_METHOD *EC_GFp_recp_method(void); /* TODO */
const EC_METHOD *EC_GFp_nist_method(void); /* TODO */
#endif


EC_GROUP *EC_GROUP_new(const EC_METHOD *);
void EC_GROUP_free(EC_GROUP *);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_copy(EC_GROUP *, const EC_GROUP *);

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
int EC_METHOD_get_field_type(const EC_METHOD *);

int EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

void EC_GROUP_set_nid(EC_GROUP *, int);
int EC_GROUP_get_nid(const EC_GROUP *);


/* We don't have types for field specifications and field elements in general.
 * Otherwise we could declare
 *     int EC_GROUP_set_curve(EC_GROUP *, .....);
 */
int EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

/* EC_GROUP_check() returns 1 if 'group' defines a valid group, 0 otherwise */
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
/* EC_GROUP_check_discriminant() returns 1 if the discriminant of the
 * elliptic curve is not zero, 0 otherwise */
int EC_GROUP_check_discriminant(const EC_GROUP *, BN_CTX *);

/* EC_GROUP_new_GFp() calls EC_GROUP_new() and EC_GROUP_set_GFp()
 * after choosing an appropriate EC_METHOD */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

/* EC_GROUP_new_by_nid() and EC_GROUP_new_by_name() also set
 * generator and order */
EC_GROUP *EC_GROUP_new_by_nid(int nid);
EC_GROUP *EC_GROUP_new_by_name(int name);
/* Currently valid arguments to EC_GROUP_new_by_name() */
#define EC_GROUP_NO_CURVE		0
#define EC_GROUP_NIST_PRIME_192		NID_X9_62_prime192v1
#define EC_GROUP_NIST_PRIME_224		NID_secp224r1
#define EC_GROUP_NIST_PRIME_256		NID_X9_62_prime256v1
#define EC_GROUP_NIST_PRIME_384		NID_secp384r1
#define EC_GROUP_NIST_PRIME_521		NID_secp521r1
#define EC_GROUP_X9_62_PRIME_192V1	NID_X9_62_prime192v1
#define EC_GROUP_X9_62_PRIME_192V2	NID_X9_62_prime192v2
#define EC_GROUP_X9_62_PRIME_192V3	NID_X9_62_prime192v3
#define EC_GROUP_X9_62_PRIME_239V1	NID_X9_62_prime239v1
#define EC_GROUP_X9_62_PRIME_239V2	NID_X9_62_prime239v2
#define EC_GROUP_X9_62_PRIME_239V3	NID_X9_62_prime239v3
#define EC_GROUP_X9_62_PRIME_256V1	NID_X9_62_prime256v1
#define EC_GROUP_SECG_PRIME_112R1	NID_secp112r1
#define EC_GROUP_SECG_PRIME_112R2	NID_secp112r2
#define EC_GROUP_SECG_PRIME_128R1	NID_secp128r1
#define EC_GROUP_SECG_PRIME_128R2	NID_secp128r2
#define EC_GROUP_SECG_PRIME_160K1	NID_secp160k1
#define EC_GROUP_SECG_PRIME_160R1	NID_secp160r1
#define EC_GROUP_SECG_PRIME_160R2	NID_secp160r2
#define EC_GROUP_SECG_PRIME_192K1	NID_secp192k1
#define EC_GROUP_SECG_PRIME_192R1	NID_X9_62_prime192v1
#define EC_GROUP_SECG_PRIME_224K1	NID_secp224k1
#define EC_GROUP_SECG_PRIME_224R1	NID_secp224r1
#define EC_GROUP_SECG_PRIME_256K1	NID_secp256k1
#define EC_GROUP_SECG_PRIME_256R1	NID_X9_62_prime256v1
#define EC_GROUP_SECG_PRIME_384R1	NID_secp384r1
#define EC_GROUP_SECG_PRIME_521R1	NID_secp521r1
#define EC_GROUP_WTLS_6			NID_wap_wsg_idm_ecid_wtls6
#define EC_GROUP_WTLS_7			NID_secp160r1
#define EC_GROUP_WTLS_8			NID_wap_wsg_idm_ecid_wtls8
#define EC_GROUP_WTLS_9			NID_wap_wsg_idm_ecid_wtls9
#define EC_GROUP_WTLS_12		NID_secp224r1

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
 
const EC_METHOD *EC_POINT_method_of(const EC_POINT *);

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

/* other interfaces to point2oct/oct2point: */
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
	point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
	EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
	point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
	EC_POINT *, BN_CTX *);

int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);



/* ASN1 stuff */
#define OPENSSL_EC_NAMED_CURVE	0x001

typedef struct ec_parameters_st ECPARAMETERS;
typedef struct ecpk_parameters_st ECPKPARAMETERS;

DECLARE_ASN1_ITEM(ECPARAMETERS)
DECLARE_ASN1_ITEM(ECPKPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECPARAMETERS, ECPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECPKPARAMETERS, ECPKPARAMETERS)

EC_GROUP *EC_ASN1_pkparameters2group(const ECPKPARAMETERS *); 
ECPKPARAMETERS *EC_ASN1_group2pkparameters(const EC_GROUP *, ECPKPARAMETERS *);

void EC_GROUP_set_asn1_flag(EC_GROUP *, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *);

void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

EC_GROUP *d2i_ECParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECParameters(const EC_GROUP *, unsigned char **out);

EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);



/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_EC_strings(void);

/* Error codes for the EC functions. */

/* Function codes. */
#define EC_F_COMPUTE_WNAF				 143
#define EC_F_D2I_ECDSAPARAMETERS			 154
#define EC_F_D2I_ECPARAMETERS				 155
#define EC_F_D2I_ECPKPARAMETERS				 161
#define EC_F_EC_ASN1_GROUP2CURVE			 159
#define EC_F_EC_ASN1_GROUP2FIELDID			 156
#define EC_F_EC_ASN1_GROUP2PARAMETERS			 160
#define EC_F_EC_ASN1_GROUP2PKPARAMETERS			 162
#define EC_F_EC_ASN1_PARAMETERS2GROUP			 157
#define EC_F_EC_ASN1_PKPARAMETERS2GROUP			 163
#define EC_F_EC_GFP_MONT_FIELD_DECODE			 133
#define EC_F_EC_GFP_MONT_FIELD_ENCODE			 134
#define EC_F_EC_GFP_MONT_FIELD_MUL			 131
#define EC_F_EC_GFP_MONT_FIELD_SQR			 132
#define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT	 152
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP		 100
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR		 101
#define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE			 102
#define EC_F_EC_GFP_SIMPLE_OCT2POINT			 103
#define EC_F_EC_GFP_SIMPLE_POINT2OCT			 104
#define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE		 137
#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP 105
#define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP 128
#define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP 129
#define EC_F_EC_GROUP_CHECK				 150
#define EC_F_EC_GROUP_CHECK_DISCRIMINANT		 153
#define EC_F_EC_GROUP_COPY				 106
#define EC_F_EC_GROUP_GET0_GENERATOR			 139
#define EC_F_EC_GROUP_GET_COFACTOR			 140
#define EC_F_EC_GROUP_GET_CURVE_GFP			 130
#define EC_F_EC_GROUP_GET_EXTRA_DATA			 107
#define EC_F_EC_GROUP_GET_ORDER				 141
#define EC_F_EC_GROUP_GROUP2NID				 147
#define EC_F_EC_GROUP_NEW				 108
#define EC_F_EC_GROUP_NEW_BY_NAME			 144
#define EC_F_EC_GROUP_NEW_BY_NID			 146
#define EC_F_EC_GROUP_NEW_GFP_FROM_HEX			 148
#define EC_F_EC_GROUP_PRECOMPUTE_MULT			 142
#define EC_F_EC_GROUP_SET_CURVE_GFP			 109
#define EC_F_EC_GROUP_SET_EXTRA_DATA			 110
#define EC_F_EC_GROUP_SET_GENERATOR			 111
#define EC_F_EC_POINTS_MAKE_AFFINE			 136
#define EC_F_EC_POINTS_MUL				 138
#define EC_F_EC_POINT_ADD				 112
#define EC_F_EC_POINT_CMP				 113
#define EC_F_EC_POINT_COPY				 114
#define EC_F_EC_POINT_DBL				 115
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP	 116
#define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP	 117
#define EC_F_EC_POINT_IS_AT_INFINITY			 118
#define EC_F_EC_POINT_IS_ON_CURVE			 119
#define EC_F_EC_POINT_MAKE_AFFINE			 120
#define EC_F_EC_POINT_NEW				 121
#define EC_F_EC_POINT_OCT2POINT				 122
#define EC_F_EC_POINT_POINT2OCT				 123
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 124
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP	 125
#define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP	 126
#define EC_F_EC_POINT_SET_TO_INFINITY			 127
#define EC_F_GFP_MONT_GROUP_SET_CURVE_GFP		 135
#define EC_F_I2D_ECDSAPARAMETERS			 158
#define EC_F_I2D_ECPARAMETERS				 164
#define EC_F_I2D_ECPKPARAMETERS				 165

/* Reason codes. */
#define EC_R_ASN1_ERROR					 130
#define EC_R_ASN1_UNKNOWN_FIELD				 131
#define EC_R_BUFFER_TOO_SMALL				 100
#define EC_R_D2I_ECPARAMETERS_FAILURE			 132
#define EC_R_D2I_ECPKPARAMETERS_FAILURE			 133
#define EC_R_D2I_EC_PARAMETERS_FAILURE			 123
#define EC_R_DISCRIMINANT_IS_ZERO			 118
#define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE		 124
#define EC_R_GROUP2PARAMETERS_FAILURE			 125
#define EC_R_GROUP2PKPARAMETERS_FAILURE			 134
#define EC_R_I2D_ECPKPARAMETERS_FAILURE			 135
#define EC_R_I2D_EC_PARAMETERS_FAILURE			 126
#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_INVALID_ARGUMENT				 112
#define EC_R_INVALID_COMPRESSED_POINT			 110
#define EC_R_INVALID_COMPRESSION_BIT			 109
#define EC_R_INVALID_ENCODING				 102
#define EC_R_INVALID_FIELD				 103
#define EC_R_INVALID_FORM				 104
#define EC_R_INVALID_GROUP_ORDER			 119
#define EC_R_MISSING_PARAMETERS				 127
#define EC_R_NOT_IMPLEMENTED				 136
#define EC_R_NOT_INITIALIZED				 111
#define EC_R_NO_SUCH_EXTRA_DATA				 105
#define EC_R_PARAMETERS2GROUP_FAILURE			 128
#define EC_R_PKPARAMETERS2GROUP_FAILURE			 137
#define EC_R_POINT_AT_INFINITY				 106
#define EC_R_POINT_IS_NOT_ON_CURVE			 107
#define EC_R_SLOT_FULL					 108
#define EC_R_UNDEFINED_GENERATOR			 113
#define EC_R_UNDEFINED_ORDER				 122
#define EC_R_UNKNOWN_GROUP				 116
#define EC_R_UNKNOWN_NID				 117
#define EC_R_UNKNOWN_ORDER				 114
#define EC_R_UNKNOWN_PARAMETERS_TYPE			 129

#ifdef  __cplusplus
}
#endif
#endif
