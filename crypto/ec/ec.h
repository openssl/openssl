/* crypto/ec/ec.h */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the Contribution as delivered hereunder 
 * (or portions thereof), provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the Contribution;
 *  2) separates from the Contribution; or
 *  3) for infringements caused by:
 *       i) the modification of the Contribution or
 *      ii) the combination of the Contribution with other software or
 *          devices where such combination causes the infringement.
 *
 * The elliptic curve binary polynomial software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
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
	 -- ASN1 stuff
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

/* EC_METHOD for curves over GF(2^m).
 */
const EC_METHOD *EC_GF2m_simple_method(void);


EC_GROUP *EC_GROUP_new(const EC_METHOD *);
void EC_GROUP_free(EC_GROUP *);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_copy(EC_GROUP *, const EC_GROUP *);
EC_GROUP *EC_GROUP_dup(const EC_GROUP *);

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
int EC_METHOD_get_field_type(const EC_METHOD *);

int EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

void EC_GROUP_set_nid(EC_GROUP *, int); /* curve name */
int EC_GROUP_get_nid(const EC_GROUP *);

void EC_GROUP_set_asn1_flag(EC_GROUP *, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *);

void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

int EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int EC_GROUP_set_curve_GF2m(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GF2m(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

int EC_GROUP_get_degree(const EC_GROUP *);

/* EC_GROUP_check() returns 1 if 'group' defines a valid group, 0 otherwise */
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
/* EC_GROUP_check_discriminant() returns 1 if the discriminant of the
 * elliptic curve is not zero, 0 otherwise */
int EC_GROUP_check_discriminant(const EC_GROUP *, BN_CTX *);

/* EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*()
 * after choosing an appropriate EC_METHOD */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

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
#define EC_GROUP_WTLS_7			NID_wap_wsg_idm_ecid_wtls7
#define EC_GROUP_WTLS_8			NID_wap_wsg_idm_ecid_wtls8
#define EC_GROUP_WTLS_9			NID_wap_wsg_idm_ecid_wtls9
#define EC_GROUP_WTLS_12		NID_wap_wsg_idm_ecid_wtls12
#define EC_GROUP_NIST_CHAR2_K163	NID_sect163k1
#define EC_GROUP_NIST_CHAR2_B163	NID_sect163r2
#define EC_GROUP_NIST_CHAR2_K233	NID_sect233k1
#define EC_GROUP_NIST_CHAR2_B233	NID_sect233r1
#define EC_GROUP_NIST_CHAR2_K283	NID_sect283k1
#define EC_GROUP_NIST_CHAR2_B283	NID_sect283r1
#define EC_GROUP_NIST_CHAR2_K409	NID_sect409k1
#define EC_GROUP_NIST_CHAR2_B409	NID_sect409r1
#define EC_GROUP_NIST_CHAR2_K571	NID_sect571k1
#define EC_GROUP_NIST_CHAR2_B571	NID_sect571r1
#define EC_GROUP_X9_62_CHAR2_163V1	NID_X9_62_c2pnb163v1
#define EC_GROUP_X9_62_CHAR2_163V2	NID_X9_62_c2pnb163v2
#define EC_GROUP_X9_62_CHAR2_163V3	NID_X9_62_c2pnb163v3
#define EC_GROUP_X9_62_CHAR2_176V1	NID_X9_62_c2pnb176v1
#define EC_GROUP_X9_62_CHAR2_191V1	NID_X9_62_c2tnb191v1
#define EC_GROUP_X9_62_CHAR2_191V2	NID_X9_62_c2tnb191v2
#define EC_GROUP_X9_62_CHAR2_191V3	NID_X9_62_c2tnb191v3
#define EC_GROUP_X9_62_CHAR2_208W1	NID_X9_62_c2pnb208w1
#define EC_GROUP_X9_62_CHAR2_239V1	NID_X9_62_c2tnb239v1
#define EC_GROUP_X9_62_CHAR2_239V2	NID_X9_62_c2tnb239v2
#define EC_GROUP_X9_62_CHAR2_239V3	NID_X9_62_c2tnb239v3
#define EC_GROUP_X9_62_CHAR2_272W1	NID_X9_62_c2pnb272w1
#define EC_GROUP_X9_62_CHAR2_304W1	NID_X9_62_c2pnb304w1
#define EC_GROUP_X9_62_CHAR2_359V1	NID_X9_62_c2tnb359v1
#define EC_GROUP_X9_62_CHAR2_368W1	NID_X9_62_c2pnb368w1
#define EC_GROUP_X9_62_CHAR2_431R1	NID_X9_62_c2tnb431r1
#define EC_GROUP_SECG_CHAR2_113R1	NID_sect113r1
#define EC_GROUP_SECG_CHAR2_113R2	NID_sect113r2
#define EC_GROUP_SECG_CHAR2_131R1	NID_sect131r1
#define EC_GROUP_SECG_CHAR2_131R2	NID_sect131r2
#define EC_GROUP_SECG_CHAR2_163K1	NID_sect163k1
#define EC_GROUP_SECG_CHAR2_163R1	NID_sect163r1
#define EC_GROUP_SECG_CHAR2_163R2	NID_sect163r2
#define EC_GROUP_SECG_CHAR2_193R1	NID_sect193r1
#define EC_GROUP_SECG_CHAR2_193R2	NID_sect193r2
#define EC_GROUP_SECG_CHAR2_233K1	NID_sect233k1
#define EC_GROUP_SECG_CHAR2_233R1	NID_sect233r1
#define EC_GROUP_SECG_CHAR2_239K1	NID_sect239k1
#define EC_GROUP_SECG_CHAR2_283K1	NID_sect283k1
#define EC_GROUP_SECG_CHAR2_283R1	NID_sect283r1
#define EC_GROUP_SECG_CHAR2_409K1	NID_sect409k1
#define EC_GROUP_SECG_CHAR2_409R1	NID_sect409r1
#define EC_GROUP_SECG_CHAR2_571K1	NID_sect571k1
#define EC_GROUP_SECG_CHAR2_571R1	NID_sect571r1
#define EC_GROUP_WTLS_1			NID_wap_wsg_idm_ecid_wtls1
#define EC_GROUP_WTLS_3			NID_wap_wsg_idm_ecid_wtls3
#define EC_GROUP_WTLS_4			NID_wap_wsg_idm_ecid_wtls4
#define EC_GROUP_WTLS_5			NID_wap_wsg_idm_ecid_wtls5
#define EC_GROUP_WTLS_10		NID_wap_wsg_idm_ecid_wtls10
#define EC_GROUP_WTLS_11		NID_wap_wsg_idm_ecid_wtls11

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);
 
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

int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
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

typedef struct ecpk_parameters_st ECPKPARAMETERS;

EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);

#define d2i_ECPKParameters_bio(bp,x) (EC_GROUP *)ASN1_d2i_bio(NULL, \
                (char *(*)())d2i_ECPKParameters,(bp),(unsigned char **)(x))
#define i2d_ECPKParameters_bio(bp,x) ASN1_i2d_bio(i2d_ECPKParameters,(bp), \
		(unsigned char *)(x))
#define d2i_ECPKParameters_fp(fp,x) (EC_GROUP *)ASN1_d2i_fp(NULL, \
                (char *(*)())d2i_ECPKParameters,(fp),(unsigned char **)(x))
#define i2d_ECPKParameters_fp(fp,x) ASN1_i2d_fp(i2d_ECPKParameters,(fp), \
		(unsigned char *)(x))

#ifndef OPENSSL_NO_BIO
int     ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
#endif
#ifndef OPENSSL_NO_FP_API
int     ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);
#endif

/* the EC_KEY stuff */
typedef struct ec_key_st EC_KEY;

typedef struct ec_key_meth_data_st {
	int (*init)(EC_KEY *);
	void (*finish)(EC_KEY *);
	} EC_KEY_METH_DATA;

struct ec_key_st {
	int version;

	EC_GROUP *group;

	EC_POINT *pub_key;
	BIGNUM	 *priv_key;

	unsigned int enc_flag;
	point_conversion_form_t conv_form;

	int 	references;

	EC_KEY_METH_DATA *meth_data;
	}/* EC_KEY */;
/* some values for the encoding_flag */
#define EC_PKEY_NO_PARAMETERS	0x001
#define EC_PKEY_NO_PUBKEY	0x002

EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);
int EC_KEY_up_ref(EC_KEY *);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);

/* de- and encode functions for the SEC1 ECPrivateKey */
EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECPrivateKey(EC_KEY *a, unsigned char **out);
/* de- and encode functions for the elliptic curve parameters */
EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECParameters(EC_KEY *a, unsigned char **out);

EC_KEY *ECPublicKey_set_octet_string(EC_KEY **a, const unsigned char **in, 
					long len);
int ECPublicKey_get_octet_string(EC_KEY *a, unsigned char **out);

#ifndef OPENSSL_NO_BIO
int	ECParameters_print(BIO *bp, const EC_KEY *x);
int	EC_KEY_print(BIO *bp, const EC_KEY *x, int off);
#endif
#ifndef OPENSSL_NO_FP_API
int	ECParameters_print_fp(FILE *fp, const EC_KEY *x);
int	EC_KEY_print_fp(FILE *fp, const EC_KEY *x, int off);
#endif

#define ECParameters_dup(x) (EC_KEY *)ASN1_dup((int (*)())i2d_ECParameters,\
		(char *(*)())d2i_ECParameters,(char *)(x))

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_EC_strings(void);

/* Error codes for the EC functions. */

/* Function codes. */
#define EC_F_COMPUTE_WNAF				 143
#define EC_F_D2I_ECPARAMETERS				 155
#define EC_F_D2I_ECPKPARAMETERS				 161
#define EC_F_D2I_ECPRIVATEKEY				 168
#define EC_F_ECPARAMETERS_PRINT				 173
#define EC_F_ECPARAMETERS_PRINT_FP			 174
#define EC_F_ECPKPARAMETERS_PRINT			 166
#define EC_F_ECPKPARAMETERS_PRINT_FP			 167
#define EC_F_ECPUBLICKEY_GET_OCTET			 170
#define EC_F_ECPUBLICKEY_SET_OCTET			 171
#define EC_F_EC_ASN1_GROUP2CURVE			 159
#define EC_F_EC_ASN1_GROUP2FIELDID			 156
#define EC_F_EC_ASN1_GROUP2PARAMETERS			 160
#define EC_F_EC_ASN1_GROUP2PKPARAMETERS			 162
#define EC_F_EC_ASN1_PARAMETERS2GROUP			 157
#define EC_F_EC_ASN1_PKPARAMETERS2GROUP			 163
#define EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT	 168
#define EC_F_EC_GF2M_SIMPLE_OCT2POINT			 169
#define EC_F_EC_GF2M_SIMPLE_POINT2OCT			 170
#define EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 171
#define EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 172
#define EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES	 182
#define EC_F_EC_GFP_MONT_FIELD_DECODE			 133
#define EC_F_EC_GFP_MONT_FIELD_ENCODE			 134
#define EC_F_EC_GFP_MONT_FIELD_MUL			 131
#define EC_F_EC_GFP_MONT_FIELD_SQR			 132
#define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT	 152
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE		 100
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR		 101
#define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE			 102
#define EC_F_EC_GFP_SIMPLE_OCT2POINT			 103
#define EC_F_EC_GFP_SIMPLE_POINT2OCT			 104
#define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE		 137
#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES	 105
#define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES	 128
#define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES	 129
#define EC_F_EC_GROUP_CHECK				 150
#define EC_F_EC_GROUP_CHECK_DISCRIMINANT		 153
#define EC_F_EC_GROUP_COPY				 106
#define EC_F_EC_GROUP_GET0_GENERATOR			 139
#define EC_F_EC_GROUP_GET_COFACTOR			 140
#define EC_F_EC_GROUP_GET_CURVE_GF2M			 173
#define EC_F_EC_GROUP_GET_CURVE_GFP			 130
#define EC_F_EC_GROUP_GET_DEGREE			 174
#define EC_F_EC_GROUP_GET_EXTRA_DATA			 107
#define EC_F_EC_GROUP_GET_ORDER				 141
#define EC_F_EC_GROUP_GROUP2NID				 147
#define EC_F_EC_GROUP_NEW				 108
#define EC_F_EC_GROUP_NEW_BY_NAME			 144
#define EC_F_EC_GROUP_NEW_BY_NID			 146
#define EC_F_EC_GROUP_NEW_GF2M_FROM_HEX			 175
#define EC_F_EC_GROUP_NEW_GFP_FROM_HEX			 148
#define EC_F_EC_GROUP_PRECOMPUTE_MULT			 142
#define EC_F_EC_GROUP_SET_CURVE_GF2M			 176
#define EC_F_EC_GROUP_SET_CURVE_GFP			 109
#define EC_F_EC_GROUP_SET_EXTRA_DATA			 110
#define EC_F_EC_GROUP_SET_GENERATOR			 111
#define EC_F_EC_KEY_CHECK_KEY				 184
#define EC_F_EC_KEY_COPY				 186
#define EC_F_EC_KEY_GENERATE_KEY			 185
#define EC_F_EC_KEY_PRINT				 175
#define EC_F_EC_KEY_PRINT_FP				 176
#define EC_F_EC_NEW					 172
#define EC_F_EC_POINTS_MAKE_AFFINE			 136
#define EC_F_EC_POINTS_MUL				 138
#define EC_F_EC_POINT_ADD				 112
#define EC_F_EC_POINT_CMP				 113
#define EC_F_EC_POINT_COPY				 114
#define EC_F_EC_POINT_DBL				 115
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M	 177
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP	 116
#define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP	 117
#define EC_F_EC_POINT_IS_AT_INFINITY			 118
#define EC_F_EC_POINT_IS_ON_CURVE			 119
#define EC_F_EC_POINT_MAKE_AFFINE			 120
#define EC_F_EC_POINT_MUL				 179
#define EC_F_EC_POINT_NEW				 121
#define EC_F_EC_POINT_OCT2POINT				 122
#define EC_F_EC_POINT_POINT2OCT				 123
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M	 180
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 124
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M	 181
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP	 125
#define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP	 126
#define EC_F_EC_POINT_SET_TO_INFINITY			 127
#define EC_F_EC_WNAF_MUL				 183
#define EC_F_EC_WNAF_PRECOMPUTE_MULT			 178
#define EC_F_GFP_MONT_GROUP_SET_CURVE			 135
#define EC_F_I2D_ECDSAPARAMETERS			 158
#define EC_F_I2D_ECPARAMETERS				 164
#define EC_F_I2D_ECPKPARAMETERS				 165
#define EC_F_I2D_ECPRIVATEKEY				 169

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
#define EC_R_INVALID_PRIVATE_KEY			 139
#define EC_R_MISSING_PARAMETERS				 127
#define EC_R_MISSING_PRIVATE_KEY			 138
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
#define EC_R_WRONG_ORDER				 140

#ifdef  __cplusplus
}
#endif
#endif
