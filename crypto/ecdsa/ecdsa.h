/* crypto/ecdsa/ecdsa.h */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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
#ifndef HEADER_ECDSA_H
#define HEADER_ECDSA_H

#ifdef OPENSSL_NO_ECDSA
#error ECDSA is disabled.
#endif

#ifndef OPENSSL_NO_BIO
#include <openssl/bio.h>
#endif
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecdsa_st ECDSA;

typedef struct ECDSA_SIG_st
{
	BIGNUM *r;
	BIGNUM *s;
} ECDSA_SIG;

typedef struct ecdsa_method 
{
	const char *name;
	ECDSA_SIG *(*ecdsa_do_sign)(const unsigned char *dgst, int dgst_len, ECDSA *ecdsa);
	int (*ecdsa_sign_setup)(ECDSA *ecdsa, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r);
	int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len, ECDSA_SIG *sig, ECDSA *ecdsa);
	int (*init)(ECDSA *ecdsa);
	int (*finish)(ECDSA *ecdsa);
	int flags;
	char *app_data;
} ECDSA_METHOD;

struct ecdsa_st
{
	int version;
	point_conversion_form_t conversion_form;

	EC_GROUP *group;

	EC_POINT *pub_key;
	BIGNUM	 *priv_key;

	BIGNUM	 *kinv; /* signing pre-calc */
	BIGNUM	 *r;	/* signing pre-calc */

	int 	references;
	int	flags;
	CRYPTO_EX_DATA ex_data;
	const ECDSA_METHOD *meth;
	struct engine_st *engine;
};

ECDSA_SIG *ECDSA_SIG_new(void);
void	  ECDSA_SIG_free(ECDSA_SIG *a);
int	  i2d_ECDSA_SIG(const ECDSA_SIG *a, unsigned char **pp);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **v, const unsigned char **pp, long length);

ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len, ECDSA *ecdsa);
int	  ECDSA_do_verify(const unsigned char *dgst, int dgst_len, ECDSA_SIG *sig, ECDSA* ecdsa);
int 	  ECDSA_generate_key(ECDSA *ecdsa);
int	  ECDSA_check_key(ECDSA *ecdsa);

const ECDSA_METHOD *ECDSA_OpenSSL(void);

void	  ECDSA_set_default_method(const ECDSA_METHOD *);
const ECDSA_METHOD *ECDSA_get_default_method(void);
int 	  ECDSA_set_method(ECDSA *, const ECDSA_METHOD *);

ECDSA	  *ECDSA_new(void);
ECDSA	  *ECDSA_new_method(ENGINE *engine);
int	  ECDSA_size(const ECDSA *);
int 	  ECDSA_sign_setup(ECDSA *ecdsa, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp);
int	  ECDSA_sign(int type, const unsigned char *dgst, int dgst_len, unsigned char *sig, 
		     unsigned int *siglen, ECDSA *ecdsa);
int 	  ECDSA_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sig,
		       int sig_len, ECDSA *ecdsa);
int	  ECDSA_up_ref(ECDSA *ecdsa);
void	  ECDSA_free(ECDSA *a);
int 	  ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     			 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int 	  ECDSA_set_ex_data(ECDSA *d, int idx, void *arg);
void 	  *ECDSA_get_ex_data(ECDSA *d, int idx);

#ifndef OPENSSL_NO_BIO
int	ECDSAParameters_print(BIO *bp, const ECDSA *x);
int	ECDSA_print(BIO *bp, const ECDSA *x, int off);
#endif
#ifndef OPENSSL_NO_FP_API
int	ECDSAParameters_print_fp(FILE *fp, const ECDSA *x);
int	ECDSA_print_fp(FILE *fp, const ECDSA *x, int off);
#endif 

/* The ECDSA_{set|get}_conversion_type() functions set/get the
 * conversion form for ec-points (see ec.h) in a ECDSA-structure */
void	ECDSA_set_conversion_form(ECDSA *, const point_conversion_form_t);
point_conversion_form_t ECDSA_get_conversion_form(const ECDSA *);
/* The ECDSA_{set|get}_default_conversion_form() functions set/get the 
 * default conversion form */
void	ECDSA_set_default_conversion_form(const point_conversion_form_t);
point_conversion_form_t ECDSA_get_default_conversion_form(void);

/* the basic de- and encode functions ( see ecs_asn1.c ) */
ECDSA   *d2i_ECDSAParameters(ECDSA **a, const unsigned char **in, long len);
int     i2d_ECDSAParameters(ECDSA *a, unsigned char **out);

ECDSA   *d2i_ECDSAPrivateKey(ECDSA **a, const unsigned char **in, long len);
int     i2d_ECDSAPrivateKey(ECDSA *a, unsigned char **out);

/* ECDSAPublicKey_set_octet_string() sets the public key in the ECDSA-structure.
 * (*a) must be a pointer to a ECDSA-structure with (*a)->group not zero 
 * (e.g. a ECDSA-structure with a valid EC_GROUP-structure) */
ECDSA 	*ECDSAPublicKey_set_octet_string(ECDSA **a, const unsigned char **in, long len);
/* ECDSAPublicKey_get_octet_string() returns the length of the octet string encoding
 * of the public key. If out != NULL then the function returns in *out 
 * a pointer to the octet string */
int 	ECDSAPublicKey_get_octet_string(ECDSA *a, unsigned char **out);


#define ECDSAParameters_dup(x) (ECDSA *)ASN1_dup((int (*)())i2d_ECDSAParameters, \
		(char *(*)())d2i_ECDSAParameters,(char *)(x))
#define d2i_ECDSAParameters_fp(fp,x) (ECDSA *)ASN1_d2i_fp((char *(*)())ECDSA_new, \
		(char *(*)())d2i_ECDSAParameters,(fp),(unsigned char **)(x))
#define i2d_ECDSAParameters_fp(fp,x) ASN1_i2d_fp(i2d_ECDSAParameters,(fp), \
		(unsigned char *)(x))
#define d2i_ECDSAParameters_bio(bp,x) (ECDSA *)ASN1_d2i_bio((char *(*)())ECDSA_new, \
		(char *(*)())d2i_ECDSAParameters,(bp),(unsigned char **)(x))
#define i2d_ECDSAParameters_bio(bp,x) ASN1_i2d_bio(i2d_ECDSAParameters,(bp), \
		(unsigned char *)(x))

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ECDSA_strings(void);

/* Error codes for the ECDSA functions. */

/* Function codes. */
#define ECDSA_F_D2I_ECDSAPARAMETERS			 100
#define ECDSA_F_D2I_ECDSAPRIVATEKEY			 101
#define ECDSA_F_ECDSAPARAMETERS_PRINT			 102
#define ECDSA_F_ECDSAPARAMETERS_PRINT_FP		 103
#define ECDSA_F_ECDSA_DO_SIGN				 104
#define ECDSA_F_ECDSA_DO_VERIFY				 105
#define ECDSA_F_ECDSA_GENERATE_KEY			 106
#define ECDSA_F_ECDSA_GET				 107
#define ECDSA_F_ECDSA_GET_CURVE_NID			 120
#define ECDSA_F_ECDSA_GET_ECDSA				 121
#define ECDSA_F_ECDSA_GET_EC_PARAMETERS			 122
#define ECDSA_F_ECDSA_GET_X9_62_CURVE			 108
#define ECDSA_F_ECDSA_GET_X9_62_EC_PARAMETERS		 109
#define ECDSA_F_ECDSA_GET_X9_62_FIELDID			 110
#define ECDSA_F_ECDSA_NEW				 111
#define ECDSA_F_ECDSA_PRINT				 112
#define ECDSA_F_ECDSA_PRINT_FP				 113
#define ECDSA_F_ECDSA_SET_GROUP_P			 114
#define ECDSA_F_ECDSA_SET_PRIME_GROUP			 123
#define ECDSA_F_ECDSA_SIGN_SETUP			 115
#define ECDSA_F_I2D_ECDSAPARAMETERS			 116
#define ECDSA_F_I2D_ECDSAPRIVATEKEY			 117
#define ECDSA_F_I2D_ECDSAPUBLICKEY			 118
#define ECDSA_F_SIG_CB					 119

/* Reason codes. */
#define ECDSA_R_BAD_SIGNATURE				 100
#define ECDSA_R_CAN_NOT_GET_GENERATOR			 101
#define ECDSA_R_D2I_ECDSAPRIVATEKEY_MISSING_PRIVATE_KEY	 102
#define ECDSA_R_D2I_ECDSA_PRIVATEKEY_FAILURE		 103
#define ECDSA_R_D2I_EC_PARAMETERS_FAILURE		 133
#define ECDSA_R_D2I_X9_62_EC_PARAMETERS_FAILURE		 104
#define ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 105
#define ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE		 106
#define ECDSA_R_ECDSA_F_ECDSA_NEW			 107
#define ECDSA_R_ECDSA_GET_EC_PARAMETERS_FAILURE		 134
#define ECDSA_R_ECDSA_GET_FAILURE			 108
#define ECDSA_R_ECDSA_GET_X9_62_CURVE_FAILURE		 109
#define ECDSA_R_ECDSA_GET_X9_62_EC_PARAMETERS_FAILURE	 110
#define ECDSA_R_ECDSA_GET_X9_62_FIELDID_FAILURE		 111
#define ECDSA_R_ECDSA_NEW_FAILURE			 112
#define ECDSA_R_ECDSA_R_D2I_EC_PARAMETERS_FAILURE	 135
#define ECDSA_R_ECDSA_R_D2I_X9_62_EC_PARAMETERS_FAILURE	 113
#define ECDSA_R_ECPARAMETERS2ECDSA_FAILURE		 138
#define ECDSA_R_EC_GROUP_NID2CURVE_FAILURE		 136
#define ECDSA_R_ERR_EC_LIB				 114
#define ECDSA_R_I2D_ECDSA_PRIVATEKEY			 115
#define ECDSA_R_I2D_ECDSA_PUBLICKEY			 116
#define ECDSA_R_MISSING_PARAMETERS			 117
#define ECDSA_R_MISSING_PRIVATE_KEY			 139
#define ECDSA_R_NOT_SUPPORTED				 118
#define ECDSA_R_NO_CURVE_PARAMETER_A_SPECIFIED		 119
#define ECDSA_R_NO_CURVE_PARAMETER_B_SPECIFIED		 120
#define ECDSA_R_NO_CURVE_SPECIFIED			 121
#define ECDSA_R_NO_FIELD_SPECIFIED			 122
#define ECDSA_R_PRIME_MISSING				 123
#define ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED		 124
#define ECDSA_R_SIGNATURE_MALLOC_FAILED			 125
#define ECDSA_R_UNEXPECTED_ASN1_TYPE			 126
#define ECDSA_R_UNEXPECTED_PARAMETER			 127
#define ECDSA_R_UNEXPECTED_PARAMETER_LENGTH		 128
#define ECDSA_R_UNEXPECTED_VERSION_NUMER		 129
#define ECDSA_R_UNKNOWN_PARAMETERS_TYPE			 137
#define ECDSA_R_WRONG_FIELD_IDENTIFIER			 130
#define ECDSA_R_X9_62_CURVE_NEW_FAILURE			 131
#define ECDSA_R_X9_62_EC_PARAMETERS_NEW_FAILURE		 132

#ifdef  __cplusplus
}
#endif
#endif
