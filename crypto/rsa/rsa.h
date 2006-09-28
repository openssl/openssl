/* crypto/rsa/rsa.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include <openssl/asn1.h>

#ifndef OPENSSL_NO_BIO
#include <openssl/bio.h>
#endif
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>

#ifdef OPENSSL_NO_RSA
#error RSA is disabled.
#endif

#if defined(OPENSSL_FIPS)
#define FIPS_RSA_SIZE_T	int
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct rsa_st RSA;

typedef struct rsa_meth_st
	{
	const char *name;
	int (*rsa_pub_enc)(int flen,const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,int padding);
	int (*rsa_pub_dec)(int flen,const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,int padding);
	int (*rsa_priv_enc)(int flen,const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,int padding);
	int (*rsa_priv_dec)(int flen,const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,int padding);
	int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa); /* Can be null */
	int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx,
			  BN_MONT_CTX *m_ctx); /* Can be null */
	int (*init)(RSA *rsa);		/* called at new */
	int (*finish)(RSA *rsa);	/* called at free */
	int flags;			/* RSA_METHOD_FLAG_* things */
	char *app_data;			/* may be needed! */
/* New sign and verify functions: some libraries don't allow arbitrary data
 * to be signed/verified: this allows them to be used. Note: for this to work
 * the RSA_public_decrypt() and RSA_private_encrypt() should *NOT* be used
 * RSA_sign(), RSA_verify() should be used instead. Note: for backwards
 * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
 * option is set in 'flags'.
 */
	int (*rsa_sign)(int type,
		const unsigned char *m, unsigned int m_length,
		unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
	int (*rsa_verify)(int dtype,
		const unsigned char *m, unsigned int m_length,
		unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

	} RSA_METHOD;

struct rsa_st
	{
	/* The first parameter is used to pickup errors where
	 * this is passed instead of aEVP_PKEY, it is set to 0 */
	int pad;
	long version;
	const RSA_METHOD *meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE *engine;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;
	/* be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;
	int references;
	int flags;

	/* Used to cache montgomery values */
	BN_MONT_CTX *_method_mod_n;
	BN_MONT_CTX *_method_mod_p;
	BN_MONT_CTX *_method_mod_q;

	/* all BIGNUM values are actually in the following data, if it is not
	 * NULL */
	char *bignum_data;
	BN_BLINDING *blinding;
	};

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif

#ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
# define OPENSSL_RSA_SMALL_MODULUS_BITS	3072
#endif
#ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
# define OPENSSL_RSA_MAX_PUBEXP_BITS	64 /* exponent limit enforced for "large" modulus only */
#endif

#define RSA_3	0x3L
#define RSA_F4	0x10001L

#define RSA_METHOD_FLAG_NO_CHECK	0x0001 /* don't check pub/private match */

#define RSA_FLAG_CACHE_PUBLIC		0x0002
#define RSA_FLAG_CACHE_PRIVATE		0x0004
#define RSA_FLAG_BLINDING		0x0008
#define RSA_FLAG_THREAD_SAFE		0x0010
/* This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag bn_mod_exp
 * gets called when private key components are absent.
 */
#define RSA_FLAG_EXT_PKEY		0x0020

/* This flag in the RSA_METHOD enables the new rsa_sign, rsa_verify functions.
 */
#define RSA_FLAG_SIGN_VER		0x0040

#define RSA_FLAG_NO_BLINDING		0x0080 /* new with 0.9.6j and 0.9.7b; the built-in
                                                * RSA implementation now uses blinding by
                                                * default (ignoring RSA_FLAG_BLINDING),
                                                * but other engines might not need it
                                                */
#define RSA_FLAG_NO_EXP_CONSTTIME	0x0100 /* new with 0.9.7h; the built-in RSA
                                                * implementation now uses constant time
                                                * modular exponentiation for secret exponents
                                                * by default. This flag causes the
                                                * faster variable sliding window method to
                                                * be used for all exponents.
                                                */

#define RSA_PKCS1_PADDING	1
#define RSA_SSLV23_PADDING	2
#define RSA_NO_PADDING		3
#define RSA_PKCS1_OAEP_PADDING	4
#define RSA_X931_PADDING	5

#define RSA_PKCS1_PADDING_SIZE	11

#define RSA_set_app_data(s,arg)         RSA_set_ex_data(s,0,arg)
#define RSA_get_app_data(s)             RSA_get_ex_data(s,0)

RSA *	RSA_new(void);
RSA *	RSA_new_method(ENGINE *engine);
int	RSA_size(const RSA *);
RSA *	RSA_generate_key(int bits, unsigned long e,void
		(*callback)(int,int,void *),void *cb_arg);
int	RSA_check_key(const RSA *);
#ifdef OPENSSL_FIPS
int RSA_X931_derive(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2,
			void (*cb)(int, int, void *), void *cb_arg,
			const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *Xp,
			const BIGNUM *Xq1, const BIGNUM *Xq2, const BIGNUM *Xq,
			const BIGNUM *e);
RSA *RSA_X931_generate_key(int bits, const BIGNUM *e,
	     void (*cb)(int,int,void *), void *cb_arg);
#endif
	/* next 4 return -1 on error */
int	RSA_public_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
int	RSA_private_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
int	RSA_public_decrypt(int flen, const unsigned char *from, 
		unsigned char *to, RSA *rsa,int padding);
int	RSA_private_decrypt(int flen, const unsigned char *from, 
		unsigned char *to, RSA *rsa,int padding);
void	RSA_free (RSA *r);
/* "up" the RSA object's reference count */
int	RSA_up_ref(RSA *r);

int	RSA_flags(const RSA *r);

void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);

/* This function needs the memory locking malloc callbacks to be installed */
int RSA_memory_lock(RSA *r);

/* these are the actual SSLeay RSA functions */
const RSA_METHOD *RSA_PKCS1_SSLeay(void);

const RSA_METHOD *RSA_null_method(void);

DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

#ifndef OPENSSL_NO_FP_API
int	RSA_print_fp(FILE *fp, const RSA *r,int offset);
#endif

#ifndef OPENSSL_NO_BIO
int	RSA_print(BIO *bp, const RSA *r,int offset);
#endif

int i2d_RSA_NET(const RSA *a, unsigned char **pp, int (*cb)(), int sgckey);
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length, int (*cb)(), int sgckey);

int i2d_Netscape_RSA(const RSA *a, unsigned char **pp, int (*cb)());
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length, int (*cb)());

/* The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption */
int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
	unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

/* The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption */
int RSA_sign_ASN1_OCTET_STRING(int type,
	const unsigned char *m, unsigned int m_length,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
	const unsigned char *m, unsigned int m_length,
	unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);

int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen,
	const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
	const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len,
	const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen,
	const unsigned char *f,int fl,
	const unsigned char *p,int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len,
	const unsigned char *p,int pl);
int RSA_padding_add_SSLv23(unsigned char *to,int tlen,
	const unsigned char *f,int fl);
int RSA_padding_check_SSLv23(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_none(unsigned char *to,int tlen,
	const unsigned char *f,int fl);
int RSA_padding_check_none(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_X931(unsigned char *to,int tlen,
	const unsigned char *f,int fl);
int RSA_padding_check_X931(unsigned char *to,int tlen,
	const unsigned char *f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);

int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
			const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
			const unsigned char *mHash,
			const EVP_MD *Hash, int sLen);

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);

RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_RSA_strings(void);

/* Error codes for the RSA functions. */

/* Function codes. */
#define RSA_F_MEMORY_LOCK				 100
#define RSA_F_RSA_CHECK_KEY				 123
#define RSA_F_RSA_EAY_PRIVATE_DECRYPT			 101
#define RSA_F_RSA_EAY_PRIVATE_ENCRYPT			 102
#define RSA_F_RSA_EAY_PUBLIC_DECRYPT			 103
#define RSA_F_RSA_EAY_PUBLIC_ENCRYPT			 104
#define RSA_F_RSA_GENERATE_KEY				 105
#define RSA_F_RSA_NEW_METHOD				 106
#define RSA_F_RSA_NULL					 124
#define RSA_F_RSA_PADDING_ADD_NONE			 107
#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP		 121
#define RSA_F_RSA_PADDING_ADD_PKCS1_PSS			 125
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1		 108
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2		 109
#define RSA_F_RSA_PADDING_ADD_SSLV23			 110
#define RSA_F_RSA_PADDING_ADD_X931			 127
#define RSA_F_RSA_PADDING_CHECK_NONE			 111
#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP		 122
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1		 112
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2		 113
#define RSA_F_RSA_PADDING_CHECK_SSLV23			 114
#define RSA_F_RSA_PADDING_CHECK_X931			 128
#define RSA_F_RSA_PRINT					 115
#define RSA_F_RSA_PRINT_FP				 116
#define RSA_F_RSA_SIGN					 117
#define RSA_F_RSA_SIGN_ASN1_OCTET_STRING		 118
#define RSA_F_RSA_VERIFY				 119
#define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING		 120
#define RSA_F_RSA_VERIFY_PKCS1_PSS			 126

/* Reason codes. */
#define RSA_R_ALGORITHM_MISMATCH			 100
#define RSA_R_BAD_E_VALUE				 101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT			 102
#define RSA_R_BAD_PAD_BYTE_COUNT			 103
#define RSA_R_BAD_SIGNATURE				 104
#define RSA_R_BLOCK_TYPE_IS_NOT_01			 106
#define RSA_R_BLOCK_TYPE_IS_NOT_02			 107
#define RSA_R_DATA_GREATER_THAN_MOD_LEN			 108
#define RSA_R_DATA_TOO_LARGE				 109
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 110
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS		 132
#define RSA_R_DATA_TOO_SMALL				 111
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE		 122
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY		 112
#define RSA_R_DMP1_NOT_CONGRUENT_TO_D			 124
#define RSA_R_DMQ1_NOT_CONGRUENT_TO_D			 125
#define RSA_R_D_E_NOT_CONGRUENT_TO_1			 123
#define RSA_R_FIRST_OCTET_INVALID			 133
#define RSA_R_INVALID_HEADER				 137
#define RSA_R_INVALID_MESSAGE_LENGTH			 131
#define RSA_R_INVALID_PADDING				 138
#define RSA_R_INVALID_TRAILER				 139
#define RSA_R_IQMP_NOT_INVERSE_OF_Q			 126
#define RSA_R_KEY_SIZE_TOO_SMALL			 120
#define RSA_R_LAST_OCTET_INVALID			 134
#define RSA_R_MODULUS_TOO_LARGE				 105
#define RSA_R_NULL_BEFORE_BLOCK_MISSING			 113
#define RSA_R_N_DOES_NOT_EQUAL_P_Q			 127
#define RSA_R_OAEP_DECODING_ERROR			 121
#define RSA_R_PADDING_CHECK_FAILED			 114
#define RSA_R_P_NOT_PRIME				 128
#define RSA_R_Q_NOT_PRIME				 129
#define RSA_R_RSA_OPERATIONS_NOT_SUPPORTED		 130
#define RSA_R_SLEN_CHECK_FAILED				 136
#define RSA_R_SLEN_RECOVERY_FAILED			 135
#define RSA_R_SSLV3_ROLLBACK_ATTACK			 115
#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 116
#define RSA_R_UNKNOWN_ALGORITHM_TYPE			 117
#define RSA_R_UNKNOWN_PADDING_TYPE			 118
#define RSA_R_WRONG_SIGNATURE_LENGTH			 119

#ifdef  __cplusplus
}
#endif
#endif
