/*
 * Support for Intel AES-NI intruction set
 *   Author: Huang Ying <ying.huang@intel.com>
 *
 * Intel AES-NI is a new set of Single Instruction Multiple Data
 * (SIMD) instructions that are going to be introduced in the next
 * generation of Intel processor, as of 2009. These instructions
 * enable fast and secure data encryption and decryption, using the
 * Advanced Encryption Standard (AES), defined by FIPS Publication
 * number 197.  The architecture introduces six instructions that
 * offer full hardware support for AES. Four of them support high
 * performance data encryption and decryption, and the other two
 * instructions support the AES key expansion procedure.
 *
 * The white paper can be downloaded from:
 *   http://softwarecommunity.intel.com/isn/downloads/intelavx/AES-Instructions-Set_WP.pdf
 *
 * This file is based on engines/e_padlock.c
 */

/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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


#include <openssl/opensslconf.h>

#if !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_AES_NI) && !defined(OPENSSL_NO_AES)

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/modes.h>

/* AES-NI is available *ONLY* on some x86 CPUs.  Not only that it
   doesn't exist elsewhere, but it even can't be compiled on other
   platforms! */
#undef COMPILE_HW_AESNI
#if (defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined(_M_X64) || \
     defined(OPENSSL_IA32_SSE2)) && !defined(OPENSSL_NO_ASM)
#define COMPILE_HW_AESNI
static ENGINE *ENGINE_aesni (void);
#endif

void ENGINE_load_aesni (void)
{
/* On non-x86 CPUs it just returns. */
#ifdef COMPILE_HW_AESNI
	ENGINE *toadd = ENGINE_aesni();
	if (!toadd)
		return;
	ENGINE_add (toadd);
	ENGINE_free (toadd);
	ERR_clear_error ();
#endif
}

#ifdef COMPILE_HW_AESNI
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in,
			   unsigned char *out,
			   size_t length,
			   const AES_KEY *key,
			   int enc);
void aesni_cbc_encrypt(const unsigned char *in,
			   unsigned char *out,
			   size_t length,
			   const AES_KEY *key,
			   unsigned char *ivec, int enc);

/* Function for ENGINE detection and control */
static int aesni_init(ENGINE *e);

/* Cipher Stuff */
static int aesni_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
				const int **nids, int nid);

#define AESNI_MIN_ALIGN	16
#define AESNI_ALIGN(x) \
	((void *)(((unsigned long)(x)+AESNI_MIN_ALIGN-1)&~(AESNI_MIN_ALIGN-1)))

/* Engine names */
static const char   aesni_id[] = "aesni",
		    aesni_name[] = "Intel AES-NI engine",
		    no_aesni_name[] = "Intel AES-NI engine (no-aesni)";

/* ===== Engine "management" functions ===== */

/* Prepare the ENGINE structure for registration */
static int
aesni_bind_helper(ENGINE *e)
{
	int engage = (OPENSSL_ia32cap_P[1] & (1 << (57-32))) != 0;

	/* Register everything or return with an error */
	if (!ENGINE_set_id(e, aesni_id) ||
	    !ENGINE_set_name(e, engage ? aesni_name : no_aesni_name) ||

	    !ENGINE_set_init_function(e, aesni_init) ||
	    (engage && !ENGINE_set_ciphers (e, aesni_ciphers))
	    )
		return 0;

	/* Everything looks good */
	return 1;
}

/* Constructor */
static ENGINE *
ENGINE_aesni(void)
{
	ENGINE *eng = ENGINE_new();

	if (!eng) {
		return NULL;
	}

	if (!aesni_bind_helper(eng)) {
		ENGINE_free(eng);
		return NULL;
	}

	return eng;
}

/* Check availability of the engine */
static int
aesni_init(ENGINE *e)
{
	return 1;
}

#if defined(NID_aes_128_cfb128) && ! defined (NID_aes_128_cfb)
#define NID_aes_128_cfb	NID_aes_128_cfb128
#endif

#if defined(NID_aes_128_ofb128) && ! defined (NID_aes_128_ofb)
#define NID_aes_128_ofb	NID_aes_128_ofb128
#endif

#if defined(NID_aes_192_cfb128) && ! defined (NID_aes_192_cfb)
#define NID_aes_192_cfb	NID_aes_192_cfb128
#endif

#if defined(NID_aes_192_ofb128) && ! defined (NID_aes_192_ofb)
#define NID_aes_192_ofb	NID_aes_192_ofb128
#endif

#if defined(NID_aes_256_cfb128) && ! defined (NID_aes_256_cfb)
#define NID_aes_256_cfb	NID_aes_256_cfb128
#endif

#if defined(NID_aes_256_ofb128) && ! defined (NID_aes_256_ofb)
#define NID_aes_256_ofb	NID_aes_256_ofb128
#endif

/* List of supported ciphers. */
static int aesni_cipher_nids[] = {
	NID_aes_128_ecb,
	NID_aes_128_cbc,
	NID_aes_128_cfb,
	NID_aes_128_ofb,

	NID_aes_192_ecb,
	NID_aes_192_cbc,
	NID_aes_192_cfb,
	NID_aes_192_ofb,

	NID_aes_256_ecb,
	NID_aes_256_cbc,
	NID_aes_256_cfb,
	NID_aes_256_ofb,
};
static int aesni_cipher_nids_num =
	(sizeof(aesni_cipher_nids)/sizeof(aesni_cipher_nids[0]));

typedef struct
{
	AES_KEY ks;
	unsigned int _pad1[3];
} AESNI_KEY;

static int
aesni_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *user_key,
		    const unsigned char *iv, int enc)
{
	int ret;
	AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

	if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE
	    || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE
	    || enc)
		ret=aesni_set_encrypt_key(user_key, ctx->key_len * 8, key);
	else
		ret=aesni_set_decrypt_key(user_key, ctx->key_len * 8, key);

	if(ret < 0) {
		EVPerr(EVP_F_AESNI_INIT_KEY,EVP_R_AES_KEY_SETUP_FAILED);
		return 0;
	}

	return 1;
}

static int aesni_cipher_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
		 const unsigned char *in, size_t inl)
{	AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);
	aesni_ecb_encrypt(in, out, inl, key, ctx->encrypt);
	return 1;
}
static int aesni_cipher_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out,
		 const unsigned char *in, size_t inl)
{	AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);
	aesni_cbc_encrypt(in, out, inl, key,
			      ctx->iv, ctx->encrypt);
	return 1;
}
static int aesni_cipher_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
		 const unsigned char *in, size_t inl)
{	AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);
	CRYPTO_cfb128_encrypt(in, out, inl, key, ctx->iv,
				&ctx->num, ctx->encrypt,
				(block128_f)aesni_encrypt);
	return 1;
}
static int aesni_cipher_ofb(EVP_CIPHER_CTX *ctx, unsigned char *out,
		 const unsigned char *in, size_t inl)
{	AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);
	CRYPTO_ofb128_encrypt(in, out, inl, key, ctx->iv,
				&ctx->num, (block128_f)aesni_encrypt);
	return 1;
}

#define AES_BLOCK_SIZE		16

#define EVP_CIPHER_block_size_ECB	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_OFB	1
#define EVP_CIPHER_block_size_CFB	1

/* Declaring so many ciphers by hand would be a pain.
   Instead introduce a bit of preprocessor magic :-) */
#define	DECLARE_AES_EVP(ksize,lmode,umode)	\
static const EVP_CIPHER aesni_##ksize##_##lmode = {	\
	NID_aes_##ksize##_##lmode,			\
	EVP_CIPHER_block_size_##umode,			\
	ksize / 8,					\
	AES_BLOCK_SIZE,					\
	0 | EVP_CIPH_##umode##_MODE,			\
	aesni_init_key,				\
	aesni_cipher_##lmode,				\
	NULL,						\
	sizeof(AESNI_KEY),				\
	EVP_CIPHER_set_asn1_iv,				\
	EVP_CIPHER_get_asn1_iv,				\
	NULL,						\
	NULL						\
}

DECLARE_AES_EVP(128,ecb,ECB);
DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(128,cfb,CFB);
DECLARE_AES_EVP(128,ofb,OFB);

DECLARE_AES_EVP(192,ecb,ECB);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(192,cfb,CFB);
DECLARE_AES_EVP(192,ofb,OFB);

DECLARE_AES_EVP(256,ecb,ECB);
DECLARE_AES_EVP(256,cbc,CBC);
DECLARE_AES_EVP(256,cfb,CFB);
DECLARE_AES_EVP(256,ofb,OFB);

static int
aesni_ciphers (ENGINE *e, const EVP_CIPHER **cipher,
		      const int **nids, int nid)
{
	/* No specific cipher => return a list of supported nids ... */
	if (!cipher) {
		*nids = aesni_cipher_nids;
		return aesni_cipher_nids_num;
	}

	/* ... or the requested "cipher" otherwise */
	switch (nid) {
	case NID_aes_128_ecb:
		*cipher = &aesni_128_ecb;
		break;
	case NID_aes_128_cbc:
		*cipher = &aesni_128_cbc;
		break;
	case NID_aes_128_cfb:
		*cipher = &aesni_128_cfb;
		break;
	case NID_aes_128_ofb:
		*cipher = &aesni_128_ofb;
		break;

	case NID_aes_192_ecb:
		*cipher = &aesni_192_ecb;
		break;
	case NID_aes_192_cbc:
		*cipher = &aesni_192_cbc;
		break;
	case NID_aes_192_cfb:
		*cipher = &aesni_192_cfb;
		break;
	case NID_aes_192_ofb:
		*cipher = &aesni_192_ofb;
		break;

	case NID_aes_256_ecb:
		*cipher = &aesni_256_ecb;
		break;
	case NID_aes_256_cbc:
		*cipher = &aesni_256_cbc;
		break;
	case NID_aes_256_cfb:
		*cipher = &aesni_256_cfb;
		break;
	case NID_aes_256_ofb:
		*cipher = &aesni_256_ofb;
		break;

	default:
		/* Sorry, we don't support this NID */
		*cipher = NULL;
		return 0;
	}

	return 1;
}

#endif /* COMPILE_HW_AESNI */
#endif /* !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_AESNI) && !defined(OPENSSL_NO_AES) */
