/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 */

#define OPENSSL_FIPSAPI

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_AES
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "evp_locl.h"
#include <openssl/modes.h>
#include <openssl/rand.h>

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
					const unsigned char *iv, int enc);

typedef struct
	{
	AES_KEY ks;
	} EVP_AES_KEY;

#define data(ctx)	EVP_C_DATA(EVP_AES_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(aes_128, ks, AES, EVP_AES_KEY,
		       NID_aes_128, 16, 16, 16, 128,
		       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
		       aes_init_key, NULL, NULL, NULL, NULL)
IMPLEMENT_BLOCK_CIPHER(aes_192, ks, AES, EVP_AES_KEY,
		       NID_aes_192, 16, 24, 16, 128,
		       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
		       aes_init_key, NULL, NULL, NULL, NULL)
IMPLEMENT_BLOCK_CIPHER(aes_256, ks, AES, EVP_AES_KEY,
		       NID_aes_256, 16, 32, 16, 128,
		       EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1,
		       aes_init_key, NULL, NULL, NULL, NULL)

#define IMPLEMENT_AES_CFBR(ksize,cbits)	IMPLEMENT_CFBR(aes,AES,EVP_AES_KEY,ks,ksize,cbits,16,EVP_CIPH_FLAG_FIPS)

IMPLEMENT_AES_CFBR(128,1)
IMPLEMENT_AES_CFBR(192,1)
IMPLEMENT_AES_CFBR(256,1)

IMPLEMENT_AES_CFBR(128,8)
IMPLEMENT_AES_CFBR(192,8)
IMPLEMENT_AES_CFBR(256,8)

static int aes_counter (EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	unsigned int num;
	num = ctx->num;
#ifdef AES_CTR_ASM
	void AES_ctr32_encrypt(const unsigned char *in, unsigned char *out,
			size_t blocks, const AES_KEY *key,
			const unsigned char ivec[AES_BLOCK_SIZE]);

	CRYPTO_ctr128_encrypt_ctr32(in,out,len,
		&((EVP_AES_KEY *)ctx->cipher_data)->ks,
		ctx->iv,ctx->buf,&num,(ctr128_f)AES_ctr32_encrypt);
#else
	CRYPTO_ctr128_encrypt(in,out,len,
		&((EVP_AES_KEY *)ctx->cipher_data)->ks,
		ctx->iv,ctx->buf,&num,(block128_f)AES_encrypt);
#endif
	ctx->num = (size_t)num;
	return 1;
}

static const EVP_CIPHER aes_128_ctr_cipher=
	{
	NID_aes_128_ctr,1,16,16,
	EVP_CIPH_CTR_MODE|EVP_CIPH_FLAG_FIPS,
	aes_init_key,
	aes_counter,
	NULL,
	sizeof(EVP_AES_KEY),
	NULL,
	NULL,
	NULL,
	NULL
	};

const EVP_CIPHER *EVP_aes_128_ctr (void)
{	return &aes_128_ctr_cipher;	}

static const EVP_CIPHER aes_192_ctr_cipher=
	{
	NID_aes_192_ctr,1,24,16,
	EVP_CIPH_CTR_MODE|EVP_CIPH_FLAG_FIPS,
	aes_init_key,
	aes_counter,
	NULL,
	sizeof(EVP_AES_KEY),
	NULL,
	NULL,
	NULL,
	NULL
	};

const EVP_CIPHER *EVP_aes_192_ctr (void)
{	return &aes_192_ctr_cipher;	}

static const EVP_CIPHER aes_256_ctr_cipher=
	{
	NID_aes_256_ctr,1,32,16,
	EVP_CIPH_CTR_MODE|EVP_CIPH_FLAG_FIPS,
	aes_init_key,
	aes_counter,
	NULL,
	sizeof(EVP_AES_KEY),
	NULL,
	NULL,
	NULL,
	NULL
	};

const EVP_CIPHER *EVP_aes_256_ctr (void)
{	return &aes_256_ctr_cipher;	}

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	int ret;

	if (((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_ECB_MODE
	    || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CBC_MODE)
	    && !enc) 
		ret=AES_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
	else
		ret=AES_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);

	if(ret < 0)
		{
		EVPerr(EVP_F_AES_INIT_KEY,EVP_R_AES_KEY_SETUP_FAILED);
		return 0;
		}

	return 1;
	}

typedef struct
	{
	/* AES key schedule to use */
	AES_KEY ks;
	/* Set if key initialised */
	int key_set;
	/* Set if an iv is set */
	int iv_set;
	/* Pointer to GCM128_CTX: FIXME actual structure later */
	GCM128_CONTEXT *gcm;
	/* Temporary IV store */
	unsigned char *iv;
	/* IV length */
	int ivlen;
	/* Tag to verify */
	unsigned char tag[16];
	int taglen;
	/* It is OK to generate IVs */
	int iv_gen;
	} EVP_AES_GCM_CTX;

static int aes_gcm_cleanup(EVP_CIPHER_CTX *c)
	{
	EVP_AES_GCM_CTX *gctx = c->cipher_data;
	if (gctx->gcm)
		CRYPTO_gcm128_release(gctx->gcm);
	if (gctx->iv != c->iv)
		OPENSSL_free(gctx->iv);
	return 1;
	}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter) {
	int n=8;
	unsigned char  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

static int aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
	{
	EVP_AES_GCM_CTX *gctx = c->cipher_data;
	switch (type)
		{
	case EVP_CTRL_INIT:
		gctx->gcm = NULL;
		gctx->key_set = 0;
		gctx->iv_set = 0;
		gctx->ivlen = c->cipher->iv_len;
		gctx->iv = c->iv;
		gctx->taglen = -1;
		gctx->iv_gen = 0;
		return 1;

	case EVP_CTRL_GCM_SET_IVLEN:
		if (arg <= 0)
			return 0;
#ifdef OPENSSL_FIPS
		if (FIPS_mode() && !(c->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW)
						 && arg < 12)
			return 0;
#endif
		/* Allocate memory for IV if needed */
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen))
			{
			if (gctx->iv != c->iv)
				OPENSSL_free(gctx->iv);
			gctx->iv = OPENSSL_malloc(arg);
			if (!gctx->iv)
				return 0;
			}
		gctx->ivlen = arg;
		return 1;

	case EVP_CTRL_GCM_SET_TAG:
		if (arg <= 0 || arg > 16 || c->encrypt)
			return 0;
		memcpy(gctx->tag, ptr, arg);
		gctx->taglen = arg;
		return 1;

	case EVP_CTRL_GCM_GET_TAG:
		if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
			return 0;
		memcpy(ptr, gctx->tag, arg);
		return 1;

	case EVP_CTRL_GCM_SET_IV_FIXED:
		/* Special case: -1 length restores whole IV */
		if (arg == -1)
			{
			memcpy(gctx->iv, ptr, gctx->ivlen);
			gctx->iv_gen = 1;
			return 1;
			}
		/* Fixed field must be at least 4 bytes and invocation field
		 * at least 8.
		 */
		if ((arg < 4) || (gctx->ivlen - arg) < 8)
			return 0;
		if (arg)
			memcpy(gctx->iv, ptr, arg);
		if (RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
			return 0;
		gctx->iv_gen = 1;
		return 1;

	case EVP_CTRL_GCM_IV_GEN:
		if (gctx->iv_gen == 0 || gctx->key_set == 0)
			return 0;
		CRYPTO_gcm128_setiv(gctx->gcm, gctx->iv, gctx->ivlen);
		memcpy(ptr, gctx->iv, gctx->ivlen);
		/* Invocation field will be at least 8 bytes in size and
		 * so no need to check wrap around or increment more than
		 * last 8 bytes.
		 */
		ctr64_inc(gctx->iv + gctx->ivlen - 8);
		gctx->iv_set = 1;
		return 1;

	default:
		return -1;

		}
	}

static int aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
	{
	EVP_AES_GCM_CTX *gctx = ctx->cipher_data;
	if (!iv && !key)
		return 1;
	if (key)
		{
		AES_set_encrypt_key(key, ctx->key_len * 8, &gctx->ks);
		if (!gctx->gcm)
			{
			gctx->gcm =
				CRYPTO_gcm128_new(&gctx->ks, (block128_f)AES_encrypt);
			if (!gctx->gcm)
				return 0;
			}
		else
			CRYPTO_gcm128_init(gctx->gcm, &gctx->ks, (block128_f)AES_encrypt);
		/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
		if (iv == NULL && gctx->iv_set)
			iv = gctx->iv;
		if (iv)
			{
			CRYPTO_gcm128_setiv(gctx->gcm, iv, gctx->ivlen);
			gctx->iv_set = 1;
			}
		gctx->key_set = 1;
		}
	else
		{
		/* If key set use IV, otherwise copy */
		if (gctx->key_set)
			CRYPTO_gcm128_setiv(gctx->gcm, iv, gctx->ivlen);
		else
			memcpy(gctx->iv, iv, gctx->ivlen);
		gctx->iv_set = 1;
		gctx->iv_gen = 0;
		}
	return 1;
	}

static int aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_AES_GCM_CTX *gctx = ctx->cipher_data;
	/* If not set up, return error */
	if (!gctx->iv_set && !gctx->key_set)
		return -1;
	if (!ctx->encrypt && gctx->taglen < 0)
		return -1;
	if (in)
		{
		if (out == NULL)
			{
			if (CRYPTO_gcm128_aad(gctx->gcm, in, len))
				return -1;
			}
		else if (ctx->encrypt)
			{
			if (CRYPTO_gcm128_encrypt(gctx->gcm, in, out, len))
				return -1;
			}
		else
			{
			if (CRYPTO_gcm128_decrypt(gctx->gcm, in, out, len))
				return -1;
			}
		return len;
		}
	else
		{
		if (!ctx->encrypt)
			{
			if (CRYPTO_gcm128_finish(gctx->gcm,
					gctx->tag, gctx->taglen) != 0)
				return -1;
			gctx->iv_set = 0;
			return 0;
			}
		CRYPTO_gcm128_tag(gctx->gcm, gctx->tag, 16);
		gctx->taglen = 16;
		/* Don't reuse the IV */
		gctx->iv_set = 0;
		return 0;
		}

	}

static const EVP_CIPHER aes_128_gcm_cipher=
	{
	NID_aes_128_gcm,1,16,12,
	EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
		| EVP_CIPH_FLAG_FIPS,
	aes_gcm_init_key,
	aes_gcm,
	aes_gcm_cleanup,
	sizeof(EVP_AES_GCM_CTX),
	NULL,
	NULL,
	aes_gcm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_128_gcm (void)
{	return &aes_128_gcm_cipher;	}

static const EVP_CIPHER aes_192_gcm_cipher=
	{
	NID_aes_128_gcm,1,24,12,
	EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
		| EVP_CIPH_FLAG_FIPS,
	aes_gcm_init_key,
	aes_gcm,
	aes_gcm_cleanup,
	sizeof(EVP_AES_GCM_CTX),
	NULL,
	NULL,
	aes_gcm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_192_gcm (void)
{	return &aes_192_gcm_cipher;	}

static const EVP_CIPHER aes_256_gcm_cipher=
	{
	NID_aes_128_gcm,1,32,12,
	EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
		| EVP_CIPH_FLAG_FIPS,
	aes_gcm_init_key,
	aes_gcm,
	aes_gcm_cleanup,
	sizeof(EVP_AES_GCM_CTX),
	NULL,
	NULL,
	aes_gcm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_256_gcm (void)
{	return &aes_256_gcm_cipher;	}
		
#endif
