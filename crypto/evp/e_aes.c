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
#include "modes_lcl.h"
#include <openssl/rand.h>

typedef struct
	{
	AES_KEY ks;
	} EVP_AES_KEY;

#if	defined(AES_ASM) && !defined(I386_ONLY) &&	(  \
	((defined(__i386)	|| defined(__i386__)	|| \
	  defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
	defined(__x86_64)	|| defined(__x86_64__)	|| \
	defined(_M_AMD64)	|| defined(_M_X64)	|| \
	defined(__INTEL__)				)

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

void aesni_ctr32_encrypt_blocks(const unsigned char *in,
			   unsigned char *out,
			   size_t blocks,
			   const void *key,
			   const unsigned char *ivec);

extern unsigned int OPENSSL_ia32cap_P[2];
#define	AESNI_CAPABLE	(1<<(57-32))

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	int ret;

	if (((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_ECB_MODE
	    || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CBC_MODE)
	    && !enc) 
		ret = OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
			aesni_set_decrypt_key(key, ctx->key_len*8, ctx->cipher_data):
			AES_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
	else
		ret = OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
			aesni_set_encrypt_key(key, ctx->key_len*8, ctx->cipher_data):
			AES_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);

	if(ret < 0)
		{
		EVPerr(EVP_F_AES_INIT_KEY,EVP_R_AES_KEY_SETUP_FAILED);
		return 0;
		}

	return 1;
	}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	if (OPENSSL_ia32cap_P[1]&AESNI_CAPABLE)
		aesni_cbc_encrypt(in,out,len,ctx->cipher_data,ctx->iv,ctx->encrypt);
	else
		AES_cbc_encrypt(in,out,len,ctx->cipher_data,ctx->iv,ctx->encrypt);

	return 1;
}

static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	size_t	bl = ctx->cipher->block_size;

	if (len<bl)	return 1;

	if (OPENSSL_ia32cap_P[1]&AESNI_CAPABLE)
		aesni_ecb_encrypt(in,out,len,ctx->cipher_data,ctx->encrypt);
	else {
		size_t i;

		if (ctx->encrypt) {
			for (i=0,len-=bl;i<=len;i+=bl)
				AES_encrypt(in+i,out+i,ctx->cipher_data);
		} else {
			for (i=0,len-=bl;i<=len;i+=bl)
				AES_decrypt(in+i,out+i,ctx->cipher_data);
		}
	}

	return 1;
}

static int aes_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_ofb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,
			OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
				(block128_f)aesni_encrypt  :
				(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
				(block128_f)aesni_encrypt  :
				(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_8_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
				(block128_f)aesni_encrypt  :
				(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_1_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			OPENSSL_ia32cap_P[1]&AESNI_CAPABLE ?
				(block128_f)aesni_encrypt  :
				(block128_f)AES_encrypt);
	return 1;
}

static int aes_counter(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	unsigned int num;
	num = ctx->num;

	if (OPENSSL_ia32cap_P[1]&AESNI_CAPABLE)
		CRYPTO_ctr128_encrypt_ctr32(in,out,len,
			ctx->cipher_data,ctx->iv,ctx->buf,&num,
			(ctr128_f)aesni_ctr32_encrypt_blocks);
	else
		CRYPTO_ctr128_encrypt(in,out,len,
			ctx->cipher_data,ctx->iv,ctx->buf,&num,
			(block128_f)AES_encrypt);
	ctx->num = (size_t)num;
	return 1;
}

#define BLOCK_CIPHER_mydef(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE, \
	aes_init_key,aes_##mode##_cipher,NULL,sizeof(EVP_AES_KEY), \
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) { return &aes_##keylen##_##mode; }

#define BLOCK_CIPHER_mydefs(nid,keylen,flags)		\
	BLOCK_CIPHER_mydef(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_mydef(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_mydef(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_mydef(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_mydef(nid,keylen,1,16,cfb1,cfb1,CFB,flags)	\
	BLOCK_CIPHER_mydef(nid,keylen,1,16,cfb8,cfb8,CFB,flags)

BLOCK_CIPHER_mydefs(NID_aes,128,EVP_CIPH_FLAG_FIPS)
BLOCK_CIPHER_mydefs(NID_aes,192,EVP_CIPH_FLAG_FIPS)
BLOCK_CIPHER_mydefs(NID_aes,256,EVP_CIPH_FLAG_FIPS)

#else

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

#endif

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

typedef struct
	{
	/* AES key schedule to use */
	AES_KEY ks;
	/* Set if key initialised */
	int key_set;
	/* Set if an iv is set */
	int iv_set;
	GCM128_CONTEXT gcm;
	/* Temporary IV store */
	unsigned char *iv;
	/* IV length */
	int ivlen;
	int taglen;
	/* It is OK to generate IVs */
	int iv_gen;
	} EVP_AES_GCM_CTX;

static int aes_gcm_cleanup(EVP_CIPHER_CTX *c)
	{
	EVP_AES_GCM_CTX *gctx = c->cipher_data;
	OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
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
		if (FIPS_module_mode() && !(c->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW)
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
		memcpy(c->buf, ptr, arg);
		gctx->taglen = arg;
		return 1;

	case EVP_CTRL_GCM_GET_TAG:
		if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
			return 0;
		memcpy(ptr, c->buf, arg);
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
		CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
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
		CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f)AES_encrypt);
		/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
		if (iv == NULL && gctx->iv_set)
			iv = gctx->iv;
		if (iv)
			{
			CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
			gctx->iv_set = 1;
			}
		gctx->key_set = 1;
		}
	else
		{
		/* If key set use IV, otherwise copy */
		if (gctx->key_set)
			CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
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
			if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
				return -1;
			}
		else if (ctx->encrypt)
			{
			if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
				return -1;
			}
		else
			{
			if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
				return -1;
			}
		return len;
		}
	else
		{
		if (!ctx->encrypt)
			{
			if (CRYPTO_gcm128_finish(&gctx->gcm,
					ctx->buf, gctx->taglen) != 0)
				return -1;
			gctx->iv_set = 0;
			return 0;
			}
		CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
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
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
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
	NID_aes_192_gcm,1,24,12,
	EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
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
	NID_aes_256_gcm,1,32,12,
	EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
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

typedef struct
	{
	/* AES key schedules to use */
	AES_KEY ks1, ks2;
	XTS128_CONTEXT xts;
	} EVP_AES_XTS_CTX;

static int aes_xts_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
	{
	EVP_AES_XTS_CTX *xctx = c->cipher_data;
	if (type != EVP_CTRL_INIT)
		return -1;
	/* key1 and key2 are used as an indicator both key and IV are set */
	xctx->xts.key1 = NULL;
	xctx->xts.key2 = NULL;
	return 1;
	}

static int aes_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
	{
	EVP_AES_XTS_CTX *xctx = ctx->cipher_data;
	if (!iv && !key)
		return 1;

	if (key)
		{
		/* key_len is two AES keys */
		if (enc)
			{
			AES_set_encrypt_key(key, ctx->key_len * 4, &xctx->ks1);
			xctx->xts.block1 = (block128_f)AES_encrypt;
			}
		else
			{
			AES_set_decrypt_key(key, ctx->key_len * 4, &xctx->ks1);
			xctx->xts.block1 = (block128_f)AES_decrypt;
			}

		AES_set_encrypt_key(key + ctx->key_len/2,
						ctx->key_len * 4, &xctx->ks2);
		xctx->xts.block2 = (block128_f)AES_encrypt;

		xctx->xts.key1 = &xctx->ks1;
		}

	if (iv)
		{
		xctx->xts.key2 = &xctx->ks2;
		memcpy(ctx->iv, iv, 16);
		}

	return 1;
	}

static int aes_xts(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_AES_XTS_CTX *xctx = ctx->cipher_data;
	if (!xctx->xts.key1 || !xctx->xts.key2)
		return -1;
	if (!out || !in)
		return -1;
#ifdef OPENSSL_FIPS
	/* Requirement of SP800-38E */
	if (FIPS_module_mode() && !(ctx->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW) &&
			(len > (1L<<20)*16))
		{
		EVPerr(EVP_F_AES_XTS, EVP_R_TOO_LARGE);
		return -1;
		}
#endif
	if (CRYPTO_xts128_encrypt(&xctx->xts, ctx->iv, in, out, len,
								ctx->encrypt))
		return -1;
	return len;
	}

static const EVP_CIPHER aes_128_xts_cipher=
	{
	NID_aes_128_xts,16,32,16,
	EVP_CIPH_XTS_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
	aes_xts_init_key,
	aes_xts,
	0,
	sizeof(EVP_AES_XTS_CTX),
	NULL,
	NULL,
	aes_xts_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_128_xts (void)
{	return &aes_128_xts_cipher;	}
	
static const EVP_CIPHER aes_256_xts_cipher=
	{
	NID_aes_256_xts,16,64,16,
	EVP_CIPH_XTS_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
	aes_xts_init_key,
	aes_xts,
	0,
	sizeof(EVP_AES_XTS_CTX),
	NULL,
	NULL,
	aes_xts_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_256_xts (void)
{	return &aes_256_xts_cipher;	}

typedef struct
	{
	/* AES key schedule to use */
	AES_KEY ks;
	/* Set if key initialised */
	int key_set;
	/* Set if an iv is set */
	int iv_set;
	/* Set if tag is valid */
	int tag_set;
	/* Set if message length set */
	int len_set;
	/* L and M parameters from RFC3610 */
	int L, M;
	CCM128_CONTEXT ccm;
	} EVP_AES_CCM_CTX;

static int aes_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
	{
	EVP_AES_CCM_CTX *cctx = c->cipher_data;
	switch (type)
		{
	case EVP_CTRL_INIT:
		cctx->key_set = 0;
		cctx->iv_set = 0;
		cctx->L = 8;
		cctx->M = 12;
		cctx->tag_set = 0;
		cctx->len_set = 0;
		return 1;

	case EVP_CTRL_CCM_SET_IVLEN:
		arg = 15 - arg;
	case EVP_CTRL_CCM_SET_L:
		if (arg < 2 || arg > 8)
			return 0;
		cctx->L = arg;
		return 1;

	case EVP_CTRL_CCM_SET_TAG:
		if ((arg & 1) || arg < 4 || arg > 16)
			return 0;
		if ((c->encrypt && ptr) || (!c->encrypt && !ptr))
			return 0;
		if (ptr)
			{
			cctx->tag_set = 1;
			memcpy(c->buf, ptr, arg);
			}
		cctx->M = arg;
		return 1;

	case EVP_CTRL_CCM_GET_TAG:
		if (!c->encrypt || !cctx->tag_set)
			return 0;
		if(!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
			return 0;
		cctx->tag_set = 0;
		cctx->iv_set = 0;
		cctx->len_set = 0;
		return 1;

	default:
		return -1;

		}
	}

static int aes_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
	{
	EVP_AES_CCM_CTX *cctx = ctx->cipher_data;
	if (!iv && !key)
		return 1;
	if (key)
		{
		AES_set_encrypt_key(key, ctx->key_len * 8, &cctx->ks);
		CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
					&cctx->ks, (block128_f)AES_encrypt);
		cctx->key_set = 1;
		}
	if (iv)
		{
		memcpy(ctx->iv, iv, 15 - cctx->L);
		cctx->iv_set = 1;
		}
	return 1;
	}

static int aes_ccm(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_AES_CCM_CTX *cctx = ctx->cipher_data;
	CCM128_CONTEXT *ccm = &cctx->ccm;
	/* If not set up, return error */
	if (!cctx->iv_set && !cctx->key_set)
		return -1;
	if (!ctx->encrypt && !cctx->tag_set)
		return -1;
	if (!out)
		{
		if (!in)
			{
			if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L,len))
				return -1;
			cctx->len_set = 1;
			return len;
			}
		/* If have AAD need message length */
		if (!cctx->len_set && len)
			return -1;
		CRYPTO_ccm128_aad(ccm, in, len);
		return len;
		}
	/* EVP_*Final() doesn't return any data */
	if (!in)
		return 0;
	/* If not set length yet do it */
	if (!cctx->len_set)
		{
		if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L, len))
			return -1;
		cctx->len_set = 1;
		}
	if (ctx->encrypt)
		{
		if (CRYPTO_ccm128_encrypt(ccm, in, out, len))
			return -1;
		cctx->tag_set = 1;
		return len;
		}
	else
		{
		int rv = -1;
		if (!CRYPTO_ccm128_decrypt(ccm, in, out, len))
			{
			unsigned char tag[16];
			if (CRYPTO_ccm128_tag(ccm, tag, cctx->M))
				{
				if (!memcmp(tag, ctx->buf, cctx->M))
					rv = len;
				}
			}
		if (rv == -1)
			OPENSSL_cleanse(out, len);
		cctx->iv_set = 0;
		cctx->tag_set = 0;
		cctx->len_set = 0;
		return rv;
		}

	}

static const EVP_CIPHER aes_128_ccm_cipher=
	{
	NID_aes_128_ccm,1,16,12,
	EVP_CIPH_CCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
	aes_ccm_init_key,
	aes_ccm,
	0,
	sizeof(EVP_AES_CCM_CTX),
	NULL,
	NULL,
	aes_ccm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_128_ccm (void)
{	return &aes_128_ccm_cipher;	}

static const EVP_CIPHER aes_192_ccm_cipher=
	{
	NID_aes_192_ccm,1,24,12,
	EVP_CIPH_CCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
	aes_ccm_init_key,
	aes_ccm,
	0,
	sizeof(EVP_AES_CCM_CTX),
	NULL,
	NULL,
	aes_ccm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_192_ccm (void)
{	return &aes_192_ccm_cipher;	}

static const EVP_CIPHER aes_256_ccm_cipher=
	{
	NID_aes_256_ccm,1,32,12,
	EVP_CIPH_CCM_MODE|EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_DEFAULT_ASN1
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT,
	aes_ccm_init_key,
	aes_ccm,
	0,
	sizeof(EVP_AES_CCM_CTX),
	NULL,
	NULL,
	aes_ccm_ctrl,
	NULL
	};

const EVP_CIPHER *EVP_aes_256_ccm (void)
{	return &aes_256_ccm_cipher;	}

#endif
