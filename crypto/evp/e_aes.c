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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_AES
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "evp_locl.h"

#ifndef OPENSSL_FIPS

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
					const unsigned char *iv, int enc);

typedef struct
	{
	AES_KEY ks;
	} EVP_AES_KEY;

#define data(ctx)	EVP_C_DATA(EVP_AES_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(aes_128, ks, AES, EVP_AES_KEY,
		       NID_aes_128, 16, 16, 16, 128,
		       0, aes_init_key, NULL, 
		       EVP_CIPHER_set_asn1_iv,
		       EVP_CIPHER_get_asn1_iv,
		       NULL)
IMPLEMENT_BLOCK_CIPHER(aes_192, ks, AES, EVP_AES_KEY,
		       NID_aes_192, 16, 24, 16, 128,
		       0, aes_init_key, NULL, 
		       EVP_CIPHER_set_asn1_iv,
		       EVP_CIPHER_get_asn1_iv,
		       NULL)
IMPLEMENT_BLOCK_CIPHER(aes_256, ks, AES, EVP_AES_KEY,
		       NID_aes_256, 16, 32, 16, 128,
		       0, aes_init_key, NULL, 
		       EVP_CIPHER_set_asn1_iv,
		       EVP_CIPHER_get_asn1_iv,
		       NULL)

#define IMPLEMENT_AES_CFBR(ksize,cbits)	IMPLEMENT_CFBR(aes,AES,EVP_AES_KEY,ks,ksize,cbits,16)

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
	EVP_CIPH_CTR_MODE,
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
	EVP_CIPH_CTR_MODE,
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
	EVP_CIPH_CTR_MODE,
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

#endif

#endif
