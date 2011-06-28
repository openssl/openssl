/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
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

typedef struct
	{
	AES_KEY ks;
	} EVP_AES_KEY;

#define MAXBITCHUNK	((size_t)1<<(sizeof(size_t)*8-4))

#if	defined(AES_ASM) && !defined(I386_ONLY) &&	(  \
	((defined(__i386)	|| defined(__i386__)	|| \
	  defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
	defined(__x86_64)	|| defined(__x86_64__)	|| \
	defined(_M_AMD64)	|| defined(_M_X64)	|| \
	defined(__INTEL__)				)
/*
 * AES-NI section
 */
extern unsigned int OPENSSL_ia32cap_P[2];
#define	AESNI_CAPABLE	(1<<(57-32))

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

static int aesni_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	int ret;

	if (((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_ECB_MODE
	    || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CBC_MODE)
	    && !enc) 
		ret = aesni_set_decrypt_key(key, ctx->key_len*8, ctx->cipher_data);
	else
		ret = aesni_set_encrypt_key(key, ctx->key_len*8, ctx->cipher_data);

	if(ret < 0)
		{
		EVPerr(EVP_F_AES_INIT_KEY,EVP_R_AES_KEY_SETUP_FAILED);
		return 0;
		}

	return 1;
	}

static int aesni_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	aesni_cbc_encrypt(in,out,len,ctx->cipher_data,ctx->iv,ctx->encrypt);

	return 1;
}

static int aesni_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	size_t	bl = ctx->cipher->block_size;

	if (len<bl)	return 1;

	aesni_ecb_encrypt(in,out,len,ctx->cipher_data,ctx->encrypt);

	return 1;
}

static int aesni_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_ofb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,
			(block128_f)aesni_encrypt);
	return 1;
}

static int aesni_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)aesni_encrypt);
	return 1;
}

static int aesni_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_8_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)aesni_encrypt);
	return 1;
}

static int aesni_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	if (ctx->flags&EVP_CIPH_FLAG_LENGTH_BITS) {
		CRYPTO_cfb128_1_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)aesni_encrypt);
		return 1;
	}

	while (len>=MAXBITCHUNK) {
		CRYPTO_cfb128_1_encrypt(in,out,MAXBITCHUNK*8,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)aesni_encrypt);
		len-=MAXBITCHUNK;
	}
	if (len)
		CRYPTO_cfb128_1_encrypt(in,out,len*8,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)aesni_encrypt);
	
	return 1;
}

static int aesni_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	unsigned int num;
	num = ctx->num;

	CRYPTO_ctr128_encrypt_ctr32(in,out,len,
			ctx->cipher_data,ctx->iv,ctx->buf,&num,
			(ctr128_f)aesni_ctr32_encrypt_blocks);

	ctx->num = (size_t)num;
	return 1;
}

#define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aesni_init_key,			\
	aesni_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,	\
	keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_init_key,			\
	aes_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return (OPENSSL_ia32cap_P[1]&AESNI_CAPABLE)? \
  &aesni_##keylen##_##mode:&aes_##keylen##_##mode; }

#else

#define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_init_key,			\
	aes_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }
#endif

#define BLOCK_CIPHER_generic_pack(nid,keylen,flags)		\
	BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ctr,ctr,CTR,flags)

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	int ret;

	if (((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_ECB_MODE
	    || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CBC_MODE)
	    && !enc) 
		ret = AES_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
	else
		ret = AES_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);

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
	AES_cbc_encrypt(in,out,len,ctx->cipher_data,ctx->iv,ctx->encrypt);

	return 1;
}

static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	size_t	bl = ctx->cipher->block_size;
	size_t	i;

	if (len<bl)	return 1;

	if (ctx->encrypt) {
		for (i=0,len-=bl;i<=len;i+=bl)
			AES_encrypt(in+i,out+i,ctx->cipher_data);
	} else {
		for (i=0,len-=bl;i<=len;i+=bl)
			AES_decrypt(in+i,out+i,ctx->cipher_data);
	}

	return 1;
}

static int aes_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_ofb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,
			(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	CRYPTO_cfb128_8_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)AES_encrypt);
	return 1;
}

static int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	if (ctx->flags&EVP_CIPH_FLAG_LENGTH_BITS) {
		CRYPTO_cfb128_1_encrypt(in,out,len,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)AES_encrypt);
		return 1;
	}

	while (len>=MAXBITCHUNK) {
		CRYPTO_cfb128_1_encrypt(in,out,MAXBITCHUNK*8,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)AES_encrypt);
		len-=MAXBITCHUNK;
	}
	if (len)
		CRYPTO_cfb128_1_encrypt(in,out,len*8,ctx->cipher_data,
			ctx->iv,&ctx->num,ctx->encrypt,
			(block128_f)AES_encrypt);
	
	return 1;
}

static int aes_ctr_cipher (EVP_CIPHER_CTX *ctx, unsigned char *out,
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

BLOCK_CIPHER_generic_pack(NID_aes,128,0)
BLOCK_CIPHER_generic_pack(NID_aes,192,0)
BLOCK_CIPHER_generic_pack(NID_aes,256,0)

#endif
#endif
