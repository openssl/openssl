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

#ifndef OPENSSL_NO_AES
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/rijndael.h>

static int aes_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
					const unsigned char *iv, int enc);
static int aes_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, unsigned int inl);
static int aes_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, unsigned int inl);

#define IMPLEMENT_AES_CIPHER(name, ciph_func, keylen, ivlen, mode) \
static const EVP_CIPHER name##_cipher_st = \
	{ \
	NID_##name, \
	16,keylen,ivlen, \
	mode, \
	aes_init, \
	ciph_func, \
	NULL, \
	sizeof(RIJNDAEL_KEY), \
	EVP_CIPHER_set_asn1_iv, \
	EVP_CIPHER_get_asn1_iv, \
	NULL, \
	NULL \
	}; \
const EVP_CIPHER * EVP_##name(void) \
	{ \
	return &name##_cipher_st; \
	}

IMPLEMENT_AES_CIPHER(aes_128_ecb, aes_ecb, 16, 0, EVP_CIPH_ECB_MODE)
IMPLEMENT_AES_CIPHER(aes_192_ecb, aes_ecb, 24, 0, EVP_CIPH_ECB_MODE)
IMPLEMENT_AES_CIPHER(aes_256_ecb, aes_ecb, 32, 0, EVP_CIPH_ECB_MODE)

IMPLEMENT_AES_CIPHER(aes_128_cbc, aes_cbc, 16, 16, EVP_CIPH_CBC_MODE)
IMPLEMENT_AES_CIPHER(aes_192_cbc, aes_cbc, 24, 24, EVP_CIPH_CBC_MODE)
IMPLEMENT_AES_CIPHER(aes_256_cbc, aes_cbc, 32, 32, EVP_CIPH_CBC_MODE)

static int aes_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	RIJNDAEL_KEY *k=ctx->cipher_data;
	if (enc) 
		k->rounds = rijndaelKeySetupEnc(k->rd_key, key, ctx->key_len * 8);
	else
		k->rounds = rijndaelKeySetupDec(k->rd_key, key, ctx->key_len * 8);

	return 1;
	}

static int aes_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 const unsigned char *in, unsigned int inl)
	{
	RIJNDAEL_KEY *k=ctx->cipher_data;
	while(inl > 0)
		{
		if(ctx->encrypt)
	    		rijndaelEncrypt(k->rd_key,k->rounds, in, out);
		else
	    		rijndaelDecrypt(k->rd_key,k->rounds, in, out);
		inl-=16;
		in+=16;
		out+=16;
		}
	assert(inl == 0);

	return 1;
	}

static int aes_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 const unsigned char *in, unsigned int inl)
	{
	int n;
	unsigned char tmp[16];
	RIJNDAEL_KEY *k=ctx->cipher_data;
	while(inl > 0)
		{
		if(ctx->encrypt)
			{
			for(n=0 ; n < 16 ; n++)
				tmp[n] = in[n] ^ ctx->iv[n];
			rijndaelEncrypt(k->rd_key,k->rounds, tmp, out);
			memcpy(ctx->iv,out,16);
			}
		else
			{
			memcpy(tmp, in, 16);
			rijndaelDecrypt(k->rd_key,k->rounds, in, out);
			for(n=0 ; n < 16 ; n++)
				out[n] ^= ctx->iv[n];
			memcpy(ctx->iv,tmp,16);
			}
		inl-=16;
		in+=16;
		out+=16;
		}
	assert(inl == 0);
	return 1;
	}
#endif
