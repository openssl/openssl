/* crypto/evp/e_des3.c */
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

#ifndef NO_DES
#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"

static int des_ede_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv,int enc);

static int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			     const unsigned char *iv,int enc);

/* Because of various casts and different args can't use IMPLEMENT_BLOCK_CIPHER */

static int des_ede_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			      const unsigned char *in, unsigned int inl)
{
	BLOCK_CIPHER_ecb_loop()
		des_ecb3_encrypt((des_cblock *)(in + i), (des_cblock *)(out + i), 
			ctx->c.des_ede.ks1, ctx->c.des_ede.ks2, ctx->c.des_ede.ks3,
			 ctx->encrypt);
	return 1;
}

static int des_ede_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			      const unsigned char *in, unsigned int inl)
{
	des_ede3_ofb64_encrypt(in, out, (long)inl,
			ctx->c.des_ede.ks1, ctx->c.des_ede.ks2, ctx->c.des_ede.ks3,
								(des_cblock *)ctx->iv, &ctx->num);
	return 1;
}

static int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			      const unsigned char *in, unsigned int inl)
{
	des_ede3_cbc_encrypt(in, out, (long)inl,
			ctx->c.des_ede.ks1, ctx->c.des_ede.ks2, ctx->c.des_ede.ks3,
 								(des_cblock *)ctx->iv, ctx->encrypt);
	return 1;
}

static int des_ede_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			      const unsigned char *in, unsigned int inl)
{
	des_ede3_cfb64_encrypt(in, out, (long)inl, 
			ctx->c.des_ede.ks1, ctx->c.des_ede.ks2, ctx->c.des_ede.ks3,
					(des_cblock *)ctx->iv, &ctx->num, ctx->encrypt);
	return 1;
}

#define NID_des_ede_ecb NID_des_ede

BLOCK_CIPHER_defs(des_ede, des_ede, NID_des_ede, 8, 16, 8,
			0, des_ede_init_key, NULL, 
			EVP_CIPHER_set_asn1_iv,
			EVP_CIPHER_get_asn1_iv,
			NULL)

#define NID_des_ede3_ecb NID_des_ede3
#define des_ede3_cfb_cipher des_ede_cfb_cipher
#define des_ede3_ofb_cipher des_ede_ofb_cipher
#define des_ede3_cbc_cipher des_ede_cbc_cipher
#define des_ede3_ecb_cipher des_ede_ecb_cipher

BLOCK_CIPHER_defs(des_ede3, des_ede, NID_des_ede3, 8, 24, 8,
			0, des_ede3_init_key, NULL, 
			EVP_CIPHER_set_asn1_iv,
			EVP_CIPHER_get_asn1_iv,
			NULL)

static int des_ede_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
	{
	des_cblock *deskey = (des_cblock *)key;

	des_set_key_unchecked(&deskey[0],ctx->c.des_ede.ks1);
	des_set_key_unchecked(&deskey[1],ctx->c.des_ede.ks2);
	memcpy( (char *)ctx->c.des_ede.ks3,
			(char *)ctx->c.des_ede.ks1,
			sizeof(ctx->c.des_ede.ks1));
	return 1;
	}

static int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			     const unsigned char *iv, int enc)
	{
	des_cblock *deskey = (des_cblock *)key;

	des_set_key_unchecked(&deskey[0],ctx->c.des_ede.ks1);
	des_set_key_unchecked(&deskey[1],ctx->c.des_ede.ks2);
	des_set_key_unchecked(&deskey[2],ctx->c.des_ede.ks3);

	return 1;
	}

EVP_CIPHER *EVP_des_ede(void)
{
	return &des_ede_ecb;
}

EVP_CIPHER *EVP_des_ede3(void)
{
	return &des_ede3_ecb;
}
#endif
