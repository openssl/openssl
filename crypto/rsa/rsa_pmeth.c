/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include "evp_locl.h"

/* RSA pkey context structure */

typedef struct
	{
	/* Key gen parameters */
	int nbits;
	BIGNUM *pub_exp;
	/* RSA padding mode */
	int pad_mode;
	} RSA_PKEY_CTX;

static int pkey_rsa_init(EVP_PKEY_CTX *ctx)
	{
	RSA_PKEY_CTX *rctx;
	rctx = OPENSSL_malloc(sizeof(RSA_PKEY_CTX));
	if (!rctx)
		return 0;
	rctx->nbits = 1024;
	rctx->pub_exp = NULL;
	rctx->pad_mode = RSA_PKCS1_PADDING;
	ctx->data = rctx;
	return 1;
	}

static void pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)
	{
	RSA_PKEY_CTX *rctx = ctx->data;
	if (rctx)
		{
		if (rctx->pub_exp)
			BN_free(rctx->pub_exp);
		}
	OPENSSL_free(rctx);
	}

static int pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, int *siglen,
                                        unsigned char *tbs, int tbslen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_private_encrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*siglen = ret;
	return 1;
	}


static int pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx,
					unsigned char *sig, int *siglen,
                                        unsigned char *tbs, int tbslen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_public_decrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*siglen = ret;
	return 1;
	}

static int pkey_rsa_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, int *outlen,
                                        unsigned char *in, int inlen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_public_encrypt(inlen, in, out, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*outlen = ret;
	return 1;
	}

static int pkey_rsa_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, int *outlen,
                                        unsigned char *in, int inlen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_private_decrypt(inlen, in, out, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*outlen = ret;
	return 1;
	}

const EVP_PKEY_METHOD rsa_pkey_meth = 
	{
	EVP_PKEY_RSA,
	0,
	pkey_rsa_init,
	pkey_rsa_cleanup,

	0,0,

	0,0,

	0,
	pkey_rsa_sign,

	0,0,

	0,
	pkey_rsa_verifyrecover,


	0,0,0,0,

	0,
	pkey_rsa_encrypt,

	0,
	pkey_rsa_decrypt,

	0,0


	};
