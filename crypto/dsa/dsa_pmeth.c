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
#include <openssl/evp.h>
#include "evp_locl.h"

/* DSA pkey context structure */

typedef struct
	{
	/* Parameter gen parameters */
	int nbits;
	/* Keygen callback info */
	int gentmp[2];
	/* message digest */
	const EVP_MD *md;
	} DSA_PKEY_CTX;

static int pkey_dsa_init(EVP_PKEY_CTX *ctx)
	{
	DSA_PKEY_CTX *dctx;
	dctx = OPENSSL_malloc(sizeof(DSA_PKEY_CTX));
	if (!dctx)
		return 0;
	dctx->nbits = 1024;
	dctx->md = NULL;

	ctx->data = dctx;
	ctx->keygen_info = dctx->gentmp;
	ctx->keygen_info_count = 2;
	
	return 1;
	}

static void pkey_dsa_cleanup(EVP_PKEY_CTX *ctx)
	{
	DSA_PKEY_CTX *dctx = ctx->data;
	if (dctx)
		OPENSSL_free(dctx);
	}

static int pkey_dsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, int *siglen,
					const unsigned char *tbs, int tbslen)
	{
	int ret, type;
	unsigned int sltmp;
	DSA_PKEY_CTX *dctx = ctx->data;
	DSA *dsa = ctx->pkey->pkey.dsa;

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;

	ret = DSA_sign(type, tbs, tbslen, sig, &sltmp, dsa);

	if (ret < 0)
		return ret;
	*siglen = sltmp;
	return 1;
	}

static int pkey_dsa_verify(EVP_PKEY_CTX *ctx,
					const unsigned char *sig, int siglen,
					const unsigned char *tbs, int tbslen)
	{
	int ret, type;
	DSA_PKEY_CTX *dctx = ctx->data;
	DSA *dsa = ctx->pkey->pkey.dsa;

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;

	ret = DSA_verify(type, tbs, tbslen, sig, siglen, dsa);

	return ret;
	}

static int pkey_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
	{
	DSA_PKEY_CTX *dctx = ctx->data;
	switch (type)
		{
		case EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
		if (p1 < 256)
			return -2;
		dctx->nbits = p1;
		return 1;

		case EVP_PKEY_CTRL_MD:
		if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1)
			{
			DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
			return 0;
			}
		dctx->md = p2;
		return 1;

		default:
		return -2;

		}
	}
			
static int pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx,
			const char *type, const char *value)
	{
	if (!strcmp(type, "dsa_paramgen_bits"))
		{
		int nbits;
		nbits = atoi(value);
		return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
		}
	return -2;
	}

static int pkey_dsa_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
	{
	DSA *dsa = NULL;
	DSA_PKEY_CTX *dctx = ctx->data;
	BN_GENCB *pcb, cb;
	int ret;
	if (ctx->pkey_gencb)
		{
		pcb = &cb;
		evp_pkey_set_cb_translate(pcb, ctx);
		}
	else
		pcb = NULL;
	dsa = DSA_new();
	if (!dsa)
		return 0;
	ret = DSA_generate_parameters_ex(dsa, dctx->nbits, NULL, 0, NULL, NULL,
									pcb);
	if (ret)
		EVP_PKEY_assign_DSA(pkey, dsa);
	else
		DSA_free(dsa);
	return ret;
	}

static int pkey_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
	{
	DSA *dsa = NULL;
	if (ctx->pkey == NULL)
		{
		DSAerr(DSA_F_PKEY_DSA_KEYGEN, DSA_R_NO_PARAMETERS_SET);
		return 0;
		}
	dsa = DSA_new();
	if (!dsa)
		return 0;
	EVP_PKEY_assign_DSA(pkey, dsa);
	/* Note: if error return, pkey is freed by parent routine */
	if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
		return 0;
	return DSA_generate_key(pkey->pkey.dsa);
	}

const EVP_PKEY_METHOD dsa_pkey_meth = 
	{
	EVP_PKEY_DSA,
	EVP_PKEY_FLAG_AUTOARGLEN,
	pkey_dsa_init,
	pkey_dsa_cleanup,

	0,
	pkey_dsa_paramgen,

	0,
	pkey_dsa_keygen,

	0,
	pkey_dsa_sign,

	0,
	pkey_dsa_verify,

	0,0,

	0,0,0,0,

	0,0,

	0,0,

	0,0,

	pkey_dsa_ctrl,
	pkey_dsa_ctrl_str


	};
