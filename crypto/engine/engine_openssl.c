/* crypto/engine/engine_openssl.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <openssl/crypto.h>
#include "cryptlib.h"
#include "engine_int.h"
#include <openssl/engine.h>
#include <openssl/dso.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

/* This is the only function we need to implement as OpenSSL
 * doesn't have a native CRT mod_exp. Perhaps this should be
 * BN_mod_exp_crt and moved into crypto/bn/ ?? ... dunno. */
static int openssl_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

/* The ENGINE structure that can be pointed to. */
static ENGINE engine_openssl =
        {
	"openssl",
	"Software default engine support",
	NULL,
	NULL,
	NULL, /* these methods are "stolen" in ENGINE_openssl() */
	NULL,
	NULL,
	openssl_mod_exp_crt,
	NULL, /* no init() */
	NULL, /* no finish() */
	NULL, /* no ctrl() */
	NULL, /* no load_privkey() */
	NULL, /* no load_pubkey() */
	0, /* no flags */
	0, 0, /* no references. */
	NULL, NULL /* unlinked */
        };

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_openssl()
	{
	/* We need to populate our structure with the software pointers
	 * that we want to steal. */
	engine_openssl.rsa_meth = RSA_get_default_openssl_method();
	engine_openssl.dsa_meth = DSA_get_default_openssl_method();
	engine_openssl.dh_meth = DH_get_default_openssl_method();
	engine_openssl.rand_meth = RAND_SSLeay();
	engine_openssl.bn_mod_exp = BN_mod_exp;
	return &engine_openssl;
	}

/* Chinese Remainder Theorem, taken and adapted from rsa_eay.c */
static int openssl_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *q, const BIGNUM *dmp1,
			const BIGNUM *dmq1, const BIGNUM *iqmp, BN_CTX *ctx)
	{
	BIGNUM r1,m1;
	int ret=0;
	BN_CTX *bn_ctx;
	BIGNUM *temp_bn = NULL;

	if (ctx)
		bn_ctx = ctx;
	else
		if ((bn_ctx=BN_CTX_new()) == NULL) goto err;
	BN_init(&m1);
	BN_init(&r1);
	/* BN_mul() cannot accept const BIGNUMs so I use the BN_CTX
	 * to duplicate what I need. <sigh> */
	if ((temp_bn = BN_CTX_get(bn_ctx)) == NULL) goto err;
	if (!BN_copy(temp_bn, iqmp)) goto err;
 
	if (!BN_mod(&r1, a, q, bn_ctx)) goto err;
	if (!engine_openssl.bn_mod_exp(&m1, &r1, dmq1, q, bn_ctx))
		goto err;
 
	if (!BN_mod(&r1, a, p, bn_ctx)) goto err;
	if (!engine_openssl.bn_mod_exp(r, &r1, dmp1, p, bn_ctx))
		goto err;

	if (!BN_sub(r, r, &m1)) goto err;
	/* This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size */
	if (r->neg)
		if (!BN_add(r, r, p)) goto err;
 
	if (!BN_mul(&r1, r, temp_bn, bn_ctx)) goto err;
	if (!BN_mod(r, &r1, p, bn_ctx)) goto err;
	/* If p < q it is occasionally possible for the correction of
	 * adding 'p' if r is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
	 * they ensure p > q [steve]
	 */
	if (r->neg)
		if (!BN_add(r, r, p)) goto err;
	/* Again, BN_mul() will need non-const values. */
	if (!BN_copy(temp_bn, q)) goto err;
	if (!BN_mul(&r1, r, temp_bn, bn_ctx)) goto err;
	if (!BN_add(r, &r1, &m1)) goto err;
 
	ret=1;
err:
	BN_clear_free(&m1);
	BN_clear_free(&r1);
	if (temp_bn)
		bn_ctx->tos--;
	if (!ctx)
		BN_CTX_free(bn_ctx);
	return(ret);
	}
