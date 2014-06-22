/* fips/rand/fips_drbg_rand.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

/* Mapping of SP800-90 DRBGs to OpenSSL RAND_METHOD */

/* Since we only have one global PRNG used at any time in OpenSSL use a global
 * variable to store context.
 */

static DRBG_CTX ossl_dctx;

DRBG_CTX *FIPS_get_default_drbg(void)
	{
	return &ossl_dctx;
	}

static int fips_drbg_bytes(unsigned char *out, int count)
	{
	DRBG_CTX *dctx = &ossl_dctx;
	int rv = 0;
	unsigned char *adin = NULL;
	size_t adinlen = 0;
	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	do
		{
		size_t rcnt;
		if (count > (int)dctx->max_request)
			rcnt = dctx->max_request;
		else
			rcnt = count;
		if (dctx->get_adin)
			{
			adinlen = dctx->get_adin(dctx, &adin);
			if (adinlen && !adin)
				{
				FIPSerr(FIPS_F_FIPS_DRBG_BYTES, FIPS_R_ERROR_RETRIEVING_ADDITIONAL_INPUT);
				goto err;
				}
			}
		rv = FIPS_drbg_generate(dctx, out, rcnt, 0, adin, adinlen);
		if (adin)
			{
			if (dctx->cleanup_adin)
				dctx->cleanup_adin(dctx, adin, adinlen);
			adin = NULL;
			}
		if (!rv)
			goto err;
		out += rcnt;
		count -= rcnt;
		}
	while (count);
	rv = 1;
	err:
	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
	return rv;
	}

static int fips_drbg_pseudo(unsigned char *out, int count)
	{
	if (fips_drbg_bytes(out, count) <= 0)
		return -1;
	return 1;
	}

static int fips_drbg_status(void)
	{
	DRBG_CTX *dctx = &ossl_dctx;
	int rv;
	CRYPTO_r_lock(CRYPTO_LOCK_RAND);
	rv = dctx->status == DRBG_STATUS_READY ? 1 : 0;
	CRYPTO_r_unlock(CRYPTO_LOCK_RAND);
	return rv;
	}

static void fips_drbg_cleanup(void)
	{
	DRBG_CTX *dctx = &ossl_dctx;
	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	FIPS_drbg_uninstantiate(dctx);
	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
	}

static int fips_drbg_seed(const void *seed, int seedlen)
	{
	DRBG_CTX *dctx = &ossl_dctx;
	if (dctx->rand_seed_cb)
		return dctx->rand_seed_cb(dctx, seed, seedlen);
	return 1;
	}

static int fips_drbg_add(const void *seed, int seedlen,
					double add_entropy)
	{
	DRBG_CTX *dctx = &ossl_dctx;
	if (dctx->rand_add_cb)
		return dctx->rand_add_cb(dctx, seed, seedlen, add_entropy);
	return 1;
	}

static const RAND_METHOD rand_drbg_meth =
	{
	fips_drbg_seed,
	fips_drbg_bytes,
	fips_drbg_cleanup,
	fips_drbg_add,
	fips_drbg_pseudo,
	fips_drbg_status
	};

const RAND_METHOD *FIPS_drbg_method(void)
	{
	return &rand_drbg_meth;
	}

