/* fips/rand/fips_drbg_lib.c */
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
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

/* Support framework for SP800-90 DRBGs */

static int fips_drbg_init(DRBG_CTX *dctx, int type, unsigned int flags)
	{
	int rv;
	memset(dctx, 0, sizeof(DRBG_CTX));
	dctx->status = DRBG_STATUS_UNINITIALISED;
	dctx->flags = flags;
	dctx->type = type;

	rv = fips_drbg_hash_init(dctx);

	if (rv == -2)
		rv = fips_drbg_ctr_init(dctx);

	return rv;
	}

DRBG_CTX *FIPS_drbg_new(int type, unsigned int flags)
	{
	DRBG_CTX *dctx;
	dctx = OPENSSL_malloc(sizeof(DRBG_CTX));
	if (!dctx)
		return NULL;
	if (fips_drbg_init(dctx, type, flags) <= 0)
		{
		OPENSSL_free(dctx);
		return NULL;
		}
	return dctx;
	}

void FIPS_drbg_free(DRBG_CTX *dctx)
	{
	dctx->uninstantiate(dctx);
	OPENSSL_cleanse(dctx, sizeof(DRBG_CTX));
	OPENSSL_free(dctx);
	}

int FIPS_drbg_instantiate(DRBG_CTX *dctx,
				int strength,
				const unsigned char *pers, size_t perslen)
	{
	size_t entlen, noncelen;

	if (perslen > dctx->max_pers)
		return 0;

	if (dctx->status != DRBG_STATUS_UNINITIALISED)
		{
		/* error */
		return 0;
		}

	dctx->status = DRBG_STATUS_ERROR;

	entlen = dctx->get_entropy(dctx, dctx->entropy, dctx->strength,
				dctx->min_entropy, dctx->max_entropy);

	if (entlen < dctx->min_entropy || entlen > dctx->max_entropy)
		goto end;

	if (dctx->max_nonce > 0)
		{

		noncelen = dctx->get_nonce(dctx, dctx->nonce,
					dctx->strength / 2,
					dctx->min_nonce, dctx->max_nonce);

		if (noncelen < dctx->min_nonce || noncelen > dctx->max_nonce)
			goto end;

		}
	else
		noncelen = 0;

	if (!dctx->instantiate(dctx, 
				dctx->entropy, entlen,
				dctx->nonce, noncelen,
				pers, perslen))
		goto end;


	dctx->status = DRBG_STATUS_READY;
	dctx->reseed_counter = 1;
	/* Initial test value for reseed interval */
	dctx->reseed_interval = 1<<24;

	end:

	OPENSSL_cleanse(dctx->entropy, sizeof(dctx->entropy));
	OPENSSL_cleanse(dctx->nonce, sizeof(dctx->nonce));

	if (dctx->status == DRBG_STATUS_READY)
		return 1;

	return 0;

	}

int FIPS_drbg_reseed(DRBG_CTX *dctx,
			const unsigned char *adin, size_t adinlen)
	{
	size_t entlen;
	if (dctx->status != DRBG_STATUS_READY
		&& dctx->status != DRBG_STATUS_RESEED)
		{
		/* error */
		return 0;
		}

	if (!adin)
		adinlen = 0;
	else if (adinlen > dctx->max_adin)
		{
		/* error */
		return 0;
		}

	dctx->status = DRBG_STATUS_ERROR;

	entlen = dctx->get_entropy(dctx, dctx->entropy, dctx->strength,
				dctx->min_entropy, dctx->max_entropy);

	if (entlen < dctx->min_entropy || entlen > dctx->max_entropy)
		goto end;

	if (!dctx->reseed(dctx, dctx->entropy, entlen, adin, adinlen))
		goto end;

	dctx->status = DRBG_STATUS_READY;
	dctx->reseed_counter = 1;
	end:
	OPENSSL_cleanse(dctx->entropy, sizeof(dctx->entropy));
	if (dctx->status == DRBG_STATUS_READY)
		return 1;
	return 0;
	}
	

int FIPS_drbg_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
			int prediction_resistance,
			const unsigned char *adin, size_t adinlen)
	{
	if (outlen > dctx->max_request)
		{
		/* Too large */
		return 0;
		}
	if (dctx->status == DRBG_STATUS_RESEED || prediction_resistance)
		{
		if (!FIPS_drbg_reseed(dctx, adin, adinlen))
			return 0;
		adin = NULL;
		adinlen = 0;
		}
	if (dctx->status != DRBG_STATUS_READY)
		{
		/* Bad error */
		return 0;
		}
	if (!dctx->generate(dctx, out, outlen, adin, adinlen))
		{
		/* Bad error */
		dctx->status = DRBG_STATUS_ERROR;
		return 0;
		}
	if (dctx->reseed_counter > dctx->reseed_interval)
		dctx->status = DRBG_STATUS_RESEED;
	else
		dctx->reseed_counter++;

	return 1;
	}

int FIPS_drbg_uninstantiate(DRBG_CTX *dctx)
	{
	int save_type, save_flags, rv;
	save_type = dctx->type;
	save_flags = dctx->flags;
	rv = dctx->uninstantiate(dctx);
	OPENSSL_cleanse(dctx, sizeof(DRBG_CTX));
	/* If method has problems uninstantiating, return error */
	if (rv <= 0)
		return rv;
	return fips_drbg_init(dctx, save_type, save_flags);
	}

int FIPS_drbg_set_test_mode(DRBG_CTX *dctx,
	size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char *out,
				int entropy, size_t min_len, size_t max_len),
	size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char *out,
				int entropy, size_t min_len, size_t max_len))
	{
	if (dctx->status != DRBG_STATUS_UNINITIALISED)
		return 0;
	dctx->flags |= DRBG_FLAG_TEST;
	dctx->get_entropy = get_entropy;
	dctx->get_nonce = get_nonce;
	return 1;
	}

void *FIPS_drbg_get_app_data(DRBG_CTX *dctx)
	{
	return dctx->app_data;
	}

void FIPS_drbg_set_app_data(DRBG_CTX *dctx, void *app_data)
	{
	dctx->app_data = app_data;
	}

size_t FIPS_drbg_get_blocklength(DRBG_CTX *dctx)
	{
	return dctx->blocklength;
	}
