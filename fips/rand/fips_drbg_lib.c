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
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

/* Support framework for SP800-90 DRBGs */

int FIPS_drbg_init(DRBG_CTX *dctx, int type, unsigned int flags)
	{
	int rv;
	memset(dctx, 0, sizeof(DRBG_CTX));
	dctx->status = DRBG_STATUS_UNINITIALISED;
	dctx->xflags = flags;
	dctx->type = type;

	dctx->iflags = 0;
	dctx->entropy_blocklen = 0;
	dctx->health_check_cnt = 0;
	dctx->health_check_interval = DRBG_HEALTH_INTERVAL;

	rv = fips_drbg_hash_init(dctx);

	if (rv == -2)
		rv = fips_drbg_ctr_init(dctx);
	if (rv == -2)
		rv = fips_drbg_hmac_init(dctx);

	if (rv <= 0)
		{
		if (rv == -2)
			FIPSerr(FIPS_F_FIPS_DRBG_INIT, FIPS_R_UNSUPPORTED_DRBG_TYPE);
		else
			FIPSerr(FIPS_F_FIPS_DRBG_INIT, FIPS_R_ERROR_INITIALISING_DRBG);
		}

	/* If not in test mode run selftests on DRBG of the same type */

	if (!(dctx->xflags & DRBG_FLAG_TEST))
		{
		if (!FIPS_drbg_health_check(dctx))
			{
			FIPSerr(FIPS_F_FIPS_DRBG_INIT, FIPS_R_SELFTEST_FAILURE);
			return 0;
			}
		}

	return rv;
	}

DRBG_CTX *FIPS_drbg_new(int type, unsigned int flags)
	{
	DRBG_CTX *dctx;
	dctx = OPENSSL_malloc(sizeof(DRBG_CTX));
	if (!dctx)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	if (type == 0)
		{
		memset(dctx, 0, sizeof(DRBG_CTX));
		dctx->type = 0;
		dctx->status = DRBG_STATUS_UNINITIALISED;
		return dctx;
		}

	if (FIPS_drbg_init(dctx, type, flags) <= 0)
		{
		OPENSSL_free(dctx);
		return NULL;
		}
		
	return dctx;
	}

void FIPS_drbg_free(DRBG_CTX *dctx)
	{
	if (dctx->uninstantiate)
		dctx->uninstantiate(dctx);
	/* Don't free up default DRBG */
	if (dctx == FIPS_get_default_drbg())
		{
		memset(dctx, 0, sizeof(DRBG_CTX));
		dctx->type = 0;
		dctx->status = DRBG_STATUS_UNINITIALISED;
		}
	else
		{
		OPENSSL_cleanse(&dctx->d, sizeof(dctx->d));
		OPENSSL_free(dctx);
		}
	}

static size_t fips_get_entropy(DRBG_CTX *dctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len)
	{
	unsigned char *tout, *p;
	size_t bl = dctx->entropy_blocklen, rv;
	if (!dctx->get_entropy)
		return 0;
	if (dctx->xflags & DRBG_FLAG_TEST || !bl)
		return dctx->get_entropy(dctx, pout, entropy, min_len, max_len);
	rv = dctx->get_entropy(dctx, &tout, entropy + bl,
				min_len + bl, max_len + bl);
	*pout = tout + bl;
	if (rv < (min_len + bl) || (rv % bl))
		return 0;
	/* Compare consecutive blocks for continuous PRNG test */
	for (p = tout; p < tout + rv - bl; p += bl)
		{
		if (!memcmp(p, p + bl, bl))
			{
			FIPSerr(FIPS_F_FIPS_GET_ENTROPY, FIPS_R_ENTROPY_SOURCE_STUCK);
			return 0;
			}
		}
	rv -= bl;
	if (rv > max_len)
		return max_len;
	return rv;
	}

static void fips_cleanup_entropy(DRBG_CTX *dctx,
					unsigned char *out, size_t olen)
	{
	size_t bl;
	if (dctx->xflags & DRBG_FLAG_TEST)
		bl = 0;
	else
		bl = dctx->entropy_blocklen;
	/* Call cleanup with original arguments */
	dctx->cleanup_entropy(dctx, out - bl, olen + bl);
	}


int FIPS_drbg_instantiate(DRBG_CTX *dctx,
				const unsigned char *pers, size_t perslen)
	{
	size_t entlen = 0, noncelen = 0;
	unsigned char *nonce = NULL, *entropy = NULL;

#if 0
	/* Put here so error script picks them up */
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE,
				FIPS_R_PERSONALISATION_STRING_TOO_LONG);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_IN_ERROR_STATE);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_ALREADY_INSTANTIATED);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_ERROR_RETRIEVING_ENTROPY);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_ERROR_RETRIEVING_NONCE);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_INSTANTIATE_ERROR);
	FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, FIPS_R_DRBG_NOT_INITIALISED);
#endif

	int r = 0;

	if (perslen > dctx->max_pers)
		{
		r = FIPS_R_PERSONALISATION_STRING_TOO_LONG;
		goto end;
		}

	if (!dctx->instantiate)
		{
		r = FIPS_R_DRBG_NOT_INITIALISED;
		goto end;
		}

	if (dctx->status != DRBG_STATUS_UNINITIALISED)
		{
		if (dctx->status == DRBG_STATUS_ERROR)
			r = FIPS_R_IN_ERROR_STATE;
		else
			r = FIPS_R_ALREADY_INSTANTIATED;
		goto end;
		}

	dctx->status = DRBG_STATUS_ERROR;

	entlen = fips_get_entropy(dctx, &entropy, dctx->strength,
				dctx->min_entropy, dctx->max_entropy);

	if (entlen < dctx->min_entropy || entlen > dctx->max_entropy)
		{
		r = FIPS_R_ERROR_RETRIEVING_ENTROPY;
		goto end;
		}

	if (dctx->max_nonce > 0 && dctx->get_nonce)
		{
		noncelen = dctx->get_nonce(dctx, &nonce,
					dctx->strength / 2,
					dctx->min_nonce, dctx->max_nonce);

		if (noncelen < dctx->min_nonce || noncelen > dctx->max_nonce)
			{
			r = FIPS_R_ERROR_RETRIEVING_NONCE;
			goto end;
			}

		}

	if (!dctx->instantiate(dctx, 
				entropy, entlen,
				nonce, noncelen,
				pers, perslen))
		{
		r = FIPS_R_ERROR_INSTANTIATING_DRBG;
		goto end;
		}


	dctx->status = DRBG_STATUS_READY;
	if (!(dctx->iflags & DRBG_CUSTOM_RESEED))
		dctx->reseed_counter = 1;

	end:

	if (entropy && dctx->cleanup_entropy)
		fips_cleanup_entropy(dctx, entropy, entlen);

	if (nonce && dctx->cleanup_nonce)
		dctx->cleanup_nonce(dctx, nonce, noncelen);

	if (dctx->status == DRBG_STATUS_READY)
		return 1;

	if (r && !(dctx->iflags & DRBG_FLAG_NOERR))
		FIPSerr(FIPS_F_FIPS_DRBG_INSTANTIATE, r);

	return 0;

	}

static int drbg_reseed(DRBG_CTX *dctx,
			const unsigned char *adin, size_t adinlen, int hcheck)
	{
	unsigned char *entropy = NULL;
	size_t entlen = 0;
	int r = 0;

#if 0
	FIPSerr(FIPS_F_DRBG_RESEED, FIPS_R_NOT_INSTANTIATED);
	FIPSerr(FIPS_F_DRBG_RESEED, FIPS_R_ADDITIONAL_INPUT_TOO_LONG);
#endif
	if (dctx->status != DRBG_STATUS_READY
		&& dctx->status != DRBG_STATUS_RESEED)
		{
		if (dctx->status == DRBG_STATUS_ERROR)
			r = FIPS_R_IN_ERROR_STATE;
		else if(dctx->status == DRBG_STATUS_UNINITIALISED)
			r = FIPS_R_NOT_INSTANTIATED;
		goto end;
		}

	if (!adin)
		adinlen = 0;
	else if (adinlen > dctx->max_adin)
		{
		r = FIPS_R_ADDITIONAL_INPUT_TOO_LONG;
		goto end;
		}

	dctx->status = DRBG_STATUS_ERROR;
	/* Peform health check on all reseed operations if not a prediction
	 * resistance request and not in test mode.
	 */
	if (hcheck && !(dctx->xflags & DRBG_FLAG_TEST))
		{
		if (!FIPS_drbg_health_check(dctx))
			{
			r = FIPS_R_SELFTEST_FAILURE;
			goto end;
			}
		}

	entlen = fips_get_entropy(dctx, &entropy, dctx->strength,
				dctx->min_entropy, dctx->max_entropy);

	if (entlen < dctx->min_entropy || entlen > dctx->max_entropy)
		{
		r = FIPS_R_ERROR_RETRIEVING_ENTROPY;
		goto end;
		}

	if (!dctx->reseed(dctx, entropy, entlen, adin, adinlen))
		goto end;

	dctx->status = DRBG_STATUS_READY;
	if (!(dctx->iflags & DRBG_CUSTOM_RESEED))
		dctx->reseed_counter = 1;
	end:

	if (entropy && dctx->cleanup_entropy)
		fips_cleanup_entropy(dctx, entropy, entlen);

	if (dctx->status == DRBG_STATUS_READY)
		return 1;

	if (r && !(dctx->iflags & DRBG_FLAG_NOERR))
		FIPSerr(FIPS_F_DRBG_RESEED, r);

	return 0;
	}

int FIPS_drbg_reseed(DRBG_CTX *dctx,
			const unsigned char *adin, size_t adinlen)
	{
	return drbg_reseed(dctx, adin, adinlen, 1);
	}

static int fips_drbg_check(DRBG_CTX *dctx)
	{
	if (dctx->xflags & DRBG_FLAG_TEST)
		return 1;
	dctx->health_check_cnt++;
	if (dctx->health_check_cnt >= dctx->health_check_interval)
		{
		if (!FIPS_drbg_health_check(dctx))
			{
			FIPSerr(FIPS_F_FIPS_DRBG_CHECK, FIPS_R_SELFTEST_FAILURE);
			return 0;
			}
		}
	return 1;
	}

int FIPS_drbg_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
			int prediction_resistance,
			const unsigned char *adin, size_t adinlen)
	{
	int r = 0;

	if (FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_FIPS_DRBG_GENERATE, FIPS_R_SELFTEST_FAILED);
		return 0;
		}

	if (!fips_drbg_check(dctx))
		return 0;

	if (dctx->status != DRBG_STATUS_READY
		&& dctx->status != DRBG_STATUS_RESEED)
		{
		if (dctx->status == DRBG_STATUS_ERROR)
			r = FIPS_R_IN_ERROR_STATE;
		else if(dctx->status == DRBG_STATUS_UNINITIALISED)
			r = FIPS_R_NOT_INSTANTIATED;
		goto end;
		}

	if (outlen > dctx->max_request)
		{
		r = FIPS_R_REQUEST_TOO_LARGE_FOR_DRBG;
		return 0;
		}

	if (adinlen > dctx->max_adin)
		{
		r = FIPS_R_ADDITIONAL_INPUT_TOO_LONG;
		goto end;
		}

	if (dctx->iflags & DRBG_CUSTOM_RESEED)
		dctx->generate(dctx, NULL, outlen, NULL, 0);
	else if (dctx->reseed_counter >= dctx->reseed_interval)
		dctx->status = DRBG_STATUS_RESEED;

	if (dctx->status == DRBG_STATUS_RESEED || prediction_resistance)
		{
		/* If prediction resistance request don't do health check */
		int hcheck = prediction_resistance ? 0 : 1;
		
		if (!drbg_reseed(dctx, adin, adinlen, hcheck))
			{
			r = FIPS_R_RESEED_ERROR;
			goto end;
			}
		adin = NULL;
		adinlen = 0;
		}

	if (!dctx->generate(dctx, out, outlen, adin, adinlen))
		{
		r = FIPS_R_GENERATE_ERROR;
		dctx->status = DRBG_STATUS_ERROR;
		goto end;
		}
	if (!(dctx->iflags & DRBG_CUSTOM_RESEED))
		{
		if (dctx->reseed_counter >= dctx->reseed_interval)
			dctx->status = DRBG_STATUS_RESEED;
		else
			dctx->reseed_counter++;
		}

	end:
	if (r)
		{
		if (!(dctx->iflags & DRBG_FLAG_NOERR))
			FIPSerr(FIPS_F_FIPS_DRBG_GENERATE, r);
		return 0;
		}

	return 1;
	}

int FIPS_drbg_uninstantiate(DRBG_CTX *dctx)
	{
	int rv;
	if (!dctx->uninstantiate)
		rv = 1;
	else
		rv = dctx->uninstantiate(dctx);
	/* Although we'd like to cleanse here we can't because we have to
	 * test the uninstantiate really zeroes the data.
	 */
	memset(&dctx->d, 0, sizeof(dctx->d));
	dctx->status = DRBG_STATUS_UNINITIALISED;
	/* If method has problems uninstantiating, return error */
	return rv;
	}

int FIPS_drbg_set_callbacks(DRBG_CTX *dctx,
	size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len),
	void (*cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
	size_t entropy_blocklen,
	size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len),
	void (*cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen))
	{
	if (dctx->status != DRBG_STATUS_UNINITIALISED)
		return 0;
	dctx->entropy_blocklen = entropy_blocklen;
	dctx->get_entropy = get_entropy;
	dctx->cleanup_entropy = cleanup_entropy;
	dctx->get_nonce = get_nonce;
	dctx->cleanup_nonce = cleanup_nonce;
	return 1;
	}

int FIPS_drbg_set_rand_callbacks(DRBG_CTX *dctx,
	size_t (*get_adin)(DRBG_CTX *ctx, unsigned char **pout),
	void (*cleanup_adin)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
	int (*rand_seed_cb)(DRBG_CTX *ctx, const void *buf, int num),
	int (*rand_add_cb)(DRBG_CTX *ctx,
				const void *buf, int num, double entropy))
	{
	if (dctx->status != DRBG_STATUS_UNINITIALISED)
		return 0;
	dctx->get_adin = get_adin;
	dctx->cleanup_adin = cleanup_adin;
	dctx->rand_seed_cb = rand_seed_cb;
	dctx->rand_add_cb = rand_add_cb;
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

int FIPS_drbg_get_strength(DRBG_CTX *dctx)
	{
	return dctx->strength;
	}

void FIPS_drbg_set_check_interval(DRBG_CTX *dctx, int interval)
	{
	dctx->health_check_interval = interval;
	}

void FIPS_drbg_set_reseed_interval(DRBG_CTX *dctx, int interval)
	{
	dctx->reseed_interval = interval;
	}

static int drbg_stick = 0;

void FIPS_drbg_stick(int onoff)
	{
	drbg_stick = onoff;
	}

/* Continuous DRBG utility function */
int fips_drbg_cprng_test(DRBG_CTX *dctx, const unsigned char *out)
	{
	/* No CPRNG in test mode */
	if (dctx->xflags & DRBG_FLAG_TEST)
		return 1;
	/* Check block is valid: should never happen */
	if (dctx->lb_valid == 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_CPRNG_TEST, FIPS_R_INTERNAL_ERROR);
		fips_set_selftest_fail();
		return 0;
		}
	if (drbg_stick)
		memcpy(dctx->lb, out, dctx->blocklength);
	/* Check against last block: fail if match */
	if (!memcmp(dctx->lb, out, dctx->blocklength))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_CPRNG_TEST, FIPS_R_DRBG_STUCK);
		fips_set_selftest_fail();
		return 0;
		}
	/* Save last block for next comparison */
	memcpy(dctx->lb, out, dctx->blocklength);
	return 1;
	}
