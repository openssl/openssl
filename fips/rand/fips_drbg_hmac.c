/* fips/rand/fips_drbg_hmac.c */
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

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

static int drbg_hmac_update(DRBG_CTX *dctx,
				const unsigned char *in1, size_t in1len,
				const unsigned char *in2, size_t in2len,
				const unsigned char *in3, size_t in3len
			)
	{
	static unsigned char c0 = 0, c1 = 1;
	DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
	HMAC_CTX *hctx = &hmac->hctx;

	if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL))
		return 0;
	if (!HMAC_Update(hctx, hmac->V, dctx->blocklength))
		return 0;
	if (!HMAC_Update(hctx, &c0, 1))
		return 0;
	if (in1len && !HMAC_Update(hctx, in1, in1len))
		return 0;
	if (in2len && !HMAC_Update(hctx, in2, in2len))
		return 0;
	if (in3len && !HMAC_Update(hctx, in3, in3len))
		return 0;

	if (!HMAC_Final(hctx, hmac->K, NULL))
		return 0;

	if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL))
		return 0;
	if (!HMAC_Update(hctx, hmac->V, dctx->blocklength))
		return 0;

	if (!HMAC_Final(hctx, hmac->V, NULL))
		return 0;

	if (!in1len && !in2len && !in3len)
		return 1;

	if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL))
		return 0;
	if (!HMAC_Update(hctx, hmac->V, dctx->blocklength))
		return 0;
	if (!HMAC_Update(hctx, &c1, 1))
		return 0;
	if (in1len && !HMAC_Update(hctx, in1, in1len))
		return 0;
	if (in2len && !HMAC_Update(hctx, in2, in2len))
		return 0;
	if (in3len && !HMAC_Update(hctx, in3, in3len))
		return 0;

	if (!HMAC_Final(hctx, hmac->K, NULL))
		return 0;

	if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength, hmac->md, NULL))
		return 0;
	if (!HMAC_Update(hctx, hmac->V, dctx->blocklength))
		return 0;

	if (!HMAC_Final(hctx, hmac->V, NULL))
		return 0;

	return 1;

	}

static int drbg_hmac_instantiate(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *nonce, size_t nonce_len,
				const unsigned char *pstr, size_t pstr_len)
	{
	DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
	memset(hmac->K, 0, dctx->blocklength);
	memset(hmac->V, 1, dctx->blocklength);
	if (!drbg_hmac_update(dctx,
			ent, ent_len, nonce, nonce_len, pstr, pstr_len))
		return 0;

#ifdef HMAC_DRBG_TRACE
	fprintf(stderr, "K+V after instantiate:\n");
	hexprint(stderr, hmac->K, hmac->blocklength);
	hexprint(stderr, hmac->V, hmac->blocklength);
#endif
	return 1;
	}

static int drbg_hmac_reseed(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *adin, size_t adin_len)
	{
	if (!drbg_hmac_update(dctx,
			ent, ent_len, adin, adin_len, NULL, 0))
		return 0;

#ifdef HMAC_DRBG_TRACE
	{
		DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
		fprintf(stderr, "K+V after reseed:\n");
		hexprint(stderr, hmac->K, hmac->blocklength);
		hexprint(stderr, hmac->V, hmac->blocklength);
	}
#endif
	return 1;
	}

static int drbg_hmac_generate(DRBG_CTX *dctx,
				unsigned char *out, size_t outlen,
				const unsigned char *adin, size_t adin_len)
	{
	DRBG_HMAC_CTX *hmac = &dctx->d.hmac;
	HMAC_CTX *hctx = &hmac->hctx;
	const unsigned char *Vtmp = hmac->V;
	if (adin_len && !drbg_hmac_update(dctx, adin, adin_len,
						NULL, 0, NULL, 0))
		return 0;
	for (;;)
		{
		if (!HMAC_Init_ex(hctx, hmac->K, dctx->blocklength,
							hmac->md, NULL))
			return 0;
		if (!HMAC_Update(hctx, Vtmp, dctx->blocklength))
			return 0;
		if (!(dctx->xflags & DRBG_FLAG_TEST) && !dctx->lb_valid)
			{
			if (!HMAC_Final(hctx, dctx->lb, NULL))
				return 0;
			dctx->lb_valid = 1;
			Vtmp = dctx->lb;
			continue;
			}
		else if (outlen > dctx->blocklength)
			{
			if (!HMAC_Final(hctx, out, NULL))
				return 0;
			if (!fips_drbg_cprng_test(dctx, out))
				return 0;
			Vtmp = out;
			}
		else
			{
			if (!HMAC_Final(hctx, hmac->V, NULL))
				return 0;
			if (!fips_drbg_cprng_test(dctx, hmac->V))
				return 0;
			memcpy(out, hmac->V, outlen);
			break;
			}
		out += dctx->blocklength;
		outlen -= dctx->blocklength;
		}
	if (!drbg_hmac_update(dctx, adin, adin_len, NULL, 0, NULL, 0))
		return 0;

	return 1;
	}

static int drbg_hmac_uninstantiate(DRBG_CTX *dctx)
	{
	HMAC_CTX_cleanup(&dctx->d.hmac.hctx);
	OPENSSL_cleanse(&dctx->d.hmac, sizeof(DRBG_HMAC_CTX));
	return 1;
	}

int fips_drbg_hmac_init(DRBG_CTX *dctx)
	{
	const EVP_MD *md = NULL;
	DRBG_HMAC_CTX *hctx = &dctx->d.hmac;
	dctx->strength = 256;
	switch (dctx->type)
		{
		case NID_hmacWithSHA1:
		md = EVP_sha1();
		dctx->strength = 128;
		break;

		case NID_hmacWithSHA224:
		md = EVP_sha224();
		dctx->strength = 192;
		break;

		case NID_hmacWithSHA256:
		md = EVP_sha256();
		break;

		case NID_hmacWithSHA384:
		md = EVP_sha384();
		break;

		case NID_hmacWithSHA512:
		md = EVP_sha512();
		break;

		default:
		dctx->strength = 0;
		return -2;
		}
        dctx->instantiate = drbg_hmac_instantiate;
        dctx->reseed = drbg_hmac_reseed;
        dctx->generate = drbg_hmac_generate;
        dctx->uninstantiate = drbg_hmac_uninstantiate;
	HMAC_CTX_init(&hctx->hctx);
	hctx->md = md;
	dctx->blocklength = M_EVP_MD_size(md);
	dctx->seedlen = M_EVP_MD_size(md);

        dctx->min_entropy = dctx->strength / 8;
        dctx->max_entropy = DRBG_MAX_LENGTH;

        dctx->min_nonce = dctx->min_entropy / 2;
        dctx->max_nonce = DRBG_MAX_LENGTH;

        dctx->max_pers = DRBG_MAX_LENGTH;
        dctx->max_adin = DRBG_MAX_LENGTH;

        dctx->max_request = 1<<16;
        dctx->reseed_interval = 1<<24;

	return 1;
	}
