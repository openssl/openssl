/* fips/rand/fips_drbg_hash.c */
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

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

/* This is Hash_df from SP 800-90 10.4.1 */

static int hash_df(DRBG_CTX *dctx, unsigned char *out,
			const unsigned char *in1, size_t in1len,
			const unsigned char *in2, size_t in2len,
			const unsigned char *in3, size_t in3len,
			const unsigned char *in4, size_t in4len)
	{
	EVP_MD_CTX *mctx = &dctx->d.hash.mctx;
	unsigned char *vtmp = dctx->d.hash.vtmp;
	unsigned char tmp[6];
	/* Standard only ever needs seedlen bytes which is always less than
	 * maximum permitted so no need to check length.
	 */
	size_t outlen = dctx->seedlen;
	tmp[0] = 1;
	tmp[1] = ((outlen * 8) >> 24) & 0xff;
	tmp[2] = ((outlen * 8) >> 16) & 0xff;
	tmp[3] = ((outlen * 8) >> 8) & 0xff;
	tmp[4] = (outlen * 8) & 0xff;
	if (!in1)
		{
		tmp[5] = (unsigned char)in1len;
		in1 = tmp + 5;
		in1len = 1;
		}
	for (;;)
		{
		if (!FIPS_digestinit(mctx, dctx->d.hash.md))
			return 0;
		if (!FIPS_digestupdate(mctx, tmp, 5))
			return 0;
		if (in1 && !FIPS_digestupdate(mctx, in1, in1len))
			return 0;
		if (in2 && !FIPS_digestupdate(mctx, in2, in2len))
			return 0;
		if (in3 && !FIPS_digestupdate(mctx, in3, in3len))
			return 0;
		if (in4 && !FIPS_digestupdate(mctx, in4, in4len))
			return 0;
		if (outlen < dctx->blocklength)
			{
			if (!FIPS_digestfinal(mctx, vtmp, NULL))
				return 0;
			memcpy(out, vtmp, outlen);
			OPENSSL_cleanse(vtmp, dctx->blocklength);
			return 1;
			}
		else if(!FIPS_digestfinal(mctx, out, NULL))
			return 0;

		outlen -= dctx->blocklength;
		if (outlen == 0)
			return 1;
		tmp[0]++;
		out += dctx->blocklength;
		}
	}


/* Add an unsigned buffer to the buf value, storing the result in buf. For
 * this algorithm the length of input never exceeds the seed length.
 */

static void ctx_add_buf(DRBG_CTX *dctx, unsigned char *buf,
				unsigned char *in, size_t inlen)
	{
	size_t i = inlen;
	const unsigned char *q;
	unsigned char c, *p;
	p = buf + dctx->seedlen;
	q = in + inlen;

	OPENSSL_assert(i <= dctx->seedlen);

	/* Special case: zero length, just increment buffer */
	if (i)
		c = 0;
	else 
		c = 1;

	while (i)
		{
		int r;
		p--;
		q--;
		r = *p + *q + c;
		/* Carry */
		if (r > 0xff)
			c = 1;
		else
			c = 0;
		*p = r & 0xff;
		i--;
		}

	i = dctx->seedlen - inlen;

	/* If not adding whole buffer handle final carries */
	if (c && i)
		{
		do
			{
			p--;
			c = *p;
			c++;
			*p = c;
			if(c)
				return;
			} while(i--);
		}
	}

/* Finalise and add hash to V */
	
static int ctx_add_md(DRBG_CTX *dctx)
	{
	if (!FIPS_digestfinal(&dctx->d.hash.mctx, dctx->d.hash.vtmp, NULL))
			return 0;
	ctx_add_buf(dctx, dctx->d.hash.V, dctx->d.hash.vtmp, dctx->blocklength);
	return 1;
	}

static int hash_gen(DRBG_CTX *dctx, unsigned char *out, size_t outlen)
	{
	DRBG_HASH_CTX *hctx = &dctx->d.hash;
	if (outlen == 0)
		return 1;
	memcpy(hctx->vtmp, hctx->V, dctx->seedlen);
	for(;;)
		{
		FIPS_digestinit(&hctx->mctx, hctx->md);
		FIPS_digestupdate(&hctx->mctx, hctx->vtmp, dctx->seedlen);
		if (!(dctx->xflags & DRBG_FLAG_TEST) && !dctx->lb_valid)
			{
			FIPS_digestfinal(&hctx->mctx, dctx->lb, NULL);
			dctx->lb_valid = 1;
			}
		else if (outlen < dctx->blocklength)
			{
			FIPS_digestfinal(&hctx->mctx, hctx->vtmp, NULL);
			if (!fips_drbg_cprng_test(dctx, hctx->vtmp))
				return 0;
			memcpy(out, hctx->vtmp, outlen);
			return 1;
			}
		else
			{
			FIPS_digestfinal(&hctx->mctx, out, NULL);
			if (!fips_drbg_cprng_test(dctx, out))
				return 0;
			outlen -= dctx->blocklength;
			if (outlen == 0)
				return 1;
			out += dctx->blocklength;
			}
		ctx_add_buf(dctx, hctx->vtmp, NULL, 0);
		}
	}

static int drbg_hash_instantiate(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *nonce, size_t nonce_len,
				const unsigned char *pstr, size_t pstr_len)
	{
	DRBG_HASH_CTX *hctx = &dctx->d.hash;
	if (!hash_df(dctx, hctx->V, 
			ent, ent_len, nonce, nonce_len, pstr, pstr_len,
			NULL, 0))
		return 0;
	if (!hash_df(dctx, hctx->C, 
			NULL, 0, hctx->V, dctx->seedlen,
			NULL, 0, NULL, 0))
		return 0;

#ifdef HASH_DRBG_TRACE
	fprintf(stderr, "V+C after instantiate:\n");
	hexprint(stderr, hctx->V, dctx->seedlen);
	hexprint(stderr, hctx->C, dctx->seedlen);
#endif
	return 1;
	}

	
static int drbg_hash_reseed(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *adin, size_t adin_len)
	{
	DRBG_HASH_CTX *hctx = &dctx->d.hash;
	/* V about to be updated so use C as output instead */
	if (!hash_df(dctx, hctx->C,
			NULL, 1, hctx->V, dctx->seedlen,
			ent, ent_len, adin, adin_len))
		return 0;
	memcpy(hctx->V, hctx->C, dctx->seedlen);
	if (!hash_df(dctx, hctx->C, NULL, 0,
			hctx->V, dctx->seedlen, NULL, 0, NULL, 0))
		return 0;
#ifdef HASH_DRBG_TRACE
	fprintf(stderr, "V+C after reseed:\n");
	hexprint(stderr, hctx->V, dctx->seedlen);
	hexprint(stderr, hctx->C, dctx->seedlen);
#endif
	return 1;
	}

static int drbg_hash_generate(DRBG_CTX *dctx,
				unsigned char *out, size_t outlen,
				const unsigned char *adin, size_t adin_len)
	{
	DRBG_HASH_CTX *hctx = &dctx->d.hash;
	EVP_MD_CTX *mctx = &hctx->mctx;
	unsigned char tmp[4];
	if (adin && adin_len)
		{
		tmp[0] = 2;
		if (!FIPS_digestinit(mctx, hctx->md))
			return 0;
		if (!EVP_DigestUpdate(mctx, tmp, 1))
			return 0;
		if (!EVP_DigestUpdate(mctx, hctx->V, dctx->seedlen))
			return 0;
		if (!EVP_DigestUpdate(mctx, adin, adin_len))
			return 0;
		if (!ctx_add_md(dctx))
			return 0;
		}
	if (!hash_gen(dctx, out, outlen))
		return 0;

	tmp[0] = 3;
	if (!FIPS_digestinit(mctx, hctx->md))
		return 0;
	if (!EVP_DigestUpdate(mctx, tmp, 1))
		return 0;
	if (!EVP_DigestUpdate(mctx, hctx->V, dctx->seedlen))
		return 0;

	if (!ctx_add_md(dctx))
		return 0;

	ctx_add_buf(dctx, hctx->V, hctx->C, dctx->seedlen);

	tmp[0] = (dctx->reseed_counter >> 24) & 0xff;
	tmp[1] = (dctx->reseed_counter >> 16) & 0xff;
	tmp[2] = (dctx->reseed_counter >> 8) & 0xff;
	tmp[3] = dctx->reseed_counter & 0xff;
	ctx_add_buf(dctx, hctx->V, tmp, 4);
#ifdef HASH_DRBG_TRACE
	fprintf(stderr, "V+C after generate:\n");
	hexprint(stderr, hctx->V, dctx->seedlen);
	hexprint(stderr, hctx->C, dctx->seedlen);
#endif
	return 1;
	}

static int drbg_hash_uninstantiate(DRBG_CTX *dctx)
	{
	EVP_MD_CTX_cleanup(&dctx->d.hash.mctx);
	OPENSSL_cleanse(&dctx->d.hash, sizeof(DRBG_HASH_CTX));
	return 1;
	}

int fips_drbg_hash_init(DRBG_CTX *dctx)
	{
	const EVP_MD *md;
	DRBG_HASH_CTX *hctx = &dctx->d.hash;
	md = FIPS_get_digestbynid(dctx->type);
	if (!md)
		return -2;
	switch (dctx->type)
		{
		case NID_sha1:
		dctx->strength = 128;
		break;

		case NID_sha224:
		dctx->strength = 192;
		break;

		default:
		dctx->strength = 256;
		break;
		}

	dctx->instantiate = drbg_hash_instantiate;
	dctx->reseed = drbg_hash_reseed;
	dctx->generate = drbg_hash_generate;
	dctx->uninstantiate = drbg_hash_uninstantiate;

	dctx->d.hash.md = md;
	EVP_MD_CTX_init(&hctx->mctx);

	/* These are taken from SP 800-90 10.1 table 2 */

	dctx->blocklength = M_EVP_MD_size(md);
	if (dctx->blocklength > 32)
		dctx->seedlen = 111;
	else
		dctx->seedlen = 55;


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
