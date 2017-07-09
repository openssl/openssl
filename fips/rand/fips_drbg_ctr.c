/* fips/rand/fips_drbg_ctr.c */
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
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

static void inc_128(DRBG_CTR_CTX *cctx)
	{
	int i;
	unsigned char c;
	unsigned char *p = cctx->V + 15;
	for (i = 0; i < 16; i++)
		{
		c = *p;
		c++;
		*p = c;
		if (c)
			return;
		p--;
		}
	}

static void ctr_XOR(DRBG_CTR_CTX *cctx, const unsigned char *in, size_t inlen)
	{
	size_t i, n;
	/* Any zero padding will have no effect on the result as we
	 * are XORing. So just process however much input we have.
	 */

	if (!in || !inlen)
		return;

	if (inlen < cctx->keylen)
		n = inlen;
	else
		n = cctx->keylen;

	for (i = 0; i < n; i++)
		cctx->K[i] ^= in[i];
	if (inlen <= cctx->keylen)
		return;

	n = inlen - cctx->keylen;
	/* Should never happen */
	if (n > 16)
		n = 16;
	for (i = 0; i < 16; i++)
		cctx->V[i] ^= in[i + cctx->keylen];
	}

/* Process a complete block using BCC algorithm of SPP 800-90 10.4.3 */

static void ctr_BCC_block(DRBG_CTR_CTX *cctx, unsigned char *out,
				const unsigned char *in)
	{
	int i;
	for (i = 0; i < 16; i++)
		out[i] ^= in[i];
	AES_encrypt(out, out, &cctx->df_ks);
#if 0
fprintf(stderr, "BCC in+out\n");
BIO_dump_fp(stderr, in, 16);
BIO_dump_fp(stderr, out, 16);
#endif
	}

/* Handle several BCC operations for as much data as we need for K and X */
static void ctr_BCC_blocks(DRBG_CTR_CTX *cctx, const unsigned char *in)
	{
	ctr_BCC_block(cctx, cctx->KX, in);
	ctr_BCC_block(cctx, cctx->KX + 16, in);
	if (cctx->keylen != 16)
		ctr_BCC_block(cctx, cctx->KX + 32, in);
	}
/* Initialise BCC blocks: these have the value 0,1,2 in leftmost positions:
 * see 10.4.2 stage 7.
 */
static void ctr_BCC_init(DRBG_CTR_CTX *cctx)
	{
	memset(cctx->KX, 0, 48);
	memset(cctx->bltmp, 0, 16);
	ctr_BCC_block(cctx, cctx->KX, cctx->bltmp);
	cctx->bltmp[3] = 1;
	ctr_BCC_block(cctx, cctx->KX + 16, cctx->bltmp);
	if (cctx->keylen != 16)
		{
		cctx->bltmp[3] = 2;
		ctr_BCC_block(cctx, cctx->KX + 32, cctx->bltmp);
		}
	}

/* Process several blocks into BCC algorithm, some possibly partial */
static void ctr_BCC_update(DRBG_CTR_CTX *cctx,
				const unsigned char *in, size_t inlen)
	{
	if (!in || !inlen)
		return;
	/* If we have partial block handle it first */
	if (cctx->bltmp_pos)
		{
		size_t left = 16 - cctx->bltmp_pos;
		/* If we now have a complete block process it */
		if (inlen >= left)
			{
			memcpy(cctx->bltmp + cctx->bltmp_pos, in, left);
			ctr_BCC_blocks(cctx, cctx->bltmp);
			cctx->bltmp_pos = 0;
			inlen -= left;
			in += left;
			}
		}
	/* Process zero or more complete blocks */
	while (inlen >= 16)
		{
		ctr_BCC_blocks(cctx, in);
		in += 16;
		inlen -= 16;
		}
	/* Copy any remaining partial block to the temporary buffer */
	if (inlen > 0)
		{
		memcpy(cctx->bltmp + cctx->bltmp_pos, in, inlen);
		cctx->bltmp_pos += inlen;
		}
	}

static void ctr_BCC_final(DRBG_CTR_CTX *cctx)
	{
	if (cctx->bltmp_pos)
		{
		memset(cctx->bltmp + cctx->bltmp_pos, 0, 16 - cctx->bltmp_pos);
		ctr_BCC_blocks(cctx, cctx->bltmp);
		}
	}

static void ctr_df(DRBG_CTR_CTX *cctx,
			const unsigned char *in1, size_t in1len,
			const unsigned char *in2, size_t in2len,
			const unsigned char *in3, size_t in3len)
	{
	size_t inlen;
	unsigned char *p = cctx->bltmp;
	static unsigned char c80 = 0x80;

	ctr_BCC_init(cctx);
	if (!in1)
		in1len = 0;
	if (!in2)
		in2len = 0;
	if (!in3)
		in3len = 0;
	inlen = in1len + in2len + in3len;
	/* Initialise L||N in temporary block */
	*p++ = (inlen >> 24) & 0xff;
	*p++ = (inlen >> 16) & 0xff;
	*p++ = (inlen >> 8) & 0xff;
	*p++ = inlen & 0xff;
	/* NB keylen is at most 32 bytes */
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;
	*p = (unsigned char)((cctx->keylen + 16) & 0xff);
	cctx->bltmp_pos = 8;
	ctr_BCC_update(cctx, in1, in1len);
	ctr_BCC_update(cctx, in2, in2len);
	ctr_BCC_update(cctx, in3, in3len);
	ctr_BCC_update(cctx, &c80, 1);
	ctr_BCC_final(cctx);
	/* Set up key K */
	AES_set_encrypt_key(cctx->KX, cctx->keylen * 8, &cctx->df_kxks);
	/* X follows key K */
	AES_encrypt(cctx->KX + cctx->keylen, cctx->KX, &cctx->df_kxks);
	AES_encrypt(cctx->KX, cctx->KX + 16, &cctx->df_kxks);
	if (cctx->keylen != 16)
		AES_encrypt(cctx->KX + 16, cctx->KX + 32, &cctx->df_kxks);
#if 0
fprintf(stderr, "Output of ctr_df:\n");
BIO_dump_fp(stderr, cctx->KX, cctx->keylen + 16);
#endif
	}

/* NB the no-df  Update in SP800-90 specifies a constant input length
 * of seedlen, however other uses of this algorithm pad the input with
 * zeroes if necessary and have up to two parameters XORed together,
 * handle both cases in this function instead.
 */

static void ctr_Update(DRBG_CTX *dctx,
		const unsigned char *in1, size_t in1len,
		const unsigned char *in2, size_t in2len,
		const unsigned char *nonce, size_t noncelen)
	{
	DRBG_CTR_CTX *cctx = &dctx->d.ctr;
	/* ks is already setup for correct key */
	inc_128(cctx);
	AES_encrypt(cctx->V, cctx->K, &cctx->ks);
	/* If keylen longer than 128 bits need extra encrypt */
	if (cctx->keylen != 16)
		{
		inc_128(cctx);
		AES_encrypt(cctx->V, cctx->K + 16, &cctx->ks);
		}
	inc_128(cctx);
	AES_encrypt(cctx->V, cctx->V, &cctx->ks);
	/* If 192 bit key part of V is on end of K */
	if (cctx->keylen == 24)
		{
		memcpy(cctx->V + 8, cctx->V, 8);
		memcpy(cctx->V, cctx->K + 24, 8);
		}

	if (dctx->xflags & DRBG_FLAG_CTR_USE_DF)
		{
		/* If no input reuse existing derived value */
		if (in1 || nonce || in2)
			ctr_df(cctx, in1, in1len, nonce, noncelen, in2, in2len);
		/* If this a reuse input in1len != 0 */
		if (in1len)
			ctr_XOR(cctx, cctx->KX, dctx->seedlen);
		}
	else
		{
		ctr_XOR(cctx, in1, in1len);
		ctr_XOR(cctx, in2, in2len);
		}

	AES_set_encrypt_key(cctx->K, dctx->strength, &cctx->ks);
#if 0
fprintf(stderr, "K+V after update is:\n");
BIO_dump_fp(stderr, cctx->K, cctx->keylen);
BIO_dump_fp(stderr, cctx->V, 16);
#endif
	}

static int drbg_ctr_instantiate(DRBG_CTX *dctx,
			const unsigned char *ent, size_t entlen,
			const unsigned char *nonce, size_t noncelen,
			const unsigned char *pers, size_t perslen)
	{
	DRBG_CTR_CTX *cctx = &dctx->d.ctr;
	memset(cctx->K, 0, sizeof(cctx->K));
	memset(cctx->V, 0, sizeof(cctx->V));
	AES_set_encrypt_key(cctx->K, dctx->strength, &cctx->ks);
	ctr_Update(dctx, ent, entlen, pers, perslen, nonce, noncelen);
	return 1;
	}

static int drbg_ctr_reseed(DRBG_CTX *dctx, 
			const unsigned char *ent, size_t entlen,
			const unsigned char *adin, size_t adinlen)
	{
	ctr_Update(dctx, ent, entlen, adin, adinlen, NULL, 0);
	return 1;
	}

static int drbg_ctr_generate(DRBG_CTX *dctx,
			unsigned char *out, size_t outlen,
			const unsigned char *adin, size_t adinlen)
	{
	DRBG_CTR_CTX *cctx = &dctx->d.ctr;
	if (adin && adinlen)
		{
		ctr_Update(dctx, adin, adinlen, NULL, 0, NULL, 0);
		/* This means we reuse derived value */
		if (dctx->xflags & DRBG_FLAG_CTR_USE_DF)
			{
			adin = NULL;
			adinlen = 1;
			}
		}
	else
		adinlen = 0;

	for (;;)
		{
		inc_128(cctx);
		if (!(dctx->xflags & DRBG_FLAG_TEST) && !dctx->lb_valid)
			{
			AES_encrypt(cctx->V, dctx->lb, &cctx->ks);
			dctx->lb_valid = 1;
			continue;
			}
		if (outlen < 16)
			{
			/* Use K as temp space as it will be updated */
			AES_encrypt(cctx->V, cctx->K, &cctx->ks);
			if (!fips_drbg_cprng_test(dctx, cctx->K))
				return 0;
			memcpy(out, cctx->K, outlen);
			break;
			}
		AES_encrypt(cctx->V, out, &cctx->ks);
		if (!fips_drbg_cprng_test(dctx, out))
			return 0;
		out += 16;
		outlen -= 16;
		if (outlen == 0)
			break;
		}

	ctr_Update(dctx, adin, adinlen, NULL, 0, NULL, 0);

	return 1;

	}

static int drbg_ctr_uninstantiate(DRBG_CTX *dctx)
	{
	memset(&dctx->d.ctr, 0, sizeof(DRBG_CTR_CTX));
	return 1;
	}

int fips_drbg_ctr_init(DRBG_CTX *dctx)
	{
	DRBG_CTR_CTX *cctx = &dctx->d.ctr;

	size_t keylen;

	switch (dctx->type)
		{
		case NID_aes_128_ctr:
		keylen = 16;
		break;

		case NID_aes_192_ctr:
		keylen = 24;
		break;

		case NID_aes_256_ctr:
		keylen = 32;
		break;

		default:
		return -2;
		}

	dctx->instantiate = drbg_ctr_instantiate;
	dctx->reseed = drbg_ctr_reseed;
	dctx->generate = drbg_ctr_generate;
	dctx->uninstantiate = drbg_ctr_uninstantiate;

	cctx->keylen = keylen;
	dctx->strength = keylen * 8;
	dctx->blocklength = 16;
	dctx->seedlen = keylen + 16;

	if (dctx->xflags & DRBG_FLAG_CTR_USE_DF)
		{
		/* df initialisation */
		static unsigned char df_key[32] =
			{
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
			0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
			0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f 
			};
		/* Set key schedule for df_key */
		AES_set_encrypt_key(df_key, dctx->strength, &cctx->df_ks);

		dctx->min_entropy = cctx->keylen;
		dctx->max_entropy = DRBG_MAX_LENGTH;
		dctx->min_nonce = dctx->min_entropy / 2;
		dctx->max_nonce = DRBG_MAX_LENGTH;
		dctx->max_pers = DRBG_MAX_LENGTH;
		dctx->max_adin = DRBG_MAX_LENGTH;
		}
	else
		{
		dctx->min_entropy = dctx->seedlen;
		dctx->max_entropy = dctx->seedlen;
		/* Nonce not used */
		dctx->min_nonce = 0;
		dctx->max_nonce = 0;
		dctx->max_pers = dctx->seedlen;
		dctx->max_adin = dctx->seedlen;
		}

	dctx->max_request = 1<<16;
	dctx->reseed_interval = 1<<24;

	return 1;
	}
