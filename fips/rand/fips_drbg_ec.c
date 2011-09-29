/* fips/rand/fips_drbg_ec.c */
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
#include <openssl/bn.h>
#include "fips_rand_lcl.h"

/*#define EC_DRBG_TRACE*/

#ifdef EC_DRBG_TRACE
static void hexprint(FILE *out, const unsigned char *buf, int buflen)
	{
	int i;
	fprintf(out, "\t");
	for (i = 0; i < buflen; i++)
		fprintf(out, "%02X", buf[i]);
	fprintf(out, "\n");
	}
static void bnprint(FILE *out, const char *name, const BIGNUM *b)
	{
	unsigned char *tmp;
	int len;
	len = BN_num_bytes(b);
	tmp = OPENSSL_malloc(len);
	BN_bn2bin(b, tmp);
	fprintf(out, "%s\n", name);
	hexprint(out, tmp, len);
	OPENSSL_free(tmp);
	}
#if 0
static void ecprint(FILE *out, EC_GROUP *grp, EC_POINT *pt)
	{
	BIGNUM *x, *y;
	x = BN_new();
	y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, NULL);
	bnprint(out, "\tPoint X: ", x);
	bnprint(out, "\tPoint Y: ", y);
	BN_free(x);
	BN_free(y);
	}
#endif
#endif

/* This is Hash_df from SP 800-90 10.4.1 */

static int hash_df(DRBG_CTX *dctx, unsigned char *out,
			const unsigned char *in1, size_t in1len,
			const unsigned char *in2, size_t in2len,
			const unsigned char *in3, size_t in3len)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	EVP_MD_CTX *mctx = &ectx->mctx;
	unsigned char *vtmp = ectx->vtmp;
	unsigned char tmp[6];
	size_t mdlen = M_EVP_MD_size(ectx->md);
	/* Standard only ever needs seedlen bytes which is always less than
	 * maximum permitted so no need to check length.
	 */
	size_t outlen = dctx->seedlen;
	size_t nbits = (outlen << 3) - ectx->exbits;
	tmp[0] = 1;
	tmp[1] = (nbits >> 24) & 0xff;
	tmp[2] = (nbits >> 16) & 0xff;
	tmp[3] = (nbits >> 8) & 0xff;
	tmp[4] = nbits & 0xff;
	if (!in1)
		{
		tmp[5] = (unsigned char)in1len;
		in1 = tmp + 5;
		in1len = 1;
		}
	for (;;)
		{
		if (!FIPS_digestinit(mctx, ectx->md))
			return 0;
		if (!FIPS_digestupdate(mctx, tmp, 5))
			return 0;
		if (in1 && !FIPS_digestupdate(mctx, in1, in1len))
			return 0;
		if (in2 && !FIPS_digestupdate(mctx, in2, in2len))
			return 0;
		if (in3 && !FIPS_digestupdate(mctx, in3, in3len))
			return 0;
		if (outlen < mdlen)
			{
			if (!FIPS_digestfinal(mctx, vtmp, NULL))
				return 0;
			memcpy(out, vtmp, outlen);
			OPENSSL_cleanse(vtmp, mdlen);
			return 1;
			}
		else if(!FIPS_digestfinal(mctx, out, NULL))
			return 0;

		outlen -= mdlen;
		if (outlen == 0)
			return 1;
		tmp[0]++;
		out += mdlen;
		}
	}

static int bn2binpad(unsigned char *to, size_t tolen, BIGNUM *b)
	{
	size_t blen;
	blen = BN_num_bytes(b);
	/* If BIGNUM length greater than buffer, mask to get rightmost
	 * bytes. NB: modifies b but this doesn't matter for our purposes.
	 */
	if (blen > tolen)
		{
		BN_mask_bits(b, tolen << 3);
		/* Update length because mask operation might create leading
		 * zeroes.
		 */
		blen = BN_num_bytes(b);
		}
	/* If b length smaller than buffer pad with zeroes */
	if (blen < tolen)
		{
		memset(to, 0, tolen - blen);
		to += tolen - blen;
		}

	/* This call cannot fail */
	BN_bn2bin(b, to);
	return 1;
	}
/* Convert buffer to a BIGNUM discarding extra bits if necessary */
static int bin2bnbits(DRBG_CTX *dctx, BIGNUM *r, const unsigned char *buf)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	if (!BN_bin2bn(buf, dctx->seedlen, r))
		return 0;
	/* If we have extra bits right shift off the end of r */
	if (ectx->exbits)
		{
		if (!BN_rshift(r, r, ectx->exbits))
			return 0;
		}
	return 1;
	}

/* Calculate r = phi(s * P) or r= phi(s * Q) */

static int drbg_ec_mul(DRBG_EC_CTX *ectx, BIGNUM *r, const BIGNUM *s, int use_q)
	{
	if (use_q)
		{
		if (!EC_POINT_mul(ectx->curve, ectx->ptmp,
						NULL, ectx->Q, s, ectx->bctx))
			return 0;
		}
	else
		{
		if (!EC_POINT_mul(ectx->curve, ectx->ptmp,
						s, NULL, NULL, ectx->bctx))
			return 0;
		}
	/* Get x coordinate of result */
	if (!EC_POINT_get_affine_coordinates_GFp(ectx->curve, ectx->ptmp, r,
							NULL, ectx->bctx))
		return 0;
	return 1;
	}

static int drbg_ec_instantiate(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *nonce, size_t nonce_len,
				const unsigned char *pstr, size_t pstr_len)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	if (!hash_df(dctx, ectx->sbuf, 
			ent, ent_len, nonce, nonce_len, pstr, pstr_len))
		return 0;
	if (!bin2bnbits(dctx, ectx->s, ectx->sbuf))
		return 0;
	return 1;
	}

	
static int drbg_ec_reseed(DRBG_CTX *dctx,
				const unsigned char *ent, size_t ent_len,
				const unsigned char *adin, size_t adin_len)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	/* Convert s value to a binary buffer. Save it to tbuf as we are
	 * about to overwrite it.
	 */
	if (ectx->exbits)
		BN_lshift(ectx->s, ectx->s, ectx->exbits);
	bn2binpad(ectx->tbuf, dctx->seedlen, ectx->s);
	if (!hash_df(dctx, ectx->sbuf, ectx->tbuf, dctx->seedlen, 
			ent, ent_len, adin, adin_len))
		return 0;
	if (!bin2bnbits(dctx, ectx->s, ectx->sbuf))
		return 0;
	dctx->reseed_counter = 0;
	return 1;
	}

static int drbg_ec_generate(DRBG_CTX *dctx,
				unsigned char *out, size_t outlen,
				const unsigned char *adin, size_t adin_len)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	BIGNUM *t, *r;
	BIGNUM *s = ectx->s;
	/* special case: check reseed interval */
	if (out == NULL)
		{
		size_t nb = (outlen + dctx->blocklength - 1)/dctx->blocklength;
		if (dctx->reseed_counter + nb > dctx->reseed_interval)
			dctx->status = DRBG_STATUS_RESEED;
		return 1;
		}

	BN_CTX_start(ectx->bctx);
	r = BN_CTX_get(ectx->bctx);
	if (!r)
		goto err;
	if (adin && adin_len)
		{
		size_t i;
		t = BN_CTX_get(ectx->bctx);
		if (!t)
			goto err;
		/* Convert s to buffer */
		if (ectx->exbits)
			BN_lshift(s, s, ectx->exbits);
		bn2binpad(ectx->sbuf, dctx->seedlen, s);
		/* Step 2 */
		if (!hash_df(dctx, ectx->tbuf, adin, adin_len,
				NULL, 0, NULL, 0))
			goto err;
		/* Step 5 */
		for (i = 0; i < dctx->seedlen; i++)
			ectx->tbuf[i] ^= ectx->sbuf[i];
		if (!bin2bnbits(dctx, t, ectx->tbuf))
			return 0;
		}
	else
		/* Note if no additional input the algorithm never
		 * needs separate values for t and s.
		 */
		t = s;

#ifdef EC_DRBG_TRACE
	bnprint(stderr, "s at start of generate: ", s);
#endif

	for (;;)
		{
		/* Step #6, calculate s = t * P */
		if (!drbg_ec_mul(ectx, s, t, 0))
			goto err;
#ifdef EC_DRBG_TRACE
		bnprint(stderr, "s in generate: ", ectx->s);
#endif
		/* Step #7, calculate r = s * Q */
		if (!drbg_ec_mul(ectx, r, s, 1))
			goto err;
#ifdef EC_DRBG_TRACE
	bnprint(stderr, "r in generate is: ", r);
#endif
		dctx->reseed_counter++;
		/* Get rightmost bits of r to output buffer */

		if (!(dctx->xflags & DRBG_FLAG_TEST) && !dctx->lb_valid)
			{
			if (!bn2binpad(dctx->lb, dctx->blocklength, r))
				goto err;
			dctx->lb_valid = 1;
			continue;
			}
		if (outlen < dctx->blocklength)
			{
			if (!bn2binpad(ectx->vtmp, dctx->blocklength, r))
				goto err;
			if (!fips_drbg_cprng_test(dctx, ectx->vtmp))
				goto err;
			memcpy(out, ectx->vtmp, outlen);
			break;
			}
		else
			{
			if (!bn2binpad(out, dctx->blocklength, r))
				goto err;
			if (!fips_drbg_cprng_test(dctx, out))
				goto err;
			}	
		outlen -= dctx->blocklength;
		if (!outlen)
			break;
		out += dctx->blocklength;
		/* Step #5 after first pass */
		t = s;
#ifdef EC_DRBG_TRACE
		fprintf(stderr, "Random bits written:\n");
		hexprint(stderr, out, dctx->blocklength);
#endif
		}
	if (!drbg_ec_mul(ectx, ectx->s, ectx->s, 0))
		return 0;
#ifdef EC_DRBG_TRACE
	bnprint(stderr, "s after generate is: ", s);
#endif
	BN_CTX_end(ectx->bctx);
	return 1;
	err:
	BN_CTX_end(ectx->bctx);
	return 0;
	}

static int drbg_ec_uninstantiate(DRBG_CTX *dctx)
	{
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	EVP_MD_CTX_cleanup(&ectx->mctx);
	EC_GROUP_free(ectx->curve);
	EC_POINT_free(ectx->Q);
	EC_POINT_free(ectx->ptmp);
	BN_clear_free(ectx->s);
	BN_CTX_free(ectx->bctx);
	OPENSSL_cleanse(&dctx->d.ec, sizeof(DRBG_EC_CTX));
	return 1;
	}

/* Q points from SP 800-90 A.1, P is generator */

__fips_constseg
static const unsigned char p_256_qx[] = {
	0xc9,0x74,0x45,0xf4,0x5c,0xde,0xf9,0xf0,0xd3,0xe0,0x5e,0x1e,
	0x58,0x5f,0xc2,0x97,0x23,0x5b,0x82,0xb5,0xbe,0x8f,0xf3,0xef,
	0xca,0x67,0xc5,0x98,0x52,0x01,0x81,0x92
};
__fips_constseg
static const unsigned char p_256_qy[] = {
	0xb2,0x8e,0xf5,0x57,0xba,0x31,0xdf,0xcb,0xdd,0x21,0xac,0x46,
	0xe2,0xa9,0x1e,0x3c,0x30,0x4f,0x44,0xcb,0x87,0x05,0x8a,0xda,
	0x2c,0xb8,0x15,0x15,0x1e,0x61,0x00,0x46
};

__fips_constseg
static const unsigned char p_384_qx[] = {
	0x8e,0x72,0x2d,0xe3,0x12,0x5b,0xdd,0xb0,0x55,0x80,0x16,0x4b,
	0xfe,0x20,0xb8,0xb4,0x32,0x21,0x6a,0x62,0x92,0x6c,0x57,0x50,
	0x2c,0xee,0xde,0x31,0xc4,0x78,0x16,0xed,0xd1,0xe8,0x97,0x69,
	0x12,0x41,0x79,0xd0,0xb6,0x95,0x10,0x64,0x28,0x81,0x50,0x65
};
__fips_constseg
static const unsigned char p_384_qy[] = {
	0x02,0x3b,0x16,0x60,0xdd,0x70,0x1d,0x08,0x39,0xfd,0x45,0xee,
	0xc3,0x6f,0x9e,0xe7,0xb3,0x2e,0x13,0xb3,0x15,0xdc,0x02,0x61,
	0x0a,0xa1,0xb6,0x36,0xe3,0x46,0xdf,0x67,0x1f,0x79,0x0f,0x84,
	0xc5,0xe0,0x9b,0x05,0x67,0x4d,0xbb,0x7e,0x45,0xc8,0x03,0xdd
};

__fips_constseg
static const unsigned char p_521_qx[] = {
	0x01,0xb9,0xfa,0x3e,0x51,0x8d,0x68,0x3c,0x6b,0x65,0x76,0x36,
	0x94,0xac,0x8e,0xfb,0xae,0xc6,0xfa,0xb4,0x4f,0x22,0x76,0x17,
	0x1a,0x42,0x72,0x65,0x07,0xdd,0x08,0xad,0xd4,0xc3,0xb3,0xf4,
	0xc1,0xeb,0xc5,0xb1,0x22,0x2d,0xdb,0xa0,0x77,0xf7,0x22,0x94,
	0x3b,0x24,0xc3,0xed,0xfa,0x0f,0x85,0xfe,0x24,0xd0,0xc8,0xc0,
	0x15,0x91,0xf0,0xbe,0x6f,0x63
};
__fips_constseg
static const unsigned char p_521_qy[] = {
	0x01,0xf3,0xbd,0xba,0x58,0x52,0x95,0xd9,0xa1,0x11,0x0d,0x1d,
	0xf1,0xf9,0x43,0x0e,0xf8,0x44,0x2c,0x50,0x18,0x97,0x6f,0xf3,
	0x43,0x7e,0xf9,0x1b,0x81,0xdc,0x0b,0x81,0x32,0xc8,0xd5,0xc3,
	0x9c,0x32,0xd0,0xe0,0x04,0xa3,0x09,0x2b,0x7d,0x32,0x7c,0x0e,
	0x7a,0x4d,0x26,0xd2,0xc7,0xb6,0x9b,0x58,0xf9,0x06,0x66,0x52,
	0x91,0x1e,0x45,0x77,0x79,0xde
};

int fips_drbg_ec_init(DRBG_CTX *dctx)
	{
	const EVP_MD *md;
	const unsigned char *Q_x, *Q_y;
	BIGNUM *x, *y;
	size_t ptlen;
	int md_nid = dctx->type & 0xffff;
	int curve_nid = dctx->type >> 16;
	DRBG_EC_CTX *ectx = &dctx->d.ec;
	md = FIPS_get_digestbynid(md_nid);
	if (!md)
		return -2;

	/* These are taken from SP 800-90 10.3.1 table 4 */
	switch (curve_nid)
		{
		case NID_X9_62_prime256v1:
		dctx->strength = 128;
		dctx->seedlen = 32;
		dctx->blocklength = 30;
		ectx->exbits = 0;
		Q_x = p_256_qx;
		Q_y = p_256_qy;
		ptlen = sizeof(p_256_qx);
		break;

		case NID_secp384r1:
		if (md_nid == NID_sha1)
			return -2;
		dctx->strength = 192;
		dctx->seedlen = 48;
		dctx->blocklength = 46;
		ectx->exbits = 0;
		Q_x = p_384_qx;
		Q_y = p_384_qy;
		ptlen = sizeof(p_384_qx);
		break;

		case NID_secp521r1:
		if (md_nid == NID_sha1 || md_nid == NID_sha224)
			return -2;
		dctx->strength = 256;
		dctx->seedlen = 66;
		dctx->blocklength = 63;
		ectx->exbits = 7;
		Q_x = p_521_qx;
		Q_y = p_521_qy;
		ptlen = sizeof(p_521_qx);
		break;

		default:
		return -2;
		}

	dctx->iflags |= DRBG_CUSTOM_RESEED;
	dctx->reseed_counter = 0;
	dctx->instantiate = drbg_ec_instantiate;
	dctx->reseed = drbg_ec_reseed;
	dctx->generate = drbg_ec_generate;
	dctx->uninstantiate = drbg_ec_uninstantiate;

	ectx->md = md;
	EVP_MD_CTX_init(&ectx->mctx);

	dctx->min_entropy = dctx->strength / 8;
	dctx->max_entropy = 2 << 10;

	dctx->min_nonce = dctx->min_entropy / 2;
	dctx->max_nonce = 2 << 10;

	dctx->max_pers = 2 << 10;
	dctx->max_adin = 2 << 10;

	dctx->reseed_interval = 1<<24;
	dctx->max_request = dctx->reseed_interval * dctx->blocklength;

	/* Setup internal structures */
	ectx->bctx = BN_CTX_new();
	if (!ectx->bctx)
		return 0;
	BN_CTX_start(ectx->bctx);

	ectx->s = BN_new();

	ectx->curve = EC_GROUP_new_by_curve_name(curve_nid);

	ectx->Q = EC_POINT_new(ectx->curve);
	ectx->ptmp = EC_POINT_new(ectx->curve);

	x = BN_CTX_get(ectx->bctx);
	y = BN_CTX_get(ectx->bctx);

	if (!ectx->s || !ectx->curve || !ectx->Q || !y)
		goto err;

	if (!BN_bin2bn(Q_x, ptlen, x) || !BN_bin2bn(Q_y, ptlen, y))
		goto err;
	if (!EC_POINT_set_affine_coordinates_GFp(ectx->curve, ectx->Q,
							x, y, ectx->bctx))
		goto err;

	BN_CTX_end(ectx->bctx);

	return 1;
	err:
	BN_CTX_end(ectx->bctx);
	drbg_ec_uninstantiate(dctx);
	return 0;
	}
