/* fips/ecdh/fips_ecdh_selftest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2011.
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
 *
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS

#include "fips_locl.h"

__fips_constseg
static const unsigned char p224_qcavsx[] = {
	0x3c,0x81,0x15,0x16,0xab,0xa6,0xad,0xd7,0xe5,0xf3,0xea,0x1f,
	0x88,0x57,0x43,0x29,0x35,0x6f,0x0a,0xd2,0x38,0xc7,0x11,0x8a,
	0x90,0xd1,0x46,0x63
};
__fips_constseg
static const unsigned char p224_qcavsy[] = {
	0x4a,0x87,0x54,0x7b,0x7d,0x69,0xdd,0xb8,0x48,0x73,0xb2,0x1e,
	0x33,0xfa,0xf6,0x32,0xb4,0x25,0x73,0x55,0x87,0x08,0x16,0xd2,
	0xdd,0xa6,0x77,0xcf
};
__fips_constseg
static const unsigned char p224_qiutx[] = {
	0x23,0xff,0x15,0x91,0x83,0xd6,0xad,0x98,0x93,0x98,0xbd,0x2e,
	0x01,0xeb,0x5a,0x45,0xe2,0x2a,0xf9,0xc5,0x3b,0x37,0xe1,0x87,
	0x32,0xa5,0x16,0x5f
};
__fips_constseg
static const unsigned char p224_qiuty[] = {
	0x5e,0x70,0xb7,0x9d,0x9e,0x55,0x2d,0x67,0x4e,0x29,0xa4,0x9d,
	0x06,0x81,0x11,0xb4,0xb4,0xab,0xe2,0xdf,0xdc,0xe4,0xf1,0x69,
	0x55,0x54,0xe3,0x37
};
__fips_constseg
static const unsigned char p224_qiutd[] = {
	0xd7,0xdc,0x9c,0x53,0x04,0x72,0x67,0x59,0x92,0x80,0x9e,0x6f,
	0xdd,0xe6,0x0b,0x35,0x09,0xe0,0x95,0x45,0xe6,0x13,0x0e,0x22,
	0x43,0x6a,0x63,0xef
};
__fips_constseg
static const unsigned char p224_ziut[] = {
	0x84,0x37,0xcf,0x6d,0xfa,0x58,0xbd,0x1f,0x47,0x15,0x45,0x1f,
	0x2c,0x20,0x53,0x7a,0xf4,0xb0,0xe6,0x19,0xcc,0xa9,0x30,0xc6,
	0x5c,0x1a,0xf2,0xdd
};

typedef struct
	{
	int curve;
	const unsigned char *x1;
	size_t x1len;
	const unsigned char *y1;
	size_t y1len;
	const unsigned char *d1;
	size_t d1len;
	const unsigned char *x2;
	size_t x2len;
	const unsigned char *y2;
	size_t y2len;
	const unsigned char *z;
	size_t zlen;
	} ECDH_SELFTEST_DATA;

#define make_ecdh_test(nid, pr) { nid, \
				pr##_qiutx, sizeof(pr##_qiutx), \
				pr##_qiuty, sizeof(pr##_qiuty), \
				pr##_qiutd, sizeof(pr##_qiutd), \
				pr##_qcavsx, sizeof(pr##_qcavsx), \
				pr##_qcavsy, sizeof(pr##_qcavsy), \
				pr##_ziut, sizeof(pr##_ziut) }

static ECDH_SELFTEST_DATA test_ecdh_data[] =
	{
	make_ecdh_test(NID_secp224r1, p224),
	};

int FIPS_selftest_ecdh(void)
	{
	EC_KEY *ec1 = NULL, *ec2 = NULL;
	const EC_POINT *ecp = NULL;
	BIGNUM *x = NULL, *y = NULL, *d = NULL;
	unsigned char *ztmp = NULL;
	int rv = 1;
	size_t i;

	for (i = 0; i < sizeof(test_ecdh_data)/sizeof(ECDH_SELFTEST_DATA); i++)
		{
		ECDH_SELFTEST_DATA *ecd = test_ecdh_data + i;
		if (!fips_post_started(FIPS_TEST_ECDH, ecd->curve, 0))
			continue;
		ztmp = OPENSSL_malloc(ecd->zlen);

		x = BN_bin2bn(ecd->x1, ecd->x1len, x);
		y = BN_bin2bn(ecd->y1, ecd->y1len, y);
		d = BN_bin2bn(ecd->d1, ecd->d1len, d);

		if (!x || !y || !d || !ztmp)
			{
			rv = -1;
			goto err;
			}

		ec1 = EC_KEY_new_by_curve_name(ecd->curve);
		if (!ec1)
			{
			rv = -1;
			goto err;
			}
		EC_KEY_set_flags(ec1, EC_FLAG_COFACTOR_ECDH);

		if (!EC_KEY_set_public_key_affine_coordinates(ec1, x, y))
			{
			rv = -1;
			goto err;
			}

		if (!EC_KEY_set_private_key(ec1, d))
			{
			rv = -1;
			goto err;
			}

		x = BN_bin2bn(ecd->x2, ecd->x2len, x);
		y = BN_bin2bn(ecd->y2, ecd->y2len, y);

		if (!x || !y)
			{
			rv = -1;
			goto err;
			}

		ec2 = EC_KEY_new_by_curve_name(ecd->curve);
		if (!ec2)
			{
			rv = -1;
			goto err;
			}
		EC_KEY_set_flags(ec1, EC_FLAG_COFACTOR_ECDH);

		if (!EC_KEY_set_public_key_affine_coordinates(ec2, x, y))
			{
			rv = -1;
			goto err;
			}

		ecp = EC_KEY_get0_public_key(ec2);
		if (!ecp)
			{
			rv = -1;
			goto err;
			}

		if (!ECDH_compute_key(ztmp, ecd->zlen, ecp, ec1, 0))
			{
			rv = -1;
			goto err;
			}

		if (!fips_post_corrupt(FIPS_TEST_ECDH, ecd->curve, NULL))
			ztmp[0] ^= 0x1;

		if (memcmp(ztmp, ecd->z, ecd->zlen))
			{
			fips_post_failed(FIPS_TEST_ECDH, ecd->curve, 0);
			rv = 0;
			}
		else if (!fips_post_success(FIPS_TEST_ECDH, ecd->curve, 0))
			goto err;

		EC_KEY_free(ec1);
		ec1 = NULL;
		EC_KEY_free(ec2);
		ec2 = NULL;
		OPENSSL_free(ztmp);
		ztmp = NULL;
		}

	err:

	if (x)
		BN_clear_free(x);
	if (y)
		BN_clear_free(y);
	if (d)
		BN_clear_free(d);
	if (ec1)
		EC_KEY_free(ec1);
	if (ec2)
		EC_KEY_free(ec2);
	if (ztmp)
		OPENSSL_free(ztmp);

	return rv;

	}

#endif
