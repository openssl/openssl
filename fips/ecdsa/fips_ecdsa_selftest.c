/* fips/ecdsa/fips_ecdsa_selftest.c */
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
#include <openssl/ecdsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS

__fips_constseg
static const char P_224_name[] = "ECDSA P-224";

__fips_constseg
static const unsigned char P_224_d[] = {
	0x98,0x1f,0xb5,0xf1,0xfc,0x87,0x1d,0x7d,0xde,0x1e,0x01,0x64,
	0x09,0x9b,0xe7,0x1b,0x9f,0xad,0x63,0xdd,0x33,0x01,0xd1,0x50,
	0x80,0x93,0x50,0x30
};
__fips_constseg
static const unsigned char P_224_qx[] = {
	0x95,0x47,0x99,0x44,0x29,0x8f,0x51,0x39,0xe2,0x53,0xec,0x79,
	0xb0,0x4d,0xde,0x87,0x1a,0x76,0x54,0xd5,0x96,0xb8,0x7a,0x6d,
	0xf4,0x1c,0x2c,0x87
};
__fips_constseg
static const unsigned char P_224_qy[] = {
	0x91,0x5f,0xd5,0x31,0xdd,0x24,0xe5,0x78,0xd9,0x08,0x24,0x8a,
	0x49,0x99,0xec,0x55,0xf2,0x82,0xb3,0xc4,0xb7,0x33,0x68,0xe4,
	0x24,0xa9,0x12,0x82
};

#ifndef OPENSSL_NO_EC2M

__fips_constseg
static const char K_233_name[] = "ECDSA K-233";

__fips_constseg
static const unsigned char K_233_d[] = {
	0x10,0x0a,0xe0,0xae,0xcf,0x1b,0xa4,0x55,0x1a,0xd4,0xc8,0x3f,
	0xc3,0x7e,0xdc,0x97,0x40,0x2c,0x6a,0xc8,0xe2,0x50,0x09,0xf8,
	0x1c,0x70,0x23,0xcb,0xde
};
__fips_constseg
static const unsigned char K_233_qx[] = {
	0x01,0xa6,0xbf,0x38,0x32,0xe2,0xd7,0x15,0x4a,0xc8,0xaa,0x1f,
	0x9d,0xdb,0xb8,0x8f,0x9a,0x9b,0xc0,0xb4,0xc1,0xb6,0xa5,0x5c,
	0x93,0xb9,0x8a,0x83,0x65,0xe9
};
__fips_constseg
static const unsigned char K_233_qy[] = {
	0x01,0x81,0x3d,0xfe,0x38,0x56,0x8f,0x3c,0x23,0x29,0xc6,0x59,
	0xcb,0xa5,0x90,0x86,0xd1,0x8c,0xd8,0xb0,0xf2,0xd4,0x35,0x2b,
	0x11,0x40,0x33,0x9a,0x88,0x10
};

#endif

typedef struct
	{
	int curve;
	const char *name;
	const unsigned char *x;
	size_t xlen;
	const unsigned char *y;
	size_t ylen;
	const unsigned char *d;
	size_t dlen;
	} EC_SELFTEST_DATA;

#define make_ecdsa_test(nid, pr) { nid, pr##_name, \
				pr##_qx, sizeof(pr##_qx), \
				pr##_qy, sizeof(pr##_qy), \
				pr##_d, sizeof(pr##_d)}

static EC_SELFTEST_DATA test_ec_data[] =
	{
	make_ecdsa_test(NID_secp224r1, P_224),
#ifndef OPENSSL_NO_EC2M
	make_ecdsa_test(NID_sect233k1, K_233)
#endif
	};

int FIPS_selftest_ecdsa()
	{
	EC_KEY *ec = NULL;
	BIGNUM *x = NULL, *y = NULL, *d = NULL;
	EVP_PKEY pk;
	int rv = 0;
	size_t i;

	for (i = 0; i < sizeof(test_ec_data)/sizeof(EC_SELFTEST_DATA); i++)
		{
		EC_SELFTEST_DATA *ecd = test_ec_data + i;

		x = BN_bin2bn(ecd->x, ecd->xlen, x);
		y = BN_bin2bn(ecd->y, ecd->ylen, y);
		d = BN_bin2bn(ecd->d, ecd->dlen, d);

		if (!x || !y || !d)
			goto err;

		ec = EC_KEY_new_by_curve_name(ecd->curve);
		if (!ec)
			goto err;

		if (!EC_KEY_set_public_key_affine_coordinates(ec, x, y))
			goto err;

		if (!EC_KEY_set_private_key(ec, d))
			goto err;

		pk.type = EVP_PKEY_EC;
		pk.pkey.ec = ec;

		if (!fips_pkey_signature_test(FIPS_TEST_SIGNATURE, &pk, NULL, 0,
						NULL, 0, EVP_sha512(), 0,
						ecd->name))
			goto err;
		EC_KEY_free(ec);
		ec = NULL;
		}

	rv = 1;

	err:

	if (x)
		BN_clear_free(x);
	if (y)
		BN_clear_free(y);
	if (d)
		BN_clear_free(d);
	if (ec)
		EC_KEY_free(ec);

	return rv;

	}

#endif
