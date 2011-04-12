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

static const char P_384_name[] = "ECDSA P-384";

static unsigned char P_384_d[] = {
	0x1d,0x84,0x42,0xde,0xa2,0x35,0x29,0xbd,0x9f,0xe2,0x6e,0x6d,
	0x01,0x26,0x30,0x79,0x33,0x57,0x01,0xf3,0x97,0x88,0x41,0xb3,
	0x82,0x07,0x08,0x5e,0x63,0x8e,0x1a,0xa6,0x9b,0x08,0xb6,0xe2,
	0xa2,0x98,0xac,0x1c,0x9b,0x25,0xb3,0xf1,0x5c,0x20,0xe9,0x85
};
static const unsigned char P_384_qx[] = {
	0x6b,0x7e,0x9c,0xbb,0x3d,0xc5,0x4d,0x53,0xf7,0x6c,0x8d,0xcc,
	0xf8,0xc3,0xa8,0x26,0xba,0xeb,0xa6,0x56,0x6a,0x41,0x98,0xb1,
	0x90,0x90,0xcc,0xe7,0x48,0x74,0x3d,0xe6,0xd7,0x65,0x90,0x3b,
	0x13,0x69,0xdc,0x8f,0x48,0xc1,0xb4,0xf4,0xb1,0x91,0x36,0x3f
};
static const unsigned char P_384_qy[] = {
	0x40,0xc2,0x62,0x2a,0xea,0xfb,0x47,0x75,0xb5,0xdc,0x2e,0x1e,
	0xa0,0xa9,0x1f,0x6a,0xb7,0x54,0xac,0xce,0x91,0xe8,0x5b,0x8c,
	0xe3,0xf5,0xb8,0x0e,0xcb,0x82,0xb0,0xd9,0x57,0x1d,0xeb,0x25,
	0xfc,0x03,0xe5,0x12,0x50,0x17,0x98,0x7f,0x14,0x7e,0x95,0x17
};

void FIPS_corrupt_ecdsa()
    	{
	P_384_d[0]++;
    	}

#ifndef OPENSSL_NO_EC2M

static const char K_409_name[] = "ECDSA K-409";

static const unsigned char K_409_d[] = {
	0x68,0xe1,0x64,0x0a,0xe6,0x80,0x57,0x53,0x8d,0x35,0xd1,0xec,
	0x69,0xea,0x82,0x05,0x47,0x48,0x4d,0xda,0x9f,0x8c,0xa0,0xf3,
	0x06,0xc7,0x77,0xcb,0x14,0x05,0x9f,0x5d,0xdd,0xe0,0x5d,0x68,
	0x4e,0x1a,0xe4,0x9c,0xe0,0x4d,0x4a,0x74,0x47,0x54,0x4e,0x55,
	0xae,0x70,0x8c
};
static const unsigned char K_409_qx[] = {
	0x01,0x07,0xd6,0x6f,0xa8,0xf8,0x0e,0xbb,0xb8,0xa7,0x83,0x04,
	0xc3,0x19,0x67,0x9e,0x73,0x7b,0xeb,0xf4,0x6c,0xf3,0xeb,0xda,
	0x0d,0xe7,0x60,0xaf,0x29,0x37,0x13,0x32,0x51,0xac,0xb6,0x35,
	0x00,0x60,0xfa,0xd5,0x8b,0x6d,0xae,0xb0,0xe9,0x46,0x7f,0xe2,
	0x2d,0x50,0x04,0x40
};
static const unsigned char K_409_qy[] = {
	0x0a,0x53,0xf1,0x4f,0x2a,0xa5,0x5a,0xfb,0x37,0xb4,0x76,0x47,
	0x1b,0x14,0xd1,0x8d,0x86,0x94,0x75,0x26,0xc3,0x0b,0x09,0x57,
	0x1d,0x26,0x38,0x33,0x84,0x97,0x9d,0x56,0xe1,0x0d,0x51,0x9b,
	0x2c,0xbb,0x3d,0x92,0x48,0xaa,0x2a,0x39,0x4f,0x07,0x92,0xbd,
	0xb0,0x4d,0x2e
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
	make_ecdsa_test(NID_secp384r1, P_384),
#ifndef OPENSSL_NO_EC2M
	make_ecdsa_test(NID_sect409k1, K_409)
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

		if (!fips_pkey_signature_test(&pk, NULL, 0,
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
