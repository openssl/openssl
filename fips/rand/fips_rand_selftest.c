/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS



typedef struct
	{
	unsigned char DT[16];
	unsigned char V[16];
	unsigned char R[16];
	} AES_PRNG_TV;

/* The following test vectors are taken directly from the RGNVS spec */

static unsigned char aes_128_key[16] =
		{0xf3,0xb1,0x66,0x6d,0x13,0x60,0x72,0x42,
		 0xed,0x06,0x1c,0xab,0xb8,0xd4,0x62,0x02};

static AES_PRNG_TV aes_128_tv =
	{
				/* DT */
		{0xe6,0xb3,0xbe,0x78,0x2a,0x23,0xfa,0x62,
		 0xd7,0x1d,0x4a,0xfb,0xb0,0xe9,0x22,0xf9},
				/* V */
		{0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				/* R */
		{0x59,0x53,0x1e,0xd1,0x3b,0xb0,0xc0,0x55,
		 0x84,0x79,0x66,0x85,0xc1,0x2f,0x76,0x41}
	};

static unsigned char aes_192_key[24] =
		{0x15,0xd8,0x78,0x0d,0x62,0xd3,0x25,0x6e,
		 0x44,0x64,0x10,0x13,0x60,0x2b,0xa9,0xbc,
		 0x4a,0xfb,0xca,0xeb,0x4c,0x8b,0x99,0x3b};

static AES_PRNG_TV aes_192_tv =
	{
				/* DT */
		{0x3f,0xd8,0xff,0xe8,0x80,0x69,0x8b,0xc1,
		 0xbf,0x99,0x7d,0xa4,0x24,0x78,0xf3,0x4b},
				/* V */
		{0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				/* R */
		{0x17,0x07,0xd5,0x28,0x19,0x79,0x1e,0xef,
		 0xa5,0x0c,0xbf,0x25,0xe5,0x56,0xb4,0x93}
	};

static unsigned char aes_256_key[32] =
		{0x6d,0x14,0x06,0x6c,0xb6,0xd8,0x21,0x2d,
		 0x82,0x8d,0xfa,0xf2,0x7a,0x03,0xb7,0x9f,
		 0x0c,0xc7,0x3e,0xcd,0x76,0xeb,0xee,0xb5,
		 0x21,0x05,0x8c,0x4f,0x31,0x7a,0x80,0xbb};

static AES_PRNG_TV aes_256_tv =
	{
				/* DT */
		{0xda,0x3a,0x41,0xec,0x1d,0xa3,0xb0,0xd5,
		 0xf2,0xa9,0x4e,0x34,0x74,0x8e,0x9e,0x88},
				/* V */
		{0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				/* R */
		{0x35,0xc7,0xef,0xa7,0x78,0x4d,0x29,0xbc,
		 0x82,0x79,0x99,0xfb,0xd0,0xb3,0x3b,0x72}
	};

#define fips_x931_test(key, tv) \
	do_x931_test(key, sizeof key, &tv)

static int do_x931_test(unsigned char *key, int keylen,
			AES_PRNG_TV *tv)
	{
	unsigned char R[16], V[16];
	int rv = 1;
	memcpy(V, tv->V, sizeof(V));
	if (!FIPS_x931_set_key(key, keylen))
		return 0;
	if (!fips_post_started(FIPS_TEST_X931, keylen, NULL))
		return 1;
	if (!fips_post_corrupt(FIPS_TEST_X931, keylen, NULL))
		V[0]++;
	FIPS_x931_seed(V, 16);
	FIPS_x931_set_dt(tv->DT);
	FIPS_x931_bytes(R, 16);
	if (memcmp(R, tv->R, 16))
		{
		fips_post_failed(FIPS_TEST_X931, keylen, NULL);
		rv = 0;
		}
	else if (!fips_post_success(FIPS_TEST_X931, keylen, NULL))
		return 0;
	return rv;
	}

int FIPS_selftest_x931()
	{
	int rv = 1;
	FIPS_x931_reset();
	if (!FIPS_x931_test_mode())
		{
		FIPSerr(FIPS_F_FIPS_SELFTEST_X931,FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	if (!fips_x931_test(aes_128_key,aes_128_tv))
		rv = 0;
	if (!fips_x931_test(aes_192_key, aes_192_tv))
		rv = 0;
	if (!fips_x931_test(aes_256_key, aes_256_tv))
		rv = 0;
	FIPS_x931_reset();
	if (!rv)
		FIPSerr(FIPS_F_FIPS_SELFTEST_X931,FIPS_R_SELFTEST_FAILED);
	return rv;
	}

#endif
