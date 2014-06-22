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
#include <openssl/cmac.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS
typedef struct {
	int nid;
	const unsigned char key[EVP_MAX_KEY_LENGTH]; size_t keysize;
	const unsigned char msg[64]; size_t msgsize;
	const unsigned char mac[32]; size_t macsize;
} CMAC_KAT;

/* from http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf */
__fips_constseg
static const CMAC_KAT vector[] = {
    {	NID_aes_128_cbc,	/* Count = 32 from CMACGenAES128.txt */
	{ 0x77,0xa7,0x7f,0xaf, 0x29,0x0c,0x1f,0xa3,
	  0x0c,0x68,0x3d,0xf1, 0x6b,0xa7,0xa7,0x7b, }, 128,
	{ 0x02,0x06,0x83,0xe1, 0xf0,0x39,0x2f,0x4c,
	  0xac,0x54,0x31,0x8b, 0x60,0x29,0x25,0x9e,
	  0x9c,0x55,0x3d,0xbc, 0x4b,0x6a,0xd9,0x98,
	  0xe6,0x4d,0x58,0xe4, 0xe7,0xdc,0x2e,0x13, }, 256,
	{ 0xfb,0xfe,0xa4,0x1b, }, 32
    },
    {	NID_aes_192_cbc,	/* Count = 23 from CMACGenAES192.txt */
	{ 0x7b,0x32,0x39,0x13, 0x69,0xaa,0x4c,0xa9,
	  0x75,0x58,0x09,0x5b, 0xe3,0xc3,0xec,0x86,
	  0x2b,0xd0,0x57,0xce, 0xf1,0xe3,0x2d,0x62, }, 192,
	{ 0x0 }, 0,
	{ 0xe4,0xd9,0x34,0x0b, 0x03,0xe6,0x7d,0xef,
	  0xd4,0x96,0x9c,0xc1, 0xed,0x37,0x35,0xe6, }, 128,
    },
    {	NID_aes_256_cbc,	/* Count = 33 from CMACGenAES256.txt */
	{ 0x0b,0x12,0x2a,0xc8, 0xf3,0x4e,0xd1,0xfe,
	  0x08,0x2a,0x36,0x25, 0xd1,0x57,0x56,0x14,
	  0x54,0x16,0x7a,0xc1, 0x45,0xa1,0x0b,0xbf,
	  0x77,0xc6,0xa7,0x05, 0x96,0xd5,0x74,0xf1, }, 256,
	{ 0x49,0x8b,0x53,0xfd, 0xec,0x87,0xed,0xcb,
	  0xf0,0x70,0x97,0xdc, 0xcd,0xe9,0x3a,0x08,
	  0x4b,0xad,0x75,0x01, 0xa2,0x24,0xe3,0x88,
	  0xdf,0x34,0x9c,0xe1, 0x89,0x59,0xfe,0x84,
	  0x85,0xf8,0xad,0x15, 0x37,0xf0,0xd8,0x96,
	  0xea,0x73,0xbe,0xdc, 0x72,0x14,0x71,0x3f, }, 384,
	{ 0xf6,0x2c,0x46,0x32, 0x9b, }, 40,
    },
    {	NID_des_ede3_cbc,	/* Count = 41 from CMACGenTDES3.req */
	{ 0x89,0xbc,0xd9,0x52, 0xa8,0xc8,0xab,0x37,
	  0x1a,0xf4,0x8a,0xc7, 0xd0,0x70,0x85,0xd5,
	  0xef,0xf7,0x02,0xe6, 0xd6,0x2c,0xdc,0x23, }, 192,
	{ 0xfa,0x62,0x0c,0x1b, 0xbe,0x97,0x31,0x9e,
	  0x9a,0x0c,0xf0,0x49, 0x21,0x21,0xf7,0xa2,
	  0x0e,0xb0,0x8a,0x6a, 0x70,0x9d,0xcb,0xd0,
	  0x0a,0xaf,0x38,0xe4, 0xf9,0x9e,0x75,0x4e, }, 256,
	{ 0x8f,0x49,0xa1,0xb7, 0xd6,0xaa,0x22,0x58, }, 64,
    },
};

int FIPS_selftest_cmac()
	{
	size_t n, outlen;
	unsigned char    out[32];
	const EVP_CIPHER *cipher;
	CMAC_CTX *ctx = CMAC_CTX_new();
	const CMAC_KAT *t;
	int subid = -1, rv = 1;

	for(n=0,t=vector; n<sizeof(vector)/sizeof(vector[0]); n++,t++)
		{
		cipher = FIPS_get_cipherbynid(t->nid);
		if (!cipher)
			{
			rv = -1;
			goto err;
			}
		subid = M_EVP_CIPHER_nid(cipher);
		if (!fips_post_started(FIPS_TEST_CMAC, subid, 0))
			continue;
		if (!CMAC_Init(ctx, t->key, t->keysize/8, cipher, 0))
			{
			rv = -1;
			goto err;
			}
		if (!CMAC_Update(ctx, t->msg, t->msgsize/8))
			{
			rv = -1;
			goto err;
			}
			
		if (!fips_post_corrupt(FIPS_TEST_CMAC, subid, NULL))
			{
			if (!CMAC_Update(ctx, t->msg, 1))
				{
				rv = -1;
				goto err;
				}
			}
		if (!CMAC_Final(ctx, out, &outlen))
			{
			rv = -1;
			goto err;
			}
		CMAC_CTX_cleanup(ctx);

		if(outlen < t->macsize/8 || memcmp(out,t->mac,t->macsize/8))
			{
			fips_post_failed(FIPS_TEST_CMAC, subid, NULL);
		    	rv = 0;
		    	}
		else if (!fips_post_success(FIPS_TEST_CMAC, subid, NULL))
			{
			rv = 0;
			goto err;
			}
		}

	err:
	CMAC_CTX_free(ctx);

	if (rv == -1)
		{
		fips_post_failed(FIPS_TEST_CMAC, subid, NULL);
		rv = 0;
		}
	if (!rv)
		   FIPSerr(FIPS_F_FIPS_SELFTEST_CMAC,FIPS_R_SELFTEST_FAILED);

	return rv;
	}
#endif
