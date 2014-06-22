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
#include <openssl/hmac.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS
typedef struct {
	int nid;
	const unsigned char kaval[EVP_MAX_MD_SIZE];
} HMAC_KAT;

/* from http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf */
/* "0123456789:;<=>?@ABC" */
__fips_constseg
static const unsigned char hmac_kat_key[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
	0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43
	};
/* "Sample #2" */
__fips_constseg
static const unsigned char hmac_kat_data[] = {
	0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x23, 0x32
	};

__fips_constseg
static const HMAC_KAT vector[] = {
    {	NID_sha1,
	{ 0x09,0x22,0xd3,0x40,0x5f,0xaa,0x3d,0x19,
	  0x4f,0x82,0xa4,0x58,0x30,0x73,0x7d,0x5c,
	  0xc6,0xc7,0x5d,0x24 }
    },
    {	NID_sha224,
	{ 0xdd,0xef,0x0a,0x40,0xcb,0x7d,0x50,0xfb,
	  0x6e,0xe6,0xce,0xa1,0x20,0xba,0x26,0xaa,
	  0x08,0xf3,0x07,0x75,0x87,0xb8,0xad,0x1b,
	  0x8c,0x8d,0x12,0xc7 }
    },
    {	NID_sha256,
	{ 0xb8,0xf2,0x0d,0xb5,0x41,0xea,0x43,0x09,
	  0xca,0x4e,0xa9,0x38,0x0c,0xd0,0xe8,0x34,
	  0xf7,0x1f,0xbe,0x91,0x74,0xa2,0x61,0x38,
	  0x0d,0xc1,0x7e,0xae,0x6a,0x34,0x51,0xd9 }
    },
    {	NID_sha384,
	{ 0x08,0xbc,0xb0,0xda,0x49,0x1e,0x87,0xad,
	  0x9a,0x1d,0x6a,0xce,0x23,0xc5,0x0b,0xf6,
	  0xb7,0x18,0x06,0xa5,0x77,0xcd,0x49,0x04,
	  0x89,0xf1,0xe6,0x23,0x44,0x51,0x51,0x9f,
	  0x85,0x56,0x80,0x79,0x0c,0xbd,0x4d,0x50,
	  0xa4,0x5f,0x29,0xe3,0x93,0xf0,0xe8,0x7f }
    },
    {	NID_sha512,
	{ 0x80,0x9d,0x44,0x05,0x7c,0x5b,0x95,0x41,
	  0x05,0xbd,0x04,0x13,0x16,0xdb,0x0f,0xac,
	  0x44,0xd5,0xa4,0xd5,0xd0,0x89,0x2b,0xd0,
	  0x4e,0x86,0x64,0x12,0xc0,0x90,0x77,0x68,
	  0xf1,0x87,0xb7,0x7c,0x4f,0xae,0x2c,0x2f,
	  0x21,0xa5,0xb5,0x65,0x9a,0x4f,0x4b,0xa7,
	  0x47,0x02,0xa3,0xde,0x9b,0x51,0xf1,0x45,
	  0xbd,0x4f,0x25,0x27,0x42,0x98,0x99,0x05 }
    },
};

int FIPS_selftest_hmac()
	{
	size_t n;
	unsigned int    outlen;
	unsigned char   out[EVP_MAX_MD_SIZE];
	const EVP_MD   *md;
	const HMAC_KAT *t;
	int rv = 1, subid = -1;
	HMAC_CTX c;
	HMAC_CTX_init(&c);


	for(n=0,t=vector; n<sizeof(vector)/sizeof(vector[0]); n++,t++)
		{
		md = FIPS_get_digestbynid(t->nid);
		if (!md)
			{
			rv = -1;
			goto err;
			}
		subid = M_EVP_MD_type(md);
		if (!fips_post_started(FIPS_TEST_HMAC, subid, 0))
			continue;
		if (!HMAC_Init_ex(&c, hmac_kat_key, sizeof(hmac_kat_key),
								md, NULL))
			{
			rv = -1;
			goto err;
			}
		if (!HMAC_Update(&c, hmac_kat_data, sizeof(hmac_kat_data)))
			{
			rv = -1;
			goto err;
			}
		if (!fips_post_corrupt(FIPS_TEST_HMAC, subid, NULL))
			{
			if (!HMAC_Update(&c, hmac_kat_data, 1))
				{
				rv = -1;
				goto err;
				}
			}
		if (!HMAC_Final(&c, out, &outlen))
			{
			rv = -1;
			goto err;
			}

		if(memcmp(out,t->kaval,outlen))
			{
			fips_post_failed(FIPS_TEST_HMAC, subid, NULL);
			rv = 0;
		    	}
		else if (!fips_post_success(FIPS_TEST_HMAC, subid, NULL))
			goto err;
		}

	err:
	HMAC_CTX_cleanup(&c);
	if (rv == -1)
		{
		fips_post_failed(FIPS_TEST_HMAC, subid, NULL);
		rv = 0;
		}
	if (!rv)
		   FIPSerr(FIPS_F_FIPS_SELFTEST_HMAC,FIPS_R_SELFTEST_FAILED);
	return rv;
	}
#endif
