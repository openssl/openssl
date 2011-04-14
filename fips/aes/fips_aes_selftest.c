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
#include <openssl/evp.h>

#ifdef OPENSSL_FIPS
static struct
    {
    const unsigned char key[16];
    const unsigned char plaintext[16];
    const unsigned char ciphertext[16];
    } tests[]=
	{
	{
	{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F },
	{ 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
	  0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF },
	{ 0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,
	  0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A },
	},
	};

int FIPS_selftest_aes()
    {
    int n;
    int ret = 0;
    EVP_CIPHER_CTX ctx;
    FIPS_cipher_ctx_init(&ctx);

    for(n=0 ; n < 1 ; ++n)
	{
	if (fips_cipher_test(FIPS_TEST_CIPHER, &ctx, EVP_aes_128_ecb(),
				tests[n].key, NULL,
				tests[n].plaintext,
				tests[n].ciphertext,
				16) <= 0)
		goto err;
	}
    ret = 1;
    err:
    FIPS_cipher_ctx_cleanup(&ctx);
    if (ret == 0)
	    FIPSerr(FIPS_F_FIPS_SELFTEST_AES,FIPS_R_SELFTEST_FAILED);
    return ret;
    }

/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
	0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
};
static const unsigned char gcm_iv[] = {
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};
static const unsigned char gcm_pt[] = {
	0xf5,0x6e,0x87,0x05,0x5b,0xc3,0x2d,0x0e,0xeb,0x31,0xb2,0xea,
	0xcc,0x2b,0xf2,0xa5
};
static const unsigned char gcm_aad[] = {
	0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
	0x7f,0xec,0x78,0xde
};
static const unsigned char gcm_ct[] = {
	0xf7,0x26,0x44,0x13,0xa8,0x4c,0x0e,0x7c,0xd5,0x36,0x86,0x7e,
	0xb9,0xf2,0x17,0x36
};
static const unsigned char gcm_tag[] = {
	0x67,0xba,0x05,0x10,0x26,0x2a,0xe4,0x87,0xd7,0x37,0xee,0x62,
	0x98,0xf7,0x7e,0x0c
};

static int corrupt_aes_gcm = 0;

void FIPS_corrupt_aes_gcm(void)
    {
    corrupt_aes_gcm = 1;
    }

int FIPS_selftest_aes_gcm(void)
	{
	int ret = 0;
	unsigned char out[128], tag[16];
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	FIPS_cipherinit(&ctx, EVP_aes_256_gcm(), NULL, NULL, 1);
	FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN,
					sizeof(gcm_iv), NULL);
	if (!FIPS_cipherinit(&ctx, NULL, gcm_key, gcm_iv, 1))
		goto err;
	if (FIPS_cipher(&ctx, NULL, gcm_aad, sizeof(gcm_aad)) < 0)
		goto err;
	if (FIPS_cipher(&ctx, out, gcm_pt, sizeof(gcm_pt)) != sizeof(gcm_ct))
		goto err;
	if (FIPS_cipher(&ctx, NULL, NULL, 0) < 0)
		goto err;

	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		goto err;

	if (memcmp(tag, gcm_tag, 16) || memcmp(out, gcm_ct, 16))
		goto err;

	/* Modify expected tag value */
	if (corrupt_aes_gcm)
		tag[0]++;

	FIPS_cipherinit(&ctx, EVP_aes_256_gcm(), NULL, NULL, 0);
	FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN,
					sizeof(gcm_iv), NULL);
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		goto err;
	if (!FIPS_cipherinit(&ctx, NULL, gcm_key, gcm_iv, 0))
		goto err;
	if (FIPS_cipher(&ctx, NULL, gcm_aad, sizeof(gcm_aad)) < 0)
		goto err;
	if (FIPS_cipher(&ctx, out, gcm_ct, sizeof(gcm_ct)) != sizeof(gcm_pt))
		goto err;
	if (FIPS_cipher(&ctx, NULL, NULL, 0) < 0)
		goto err;

	if (memcmp(out, gcm_pt, 16))
		goto err;

	ret = 1;

	err:

	if (ret == 0)
		FIPSerr(FIPS_F_FIPS_SELFTEST_AES_GCM,FIPS_R_SELFTEST_FAILED);

	FIPS_cipher_ctx_cleanup(&ctx);

	return ret;
	}

#endif
