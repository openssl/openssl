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
#include "fips_locl.h"

#ifdef OPENSSL_FIPS
__fips_constseg
static const struct
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

/* AES-CCM test data from NIST public test vectors */

__fips_constseg
static const unsigned char ccm_key[] = {
	0xce,0xb0,0x09,0xae,0xa4,0x45,0x44,0x51,0xfe,0xad,0xf0,0xe6,
	0xb3,0x6f,0x45,0x55,0x5d,0xd0,0x47,0x23,0xba,0xa4,0x48,0xe8
};
__fips_constseg
static const unsigned char ccm_nonce[] = {
	0x76,0x40,0x43,0xc4,0x94,0x60,0xb7
};
__fips_constseg
static const unsigned char ccm_adata[] = {
	0x6e,0x80,0xdd,0x7f,0x1b,0xad,0xf3,0xa1,0xc9,0xab,0x25,0xc7,
	0x5f,0x10,0xbd,0xe7,0x8c,0x23,0xfa,0x0e,0xb8,0xf9,0xaa,0xa5,
	0x3a,0xde,0xfb,0xf4,0xcb,0xf7,0x8f,0xe4
};
__fips_constseg
static const unsigned char ccm_pt[] = {
	0xc8,0xd2,0x75,0xf9,0x19,0xe1,0x7d,0x7f,0xe6,0x9c,0x2a,0x1f,
	0x58,0x93,0x9d,0xfe,0x4d,0x40,0x37,0x91,0xb5,0xdf,0x13,0x10
};
__fips_constseg
static const unsigned char ccm_ct[] = {
	0x8a,0x0f,0x3d,0x82,0x29,0xe4,0x8e,0x74,0x87,0xfd,0x95,0xa2,
	0x8a,0xd3,0x92,0xc8,0x0b,0x36,0x81,0xd4,0xfb,0xc7,0xbb,0xfd
};
__fips_constseg
static const unsigned char ccm_tag[] = {
	0x2d,0xd6,0xef,0x1c,0x45,0xd4,0xcc,0xb7,0x23,0xdc,0x07,0x44,
	0x14,0xdb,0x50,0x6d
};

int FIPS_selftest_aes_ccm(void)
	{
	int ret = 0, do_corrupt = 0;
	unsigned char out[128], tag[16];
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	memset(out, 0, sizeof(out));
	if (!fips_post_started(FIPS_TEST_CCM, 0, 0))
		return 1;
	if (!fips_post_corrupt(FIPS_TEST_CCM, 0, NULL))
		do_corrupt = 1;
	if (!FIPS_cipherinit(&ctx, EVP_aes_192_ccm(), NULL, NULL, 1))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN,
					sizeof(ccm_nonce), NULL))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG,
					sizeof(ccm_tag), NULL))
		goto err;
	if (!FIPS_cipherinit(&ctx, NULL, ccm_key, ccm_nonce, 1))
		goto err;
	if (FIPS_cipher(&ctx, NULL, NULL, sizeof(ccm_pt)) != sizeof(ccm_pt))
		goto err;
	if (FIPS_cipher(&ctx, NULL, ccm_adata, sizeof(ccm_adata)) < 0)
		goto err;
	if (FIPS_cipher(&ctx, out, ccm_pt, sizeof(ccm_pt)) != sizeof(ccm_ct))
		goto err;

	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, 16, tag))
		goto err;
	if (memcmp(tag, ccm_tag, sizeof(ccm_tag))
		|| memcmp(out, ccm_ct, sizeof(ccm_ct)))
		goto err;

	memset(out, 0, sizeof(out));

	/* Modify expected tag value */
	if (do_corrupt)
		tag[0]++;

	if (!FIPS_cipherinit(&ctx, EVP_aes_192_ccm(), NULL, NULL, 0))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN,
					sizeof(ccm_nonce), NULL))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, 16, tag))
		goto err;
	if (!FIPS_cipherinit(&ctx, NULL, ccm_key, ccm_nonce, 0))
		goto err;
	if (FIPS_cipher(&ctx, NULL, NULL, sizeof(ccm_ct)) != sizeof(ccm_ct))
		goto err;
	if (FIPS_cipher(&ctx, NULL, ccm_adata, sizeof(ccm_adata)) < 0)
		goto err;
	if (FIPS_cipher(&ctx, out, ccm_ct, sizeof(ccm_ct)) != sizeof(ccm_pt))
		goto err;

	if (memcmp(out, ccm_pt, sizeof(ccm_pt)))
		goto err;

	ret = 1;

	err:
	FIPS_cipher_ctx_cleanup(&ctx);

	if (ret == 0)
		{
		fips_post_failed(FIPS_TEST_CCM, 0, NULL);
		FIPSerr(FIPS_F_FIPS_SELFTEST_AES_CCM,FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	else
		return fips_post_success(FIPS_TEST_CCM, 0, NULL);

	}

/* AES-GCM test data from NIST public test vectors */

__fips_constseg
static const unsigned char gcm_key[] = {
	0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
};
__fips_constseg
static const unsigned char gcm_iv[] = {
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};
__fips_constseg
static const unsigned char gcm_pt[] = {
	0xf5,0x6e,0x87,0x05,0x5b,0xc3,0x2d,0x0e,0xeb,0x31,0xb2,0xea,
	0xcc,0x2b,0xf2,0xa5
};
__fips_constseg
static const unsigned char gcm_aad[] = {
	0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
	0x7f,0xec,0x78,0xde
};
__fips_constseg
static const unsigned char gcm_ct[] = {
	0xf7,0x26,0x44,0x13,0xa8,0x4c,0x0e,0x7c,0xd5,0x36,0x86,0x7e,
	0xb9,0xf2,0x17,0x36
};
__fips_constseg
static const unsigned char gcm_tag[] = {
	0x67,0xba,0x05,0x10,0x26,0x2a,0xe4,0x87,0xd7,0x37,0xee,0x62,
	0x98,0xf7,0x7e,0x0c
};

int FIPS_selftest_aes_gcm(void)
	{
	int ret = 0, do_corrupt = 0;
	unsigned char out[128], tag[16];
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	memset(out, 0, sizeof(out));
	memset(tag, 0, sizeof(tag));
	if (!fips_post_started(FIPS_TEST_GCM, 0, 0))
		return 1;
	if (!fips_post_corrupt(FIPS_TEST_GCM, 0, NULL))
		do_corrupt = 1;
	if (!FIPS_cipherinit(&ctx, EVP_aes_256_gcm(), NULL, NULL, 1))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN,
					sizeof(gcm_iv), NULL))
		goto err;
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

	memset(out, 0, sizeof(out));

	/* Modify expected tag value */
	if (do_corrupt)
		tag[0]++;

	if (!FIPS_cipherinit(&ctx, EVP_aes_256_gcm(), NULL, NULL, 0))
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN,
					sizeof(gcm_iv), NULL))
		goto err;
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
	FIPS_cipher_ctx_cleanup(&ctx);

	if (ret == 0)
		{
		fips_post_failed(FIPS_TEST_GCM, 0, NULL);
		FIPSerr(FIPS_F_FIPS_SELFTEST_AES_GCM,FIPS_R_SELFTEST_FAILED);
		return 0;
		}
	else
		return fips_post_success(FIPS_TEST_GCM, 0, NULL);

	}


__fips_constseg
static const unsigned char XTS_128_key[] = {
	0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,
	0x76,0x08,0x17,0x62,0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,
	0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f
};
__fips_constseg
static const unsigned char XTS_128_i[] = {
	0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,0x6e,0x4b,0x92,0x01,
	0x3e,0x76,0x8a,0xd5
};
__fips_constseg
static const unsigned char XTS_128_pt[] = {
	0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,0x6f,0xb3,0x50,0x39,
	0x07,0x90,0x31,0x1c
};
__fips_constseg
static const unsigned char XTS_128_ct[] = {
	0x77,0x8a,0xe8,0xb4,0x3c,0xb9,0x8d,0x5a,0x82,0x50,0x81,0xd5,
	0xbe,0x47,0x1c,0x63
};

__fips_constseg
static const unsigned char XTS_256_key[] = {
	0x1e,0xa6,0x61,0xc5,0x8d,0x94,0x3a,0x0e,0x48,0x01,0xe4,0x2f,
	0x4b,0x09,0x47,0x14,0x9e,0x7f,0x9f,0x8e,0x3e,0x68,0xd0,0xc7,
	0x50,0x52,0x10,0xbd,0x31,0x1a,0x0e,0x7c,0xd6,0xe1,0x3f,0xfd,
	0xf2,0x41,0x8d,0x8d,0x19,0x11,0xc0,0x04,0xcd,0xa5,0x8d,0xa3,
	0xd6,0x19,0xb7,0xe2,0xb9,0x14,0x1e,0x58,0x31,0x8e,0xea,0x39,
	0x2c,0xf4,0x1b,0x08
};
__fips_constseg
static const unsigned char XTS_256_i[] = {
	0xad,0xf8,0xd9,0x26,0x27,0x46,0x4a,0xd2,0xf0,0x42,0x8e,0x84,
	0xa9,0xf8,0x75,0x64
};
__fips_constseg
static const unsigned char XTS_256_pt[] = {
	0x2e,0xed,0xea,0x52,0xcd,0x82,0x15,0xe1,0xac,0xc6,0x47,0xe8,
	0x10,0xbb,0xc3,0x64,0x2e,0x87,0x28,0x7f,0x8d,0x2e,0x57,0xe3,
	0x6c,0x0a,0x24,0xfb,0xc1,0x2a,0x20,0x2e
};
__fips_constseg
static const unsigned char XTS_256_ct[] = {
	0xcb,0xaa,0xd0,0xe2,0xf6,0xce,0xa3,0xf5,0x0b,0x37,0xf9,0x34,
	0xd4,0x6a,0x9b,0x13,0x0b,0x9d,0x54,0xf0,0x7e,0x34,0xf3,0x6a,
	0xf7,0x93,0xe8,0x6f,0x73,0xc6,0xd7,0xdb
};

int FIPS_selftest_aes_xts()
	{
	int ret = 1;
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);

	if (fips_cipher_test(FIPS_TEST_XTS, &ctx, EVP_aes_128_xts(),
				XTS_128_key, XTS_128_i, XTS_128_pt, XTS_128_ct,
				sizeof(XTS_128_pt)) <= 0)
		ret = 0;

	if (fips_cipher_test(FIPS_TEST_XTS, &ctx, EVP_aes_256_xts(),
				XTS_256_key, XTS_256_i, XTS_256_pt, XTS_256_ct,
				sizeof(XTS_256_pt)) <= 0)
		ret = 0;

	FIPS_cipher_ctx_cleanup(&ctx);
	if (ret == 0)
		FIPSerr(FIPS_F_FIPS_SELFTEST_AES_XTS,FIPS_R_SELFTEST_FAILED);
	return ret;
	}

#endif
