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

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <string.h>
#include <limits.h>

#ifdef OPENSSL_FIPS

/* Power on self test (POST) support functions */

#include <openssl/fips.h>
#include "fips_locl.h"

/* POST notification callback */

int (*fips_post_cb)(int op, int id, int subid, void *ex);

void FIPS_post_set_callback(
	int (*post_cb)(int op, int id, int subid, void *ex))
	{
	fips_post_cb = post_cb;
	}

/* POST status: i.e. status of all tests */
#define FIPS_POST_STATUS_NOT_STARTED	0
#define FIPS_POST_STATUS_OK		1
#define FIPS_POST_STATUS_RUNNING	2
#define FIPS_POST_STATUS_FAILED		-1
static int post_status = 0;
/* Set to 1 if any test failed */
static int post_failure = 0;

/* All tests started */

int fips_post_begin(void)
	{
	post_failure = 0;
	post_status = FIPS_POST_STATUS_NOT_STARTED;
	if (fips_post_cb)
		if (!fips_post_cb(FIPS_POST_BEGIN, 0, 0, NULL))
			return 0;
	post_status = FIPS_POST_STATUS_RUNNING;
	return 1;
	}

void fips_post_end(void)
	{
	if (post_failure)
		{
		post_status = FIPS_POST_STATUS_FAILED;
		if(fips_post_cb)
			fips_post_cb(FIPS_POST_END, 0, 0, NULL);
		}
	else
		{
		post_status = FIPS_POST_STATUS_OK;
		if (fips_post_cb)
			fips_post_cb(FIPS_POST_END, 1, 0, NULL);
		}
	}

/* A self test started */
int fips_post_started(int id, int subid, void *ex)
	{
	if (fips_post_cb)
		return fips_post_cb(FIPS_POST_STARTED, id, subid, ex);
	return 1;
	}
/* A self test passed successfully */
int fips_post_success(int id, int subid, void *ex)
	{
	if (fips_post_cb)
		return fips_post_cb(FIPS_POST_SUCCESS, id, subid, ex);
	return 1;
	}
/* A self test failed */
int fips_post_failed(int id, int subid, void *ex)
	{
	post_failure = 1;
	if (fips_post_cb)
		return fips_post_cb(FIPS_POST_FAIL, id, subid, ex);
	return 1;
	}
/* Indicate if a self test failure should be induced */
int fips_post_corrupt(int id, int subid, void *ex)
	{
	if (fips_post_cb)
		return fips_post_cb(FIPS_POST_CORRUPT, id, subid, ex);
	return 1;
	}
/* Note: if selftests running return status OK so their operation is
 * not interrupted. This will only happen while selftests are actually
 * running so will not interfere with normal operation.
 */
int fips_post_status(void)
	{
	return post_status > 0 ? 1 : 0;
	}
/* Run all selftests */
int FIPS_selftest(void)
	{
	int rv = 1;
	fips_post_begin();
	if(!FIPS_check_incore_fingerprint())
		rv = 0;
	if (!FIPS_selftest_drbg())
		rv = 0;
	if (!FIPS_selftest_x931())
		rv = 0;
    	if (!FIPS_selftest_sha1())
		rv = 0;
	if (!FIPS_selftest_hmac())
		rv = 0;
	if (!FIPS_selftest_cmac())
		rv = 0;
	if (!FIPS_selftest_aes())
		rv = 0;
	if (!FIPS_selftest_aes_ccm())
		rv = 0;
	if (!FIPS_selftest_aes_gcm())
		rv = 0;
	if (!FIPS_selftest_aes_xts())
		rv = 0;
	if (!FIPS_selftest_des())
		rv = 0;
	if (!FIPS_selftest_rsa())
		rv = 0;
	if (!FIPS_selftest_ecdsa())
		rv = 0;
	if (!FIPS_selftest_dsa())
		rv = 0;
	if (!FIPS_selftest_ecdh())
		rv = 0;
	fips_post_end();
	return rv;
	}

/* Generalized public key test routine. Signs and verifies the data
 * supplied in tbs using mesage digest md and setting RSA padding mode
 * pad_mode. If the 'kat' parameter is not NULL it will
 * additionally check the signature matches it: a known answer test
 * The string "fail_str" is used for identification purposes in case
 * of failure. If "pkey" is NULL just perform a message digest check.
 */

int fips_pkey_signature_test(int id, EVP_PKEY *pkey,
			const unsigned char *tbs, size_t tbslen,
			const unsigned char *kat, size_t katlen,
			const EVP_MD *digest, int pad_mode,
			const char *fail_str)
	{	
	int subid;
	int ret = 0;
	unsigned char *sig = NULL;
	unsigned int siglen;
	__fips_constseg
	static const unsigned char str1[]="12345678901234567890";
	DSA_SIG *dsig = NULL;
	ECDSA_SIG *esig = NULL;
	EVP_MD_CTX mctx;
	FIPS_md_ctx_init(&mctx);

	if (tbs == NULL)
		tbs = str1;

	if (tbslen == 0)
		tbslen = strlen((char *)tbs);

	if (digest == NULL)
		digest = EVP_sha256();

	subid = M_EVP_MD_type(digest);


	if (!fips_post_started(id, subid, pkey))
		return 1;

	if (!pkey || pkey->type == EVP_PKEY_RSA)
		{
		size_t sigsize;
		if (!pkey)
			sigsize = EVP_MAX_MD_SIZE;
		else
			sigsize = RSA_size(pkey->pkey.rsa);

		sig = OPENSSL_malloc(sigsize);
		if (!sig)
			{
			FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST,ERR_R_MALLOC_FAILURE);
			goto error;
			}
		}

	if (!FIPS_digestinit(&mctx, digest))
		goto error;
	if (!FIPS_digestupdate(&mctx, tbs, tbslen))
		goto error;

	if (!fips_post_corrupt(id, subid, pkey))
		{
		if (!FIPS_digestupdate(&mctx, tbs, 1))
			goto error;
		}

	if (pkey == NULL)
		{
		if (!FIPS_digestfinal(&mctx, sig, &siglen))
			goto error;
		}
	else if (pkey->type == EVP_PKEY_RSA)
		{
		if (!FIPS_rsa_sign_ctx(pkey->pkey.rsa, &mctx,
					pad_mode, 0, NULL, sig, &siglen))
			goto error;
		}
	else if (pkey->type == EVP_PKEY_DSA)
		{
		dsig = FIPS_dsa_sign_ctx(pkey->pkey.dsa, &mctx);
		if (!dsig)
			goto error;
		}
	else if (pkey->type == EVP_PKEY_EC)
		{
		esig = FIPS_ecdsa_sign_ctx(pkey->pkey.ec, &mctx);
		if (!esig)
			goto error;
		}

	if (kat && ((siglen != katlen) || memcmp(kat, sig, katlen)))
		goto error;
#if 0
	{
	/* Debug code to print out self test KAT discrepancies */
	unsigned int i;
	fprintf(stderr, "%s=", fail_str);
	for (i = 0; i < siglen; i++)
			fprintf(stderr, "%02X", sig[i]);
	fprintf(stderr, "\n");
	goto error;
	}
#endif
	/* If just digest test we've finished */
	if (pkey == NULL)
		{
		ret = 1;
		/* Well actually success as we've set ret to 1 */
		goto error;
		}
	if (!FIPS_digestinit(&mctx, digest))
		goto error;
	if (!FIPS_digestupdate(&mctx, tbs, tbslen))
		goto error;
	if (pkey->type == EVP_PKEY_RSA)
		{
		ret = FIPS_rsa_verify_ctx(pkey->pkey.rsa, &mctx,
						pad_mode, 0, NULL, sig, siglen);
		}
	else if (pkey->type == EVP_PKEY_DSA)
		{
		ret = FIPS_dsa_verify_ctx(pkey->pkey.dsa, &mctx, dsig);
		}
	else if (pkey->type == EVP_PKEY_EC)
		{
		ret = FIPS_ecdsa_verify_ctx(pkey->pkey.ec, &mctx, esig);
		}

	error:
	if (dsig != NULL)
		FIPS_dsa_sig_free(dsig);
	if (esig != NULL)
		FIPS_ecdsa_sig_free(esig);
	if (sig)
		OPENSSL_free(sig);
	FIPS_md_ctx_cleanup(&mctx);
	if (ret != 1)
		{
		FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST,FIPS_R_TEST_FAILURE);
		if (fail_str)
			FIPS_add_error_data(2, "Type=", fail_str);
		fips_post_failed(id, subid, pkey);
		return 0;
		}
	return fips_post_success(id, subid, pkey);
	}

/* Generalized symmetric cipher test routine. Encrypt data, verify result
 * against known answer, decrypt and compare with original plaintext.
 */

int fips_cipher_test(int id, EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
			const unsigned char *key,
			const unsigned char *iv,
			const unsigned char *plaintext,
			const unsigned char *ciphertext,
			int len)
	{
	unsigned char pltmp[FIPS_MAX_CIPHER_TEST_SIZE];
	unsigned char citmp[FIPS_MAX_CIPHER_TEST_SIZE];
	int subid = M_EVP_CIPHER_nid(cipher);
	int rv = 0;
	OPENSSL_assert(len <= FIPS_MAX_CIPHER_TEST_SIZE);
	memset(pltmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);
	memset(citmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);

	if (!fips_post_started(id, subid, NULL))
		return 1;
	if (FIPS_cipherinit(ctx, cipher, key, iv, 1) <= 0)
		goto error;
	if (!FIPS_cipher(ctx, citmp, plaintext, len))
		goto error;
	if (memcmp(citmp, ciphertext, len))
		goto error;
	if (!fips_post_corrupt(id, subid, NULL))
			citmp[0] ^= 0x1;
	if (FIPS_cipherinit(ctx, cipher, key, iv, 0) <= 0)
		goto error;
	FIPS_cipher(ctx, pltmp, citmp, len);
	if (memcmp(pltmp, plaintext, len))
		goto error;
	rv = 1;
	error:
	if (rv == 0)
		{
		fips_post_failed(id, subid, NULL);
		return 0;
		}
	return fips_post_success(id, subid, NULL);
	}

#endif
