/* fips/rand/fips_drbg_selftest.c */
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

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"
#include "fips_locl.h"

#include "fips_drbg_selftest.h"

typedef struct {
	int post;
	int nid;
	unsigned int flags;

	/* KAT data for no PR */
	const unsigned char *ent;
	size_t entlen;
	const unsigned char *nonce;
	size_t noncelen;
	const unsigned char *pers;
	size_t perslen;
	const unsigned char *adin;
	size_t adinlen;
	const unsigned char *entreseed;
	size_t entreseedlen;
	const unsigned char *adinreseed;
	size_t adinreseedlen;
	const unsigned char *adin2;
	size_t adin2len;
	const unsigned char *kat;
	size_t katlen;
	const unsigned char *kat2;
	size_t kat2len;

	/* KAT data for PR */
	const unsigned char *ent_pr;
	size_t entlen_pr;
	const unsigned char *nonce_pr;
	size_t noncelen_pr;
	const unsigned char *pers_pr;
	size_t perslen_pr;
	const unsigned char *adin_pr;
	size_t adinlen_pr;
	const unsigned char *entpr_pr;
	size_t entprlen_pr;
	const unsigned char *ading_pr;
	size_t adinglen_pr;
	const unsigned char *entg_pr;
	size_t entglen_pr;
	const unsigned char *kat_pr;
	size_t katlen_pr;
	const unsigned char *kat2_pr;
	size_t kat2len_pr;

	} DRBG_SELFTEST_DATA;

#define make_drbg_test_data(nid, flag, pr, p) {p, nid, flag | DRBG_FLAG_TEST, \
	pr##_entropyinput, sizeof(pr##_entropyinput), \
	pr##_nonce, sizeof(pr##_nonce), \
	pr##_personalizationstring, sizeof(pr##_personalizationstring), \
	pr##_additionalinput, sizeof(pr##_additionalinput), \
	pr##_entropyinputreseed, sizeof(pr##_entropyinputreseed), \
	pr##_additionalinputreseed, sizeof(pr##_additionalinputreseed), \
	pr##_additionalinput2, sizeof(pr##_additionalinput2), \
	pr##_int_returnedbits, sizeof(pr##_int_returnedbits), \
	pr##_returnedbits, sizeof(pr##_returnedbits), \
	pr##_pr_entropyinput, sizeof(pr##_pr_entropyinput), \
	pr##_pr_nonce, sizeof(pr##_pr_nonce), \
	pr##_pr_personalizationstring, sizeof(pr##_pr_personalizationstring), \
	pr##_pr_additionalinput, sizeof(pr##_pr_additionalinput), \
	pr##_pr_entropyinputpr, sizeof(pr##_pr_entropyinputpr), \
	pr##_pr_additionalinput2, sizeof(pr##_pr_additionalinput2), \
	pr##_pr_entropyinputpr2, sizeof(pr##_pr_entropyinputpr2), \
	pr##_pr_int_returnedbits, sizeof(pr##_pr_int_returnedbits), \
	pr##_pr_returnedbits, sizeof(pr##_pr_returnedbits), \
	}

#define make_drbg_test_data_df(nid, pr, p) \
	make_drbg_test_data(nid, DRBG_FLAG_CTR_USE_DF, pr, p)

#define make_drbg_test_data_ec(curve, md, pr, p) \
	make_drbg_test_data((curve << 16) | md , 0, pr, p)

static DRBG_SELFTEST_DATA drbg_test[] = {
	make_drbg_test_data_df(NID_aes_128_ctr, aes_128_use_df, 0),
	make_drbg_test_data_df(NID_aes_192_ctr, aes_192_use_df, 0),
	make_drbg_test_data_df(NID_aes_256_ctr, aes_256_use_df, 1),
	make_drbg_test_data(NID_aes_128_ctr, 0, aes_128_no_df, 0),
	make_drbg_test_data(NID_aes_192_ctr, 0, aes_192_no_df, 0),
	make_drbg_test_data(NID_aes_256_ctr, 0, aes_256_no_df, 1),
	make_drbg_test_data(NID_sha1, 0, sha1, 0),
	make_drbg_test_data(NID_sha224, 0, sha224, 0),
	make_drbg_test_data(NID_sha256, 0, sha256, 1),
	make_drbg_test_data(NID_sha384, 0, sha384, 0),
	make_drbg_test_data(NID_sha512, 0, sha512, 0),
	make_drbg_test_data(NID_hmacWithSHA1, 0, hmac_sha1, 0),
	make_drbg_test_data(NID_hmacWithSHA224, 0, hmac_sha224, 0),
	make_drbg_test_data(NID_hmacWithSHA256, 0, hmac_sha256, 1),
	make_drbg_test_data(NID_hmacWithSHA384, 0, hmac_sha384, 0),
	make_drbg_test_data(NID_hmacWithSHA512, 0, hmac_sha512, 0),
	make_drbg_test_data_ec(NID_X9_62_prime256v1, NID_sha1, p_256_sha1, 0),
	make_drbg_test_data_ec(NID_X9_62_prime256v1, NID_sha224, p_256_sha224, 0),
	make_drbg_test_data_ec(NID_X9_62_prime256v1, NID_sha256, p_256_sha256, 1),
	make_drbg_test_data_ec(NID_X9_62_prime256v1, NID_sha384, p_256_sha384, 0),
	make_drbg_test_data_ec(NID_X9_62_prime256v1, NID_sha512, p_256_sha512, 0),
	make_drbg_test_data_ec(NID_secp384r1, NID_sha224, p_384_sha224, 0),
	make_drbg_test_data_ec(NID_secp384r1, NID_sha256, p_384_sha256, 0),
	make_drbg_test_data_ec(NID_secp384r1, NID_sha384, p_384_sha384, 0),
	make_drbg_test_data_ec(NID_secp384r1, NID_sha512, p_384_sha512, 0),
	make_drbg_test_data_ec(NID_secp521r1, NID_sha256, p_521_sha256, 0),
	make_drbg_test_data_ec(NID_secp521r1, NID_sha384, p_521_sha384, 0),
	make_drbg_test_data_ec(NID_secp521r1, NID_sha512, p_521_sha512, 0),
	{0,0,0}
	};

typedef struct
	{
	const unsigned char *ent;
	size_t entlen;
	int entcnt;
	const unsigned char *nonce;
	size_t noncelen;
	int noncecnt;
	} TEST_ENT;

static size_t test_entropy(DRBG_CTX *dctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	*pout = (unsigned char *)t->ent;
	t->entcnt++;
	return t->entlen;
	}

static size_t test_nonce(DRBG_CTX *dctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	*pout = (unsigned char *)t->nonce;
	t->noncecnt++;
	return t->noncelen;
	}

static int fips_drbg_single_kat(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td,
								int quick)
	{
	TEST_ENT t;
	int rv = 0;
	size_t adinlen;
	unsigned char randout[1024];

	/* Initial test without PR */

	/* Instantiate DRBG with test entropy, nonce and personalisation
	 * string.
	 */

	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		return 0;
	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, 0, 0, test_nonce, 0))
		return 0;

	FIPS_drbg_set_app_data(dctx, &t);

	t.ent = td->ent;
	t.entlen = td->entlen;
	t.nonce = td->nonce;
	t.noncelen = td->noncelen;
	t.entcnt = 0;
	t.noncecnt = 0;

	if (!FIPS_drbg_instantiate(dctx, td->pers, td->perslen))
		goto err;

	/* Note for CTR without DF some additional input values
	 * ignore bytes after the keylength: so reduce adinlen
	 * to half to ensure invalid data is fed in.
	 */
	if (!fips_post_corrupt(FIPS_TEST_DRBG, dctx->type, &dctx->iflags))
		adinlen = td->adinlen / 2;
	else
		adinlen = td->adinlen;

	/* Generate with no PR and verify output matches expected data */
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, adinlen))
		goto err;

	if (memcmp(randout, td->kat, td->katlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_SINGLE_KAT, FIPS_R_NOPR_TEST1_FAILURE);
		goto err2;
		}
	/* If abbreviated POST end of test */
	if (quick)
		{
		rv = 1;
		goto err;
		}
	/* Reseed DRBG with test entropy and additional input */
	t.ent = td->entreseed;
	t.entlen = td->entreseedlen;

	if (!FIPS_drbg_reseed(dctx, td->adinreseed, td->adinreseedlen))
		goto err;

	/* Generate with no PR and verify output matches expected data */
	if (!FIPS_drbg_generate(dctx, randout, td->kat2len, 0,
				td->adin2, td->adin2len))
		goto err;

	if (memcmp(randout, td->kat2, td->kat2len))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_SINGLE_KAT, FIPS_R_NOPR_TEST2_FAILURE);
		goto err2;
		}

	FIPS_drbg_uninstantiate(dctx);

	/* Now test with PR */

	/* Instantiate DRBG with test entropy, nonce and personalisation
	 * string.
	 */
	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		return 0;
	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, 0, 0, test_nonce, 0))
		return 0;

	FIPS_drbg_set_app_data(dctx, &t);

	t.ent = td->ent_pr;
	t.entlen = td->entlen_pr;
	t.nonce = td->nonce_pr;
	t.noncelen = td->noncelen_pr;
	t.entcnt = 0;
	t.noncecnt = 0;

	if (!FIPS_drbg_instantiate(dctx, td->pers_pr, td->perslen_pr))
		goto err;

	/* Now generate with PR: we need to supply entropy as this will
	 * perform a reseed operation. Check output matches expected value.
	 */

	t.ent = td->entpr_pr;
	t.entlen = td->entprlen_pr;

	/* Note for CTR without DF some additional input values
	 * ignore bytes after the keylength: so reduce adinlen
	 * to half to ensure invalid data is fed in.
	 */
	if (!fips_post_corrupt(FIPS_TEST_DRBG, dctx->type, &dctx->iflags))
		adinlen = td->adinlen_pr / 2;
	else
		adinlen = td->adinlen_pr;
	if (!FIPS_drbg_generate(dctx, randout, td->katlen_pr, 1,
				td->adin_pr, adinlen))
		goto err;

	if (memcmp(randout, td->kat_pr, td->katlen_pr))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_SINGLE_KAT, FIPS_R_PR_TEST1_FAILURE);
		goto err2;
		}

	/* Now generate again with PR: supply new entropy again.
	 * Check output matches expected value.
	 */

	t.ent = td->entg_pr;
	t.entlen = td->entglen_pr;

	if (!FIPS_drbg_generate(dctx, randout, td->kat2len_pr, 1,
				td->ading_pr, td->adinglen_pr))
		goto err;

	if (memcmp(randout, td->kat2_pr, td->kat2len_pr))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_SINGLE_KAT, FIPS_R_PR_TEST2_FAILURE);
		goto err2;
		}
	/* All OK, test complete */
	rv = 1;

	err:
	if (rv == 0)
		FIPSerr(FIPS_F_FIPS_DRBG_SINGLE_KAT, FIPS_R_SELFTEST_FAILED);
	err2:
	FIPS_drbg_uninstantiate(dctx);
	
	return rv;

	}

/* Initialise a DRBG based on selftest data */

static int do_drbg_init(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td, TEST_ENT *t)
	{

	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		return 0;

	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, 0, 0, test_nonce, 0))
		return 0;

	FIPS_drbg_set_app_data(dctx, t);

	t->ent = td->ent;
	t->entlen = td->entlen;
	t->nonce = td->nonce;
	t->noncelen = td->noncelen;
	t->entcnt = 0;
	t->noncecnt = 0;
	return 1;
	}

/* Initialise and instantiate DRBG based on selftest data */
static int do_drbg_instantiate(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td,
								TEST_ENT *t)
	{
	if (!do_drbg_init(dctx, td, t))
		return 0;
	if (!FIPS_drbg_instantiate(dctx, td->pers, td->perslen))
		return 0;

	return 1;
	}

/* This function performs extensive error checking as required by SP800-90.
 * Induce several failure modes and check an error condition is set.
 * This function along with fips_drbg_single_kat peforms the health checking
 * operation.
 */

static int fips_drbg_error_check(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td)
	{
	unsigned char randout[1024];
	TEST_ENT t;
	size_t i;
	unsigned int reseed_counter_tmp;
	unsigned char *p = (unsigned char *)dctx;

	/* Initialise DRBG */

	if (!do_drbg_init(dctx, td, &t))
		goto err;

	/* Don't report induced errors */
	dctx->iflags |= DRBG_FLAG_NOERR;

	/* Personalisation string tests */

	/* Test detection of too large personlisation string */

	if (FIPS_drbg_instantiate(dctx, td->pers, dctx->max_pers + 1) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_PERSONALISATION_ERROR_UNDETECTED);
		goto err;
		}

	/* Entropy source tests */

	/* Test entropy source failure detecion: i.e. returns no data */

	t.entlen = 0;

	if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	/* Try to generate output from uninstantiated DRBG */
	if (FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_GENERATE_ERROR_UNDETECTED);
		goto err;
		}

	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	if (!do_drbg_init(dctx, td, &t))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	/* Test insufficient entropy */

	t.entlen = dctx->min_entropy - 1;

	if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Test too much entropy */

	if (!do_drbg_init(dctx, td, &t))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	t.entlen = dctx->max_entropy + 1;

	if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Nonce tests */

	/* Test too small nonce */

	if (dctx->min_nonce)
		{

		if (!do_drbg_init(dctx, td, &t))
			goto err;

		dctx->iflags |= DRBG_FLAG_NOERR;

		t.noncelen = dctx->min_nonce - 1;

		if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
			{
			FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_NONCE_ERROR_UNDETECTED);
			goto err;
			}

		dctx->iflags &= ~DRBG_FLAG_NOERR;
		if (!FIPS_drbg_uninstantiate(dctx))
			{
			FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
			goto err;
			}

		}

	/* Test too large nonce */

	if (dctx->max_nonce)
		{

		if (!do_drbg_init(dctx, td, &t))
			goto err;

		dctx->iflags |= DRBG_FLAG_NOERR;

		t.noncelen = dctx->max_nonce + 1;

		if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
			{
			FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_NONCE_ERROR_UNDETECTED);
			goto err;
			}

		dctx->iflags &= ~DRBG_FLAG_NOERR;
		if (!FIPS_drbg_uninstantiate(dctx))
			{
			FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
			goto err;
			}

		}

	/* Instantiate with valid data. */
	if (!do_drbg_instantiate(dctx, td, &t))
			goto err;

	/* Check generation is now OK */
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, td->adinlen))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	/* Request too much data for one request */
	if (FIPS_drbg_generate(dctx, randout, dctx->max_request + 1, 0,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_REQUEST_LENGTH_ERROR_UNDETECTED);
		goto err;
		}

	/* Try too large additional input */
	if (FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, dctx->max_adin + 1))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ADDITIONAL_INPUT_ERROR_UNDETECTED);
		goto err;
		}

	/* Check prediction resistance request fails if entropy source
	 * failure.
	 */

	t.entlen = 0;

	if (FIPS_drbg_generate(dctx, randout, td->katlen, 1,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}
		
	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}


	/* Instantiate again with valid data */

	if (!do_drbg_instantiate(dctx, td, &t))
			goto err;
	/* Test reseed counter works */
	/* Save initial reseed counter */
	reseed_counter_tmp = dctx->reseed_counter;
	/* Set reseed counter to beyond interval */
	dctx->reseed_counter = dctx->reseed_interval;

	/* Generate output and check entropy has been requested for reseed */
	t.entcnt = 0;
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, td->adinlen))
		goto err;
	if (t.entcnt != 1)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED);
		goto err;
		}
	/* Check reseed counter has been reset */
	if (dctx->reseed_counter != reseed_counter_tmp + 1)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_RESEED_COUNTER_ERROR);
		goto err;
		}

	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Check prediction resistance request fails if entropy source
	 * failure.
	 */

	t.entlen = 0;

	dctx->iflags |= DRBG_FLAG_NOERR;
	if (FIPS_drbg_generate(dctx, randout, td->katlen, 1,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}
		
	dctx->iflags &= ~DRBG_FLAG_NOERR;

	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}


	if (!do_drbg_instantiate(dctx, td, &t))
			goto err;
	/* Test reseed counter works */
	/* Save initial reseed counter */
	reseed_counter_tmp = dctx->reseed_counter;
	/* Set reseed counter to beyond interval */
	dctx->reseed_counter = dctx->reseed_interval;

	/* Generate output and check entropy has been requested for reseed */
	t.entcnt = 0;
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0,
				td->adin, td->adinlen))
		goto err;
	if (t.entcnt != 1)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED);
		goto err;
		}
	/* Check reseed counter has been reset */
	if (dctx->reseed_counter != reseed_counter_tmp + 1)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_RESEED_COUNTER_ERROR);
		goto err;
		}

	dctx->iflags &= ~DRBG_FLAG_NOERR;
	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Explicit reseed tests */

	/* Test explicit reseed with too large additional input */
	if (!do_drbg_init(dctx, td, &t))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	if (FIPS_drbg_reseed(dctx, td->adin, dctx->max_adin + 1) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ADDITIONAL_INPUT_ERROR_UNDETECTED);
		goto err;
		}

	/* Test explicit reseed with entropy source failure */

	t.entlen = 0;

	if (FIPS_drbg_reseed(dctx, td->adin, td->adinlen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Test explicit reseed with too much entropy */

	if (!do_drbg_init(dctx, td, &t))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	t.entlen = dctx->max_entropy + 1;

	if (FIPS_drbg_reseed(dctx, td->adin, td->adinlen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	/* Test explicit reseed with too little entropy */

	if (!do_drbg_init(dctx, td, &t))
		goto err;

	dctx->iflags |= DRBG_FLAG_NOERR;

	t.entlen = dctx->min_entropy - 1;

	if (FIPS_drbg_reseed(dctx, td->adin, td->adinlen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	if (!FIPS_drbg_uninstantiate(dctx))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ERROR);
		goto err;
		}

	p = (unsigned char *)&dctx->d;
	/* Standard says we have to check uninstantiate really zeroes
	 * the data...
	 */
	for (i = 0; i < sizeof(dctx->d); i++)
		{
		if (*p != 0)
			{
			FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_UNINSTANTIATE_ZEROISE_ERROR);
			goto err;
			}
		p++;
		}

	return 1;

	err:
	/* A real error as opposed to an induced one: underlying function will
	 * indicate the error.
	 */
	if (!(dctx->iflags & DRBG_FLAG_NOERR))
		FIPSerr(FIPS_F_FIPS_DRBG_ERROR_CHECK, FIPS_R_FUNCTION_ERROR);
	FIPS_drbg_uninstantiate(dctx);
	return 0;

	}

int fips_drbg_kat(DRBG_CTX *dctx, int nid, unsigned int flags)
	{
	DRBG_SELFTEST_DATA *td;
	flags |= DRBG_FLAG_TEST;
	for (td = drbg_test; td->nid != 0; td++)
		{
		if (td->nid == nid && td->flags == flags)
			{
			if (!fips_drbg_single_kat(dctx, td, 0))
				return 0;
			return fips_drbg_error_check(dctx, td);
			}
		}
	return 0;
	}

int FIPS_drbg_health_check(DRBG_CTX *dctx)
	{
	int rv;
	DRBG_CTX *tctx = NULL;
	tctx = FIPS_drbg_new(0, 0);
	fips_post_started(FIPS_TEST_DRBG, dctx->type, &dctx->xflags);
	if (!tctx)
		return 0;
	rv = fips_drbg_kat(tctx, dctx->type, dctx->xflags);
	if (tctx)
		FIPS_drbg_free(tctx);
	if (rv)
		fips_post_success(FIPS_TEST_DRBG, dctx->type, &dctx->xflags);
	else
		fips_post_failed(FIPS_TEST_DRBG, dctx->type, &dctx->xflags);
	if (!rv)
		dctx->status = DRBG_STATUS_ERROR;
	else
		dctx->health_check_cnt = 0;
	return rv;
	}

int FIPS_selftest_drbg(void)
	{
	DRBG_CTX *dctx;
	DRBG_SELFTEST_DATA *td;
	int rv = 1;
	dctx = FIPS_drbg_new(0, 0);
	if (!dctx)
		return 0;
	for (td = drbg_test; td->nid != 0; td++)
		{
		if (td->post != 1)
			continue;
		if (!fips_post_started(FIPS_TEST_DRBG, td->nid, &td->flags))
			return 1;
		if (!fips_drbg_single_kat(dctx, td, 1))
			{
			fips_post_failed(FIPS_TEST_DRBG, td->nid, &td->flags);
			rv = 0;
			continue;
			}
		if (!fips_post_success(FIPS_TEST_DRBG, td->nid, &td->flags))
			return 0;
		}
	FIPS_drbg_free(dctx);
	return rv;
	}


int FIPS_selftest_drbg_all(void)
	{
	DRBG_CTX *dctx;
	DRBG_SELFTEST_DATA *td;
	int rv = 1;
	dctx = FIPS_drbg_new(0, 0);
	if (!dctx)
		return 0;
	for (td = drbg_test; td->nid != 0; td++)
		{
		if (!fips_post_started(FIPS_TEST_DRBG, td->nid, &td->flags))
			return 1;
		if (!fips_drbg_single_kat(dctx, td, 0))
			{
			fips_post_failed(FIPS_TEST_DRBG, td->nid, &td->flags);
			rv = 0;
			continue;
			}
		if (!fips_drbg_error_check(dctx, td))
			{
			fips_post_failed(FIPS_TEST_DRBG, td->nid, &td->flags);
			rv = 0;
			continue;
			}
		if (!fips_post_success(FIPS_TEST_DRBG, td->nid, &td->flags))
			return 0;
		}
	FIPS_drbg_free(dctx);
	return rv;
	}

