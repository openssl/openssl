/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../crypto/rand/rand_local.h"

#include "testutil.h"
#include "drbg_extra_test.h"

static unsigned char zerobuff[32];

static size_t kat_entropy(RAND_DRBG *drbg, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len,
                          int prediction_resistance)
{
    *pout = zerobuff;
    return sizeof(zerobuff);
}

static size_t kat_nonce(RAND_DRBG *drbg, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    *pout = zerobuff;
    return sizeof(zerobuff);
}

static int run_extra_kat(const struct drbg_extra_kat *td)
{
    unsigned long long i;
    RAND_DRBG *drbg = NULL;
    unsigned char buff[BUFFSIZE];
    unsigned int flags = 0;
    int failures = 0;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, flags, NULL)))
        return 0;

    /* Set deterministic entropy callback. */
    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))) {
        failures++;
        goto err;
    }

    /* Set fixed reseed intervall. */
    if (!TEST_true(RAND_DRBG_set_reseed_interval(drbg, RESEEDINTERVAL))) {
        failures++;
        goto err;
    }

    if (!TEST_true(RAND_DRBG_instantiate(drbg, NULL, 0)))
        failures++;

    for (i = 0; i < td->ngen; i++) {
        if(!TEST_true(RAND_DRBG_generate(drbg, buff, sizeof(buff), 0, NULL,
                                         0)))
            failures++;
    }

    if (!TEST_true(RAND_DRBG_uninstantiate(drbg))
        || !TEST_mem_eq(td->expected, sizeof(buff), buff, sizeof(buff)))
        failures++;

err:
    if (drbg != NULL) {
        RAND_DRBG_uninstantiate(drbg);
        RAND_DRBG_free(drbg);
    }
    return failures == 0;
}

static int test_extra_kats(int i)
{
    return run_extra_kat(drbg_extra_test[i]);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_extra_kats, OSSL_NELEM(drbg_extra_test));
    return 1;
}
