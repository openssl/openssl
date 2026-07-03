/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>

#include "crypto/mtc_ca.h"
#include "testutil.h"

/* A CA ID: the TrustAnchorID 32473.1 in relative-OID bytes. */
static const uint8_t ca_id[] = { 0x81, 0xfd, 0x59, 0x01 };

/* Build a throwaway cosigner key for the tests; MTC CA cosigners are ML-DSA. */
static EVP_PKEY *gen_cosigner_key(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
}

/*
 * Construct a CA from configured fields and confirm each is stored and
 * retrievable, that the CA ID is copied rather than aliased, and that the
 * cosigner key survives the caller dropping its own reference.
 */
static int test_ca_roundtrip(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_MTC_CA *ca = NULL;
    const uint8_t *got_id = NULL;
    size_t got_len = 0;
    int ret = 0;

    if (!TEST_ptr(pkey = gen_cosigner_key()))
        goto err;

    if (!TEST_ptr(ca = ossl_mtc_ca_new(ca_id, sizeof(ca_id), EVP_sha256(), 5,
                      pkey)))
        goto err;

    /* The CA holds a reference of its own, so ours is no longer needed. */
    EVP_PKEY_free(pkey);
    pkey = NULL;

    got_id = ossl_mtc_ca_id(ca, &got_len);
    if (!TEST_mem_eq(got_id, got_len, ca_id, sizeof(ca_id))
        || !TEST_ptr_ne(got_id, ca_id)
        || !TEST_ptr_eq(ossl_mtc_ca_hash(ca), EVP_sha256())
        || !TEST_true(EVP_PKEY_is_a(ossl_mtc_ca_cosigner_pkey(ca), "ML-DSA-44"))
        || !TEST_uint64_t_eq(ca->min_serial, 5))
        goto err;

    ret = 1;
err:
    ossl_mtc_ca_free(ca);
    EVP_PKEY_free(pkey);
    return ret;
}

/* ossl_mtc_ca_free(NULL) must be a no-op. */
static int test_ca_free_null(void)
{
    ossl_mtc_ca_free(NULL);
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_ca_roundtrip);
    ADD_TEST(test_ca_free_null);
    return 1;
}
