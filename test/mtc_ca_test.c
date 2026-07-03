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

/* Two additional cosigner IDs: 32473.0 and 32473.2. */
static const uint8_t cosigner0_id[] = { 0x81, 0xfd, 0x59, 0x00 };
static const uint8_t cosigner2_id[] = { 0x81, 0xfd, 0x59, 0x02 };

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

/*
 * Add two distinct cosigners and confirm each is stored with its ID copied
 * (not aliased) and its key shared by reference.
 */
static int test_ca_add_cosigners(void)
{
    EVP_PKEY *ca_key = NULL, *k0 = NULL, *k2 = NULL;
    OSSL_MTC_CA *ca = NULL;
    int ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(k0 = gen_cosigner_key())
        || !TEST_ptr(k2 = gen_cosigner_key()))
        goto err;

    if (!TEST_ptr(ca = ossl_mtc_ca_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                      ca_key)))
        goto err;

    if (!TEST_true(ossl_mtc_ca_add_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_true(ossl_mtc_ca_add_cosigner(ca, cosigner2_id,
            sizeof(cosigner2_id), "ML-DSA-44", k2))
        || !TEST_size_t_eq(ca->cosigner_count, 2))
        goto err;

    if (!TEST_mem_eq(ca->cosigners[0].id, ca->cosigners[0].id_len,
            cosigner0_id, sizeof(cosigner0_id))
        || !TEST_ptr_ne(ca->cosigners[0].id, cosigner0_id)
        || !TEST_str_eq(ca->cosigners[0].sig_name, "ML-DSA-44")
        || !TEST_ptr_eq(ca->cosigners[0].pkey, k0)
        || !TEST_mem_eq(ca->cosigners[1].id, ca->cosigners[1].id_len,
            cosigner2_id, sizeof(cosigner2_id))
        || !TEST_ptr_eq(ca->cosigners[1].pkey, k2))
        goto err;

    ret = 1;
err:
    ossl_mtc_ca_free(ca);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(k0);
    EVP_PKEY_free(k2);
    return ret;
}

/*
 * Cosigner IDs must be distinct (section 5.3): a repeated ID and the CA's own
 * ID (the CA cosigner) are both rejected, leaving the list unchanged.
 */
static int test_ca_add_cosigner_duplicate(void)
{
    EVP_PKEY *ca_key = NULL, *k0 = NULL;
    OSSL_MTC_CA *ca = NULL;
    int ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(k0 = gen_cosigner_key()))
        goto err;

    if (!TEST_ptr(ca = ossl_mtc_ca_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                      ca_key)))
        goto err;

    if (!TEST_true(ossl_mtc_ca_add_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_false(ossl_mtc_ca_add_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_false(ossl_mtc_ca_add_cosigner(ca, ca_id, sizeof(ca_id),
            "ML-DSA-44", k0))
        || !TEST_size_t_eq(ca->cosigner_count, 1))
        goto err;

    ret = 1;
err:
    ossl_mtc_ca_free(ca);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(k0);
    return ret;
}

/*
 * Revoked ranges (section 7.5): the implied [0, min_serial) range applies, added
 * half-open ranges are honoured at their boundaries, and empty/inverted ranges
 * are rejected without changing the list.
 */
static int test_ca_revoked_ranges(void)
{
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    int ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key()))
        goto err;

    /* min_serial = 5, so serials 0..4 are revoked by implication. */
    if (!TEST_ptr(ca = ossl_mtc_ca_new(ca_id, sizeof(ca_id), EVP_sha256(), 5,
                      ca_key)))
        goto err;

    if (!TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 0), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 4), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 5), 0))
        goto err;

    /* Add [10, 20): 9 out, 10 and 19 in, 20 out. */
    if (!TEST_true(ossl_mtc_ca_add_revoked_range(ca, 10, 20))
        || !TEST_size_t_eq(ca->revoked_count, 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 9), 0)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 10), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 19), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 20), 0))
        goto err;

    /* A second, disjoint range is also honoured. */
    if (!TEST_true(ossl_mtc_ca_add_revoked_range(ca, 100, 101))
        || !TEST_size_t_eq(ca->revoked_count, 2)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 100), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, 101), 0))
        goto err;

    /* Empty and inverted ranges are rejected, list unchanged. */
    if (!TEST_false(ossl_mtc_ca_add_revoked_range(ca, 30, 30))
        || !TEST_false(ossl_mtc_ca_add_revoked_range(ca, 40, 30))
        || !TEST_size_t_eq(ca->revoked_count, 2))
        goto err;

    ret = 1;
err:
    ossl_mtc_ca_free(ca);
    EVP_PKEY_free(ca_key);
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
    ADD_TEST(test_ca_add_cosigners);
    ADD_TEST(test_ca_add_cosigner_duplicate);
    ADD_TEST(test_ca_revoked_ranges);
    ADD_TEST(test_ca_free_null);
    return 1;
}
