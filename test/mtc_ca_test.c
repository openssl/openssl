/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto/mtc_ca.h"
#include "crypto/mtc_cosigner.h"
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

    if (!TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 5,
                      pkey)))
        goto err;

    /* The CA holds a reference of its own, so ours is no longer needed. */
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (!TEST_true(OSSL_MTC_CA_get0_id(ca, &got_id, &got_len))
        || !TEST_mem_eq(got_id, got_len, ca_id, sizeof(ca_id))
        || !TEST_ptr_ne(got_id, ca_id)
        || !TEST_ptr_eq(ossl_mtc_ca_hash(ca), EVP_sha256())
        || !TEST_true(EVP_PKEY_is_a(ossl_mtc_ca_cosigner_pkey(ca),
            "ML-DSA-44"))
        || !TEST_uint64_t_eq(ca->min_serial, 5))
        goto err;

    ret = 1;
err:
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(pkey);
    return ret;
}

/* A NULL hash is rejected. */
static int test_ca_null_hash(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_MTC_CA *ca = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = gen_cosigner_key()))
        goto err;
    if (!TEST_ptr_null(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), NULL, 0,
                           pkey)))
        goto err;

    ret = 1;
err:
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * Construct a trusted cosigner and confirm its ID is a copy and its key
 * survives the caller dropping its own reference.  A NULL key and an empty ID
 * are rejected.
 */
static int test_cosigner_roundtrip(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_MTC_COSIGNER *cosigner = NULL;
    const uint8_t *got_id = NULL;
    size_t got_len = 0;
    int ret = 0;

    if (!TEST_ptr(pkey = gen_cosigner_key())
        || !TEST_ptr_null(OSSL_MTC_COSIGNER_new(cosigner0_id,
            sizeof(cosigner0_id), NULL))
        || !TEST_ptr_null(OSSL_MTC_COSIGNER_new(cosigner0_id, 0, pkey))
        || !TEST_ptr(cosigner = OSSL_MTC_COSIGNER_new(cosigner0_id,
                         sizeof(cosigner0_id), pkey)))
        goto err;

    /* The cosigner holds its own reference; the caller's is released here. */
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (!TEST_true(OSSL_MTC_COSIGNER_get0_id(cosigner, &got_id, &got_len))
        || !TEST_mem_eq(got_id, got_len, cosigner0_id, sizeof(cosigner0_id))
        || !TEST_ptr_ne(got_id, cosigner0_id)
        || !TEST_true(EVP_PKEY_is_a(ossl_mtc_cosigner_pkey(cosigner),
            "ML-DSA-44")))
        goto err;

    ret = 1;
err:
    OSSL_MTC_COSIGNER_free(cosigner);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * A stack of trusted cosigners is kept sorted by ID, rejects a duplicate ID,
 * and is searched by ID.
 */
static int test_cosigner_stack(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_MTC_COSIGNER *c0 = NULL, *c2 = NULL, *dup = NULL;
    STACK_OF(OSSL_MTC_COSIGNER) *cosigners = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = gen_cosigner_key())
        || !TEST_ptr(c0 = OSSL_MTC_COSIGNER_new(cosigner0_id,
                         sizeof(cosigner0_id), pkey))
        || !TEST_ptr(c2 = OSSL_MTC_COSIGNER_new(cosigner2_id,
                         sizeof(cosigner2_id), pkey))
        || !TEST_ptr(dup = OSSL_MTC_COSIGNER_new(cosigner0_id,
                         sizeof(cosigner0_id), pkey))
        || !TEST_ptr(cosigners = sk_OSSL_MTC_COSIGNER_new(OSSL_MTC_COSIGNER_cmp)))
        goto err;

    if (!TEST_true(ossl_mtc_cosigner_stack_add(cosigners, c2))
        || !TEST_true(ossl_mtc_cosigner_stack_add(cosigners, c0))
        || !TEST_false(ossl_mtc_cosigner_stack_add(cosigners, dup))
        || !TEST_int_eq(sk_OSSL_MTC_COSIGNER_num(cosigners), 2)
        || !TEST_ptr_eq(sk_OSSL_MTC_COSIGNER_value(cosigners, 0), c0)
        || !TEST_ptr_eq(sk_OSSL_MTC_COSIGNER_value(cosigners, 1), c2)
        || !TEST_ptr_eq(ossl_mtc_cosigner_stack_lookup(cosigners, cosigner2_id,
                            sizeof(cosigner2_id)),
            c2)
        || !TEST_ptr_null(ossl_mtc_cosigner_stack_lookup(cosigners, ca_id,
            sizeof(ca_id)))
        || !TEST_ptr_null(ossl_mtc_cosigner_stack_lookup(NULL, cosigner0_id,
            sizeof(cosigner0_id))))
        goto err;

    ret = 1;
err:
    sk_OSSL_MTC_COSIGNER_free(cosigners);
    OSSL_MTC_COSIGNER_free(c0);
    OSSL_MTC_COSIGNER_free(c2);
    OSSL_MTC_COSIGNER_free(dup);
    EVP_PKEY_free(pkey);
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

    /* Serials are index 5 onward of log 1; indices 0..4 are revoked by
     * implication. */
    if (!TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(),
                      OSSL_MTC_serial(1, 5), ca_key)))
        goto err;

    if (!TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 0)), 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 4)),
            1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 5)),
            0))
        goto err;

    /* Add log 1 indices [10, 20): 9 out, 10 and 19 in, 20 out. */
    if (!TEST_true(OSSL_MTC_CA_add_revoked_range(ca, OSSL_MTC_serial(1, 10),
            OSSL_MTC_serial(1, 20)))
        || !TEST_size_t_eq(ca->revoked_count, 1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 9)),
            0)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 10)),
            1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 19)),
            1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 20)),
            0))
        goto err;

    /* A second, disjoint range is also honoured. */
    if (!TEST_true(OSSL_MTC_CA_add_revoked_range(ca, OSSL_MTC_serial(1, 100),
            OSSL_MTC_serial(1, 101)))
        || !TEST_size_t_eq(ca->revoked_count, 2)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca,
                            OSSL_MTC_serial(1, 100)),
            1)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca,
                            OSSL_MTC_serial(1, 101)),
            0))
        goto err;

    /* Empty and inverted ranges are rejected, list unchanged. */
    if (!TEST_false(OSSL_MTC_CA_add_revoked_range(ca, OSSL_MTC_serial(1, 30),
            OSSL_MTC_serial(1, 30)))
        || !TEST_false(OSSL_MTC_CA_add_revoked_range(ca, OSSL_MTC_serial(1, 40),
            OSSL_MTC_serial(1, 30)))
        || !TEST_size_t_eq(ca->revoked_count, 2))
        goto err;

    /*
     * An upper bound: (max_serial, 2^64) is revoked by implication.  Index 200
     * is accepted until max_serial is set to it; index 201 is then revoked.
     */
    if (!TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca, OSSL_MTC_serial(1, 200)),
            0)
        || !TEST_true(OSSL_MTC_CA_set_max_serial(ca, OSSL_MTC_serial(1, 200)))
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca,
                            OSSL_MTC_serial(1, 200)),
            0)
        || !TEST_int_eq(ossl_mtc_ca_serial_is_revoked(ca,
                            OSSL_MTC_serial(1, 201)),
            1))
        goto err;

    ret = 1;
err:
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(ca_key);
    return ret;
}

/* Find a CA's issuance log by number (white-box helper for the tests). */
static OSSL_MTC_LOG *ca_log(OSSL_MTC_CA *ca, uint64_t n)
{
    int i;

    for (i = 0; i < sk_OSSL_MTC_LOG_num(ca->logs); i++) {
        OSSL_MTC_LOG *l = sk_OSSL_MTC_LOG_value(ca->logs, i);

        if (l->log_number == n)
            return l;
    }
    return NULL;
}

/* Number of subtrees held for a CA's log (0 if the log is absent). */
static int ca_log_count(OSSL_MTC_CA *ca, uint64_t n)
{
    OSSL_MTC_LOG *l = ca_log(ca, n);

    return l == NULL ? 0 : sk_OSSL_MTC_TRUSTED_SUBTREE_num(l->subtrees);
}

/* The idx'th subtree (sorted by (start, end)) held for a CA's log. */
static OSSL_MTC_TRUSTED_SUBTREE *ca_log_subtree(OSSL_MTC_CA *ca, uint64_t n,
    int idx)
{
    OSSL_MTC_LOG *l = ca_log(ca, n);

    return l == NULL ? NULL
                     : sk_OSSL_MTC_TRUSTED_SUBTREE_value(l->subtrees, idx);
}

/* Whether the subtree [start, end) is in a CA log's active window. */
static int ca_log_has_subtree(OSSL_MTC_CA *ca, uint64_t n, uint64_t start,
    uint64_t end)
{
    int i;

    for (i = 0; i < ca_log_count(ca, n); i++) {
        OSSL_MTC_TRUSTED_SUBTREE *ts = ca_log_subtree(ca, n, i);

        if (ts->start == start && ts->end == end)
            return 1;
    }
    return 0;
}

/*
 * OSSL_MTC_CA_find locates a CA in a stack by CA ID given either as wire-form
 * relative-OID bytes or as a dotted-decimal string; a malformed string or an
 * absent ID matches nothing.
 */
static int test_ca_find(void)
{
    EVP_PKEY *k0 = NULL, *k1 = NULL;
    OSSL_MTC_CA *ca0 = NULL, *ca1 = NULL;
    STACK_OF(OSSL_MTC_CA) *cas = NULL;
    /* 32473.9, not in the stack. */
    static const uint8_t absent_id[] = { 0x81, 0xfd, 0x59, 0x09 };
    int ret = 0;

    if (!TEST_ptr(k0 = gen_cosigner_key())
        || !TEST_ptr(k1 = gen_cosigner_key())
        || !TEST_ptr(ca0 = OSSL_MTC_CA_new(cosigner0_id, sizeof(cosigner0_id),
                         EVP_sha256(), 0, k0))
        || !TEST_ptr(ca1 = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(),
                         0, k1))
        || !TEST_ptr(cas = sk_OSSL_MTC_CA_new(OSSL_MTC_CA_cmp))
        || !TEST_true(ossl_mtc_ca_stack_add(cas, ca0))
        || !TEST_true(ossl_mtc_ca_stack_add(cas, ca1)))
        goto err;

    /* Wire form (ca_id_str NULL) and dotted-decimal find the same CA. */
    if (!TEST_ptr_eq(OSSL_MTC_CA_find(cas, ca_id, sizeof(ca_id), NULL), ca1)
        || !TEST_ptr_eq(OSSL_MTC_CA_find(cas, NULL, 0, "32473.1"), ca1)
        || !TEST_ptr_eq(OSSL_MTC_CA_find(cas, NULL, 0, "32473.0"), ca0))
        goto err;

    /* Absent ID, and a malformed dotted-decimal string, both miss. */
    if (!TEST_ptr_null(OSSL_MTC_CA_find(cas, absent_id, sizeof(absent_id),
            NULL))
        || !TEST_ptr_null(OSSL_MTC_CA_find(cas, NULL, 0, "32473.9"))
        || !TEST_ptr_null(OSSL_MTC_CA_find(cas, NULL, 0, "not.an.oid")))
        goto err;

    ret = 1;
err:
    sk_OSSL_MTC_CA_free(cas);
    OSSL_MTC_CA_free(ca0);
    OSSL_MTC_CA_free(ca1);
    EVP_PKEY_free(k0);
    EVP_PKEY_free(k1);
    return ret;
}

/*
 * OSSL_MTC_CA_find over a stack of several CAs: each is found by either form of
 * its ID, and an absent ID misses wherever it would fall.
 */
static int test_ca_find_ordering(void)
{
    /* 32473.0, 32473.1, 32473.2 and 32474.1, then 32473.1.5 and 32473.200. */
    static const uint8_t id_32473_0[] = { 0x81, 0xfd, 0x59, 0x00 };
    static const uint8_t id_32473_1[] = { 0x81, 0xfd, 0x59, 0x01 };
    static const uint8_t id_32473_2[] = { 0x81, 0xfd, 0x59, 0x02 };
    static const uint8_t id_32474_1[] = { 0x81, 0xfd, 0x5a, 0x01 };
    static const uint8_t id_32473_1_5[] = { 0x81, 0xfd, 0x59, 0x01, 0x05 };
    static const uint8_t id_32473_200[] = { 0x81, 0xfd, 0x59, 0x81, 0x48 };
    static const struct {
        const uint8_t *id;
        size_t id_len;
        const char *text;
    } ids[] = {
        { id_32473_0, sizeof(id_32473_0), "32473.0" },
        { id_32473_1, sizeof(id_32473_1), "32473.1" },
        { id_32473_2, sizeof(id_32473_2), "32473.2" },
        { id_32474_1, sizeof(id_32474_1), "32474.1" },
        { id_32473_1_5, sizeof(id_32473_1_5), "32473.1.5" },
        { id_32473_200, sizeof(id_32473_200), "32473.200" },
    };
    /*
     * Absent IDs: shorter than every CA in the stack, in the gap between two of
     * the four-byte ones, one component on from a five-byte one, and longer
     * than all of them.
     */
    static const uint8_t short_id[] = { 0x81, 0xfd, 0x59 };
    static const uint8_t gap_id[] = { 0x81, 0xfd, 0x59, 0x09 };
    static const uint8_t next_id[] = { 0x81, 0xfd, 0x59, 0x01, 0x06 };
    static const uint8_t long_id[] = { 0x81, 0xfd, 0x59, 0x01, 0x05, 0x07 };
    static const struct {
        const uint8_t *id;
        size_t id_len;
    } absent[] = {
        { short_id, sizeof(short_id) },
        { gap_id, sizeof(gap_id) },
        { next_id, sizeof(next_id) },
        { long_id, sizeof(long_id) },
    };
    /* The order the CAs are added in, so that it is not the sorted order. */
    static const int added[] = { 4, 1, 5, 0, 3, 2 };
    EVP_PKEY *key = NULL;
    OSSL_MTC_CA *cas_by_id[OSSL_NELEM(ids)] = { NULL };
    STACK_OF(OSSL_MTC_CA) *cas = NULL;
    size_t i;
    int ret = 0;

    if (!TEST_ptr(key = gen_cosigner_key())
        || !TEST_ptr(cas = sk_OSSL_MTC_CA_new(OSSL_MTC_CA_cmp)))
        goto err;

    for (i = 0; i < OSSL_NELEM(ids); i++)
        if (!TEST_ptr(cas_by_id[i] = OSSL_MTC_CA_new(ids[i].id, ids[i].id_len,
                          EVP_sha256(), 0, key)))
            goto err;

    for (i = 0; i < OSSL_NELEM(added); i++)
        if (!TEST_true(ossl_mtc_ca_stack_add(cas, cas_by_id[added[i]])))
            goto err;

    /* The stack is in CA ID order however the CAs arrived. */
    if (!TEST_int_eq(sk_OSSL_MTC_CA_num(cas), (int)OSSL_NELEM(ids)))
        goto err;
    for (i = 0; i < OSSL_NELEM(ids); i++)
        if (!TEST_ptr_eq(sk_OSSL_MTC_CA_value(cas, (int)i), cas_by_id[i]))
            goto err;

    /* Each CA is found by its wire-form ID and by its dotted-decimal one. */
    for (i = 0; i < OSSL_NELEM(ids); i++)
        if (!TEST_ptr_eq(OSSL_MTC_CA_find(cas, ids[i].id, ids[i].id_len, NULL),
                cas_by_id[i])
            || !TEST_ptr_eq(OSSL_MTC_CA_find(cas, NULL, 0, ids[i].text),
                cas_by_id[i]))
            goto err;

    for (i = 0; i < OSSL_NELEM(absent); i++)
        if (!TEST_ptr_null(OSSL_MTC_CA_find(cas, absent[i].id,
                absent[i].id_len, NULL)))
            goto err;

    ret = 1;
err:
    sk_OSSL_MTC_CA_free(cas);
    for (i = 0; i < OSSL_NELEM(ids); i++)
        OSSL_MTC_CA_free(cas_by_id[i]);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A landmark update establishes the active window's subtrees (without hashes),
 * add_subtree_hash then makes a subtree usable, and a fresh update carries the
 * hash forward for a still-active subtree while dropping one that aged out.
 */
static int test_ca_load_landmarks(void)
{
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;
    static const uint8_t hash[32] = { 0x5a };
    static const uint8_t other[32] = { 0xa5 };
    /*
     * latest_landmark 3, then tree sizes and expiries for landmarks 3, 2, 1:
     * 8 6 3, the last bounding landmark 2.  Landmark 3 covers [6, 8), landmark
     * 2 covers
     * [3, 6).  Per section 4.5, find_subtrees([6,8)) = {[6,7), [7,8)} and
     * find_subtrees([3,6)) = {[3,4), [4,6)}: four active subtrees in all.
     */
    int found = 0, i, ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                         ca_key))
        || !TEST_ptr(bio = BIO_new_mem_buf("3\n8 100\n6 100\n3 50\n", -1))
        || !TEST_true(OSSL_MTC_CA_load_landmarks(ca, 1, bio, INT64_MIN)))
        goto err;

    /* Four landmark subtrees are active: [3,4), [4,6), [6,7), [7,8). */
    if (!TEST_int_eq(ca_log_count(ca, 1), 4))
        goto err;

    /* The window is held sorted ascending by (start, end). */
    for (i = 1; i < ca_log_count(ca, 1); i++) {
        OSSL_MTC_TRUSTED_SUBTREE *prev = ca_log_subtree(ca, 1, i - 1);
        OSSL_MTC_TRUSTED_SUBTREE *cur = ca_log_subtree(ca, 1, i);

        if (!TEST_true(prev->start < cur->start
                || (prev->start == cur->start && prev->end < cur->end)))
            goto err;
    }

    /* The log records the newest landmark the description named. */
    if (!TEST_uint64_t_eq(ca_log(ca, 1)->last_landmark, 3))
        goto err;

    /* Active but unhashed: not a trusted subtree, so not found. */
    if (!TEST_true(ca_log_has_subtree(ca, 1, 7, 8))
        || !TEST_int_eq(ossl_mtc_ca_trusted_subtree_matches(ca, 1, 7, 8, hash,
                            sizeof(hash), &found),
            0)
        || !TEST_int_eq(found, 0))
        goto err;

    /* A subtree outside the window cannot be hashed. */
    if (!TEST_false(OSSL_MTC_CA_add_subtree_hash(ca, 1, 0, 2, hash,
            sizeof(hash)))
        /* Wrong hash length is rejected. */
        || !TEST_false(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, hash, 16))
        /* Hashing an active subtree succeeds and makes it match. */
        || !TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, hash,
            sizeof(hash))))
        goto err;
    if (!TEST_int_eq(ossl_mtc_ca_trusted_subtree_matches(ca, 1, 7, 8, hash,
                         sizeof(hash), &found),
            1))
        goto err;

    /* Hashed, but asked about a different hash: found, and does not match. */
    if (!TEST_int_eq(ossl_mtc_ca_trusted_subtree_matches(ca, 1, 7, 8, other,
                         sizeof(other), &found),
            0)
        || !TEST_int_eq(found, 1))
        goto err;

    /* The hash is immutable: same value is a no-op, a different value fails. */
    if (!TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, hash,
            sizeof(hash)))
        || !TEST_false(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, other,
            sizeof(other))))
        goto err;

    /*
     * A newer update: latest_landmark 4, sizes 10 8 6 for landmarks 4, 3, 2.
     * Landmark 4 covers [8,10) = {[8,9), [9,10)}; landmark 3 still covers
     * [6,8) = {[6,7), [7,8)}, so [7,8) stays active and keeps its hash.  The
     * subtrees of landmark 2 ([3,4), [4,6)) age out.
     */
    BIO_free(bio);
    if (!TEST_ptr(bio = BIO_new_mem_buf("4\n10 100\n8 100\n6 50\n", -1))
        || !TEST_true(OSSL_MTC_CA_load_landmarks(ca, 1, bio, INT64_MIN)))
        goto err;

    /*
     * [7,8) survived with its hash; [4,6) is gone; the window is four again and
     * the newest landmark advanced.  The window is the only retention bound:
     * a subtree and its hash live exactly as long as the window holds them.
     */
    if (!TEST_int_eq(ca_log_count(ca, 1), 4)
        || !TEST_uint64_t_eq(ca_log(ca, 1)->last_landmark, 4)
        || !TEST_int_eq(ossl_mtc_ca_trusted_subtree_matches(ca, 1, 7, 8, hash,
                            sizeof(hash), &found),
            1))
        goto err;
    if (!TEST_false(ca_log_has_subtree(ca, 1, 4, 6)))
        goto err;

    /* An aged-out subtree cannot be re-hashed: it is no longer in the window. */
    if (!TEST_false(OSSL_MTC_CA_add_subtree_hash(ca, 1, 4, 6, hash,
            sizeof(hash))))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(ca_key);
    return ret;
}

/* Emit a CA's advertised IDs and compare them against the expected bytes. */
static int advertised_ids_are(OSSL_MTC_CA *ca, const uint8_t *expect,
    size_t expect_len)
{
    WPACKET pkt;
    uint8_t buf[128];
    size_t written = 0;
    int ok;

    if (!TEST_true(WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)))
        return 0;
    ok = TEST_true(ossl_mtc_ca_put_advertised_ids(ca, &pkt))
        && TEST_true(WPACKET_get_total_written(&pkt, &written))
        && TEST_mem_eq(buf, written, expect, expect_len);
    WPACKET_cleanup(&pkt);
    return ok;
}

/*
 * Advertised trust anchor IDs (section 8.2.1) are precomputed on the CA and
 * repacked on each update: a CA without landmark state advertises its bare CA
 * ID; once a log has a hashed landmark subtree it advertises that log's
 * landmark group ID (CA ID . 2 . log . newest landmark) instead;
 * directly-added subtrees never contribute a group.  Each emitted ID carries
 * a u8 length prefix.
 */
static int test_ca_advertised_ids(void)
{
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;
    static const uint8_t hash[32] = { 0x5a };
    /* The bare CA ID 32473.1, length-prefixed. */
    static const uint8_t bare[] = { 0x04, 0x81, 0xfd, 0x59, 0x01 };
    /* 32473.1.2.1.2 and 32473.1.2.1.3: the log-1 groups for landmarks 2, 3. */
    static const uint8_t group_l2[] = { 0x07, 0x81, 0xfd, 0x59, 0x01, 0x02,
        0x01, 0x02 };
    static const uint8_t group_l3[] = { 0x07, 0x81, 0xfd, 0x59, 0x01, 0x02,
        0x01, 0x03 };
    /* Log 1's group followed by log 2's, 32473.1.2.2.5; logs are sorted. */
    static const uint8_t two_groups[] = { 0x07, 0x81, 0xfd, 0x59, 0x01, 0x02,
        0x01, 0x03, 0x07, 0x81, 0xfd, 0x59, 0x01, 0x02, 0x02, 0x05 };
    int ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                         ca_key)))
        goto err;

    /* No landmark state at all: the bare CA ID. */
    if (!advertised_ids_are(ca, bare, sizeof(bare)))
        goto err;

    /* A window with no vetted hashes still advertises only the bare CA ID. */
    if (!TEST_ptr(bio = BIO_new_mem_buf("3\n8 100\n6 100\n3 50\n", -1))
        || !TEST_true(OSSL_MTC_CA_load_landmarks(ca, 1, bio, INT64_MIN))
        || !advertised_ids_are(ca, bare, sizeof(bare)))
        goto err;

    /* Hash [3,4) (landmark 2): the group for landmark 2 replaces the CA ID. */
    if (!TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 1, 3, 4, hash,
            sizeof(hash)))
        || !advertised_ids_are(ca, group_l2, sizeof(group_l2)))
        goto err;

    /* Hash [7,8) (landmark 3): the newest hashed landmark wins. */
    if (!TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, hash,
            sizeof(hash)))
        || !advertised_ids_are(ca, group_l3, sizeof(group_l3)))
        goto err;

    /*
     * A second log with its own landmark state contributes its own group, after
     * the first log's: landmark 5 of log 2 is tree size 4, covered by [0,2) and
     * [2,4), and hashing [0,2) makes log 2 advertise 32473.1.2.2.5.
     */
    BIO_free(bio);
    if (!TEST_ptr(bio = BIO_new_mem_buf("5\n4 100\n0 50\n", -1))
        || !TEST_true(OSSL_MTC_CA_load_landmarks(ca, 2, bio, INT64_MIN))
        || !TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 2, 0, 2, hash,
            sizeof(hash)))
        || !advertised_ids_are(ca, two_groups, sizeof(two_groups)))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(ca_key);
    return ret;
}

/*
 * A cutoff ends the description at the first landmark that expired before it:
 * that landmark and everything after it are not loaded, and the lines after it
 * are not read.
 */
static int test_ca_load_landmarks_cutoff(void)
{
    static const char desc[] = "5\n10 300\n8 200\n6 100\n3 50\ngarbage\n";
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;
    int ret = 0;

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(ca = ossl_mtc_ca_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                         ca_key)))
        goto err;

    /* Read to the end, the garbage line is rejected. */
    if (!TEST_ptr(bio = BIO_new_mem_buf(desc, -1))
        || !TEST_false(ossl_mtc_ca_load_landmarks(ca, 1, bio, INT64_MIN)))
        goto err;
    BIO_free(bio);

    /*
     * With cutoff 150, landmark 3 (expiry 100) ends the description: landmark
     * 5 covers [8, 10) with the subtrees [8, 9) and [9, 10), landmark 4 covers
     * [6, 8) with [6, 7) and [7, 8), and landmark 3's [3, 4) and [4, 6) are
     * not loaded.
     */
    if (!TEST_ptr(bio = BIO_new_mem_buf(desc, -1))
        || !TEST_true(ossl_mtc_ca_load_landmarks(ca, 1, bio, 150))
        || !TEST_int_eq(ca_log_count(ca, 1), 4)
        || !TEST_true(ca_log_has_subtree(ca, 1, 8, 9))
        || !TEST_true(ca_log_has_subtree(ca, 1, 7, 8))
        || !TEST_false(ca_log_has_subtree(ca, 1, 4, 6)))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    ossl_mtc_ca_free(ca);
    EVP_PKEY_free(ca_key);
    return ret;
}

/* Malformed or inconsistent landmark descriptions are rejected wholesale. */
static int test_ca_load_landmarks_bad(void)
{
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;
    size_t i;
    int ret = 0;
    static const char *bad[] = {
        "garbage\n", /* not a number */
        "3\n", /* no landmarks */
        "3 2\n8 100\n6 100\n3 50\n", /* more than latest_landmark on line 1 */
        "1\n8 100\n6 100\n3 50\n", /* more landmarks than latest_landmark */
        "3\n8 100\n6 100\n6 50\n", /* tree sizes not strictly decreasing */
        "3\n8 100\n6 200\n3 50\n", /* expiries increasing */
        "3\n8 100\n6 100\n3 50\nextra\n", /* trailing garbage */
        "3\n8 100\n6 100\n3 50", /* missing final newline */
        "3\n8 100\n6 100\n3\n", /* missing expiry */
        "-3\n8 100\n6 100\n3 50\n", /* sign */
        "+3\n8 100\n6 100\n3 50\n", /* sign */
        " 3\n8 100\n6 100\n3 50\n", /* leading space */
        "03\n8 100\n6 100\n3 50\n", /* leading zero */
        "3\n08 100\n6 100\n3 50\n", /* leading zero */
        "3\n8 100\n6 100\n3 50 \n", /* trailing space */
        "3\n8  100\n6 100\n3 50\n", /* two spaces */
        "3\n8 100\r\n6 100\n3 50\n", /* carriage return */
        "281474976710656\n8 100\n6 100\n3 50\n", /* latest_landmark >= 2^48 */
        "3\n281474976710656 100\n6 100\n3 50\n", /* tree size >= 2^48 */
        "3\n8 9223372036854775808\n6 100\n3 50\n", /* expiry > INT64_MAX */
    };

    if (!TEST_ptr(ca_key = gen_cosigner_key())
        || !TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                         ca_key)))
        goto err;

    for (i = 0; i < OSSL_NELEM(bad); i++) {
        if (!TEST_ptr(bio = BIO_new_mem_buf(bad[i], -1)))
            goto err;
        if (!TEST_false(OSSL_MTC_CA_load_landmarks(ca, 1, bio, INT64_MIN))) {
            TEST_info("input %zu should have failed: %s", i, bad[i]);
            goto err;
        }
        BIO_free(bio);
        bio = NULL;
    }

    /* Every rejection left the CA with no window installed. */
    if (!TEST_int_eq(ca_log_count(ca, 1), 0))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(ca_key);
    return ret;
}

/*
 * A stack of trusted CAs keeps borrowed CAs sorted by CA ID: adds land in order
 * regardless of insertion sequence, lookups hit by CA ID and miss otherwise, a
 * duplicate CA ID is rejected, and freeing the stack leaves the CAs intact.
 */
static int test_ca_stack(void)
{
    EVP_PKEY *k0 = NULL, *k1 = NULL, *k2 = NULL;
    OSSL_MTC_CA *ca0 = NULL, *ca1 = NULL, *ca2 = NULL, *dup = NULL;
    STACK_OF(OSSL_MTC_CA) *cas = NULL;
    const uint8_t *id = NULL;
    size_t idlen = 0;
    /* A CA ID that is not in the stack: 32473.9. */
    static const uint8_t absent_id[] = { 0x81, 0xfd, 0x59, 0x09 };
    int ret = 0;

    if (!TEST_ptr(k0 = gen_cosigner_key())
        || !TEST_ptr(k1 = gen_cosigner_key())
        || !TEST_ptr(k2 = gen_cosigner_key()))
        goto err;

    if (!TEST_ptr(ca0 = OSSL_MTC_CA_new(cosigner0_id, sizeof(cosigner0_id),
                      EVP_sha256(), 0, k0))
        || !TEST_ptr(ca1 = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(),
                         0, k1))
        || !TEST_ptr(ca2 = OSSL_MTC_CA_new(cosigner2_id, sizeof(cosigner2_id),
                         EVP_sha256(), 0, k2)))
        goto err;

    if (!TEST_ptr(cas = sk_OSSL_MTC_CA_new(OSSL_MTC_CA_cmp)))
        goto err;

    /* Add out of order; the stack must sort by CA ID (32473.0/.1/.2). */
    if (!TEST_true(ossl_mtc_ca_stack_add(cas, ca1))
        || !TEST_true(ossl_mtc_ca_stack_add(cas, ca2))
        || !TEST_true(ossl_mtc_ca_stack_add(cas, ca0))
        || !TEST_int_eq(sk_OSSL_MTC_CA_num(cas), 3))
        goto err;

    if (!TEST_ptr_eq(sk_OSSL_MTC_CA_value(cas, 0), ca0)
        || !TEST_ptr_eq(sk_OSSL_MTC_CA_value(cas, 1), ca1)
        || !TEST_ptr_eq(sk_OSSL_MTC_CA_value(cas, 2), ca2))
        goto err;

    /* Lookups hit by CA ID and return the borrowed CA. */
    if (!TEST_ptr_eq(ossl_mtc_ca_stack_lookup(cas, cosigner0_id,
                         sizeof(cosigner0_id)),
            ca0)
        || !TEST_ptr_eq(ossl_mtc_ca_stack_lookup(cas, ca_id, sizeof(ca_id)),
            ca1)
        || !TEST_ptr_eq(ossl_mtc_ca_stack_lookup(cas, cosigner2_id,
                            sizeof(cosigner2_id)),
            ca2))
        goto err;

    /* A CA ID that is not present misses. */
    if (!TEST_ptr_null(ossl_mtc_ca_stack_lookup(cas, absent_id,
            sizeof(absent_id))))
        goto err;

    /* A second CA with a duplicate CA ID is rejected and not added. */
    if (!TEST_ptr(dup = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                      k1))
        || !TEST_false(ossl_mtc_ca_stack_add(cas, dup))
        || !TEST_int_eq(sk_OSSL_MTC_CA_num(cas), 3))
        goto err;

    /* Freeing the stack container leaves the borrowed CAs usable. */
    sk_OSSL_MTC_CA_free(cas);
    cas = NULL;
    if (!TEST_true(OSSL_MTC_CA_get0_id(ca1, &id, &idlen))
        || !TEST_mem_eq(id, idlen, ca_id, sizeof(ca_id)))
        goto err;

    ret = 1;
err:
    sk_OSSL_MTC_CA_free(cas);
    OSSL_MTC_CA_free(ca0);
    OSSL_MTC_CA_free(ca1);
    OSSL_MTC_CA_free(ca2);
    OSSL_MTC_CA_free(dup);
    EVP_PKEY_free(k0);
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return ret;
}

/* OSSL_MTC_CA_free(NULL) must be a no-op. */
static int test_ca_free_null(void)
{
    OSSL_MTC_CA_free(NULL);
    return 1;
}

/*
 * The value of an experimental id-pe-mtcCertificationAuthority-SHA256
 * extension:
 * MTCCertificationAuthority SEQUENCE {
 *   sigAlg    AlgorithmIdentifier = ecdsa-with-SHA256,
 *   minSerial INTEGER 2^48,
 *   maxSerial INTEGER 2^48 + 100 }
 */
static const uint8_t ca_ext_der[] = {
    0x30, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64
};
/* The same with minSerial 0 and maxSerial 100, both below mtcMinSerial. */
static const uint8_t ca_ext_low_serial_der[] = {
    0x30, 0x12, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x64
};
/* The same with minSerial 2^48 + 100 and maxSerial 2^48: inverted bounds. */
static const uint8_t ca_ext_inverted_der[] = {
    0x30, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x02,
    0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/* ca_ext_der followed by a byte the value does not account for. */
static const uint8_t ca_ext_trailing_der[] = {
    0x30, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00
};
/* 32473.1 as TrustAnchorID relative-OID bytes. */
static const uint8_t expect_ca_id[] = { 0x81, 0xfd, 0x59, 0x01 };
/* A component with a leading zero continuation byte: not minimal. */
static const uint8_t nonminimal_ca_id[] = { 0x80, 0x81, 0xfd, 0x59, 0x01 };
/* A final component with its continuation bit set: truncated. */
static const uint8_t truncated_ca_id[] = { 0x81, 0xfd, 0x59, 0x81 };

/* The universal tag of a RELATIVE-OID, the type of the CA ID attribute. */
#define TEST_ASN1_RELATIVE_OID 13

/*
 * Write to a new memory BIO a certificate whose subject is the single
 * trustAnchorID attribute (id, id_len) of the given type.  With ext non-NULL
 * it carries that id-pe-mtcCertificationAuthority-SHA256 extension value,
 * marked critical when critical is set, and represents an MTC CA; with ext
 * NULL it represents a cosigner.
 */
static BIO *ca_cert_bio(int type, const uint8_t *id, size_t id_len,
    const uint8_t *ext, size_t ext_len, int critical)
{
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    ASN1_OBJECT *ext_obj = NULL;
    ASN1_OCTET_STRING *ext_data = NULL;
    X509_EXTENSION *x509_ext = NULL;
    BIO *bio = NULL, *ret = NULL;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(cert = X509_new())
        || !TEST_true(X509_set_version(cert, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(cert), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(cert), 3600))
        || !TEST_true(X509_set_pubkey(cert, key))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name,
            "1.3.6.1.4.1.44363.47.3", type, id, (int)id_len, -1, 0))
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(X509_set_issuer_name(cert, name)))
        goto err;

    if (ext != NULL
        && (!TEST_ptr(ext_obj = OBJ_txt2obj("1.3.6.1.4.1.44363.47.4", 1))
            || !TEST_ptr(ext_data = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(ext_data, ext, (int)ext_len))
            || !TEST_ptr(x509_ext = X509_EXTENSION_create_by_OBJ(NULL, ext_obj,
                             critical, ext_data))
            || !TEST_true(X509_add_ext(cert, x509_ext, -1))))
        goto err;
    if (!TEST_int_gt(X509_sign(cert, key, EVP_sha256()), 0))
        goto err;

    if (!TEST_ptr(bio = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_X509(bio, cert)))
        goto err;
    ret = bio;
    bio = NULL;
err:
    BIO_free(bio);
    X509_EXTENSION_free(x509_ext);
    ASN1_OCTET_STRING_free(ext_data);
    ASN1_OBJECT_free(ext_obj);
    X509_NAME_free(name);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Build a certificate representing an MTC CA and parse it back; then check
 * that certificates with serial bounds below mtcMinSerial or inverted, a CA
 * extension that is not critical or has trailing bytes, a CA ID attribute
 * that is not a RELATIVE-OID, a malformed CA ID, or no CA extension (a
 * cosigner certificate) are rejected.
 */
static int test_ca_parse_certificate(void)
{
    static const struct {
        const char *desc;
        int type;
        const uint8_t *id;
        size_t id_len;
        const uint8_t *ext;
        size_t ext_len;
        int critical;
    } bad[] = {
        { "serials below 2^48", TEST_ASN1_RELATIVE_OID, expect_ca_id,
            sizeof(expect_ca_id), ca_ext_low_serial_der,
            sizeof(ca_ext_low_serial_der), 1 },
        { "minSerial above maxSerial", TEST_ASN1_RELATIVE_OID, expect_ca_id,
            sizeof(expect_ca_id), ca_ext_inverted_der,
            sizeof(ca_ext_inverted_der), 1 },
        { "non-critical CA extension", TEST_ASN1_RELATIVE_OID, expect_ca_id,
            sizeof(expect_ca_id), ca_ext_der, sizeof(ca_ext_der), 0 },
        { "trailing byte in CA extension", TEST_ASN1_RELATIVE_OID,
            expect_ca_id, sizeof(expect_ca_id), ca_ext_trailing_der,
            sizeof(ca_ext_trailing_der), 1 },
        { "UTF8String CA ID", V_ASN1_UTF8STRING,
            (const uint8_t *)"32473.1", 7, ca_ext_der, sizeof(ca_ext_der), 1 },
        { "non-minimal CA ID", TEST_ASN1_RELATIVE_OID, nonminimal_ca_id,
            sizeof(nonminimal_ca_id), ca_ext_der, sizeof(ca_ext_der), 1 },
        { "truncated CA ID", TEST_ASN1_RELATIVE_OID, truncated_ca_id,
            sizeof(truncated_ca_id), ca_ext_der, sizeof(ca_ext_der), 1 },
        { "cosigner certificate", TEST_ASN1_RELATIVE_OID, expect_ca_id,
            sizeof(expect_ca_id), NULL, 0, 1 }
    };
    BIO *bio = NULL;
    STACK_OF(OSSL_MTC_CA) *cas = NULL;
    OSSL_MTC_CA *ca;
    const uint8_t *id;
    size_t id_len, i;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!TEST_ptr(bio = ca_cert_bio(TEST_ASN1_RELATIVE_OID, expect_ca_id,
                      sizeof(expect_ca_id), ca_ext_der, sizeof(ca_ext_der), 1))
        || !TEST_ptr(cas = sk_OSSL_MTC_CA_new_null()))
        goto err;

    if (!TEST_true(OSSL_MTC_CA_parse_certificates(NULL, NULL, bio, cas))
        || !TEST_int_eq(sk_OSSL_MTC_CA_num(cas), 1))
        goto err;
    ca = sk_OSSL_MTC_CA_value(cas, 0);
    if (!TEST_true(OSSL_MTC_CA_get0_id(ca, &id, &id_len))
        || !TEST_mem_eq(id, id_len, expect_ca_id, sizeof(expect_ca_id)))
        goto err;

    for (i = 0; i < OSSL_NELEM(bad); i++) {
        BIO_free(bio);
        if (!TEST_ptr(bio = ca_cert_bio(bad[i].type, bad[i].id,
                          bad[i].id_len, bad[i].ext, bad[i].ext_len,
                          bad[i].critical)))
            goto err;
        if (!TEST_false(OSSL_MTC_CA_parse_certificates(NULL, NULL, bio, cas))
            || !TEST_int_eq(sk_OSSL_MTC_CA_num(cas), 1)) {
            TEST_info("case: %s", bad[i].desc);
            goto err;
        }
    }
    ret = 1;
err:
    sk_OSSL_MTC_CA_pop_free(cas, OSSL_MTC_CA_free);
    BIO_free(bio);
    return ret;
}

/*
 * Build a certificate representing a cosigner and parse it back; then check
 * that a CA certificate, a cosigner ID attribute that is not a RELATIVE-OID,
 * and a malformed cosigner ID are rejected, leaving the stack as it was.
 */
static int test_cosigner_parse_certificate(void)
{
    static const struct {
        const char *desc;
        int type;
        const uint8_t *id;
        size_t id_len;
        const uint8_t *ext;
        size_t ext_len;
        int critical;
    } bad[] = {
        { "CA certificate", TEST_ASN1_RELATIVE_OID, cosigner0_id,
            sizeof(cosigner0_id), ca_ext_der, sizeof(ca_ext_der), 1 },
        { "non-critical CA certificate", TEST_ASN1_RELATIVE_OID, cosigner0_id,
            sizeof(cosigner0_id), ca_ext_der, sizeof(ca_ext_der), 0 },
        { "UTF8String cosigner ID", V_ASN1_UTF8STRING,
            (const uint8_t *)"32473.0", 7, NULL, 0, 0 },
        { "non-minimal cosigner ID", TEST_ASN1_RELATIVE_OID, nonminimal_ca_id,
            sizeof(nonminimal_ca_id), NULL, 0, 0 },
        { "truncated cosigner ID", TEST_ASN1_RELATIVE_OID, truncated_ca_id,
            sizeof(truncated_ca_id), NULL, 0, 0 }
    };
    BIO *bio = NULL;
    STACK_OF(OSSL_MTC_COSIGNER) *cosigners = NULL;
    OSSL_MTC_COSIGNER *cosigner;
    const uint8_t *id;
    size_t id_len, i;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!TEST_ptr(bio = ca_cert_bio(TEST_ASN1_RELATIVE_OID, cosigner0_id,
                      sizeof(cosigner0_id), NULL, 0, 0))
        || !TEST_ptr(cosigners = sk_OSSL_MTC_COSIGNER_new_null()))
        goto err;

    if (!TEST_true(OSSL_MTC_COSIGNER_parse_certificates(NULL, NULL, bio,
            cosigners))
        || !TEST_int_eq(sk_OSSL_MTC_COSIGNER_num(cosigners), 1))
        goto err;
    cosigner = sk_OSSL_MTC_COSIGNER_value(cosigners, 0);
    if (!TEST_true(OSSL_MTC_COSIGNER_get0_id(cosigner, &id, &id_len))
        || !TEST_mem_eq(id, id_len, cosigner0_id, sizeof(cosigner0_id))
        || !TEST_true(EVP_PKEY_is_a(ossl_mtc_cosigner_pkey(cosigner), "EC")))
        goto err;

    for (i = 0; i < OSSL_NELEM(bad); i++) {
        BIO_free(bio);
        if (!TEST_ptr(bio = ca_cert_bio(bad[i].type, bad[i].id,
                          bad[i].id_len, bad[i].ext, bad[i].ext_len,
                          bad[i].critical)))
            goto err;
        if (!TEST_false(OSSL_MTC_COSIGNER_parse_certificates(NULL, NULL, bio,
                cosigners))
            || !TEST_int_eq(sk_OSSL_MTC_COSIGNER_num(cosigners), 1)) {
            TEST_info("case: %s", bad[i].desc);
            goto err;
        }
    }
    ret = 1;
err:
    sk_OSSL_MTC_COSIGNER_pop_free(cosigners, OSSL_MTC_COSIGNER_free);
    BIO_free(bio);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_ca_roundtrip);
    ADD_TEST(test_ca_null_hash);
    ADD_TEST(test_cosigner_roundtrip);
    ADD_TEST(test_cosigner_stack);
    ADD_TEST(test_ca_revoked_ranges);
    ADD_TEST(test_ca_find);
    ADD_TEST(test_ca_find_ordering);
    ADD_TEST(test_ca_load_landmarks);
    ADD_TEST(test_ca_load_landmarks_cutoff);
    ADD_TEST(test_ca_advertised_ids);
    ADD_TEST(test_ca_load_landmarks_bad);
    ADD_TEST(test_ca_stack);
    ADD_TEST(test_ca_parse_certificate);
    ADD_TEST(test_cosigner_parse_certificate);
    ADD_TEST(test_ca_free_null);
    return 1;
}
