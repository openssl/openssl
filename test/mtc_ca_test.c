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

    if (!TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                      ca_key)))
        goto err;

    if (!TEST_true(OSSL_MTC_CA_add1_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_true(OSSL_MTC_CA_add1_cosigner(ca, cosigner2_id,
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
    OSSL_MTC_CA_free(ca);
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

    if (!TEST_ptr(ca = OSSL_MTC_CA_new(ca_id, sizeof(ca_id), EVP_sha256(), 0,
                      ca_key)))
        goto err;

    if (!TEST_true(OSSL_MTC_CA_add1_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_false(OSSL_MTC_CA_add1_cosigner(ca, cosigner0_id,
            sizeof(cosigner0_id), "ML-DSA-44", k0))
        || !TEST_false(OSSL_MTC_CA_add1_cosigner(ca, ca_id, sizeof(ca_id),
            "ML-DSA-44", k0))
        || !TEST_size_t_eq(ca->cosigner_count, 1))
        goto err;

    ret = 1;
err:
    OSSL_MTC_CA_free(ca);
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

    if (!TEST_ptr(cas = sk_OSSL_MTC_CA_new(ossl_mtc_ca_cmp)))
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

int setup_tests(void)
{
    ADD_TEST(test_ca_roundtrip);
    ADD_TEST(test_ca_null_hash);
    ADD_TEST(test_ca_add_cosigners);
    ADD_TEST(test_ca_add_cosigner_duplicate);
    ADD_TEST(test_ca_revoked_ranges);
    ADD_TEST(test_ca_load_landmarks);
    ADD_TEST(test_ca_load_landmarks_cutoff);
    ADD_TEST(test_ca_load_landmarks_bad);
    ADD_TEST(test_ca_stack);
    ADD_TEST(test_ca_free_null);
    return 1;
}
