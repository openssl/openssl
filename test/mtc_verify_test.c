/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Verify Merkle Tree Certificates end to end (section 7.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/)
 * against the test certificates in test/mtc (see its README.md).  The CA
 * parameters below are those the certificates were generated with: CA ID
 * 32473.1, log 1, a 10-entry tree, and an ML-DSA-44 CA cosigner keyed from the
 * seed 00..1f.
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/mtc.h>

#include "crypto/mtc_ca.h"
#include "crypto/mtc_cosigner.h"
#include "crypto/mtc_verify.h"
#include "crypto/x509.h"
#include "testutil.h"

static const char *certs_dir;

/* The CA ID: the TrustAnchorID 32473.1 in relative-OID bytes. */
static const uint8_t ca_id[] = { 0x81, 0xfd, 0x59, 0x01 };

/* The CA cosigner seed (config 32473.1); its ML-DSA-44 key signs the subtree. */
static const uint8_t ca_seed[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* A different seed, so the derived cosigner key does not match the proof. */
static const uint8_t wrong_seed[32] = { 0x00 };

/* The additional cosigners 32473.0 and 32473.2 (config seeds) that cosign. */
static const uint8_t cosigner0_id[] = { 0x81, 0xfd, 0x59, 0x00 };
static const uint8_t cosigner0_seed[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xa1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
static const uint8_t cosigner2_id[] = { 0x81, 0xfd, 0x59, 0x02 };
static const uint8_t cosigner2_seed[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

/*
 * The mtc-landmark.pem fixture's landmark state: log 1 has one active landmark,
 * number 1, at tree size 8, so the window is the subtrees [0, 4) and [4, 8); the
 * leaf's signatureless proof is into [0, 4), whose vetted hash is below.
 */
static const char landmark_desc[] = "1\n8 100\n0 50\n";
static const uint64_t landmark_log = 1;
static const uint64_t landmark_start = 0, landmark_end = 4;
static const uint8_t subtree_hash[] = {
    0xf6, 0x8f, 0x98, 0x02, 0x58, 0xf1, 0xdc, 0x9f, 0x89, 0x0a, 0x1c, 0xf9,
    0x5d, 0x7d, 0xd8, 0x54, 0xba, 0x26, 0xc9, 0x78, 0xb6, 0x69, 0x40, 0x09,
    0x22, 0xe9, 0x28, 0x92, 0xa9, 0x74, 0x61, 0xb7
};

/* A subtree hash that does not match the reconstructed one. */
static const uint8_t wrong_subtree_hash[32] = { 0x01 };

/* Derive the ML-DSA-44 cosigner key from a 32-byte seed. */
static EVP_PKEY *cosigner_key(const uint8_t *seed, size_t seed_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
        (void *)seed, seed_len);
    *p = OSSL_PARAM_construct_end();

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL)) != NULL
        && EVP_PKEY_keygen_init(ctx) == 1
        && EVP_PKEY_CTX_set_params(ctx, params) == 1)
        (void)EVP_PKEY_generate(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Give the landmark leaf's log its active landmarks, with no subtree hashes. */
static int load_landmark_window(OSSL_MTC_CA *ca)
{
    BIO *bio = BIO_new_mem_buf(landmark_desc, -1);
    int ret;

    ret = bio != NULL
        && OSSL_MTC_CA_load_landmarks(ca, landmark_log, bio, INT64_MIN);
    BIO_free(bio);
    return ret;
}

/*
 * Build a trusted CA matching the fixture.  Its ML-DSA-44 cosigner key is
 * derived from seed.  If hash is non-NULL the landmark leaf's log is given its
 * active landmarks and hash is recorded for the subtree that leaf proves into,
 * which is what lets a signatureless certificate verify; passing a hash other
 * than the true one leaves the subtree trusted but not matching.
 */
static OSSL_MTC_CA *make_ca(const uint8_t *id, size_t id_len,
    const uint8_t *seed, size_t seed_len, const uint8_t *hash)
{
    EVP_PKEY *pkey = cosigner_key(seed, seed_len);
    OSSL_MTC_CA *ca = NULL;

    if (pkey == NULL)
        return NULL;
    ca = OSSL_MTC_CA_new(id, id_len, EVP_sha256(), 0, pkey);
    EVP_PKEY_free(pkey); /* the CA holds its own reference */
    if (ca == NULL || hash == NULL)
        return ca;

    if (!load_landmark_window(ca)
        || !OSSL_MTC_CA_add_subtree_hash(ca, landmark_log, landmark_start,
            landmark_end, hash, sizeof(subtree_hash))) {
        OSSL_MTC_CA_free(ca);
        return NULL;
    }
    return ca;
}

/*
 * make_ca() with the landmark leaf's log given its active landmarks but no
 * subtree hash, the state between OSSL_MTC_CA_load_landmarks() and
 * OSSL_MTC_CA_add_subtree_hash().
 */
static OSSL_MTC_CA *make_ca_unhashed(void)
{
    OSSL_MTC_CA *ca = make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed),
        NULL);

    if (ca != NULL && !load_landmark_window(ca)) {
        OSSL_MTC_CA_free(ca);
        return NULL;
    }
    return ca;
}

/* The cosigner lookup for ossl_mtc_verify(): a plain sorted stack. */
static OSSL_MTC_COSIGNER *stack_lookup(const uint8_t *id, size_t id_len,
    void *arg)
{
    return ossl_mtc_cosigner_stack_lookup(arg, id, id_len);
}

/* Build a trusted cosigner with the given ID and ML-DSA-44 key seed. */
static OSSL_MTC_COSIGNER *make_cosigner(const uint8_t *id, size_t id_len,
    const uint8_t *seed, size_t seed_len)
{
    EVP_PKEY *pkey = cosigner_key(seed, seed_len);
    OSSL_MTC_COSIGNER *cosigner = NULL;

    if (pkey != NULL)
        cosigner = OSSL_MTC_COSIGNER_new(id, id_len, pkey);
    EVP_PKEY_free(pkey); /* the cosigner holds its own reference */
    return cosigner;
}

/*
 * Load cert_name, trust ca, resolve the issuing CA and verify its proof
 * against the trusted cosigners and quorum, and confirm the outcome is
 * expect_ret with expect_error recorded.  ca and cosigners are consumed.
 */
static int check_policy(const char *cert_name, OSSL_MTC_CA *ca,
    STACK_OF(OSSL_MTC_COSIGNER) *cosigners, size_t quorum, int expect_ret,
    int expect_error)
{
    char *path = NULL;
    X509 *cert = NULL;
    unsigned char *tbs = NULL;
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;
    STACK_OF(OSSL_MTC_CA) *cas = NULL;
    OSSL_MTC_CA *found;
    int error = X509_V_OK, verified = 0, tbs_len, ret = 0;

    if (!TEST_ptr(ca)
        || !TEST_ptr(path = test_mk_file_path(certs_dir, cert_name))
        || !TEST_ptr(cert = load_cert_pem(path, NULL))
        || !TEST_int_gt(tbs_len = i2d_re_X509_tbs(cert, &tbs), 0)
        || !TEST_ptr(cas = sk_OSSL_MTC_CA_new(OSSL_MTC_CA_cmp))
        || !TEST_int_eq(ossl_mtc_ca_stack_add(cas, ca), 1))
        goto err;
    X509_get0_signature(&sig, &alg, cert); /* the MTCProof is the signatureValue */
    found = ossl_mtc_ca_for_cert(cas, cert, &error);
    if (found != NULL)
        verified = ossl_mtc_verify(found, stack_lookup, cosigners, quorum,
            tbs, (size_t)tbs_len, ASN1_STRING_get0_data(sig),
            ASN1_STRING_get_length(sig), &error);
    if (!TEST_int_eq(verified, expect_ret) || !TEST_int_eq(error, expect_error))
        goto err;
    ret = 1;
err:
    sk_OSSL_MTC_CA_free(cas);
    OSSL_MTC_CA_free(ca);
    sk_OSSL_MTC_COSIGNER_pop_free(cosigners, OSSL_MTC_COSIGNER_free);
    OPENSSL_free(tbs);
    X509_free(cert);
    OPENSSL_free(path);
    return ret;
}

/* check_policy() with no trusted cosigners and no quorum. */
static int check(const char *cert_name, OSSL_MTC_CA *ca, int expect_ret,
    int expect_error)
{
    return check_policy(cert_name, ca, NULL, 0, expect_ret, expect_error);
}

/*
 * A sorted stack of the trusted cosigners among 32473.0 (keyed from seed0) and
 * 32473.2 (keyed from seed2); a NULL seed leaves that cosigner out.
 */
static STACK_OF(OSSL_MTC_COSIGNER) *make_cosigners(const uint8_t *seed0,
    const uint8_t *seed2)
{
    STACK_OF(OSSL_MTC_COSIGNER) *cosigners;
    OSSL_MTC_COSIGNER *cosigner;

    if (!TEST_ptr(cosigners = sk_OSSL_MTC_COSIGNER_new(OSSL_MTC_COSIGNER_cmp)))
        return NULL;
    if (seed0 != NULL) {
        if (!TEST_ptr(cosigner = make_cosigner(cosigner0_id,
                          sizeof(cosigner0_id), seed0, 32))
            || !TEST_true(ossl_mtc_cosigner_stack_add(cosigners, cosigner)))
            goto err;
    }
    if (seed2 != NULL) {
        if (!TEST_ptr(cosigner = make_cosigner(cosigner2_id,
                          sizeof(cosigner2_id), seed2, 32))
            || !TEST_true(ossl_mtc_cosigner_stack_add(cosigners, cosigner)))
            goto err;
    }
    return cosigners;
err:
    sk_OSSL_MTC_COSIGNER_pop_free(cosigners, OSSL_MTC_COSIGNER_free);
    return NULL;
}

/* A signatureless MTC verifies via a matching trusted subtree. */
static int test_signatureless_trusted_subtree(void)
{
    return check("mtc-landmark.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), subtree_hash),
        1, X509_V_OK);
}

/* A signatureless MTC has no cosignature, so no trusted subtree means failure. */
static int test_signatureless_no_subtree(void)
{
    return check("mtc-landmark.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_NOT_TRUSTED);
}

/* A trusted subtree whose hash differs from the reconstructed one is rejected. */
static int test_wrong_subtree_hash(void)
{
    return check("mtc-landmark.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed),
            wrong_subtree_hash),
        0, X509_V_ERR_MTC_NOT_TRUSTED);
}

/* A signatureless MTC over an active subtree with no hash is not trusted. */
static int test_signatureless_unhashed_subtree(void)
{
    return check("mtc-landmark.pem", make_ca_unhashed(), 0,
        X509_V_ERR_MTC_NOT_TRUSTED);
}

/*
 * A standalone MTC whose subtree is active but has no hash is not over a
 * trusted subtree (7.4), so it verifies via its CA cosignature (7.2 step 12).
 */
static int test_standalone_unhashed_subtree(void)
{
    return check("mtc-landmark-standalone.pem", make_ca_unhashed(), 1,
        X509_V_OK);
}

/* The same standalone MTC also verifies against the subtree's true hash. */
static int test_standalone_trusted_subtree(void)
{
    return check("mtc-landmark-standalone.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), subtree_hash),
        1, X509_V_OK);
}

/*
 * A trusted subtree whose hash differs from the reconstructed one is rejected
 * even when the CA cosignature over the subtree is valid.
 */
static int test_standalone_wrong_subtree_hash(void)
{
    return check("mtc-landmark-standalone.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed),
            wrong_subtree_hash),
        0, X509_V_ERR_MTC_NOT_TRUSTED);
}

/* A standalone MTC verifies via the CA cosignature when the key is correct. */
static int test_standalone_cosignature(void)
{
    return check("mtc-leaf-standalone.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        1, X509_V_OK);
}

/* The same standalone MTC fails against the wrong CA cosigner key. */
static int test_standalone_wrong_key(void)
{
    return check("mtc-leaf-standalone.pem",
        make_ca(ca_id, sizeof(ca_id), wrong_seed, sizeof(wrong_seed), NULL),
        0, X509_V_ERR_MTC_NOT_TRUSTED);
}

/* Extra unrecognised cosignatures are ignored; the CA cosignature suffices. */
static int test_three_cosigners(void)
{
    return check("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        1, X509_V_OK);
}

/* A cosignature from a non-CA cosigner only does not satisfy the policy. */
static int test_no_ca_signer(void)
{
    return check("mtc-leaf-standalone-no_ca_signer.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_NOT_TRUSTED);
}

/*
 * Cosignatures must be strictly ordered with no duplicates (section 6.2); a
 * list that is not is a malformed proof.
 */
static int test_duplicate_ca_signer(void)
{
    return check("mtc-leaf-standalone-duplicate_ca_signer.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_BAD_PROOF);
}

static int test_cosigner_wrong_order(void)
{
    return check("mtc-leaf-standalone-cosigner_wrong_order.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_BAD_PROOF);
}

/* Both trusted cosigners cosigned, so a quorum of two is met. */
static int test_quorum_met(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(cosigner0_seed, cosigner2_seed), 2, 1, X509_V_OK);
}

/* One trusted cosigner cosigned; a quorum of one is met, two is not. */
static int test_quorum_one_of_one(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(cosigner0_seed, NULL), 1, 1, X509_V_OK);
}

static int test_quorum_short(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(cosigner0_seed, NULL), 2, 0,
        X509_V_ERR_MTC_COSIGNER_QUORUM);
}

/* Cosignatures from cosigners that are not trusted do not count. */
static int test_quorum_untrusted_cosigners(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(NULL, NULL), 1, 0, X509_V_ERR_MTC_COSIGNER_QUORUM);
}

/*
 * A trusted cosigner's cosignature that does not verify neither counts nor
 * fails the certificate on its own: the other trusted cosigner still meets a
 * quorum of one, and a quorum of two is short.
 */
static int test_quorum_bad_cosignature(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(wrong_seed, cosigner2_seed), 1, 1, X509_V_OK);
}

static int test_quorum_bad_cosignature_short(void)
{
    return check_policy("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(wrong_seed, cosigner2_seed), 2, 0,
        X509_V_ERR_MTC_COSIGNER_QUORUM);
}

/* A standalone MTC with only the CA cosignature is short of any quorum. */
static int test_quorum_ca_only(void)
{
    return check_policy("mtc-leaf-standalone.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(cosigner0_seed, cosigner2_seed), 1, 0,
        X509_V_ERR_MTC_COSIGNER_QUORUM);
}

/* Trusted cosignatures never stand in for the missing CA cosignature. */
static int test_quorum_no_ca_signer(void)
{
    return check_policy("mtc-leaf-standalone-no_ca_signer.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), NULL),
        make_cosigners(cosigner0_seed, cosigner2_seed), 1, 0,
        X509_V_ERR_MTC_NOT_TRUSTED);
}

/* A landmark-relative MTC verifies via its trusted subtree, whatever the quorum. */
static int test_quorum_landmark(void)
{
    return check_policy("mtc-landmark.pem",
        make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed), subtree_hash),
        make_cosigners(NULL, NULL), 5, 1, X509_V_OK);
}

/* A CA whose ID does not match the certificate issuer is not consulted. */
static int test_untrusted_ca(void)
{
    static const uint8_t other_id[] = { 0x81, 0xfd, 0x59, 0x02 };

    return check("mtc-leaf.pem",
        make_ca(other_id, sizeof(other_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_UNTRUSTED_CA);
}

/* Times within, before and past the leaf's validity (2020-01-01..2030-12-31). */
static const int64_t valid_time = 1609459200; /* 2021-01-01T00:00:00Z */
static const int64_t early_time = 1262304000; /* 2010-01-01T00:00:00Z */
static const int64_t expired_time = 4102444800; /* 2100-01-01T00:00:00Z */

/*
 * Drive the shim ossl_x509_verify_mtc(): trust ca in a store, initialise a
 * context for cert_name, apply the optional host, verification time, purpose
 * and authentication level (-1 leaves it unset), verify, and report ret and
 * *error.  ca is borrowed.
 */
static int shim_verify(const char *cert_name, OSSL_MTC_CA *ca, const char *host,
    int64_t vtime, int purpose, int auth_level, int *error)
{
    char *path = NULL;
    X509 *cert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_VERIFY_PARAM *param;
    int ret = -1;

    *error = X509_V_OK;
    if (!TEST_ptr(ca)
        || !TEST_ptr(path = test_mk_file_path(certs_dir, cert_name))
        || !TEST_ptr(cert = load_cert_pem(path, NULL))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_int_eq(X509_STORE_trust_mtc_ca(store, ca), 1)
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_int_eq(X509_STORE_CTX_init(ctx, store, cert, NULL), 1))
        goto err;

    param = X509_STORE_CTX_get0_param(ctx);
    if (vtime != 0)
        ossl_x509_verify_param_set_time_posix(param, vtime);
    if (host != NULL
        && !TEST_int_eq(X509_VERIFY_PARAM_set1_host(param, host, 0), 1))
        goto err;
    if (purpose != 0
        && !TEST_int_eq(X509_VERIFY_PARAM_set_purpose(param, purpose), 1))
        goto err;
    if (auth_level >= 0)
        X509_VERIFY_PARAM_set_auth_level(param, auth_level);

    ret = ossl_x509_verify_mtc(ctx, 0);
    *error = X509_STORE_CTX_get_error(ctx);
err:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    OPENSSL_free(path);
    return ret;
}

/* The trusted CA (with the correct subtree) the shim leaf-check tests use. */
static OSSL_MTC_CA *shim_ca(void)
{
    return make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed),
        subtree_hash);
}

/* A verified proof plus passing leaf checks succeeds. */
static int test_shim_basic(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, NULL, valid_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 1) && TEST_int_eq(error, X509_V_OK);
}

/* The certificate's SAN matches a.example. */
static int test_shim_host_match(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, "a.example", valid_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 1) && TEST_int_eq(error, X509_V_OK);
}

/* A non-matching host is rejected. */
static int test_shim_host_mismatch(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, "other.example", valid_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0)
        && TEST_int_eq(error, X509_V_ERR_HOSTNAME_MISMATCH);
}

/* A verification time past notAfter is rejected. */
static int test_shim_expired(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, NULL, expired_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0)
        && TEST_int_eq(error, X509_V_ERR_CERT_HAS_EXPIRED);
}

/* A verification time before notBefore is rejected as not yet valid. */
static int test_shim_not_yet_valid(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, NULL, early_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0)
        && TEST_int_eq(error, X509_V_ERR_CERT_NOT_YET_VALID);
}

/* The certificate's EKU permits TLS server authentication. */
static int test_shim_purpose_ok(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, NULL, valid_time,
        X509_PURPOSE_SSL_SERVER, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 1) && TEST_int_eq(error, X509_V_OK);
}

/* It does not permit TLS client authentication. */
static int test_shim_purpose_mismatch(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, NULL, valid_time,
        X509_PURPOSE_SSL_CLIENT, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0) && TEST_int_eq(error, X509_V_ERR_INVALID_PURPOSE);
}

/*
 * auth_level rates the leaf key, the only key an MTC has: the fixture's P-256
 * key meets level 3 (128 bits) and not level 4 (192 bits).  A build without
 * EC cannot decode that key, so it has nothing to rate.
 */
static int test_shim_auth_level_ok(void)
{
    OSSL_MTC_CA *ca;
    int error, ret;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    ca = shim_ca();
    ret = shim_verify("mtc-landmark.pem", ca, NULL, valid_time, 0, 3, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 1) && TEST_int_eq(error, X509_V_OK);
}

static int test_shim_auth_level_too_small(void)
{
    OSSL_MTC_CA *ca;
    int error, ret;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    ca = shim_ca();
    ret = shim_verify("mtc-landmark.pem", ca, NULL, valid_time, 0, 4, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0) && TEST_int_eq(error, X509_V_ERR_EE_KEY_TOO_SMALL);
}

/* When the proof fails, the shim reports it and does not reach the leaf checks. */
static int test_shim_proof_failure(void)
{
    OSSL_MTC_CA *ca = make_ca(ca_id, sizeof(ca_id), ca_seed, sizeof(ca_seed),
        NULL);
    int error, ret;

    ret = shim_verify("mtc-landmark.pem", ca, "other.example", expired_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0) && TEST_int_eq(error, X509_V_ERR_MTC_NOT_TRUSTED);
}

/* Reparse cert from its encoding, so that its extensions are cached afresh. */
static X509 *reencode_cert(X509 *cert)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    X509 *out = NULL;
    int len;

    if ((len = i2d_X509(cert, &der)) > 0) {
        p = der;
        out = d2i_X509(NULL, &p, len);
    }
    OPENSSL_free(der);
    return out;
}

/* Run just the leaf checks over cert, at a time it is valid. */
static int leaf_checks(X509 *cert, unsigned long flags, int *error)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_VERIFY_PARAM *param;
    int ret = -1;

    *error = X509_V_OK;
    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_int_eq(X509_STORE_CTX_init(ctx, store, cert, NULL), 1))
        goto err;
    param = X509_STORE_CTX_get0_param(ctx);
    ossl_x509_verify_param_set_time_posix(param, valid_time);
    if (flags != 0 && !TEST_int_eq(X509_VERIFY_PARAM_set_flags(param, flags), 1))
        goto err;

    ret = ossl_x509_mtc_leaf_checks(ctx);
    *error = X509_STORE_CTX_get_error(ctx);
err:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ret;
}

/* A certificate that passes the leaf checks as issued. */
static X509 *leaf_cert(void)
{
    char *path = test_mk_file_path(certs_dir, "mtc-leaf.pem");
    X509 *cert = NULL;

    if (path != NULL)
        cert = load_cert_pem(path, NULL);
    OPENSSL_free(path);
    return cert;
}

static int test_leaf_checks_pass(void)
{
    X509 *cert = leaf_cert();
    int error, ret;

    if (!TEST_ptr(cert))
        return 0;
    ret = leaf_checks(cert, 0, &error);
    X509_free(cert);
    return TEST_int_eq(ret, 1) && TEST_int_eq(error, X509_V_OK);
}

/* Two copies of one extension, under an OID nothing else inspects. */
static int test_leaf_checks_duplicate_extension(void)
{
    X509 *cert = leaf_cert(), *dup = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *value = NULL;
    X509_EXTENSION *ext = NULL;
    int error, testresult = 0;

    if (!TEST_ptr(cert)
        /* 1.3.6.1.4.1.32473 is the OID arc reserved for examples (RFC 5612). */
        || !TEST_ptr(obj = OBJ_txt2obj("1.3.6.1.4.1.32473.99", 1))
        || !TEST_ptr(value = ASN1_OCTET_STRING_new())
        || !TEST_int_eq(ASN1_OCTET_STRING_set(value, (unsigned char *)"!", 1), 1)
        || !TEST_ptr(ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, value))
        || !TEST_int_eq(X509_add_ext(cert, ext, -1), 1)
        || !TEST_int_eq(X509_add_ext(cert, ext, -1), 1)
        || !TEST_ptr(dup = reencode_cert(cert)))
        goto err;

    testresult = TEST_int_eq(leaf_checks(dup, 0, &error), 0)
        && TEST_int_eq(error, X509_V_ERR_DUPLICATE_EXTENSION);
err:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(value);
    ASN1_OBJECT_free(obj);
    X509_free(dup);
    X509_free(cert);
    return testresult;
}

/* A present but empty subject alternative name. */
static int test_leaf_checks_empty_san(void)
{
    X509 *cert = leaf_cert(), *empty = NULL;
    GENERAL_NAMES *names = NULL;
    int error, loc, testresult = 0;

    if (!TEST_ptr(cert) || !TEST_ptr(names = sk_GENERAL_NAME_new_null()))
        goto err;
    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (!TEST_int_ge(loc, 0))
        goto err;
    X509_EXTENSION_free(X509_delete_ext(cert, loc));
    if (!TEST_int_eq(X509_add1_ext_i2d(cert, NID_subject_alt_name, names, 0,
                         X509V3_ADD_DEFAULT),
            1)
        || !TEST_ptr(empty = reencode_cert(cert)))
        goto err;

    testresult = TEST_int_eq(leaf_checks(empty, 0, &error), 0)
        && TEST_int_eq(error, X509_V_ERR_EMPTY_SUBJECT_ALT_NAME);
err:
    sk_GENERAL_NAME_free(names);
    X509_free(empty);
    X509_free(cert);
    return testresult;
}

/*
 * A proxy certificate, which the caller has to ask for explicitly.  Such a
 * certificate may not have a subject alternative name.
 */
static int test_leaf_checks_proxy(void)
{
    X509 *cert = leaf_cert(), *proxy = NULL;
    PROXY_CERT_INFO_EXTENSION *pci = NULL;
    int error, loc, testresult = 0;

    if (!TEST_ptr(cert))
        goto err;
    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (!TEST_int_ge(loc, 0))
        goto err;
    X509_EXTENSION_free(X509_delete_ext(cert, loc));

    if (!TEST_ptr(pci = PROXY_CERT_INFO_EXTENSION_new())
        || !TEST_ptr(pci->proxyPolicy))
        goto err;
    ASN1_OBJECT_free(pci->proxyPolicy->policyLanguage);
    pci->proxyPolicy->policyLanguage = OBJ_nid2obj(NID_id_ppl_anyLanguage);
    if (!TEST_int_eq(X509_add1_ext_i2d(cert, NID_proxyCertInfo, pci, 0,
                         X509V3_ADD_DEFAULT),
            1)
        || !TEST_ptr(proxy = reencode_cert(cert)))
        goto err;

    testresult = TEST_int_eq(leaf_checks(proxy, 0, &error), 0)
        && TEST_int_eq(error, X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED)
        /* With X509_V_FLAG_ALLOW_PROXY_CERTS the same certificate passes. */
        && TEST_int_eq(leaf_checks(proxy, X509_V_FLAG_ALLOW_PROXY_CERTS, &error),
            1)
        && TEST_int_eq(error, X509_V_OK);
err:
    PROXY_CERT_INFO_EXTENSION_free(pci);
    X509_free(proxy);
    X509_free(cert);
    return testresult;
}

/*
 * The signature algorithm inside the TBSCertificate must equal the one outside
 * it, which is the one that says this is an MTC at all.
 */
static int test_leaf_checks_sigalg_mismatch(void)
{
    X509 *cert = leaf_cert(), *mangled = NULL;
    unsigned char *der = NULL;
    const unsigned char *p, *q, *end;
    long len;
    int der_len = 0, error, tag, xclass, testresult = 0;

    if (!TEST_ptr(cert) || !TEST_int_gt(der_len = i2d_X509(cert, &der), 0))
        goto err;

    /*
     * Certificate ::= SEQUENCE { tbsCertificate, ... } and TBSCertificate ::=
     * SEQUENCE { [0] version, serialNumber, signature, ... }: walk to that
     * signature AlgorithmIdentifier and alter its algorithm.
     */
    q = der;
    if ((ASN1_get_object(&q, &len, &tag, &xclass, der_len) & 0x80) != 0
        || tag != V_ASN1_SEQUENCE
        || (ASN1_get_object(&q, &len, &tag, &xclass, (long)(der + der_len - q))
               & 0x80)
            != 0
        || tag != V_ASN1_SEQUENCE)
        goto err;
    end = q + len;
    if (q < end && (*q & 0xa0) == 0xa0) { /* version [0] is optional */
        if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80)
            != 0)
            goto err;
        q += len;
    }
    if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80) != 0
        || tag != V_ASN1_INTEGER) /* serialNumber */
        goto err;
    q += len;
    if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80) != 0
        || tag != V_ASN1_SEQUENCE
        || (ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80)
            != 0
        || tag != V_ASN1_OBJECT || len < 1)
        goto err;
    der[q + len - 1 - der] ^= 0x01;

    p = der;
    if (!TEST_ptr(mangled = d2i_X509(NULL, &p, der_len)))
        goto err;

    testresult = TEST_int_eq(leaf_checks(mangled, 0, &error), 0)
        && TEST_int_eq(error, X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY);
err:
    X509_free(mangled);
    OPENSSL_free(der);
    X509_free(cert);
    return testresult;
}

/*
 * A signatureValue whose BIT STRING is not a whole number of octets (it has
 * unused bits) is rejected (section 7.2).  The malformed encoding is crafted
 * from a good certificate's DER by setting the signatureValue BIT STRING's
 * leading unused-bit count to a non-zero value.
 */
static int test_shim_nonoctet_signature(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    char *path = NULL;
    X509 *cert = NULL, *mangled = NULL;
    unsigned char *der = NULL;
    const unsigned char *p, *q, *end;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    long len;
    int der_len = 0, tag, xclass, testresult = 0;

    if (!TEST_ptr(ca)
        || !TEST_ptr(path = test_mk_file_path(certs_dir, "mtc-leaf.pem"))
        || !TEST_ptr(cert = load_cert_pem(path, NULL))
        || !TEST_int_gt(der_len = i2d_X509(cert, &der), 0))
        goto err;

    /*
     * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     * signatureValue BIT STRING }.  Walk to the BIT STRING and set its leading
     * unused-bit count to 1 so the signatureValue is no longer octet-aligned.
     */
    q = der;
    if ((ASN1_get_object(&q, &len, &tag, &xclass, der_len) & 0x80) != 0
        || tag != V_ASN1_SEQUENCE)
        goto err;
    end = q + len;
    /* Skip tbsCertificate and signatureAlgorithm. */
    if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80) != 0)
        goto err;
    q += len;
    if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80) != 0)
        goto err;
    q += len;
    /* signatureValue: the first content octet is the unused-bit count. */
    if ((ASN1_get_object(&q, &len, &tag, &xclass, (long)(end - q)) & 0x80) != 0
        || tag != V_ASN1_BIT_STRING || len < 1)
        goto err;
    der[q - der] = 0x01;

    p = der;
    if (!TEST_ptr(mangled = d2i_X509(NULL, &p, der_len))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_int_eq(X509_STORE_trust_mtc_ca(store, ca), 1)
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_int_eq(X509_STORE_CTX_init(ctx, store, mangled, NULL), 1))
        goto err;

    testresult = TEST_int_eq(ossl_x509_verify_mtc(ctx, 0), 0)
        && TEST_int_eq(X509_STORE_CTX_get_error(ctx), X509_V_ERR_MTC_BAD_PROOF);
err:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(mangled);
    X509_free(cert);
    OPENSSL_free(der);
    OPENSSL_free(path);
    OSSL_MTC_CA_free(ca);
    return testresult;
}

/* ossl_mtc_is_mtc() detects the id-alg-mtcProof signatureAlgorithm. */
static int test_is_mtc(void)
{
    char *path = test_mk_file_path(certs_dir, "mtc-leaf.pem");
    X509 *cert = NULL;
    int ret = 0;

    if (TEST_ptr(path) && TEST_ptr(cert = load_cert_pem(path, NULL)))
        ret = TEST_int_eq(ossl_mtc_is_mtc(cert), 1)
            && TEST_int_eq(ossl_mtc_is_mtc(NULL), 0);
    X509_free(cert);
    OPENSSL_free(path);
    return ret;
}

/* A certificate whose signatureAlgorithm is not id-alg-mtcProof is refused. */
static int test_shim_not_mtc(void)
{
    OSSL_MTC_CA *ca = shim_ca();
    int error, ret;

    ret = shim_verify("mtc-ca-cert.pem", ca, NULL, valid_time, 0, -1, &error);
    OSSL_MTC_CA_free(ca);
    return TEST_int_eq(ret, 0) && TEST_int_eq(error, X509_V_ERR_MTC_NOT_MTC);
}

int setup_tests(void)
{
    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_signatureless_trusted_subtree);
    ADD_TEST(test_signatureless_no_subtree);
    ADD_TEST(test_wrong_subtree_hash);
    ADD_TEST(test_signatureless_unhashed_subtree);
    ADD_TEST(test_standalone_unhashed_subtree);
    ADD_TEST(test_standalone_trusted_subtree);
    ADD_TEST(test_standalone_wrong_subtree_hash);
    ADD_TEST(test_standalone_cosignature);
    ADD_TEST(test_standalone_wrong_key);
    ADD_TEST(test_three_cosigners);
    ADD_TEST(test_no_ca_signer);
    ADD_TEST(test_duplicate_ca_signer);
    ADD_TEST(test_cosigner_wrong_order);
    ADD_TEST(test_quorum_met);
    ADD_TEST(test_quorum_one_of_one);
    ADD_TEST(test_quorum_short);
    ADD_TEST(test_quorum_untrusted_cosigners);
    ADD_TEST(test_quorum_bad_cosignature);
    ADD_TEST(test_quorum_bad_cosignature_short);
    ADD_TEST(test_quorum_ca_only);
    ADD_TEST(test_quorum_no_ca_signer);
    ADD_TEST(test_quorum_landmark);
    ADD_TEST(test_untrusted_ca);
    ADD_TEST(test_shim_basic);
    ADD_TEST(test_shim_host_match);
    ADD_TEST(test_shim_host_mismatch);
    ADD_TEST(test_shim_expired);
    ADD_TEST(test_shim_not_yet_valid);
    ADD_TEST(test_shim_purpose_ok);
    ADD_TEST(test_shim_purpose_mismatch);
    ADD_TEST(test_shim_auth_level_ok);
    ADD_TEST(test_shim_auth_level_too_small);
    ADD_TEST(test_shim_proof_failure);
    ADD_TEST(test_shim_nonoctet_signature);
    ADD_TEST(test_leaf_checks_pass);
    ADD_TEST(test_leaf_checks_duplicate_extension);
    ADD_TEST(test_leaf_checks_empty_san);
    ADD_TEST(test_leaf_checks_proxy);
    ADD_TEST(test_leaf_checks_sigalg_mismatch);
    ADD_TEST(test_is_mtc);
    ADD_TEST(test_shim_not_mtc);
    return 1;
}
