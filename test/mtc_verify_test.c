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
#include <openssl/x509_vfy.h>
#include <openssl/mtc.h>

#include "crypto/mtc_ca.h"
#include "crypto/mtc_verify.h"
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

/*
 * Build a trusted CA matching the fixture.  Its ML-DSA-44 cosigner key is
 * derived from seed.  If hash is non-NULL the landmark leaf's log is given its
 * active landmarks and hash is recorded for the subtree that leaf proves into,
 * which is what lets a signatureless certificate verify; passing a hash other
 * than the true one leaves the subtree active but not matching.
 */
static OSSL_MTC_CA *make_ca(const uint8_t *id, size_t id_len,
    const uint8_t *seed, size_t seed_len, const uint8_t *hash)
{
    EVP_PKEY *pkey = cosigner_key(seed, seed_len);
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;

    if (pkey == NULL)
        return NULL;
    ca = OSSL_MTC_CA_new(id, id_len, EVP_sha256(), 0, pkey);
    EVP_PKEY_free(pkey); /* the CA holds its own reference */
    if (ca == NULL || hash == NULL)
        return ca;

    if ((bio = BIO_new_mem_buf(landmark_desc, -1)) == NULL
        || !OSSL_MTC_CA_load_landmarks(ca, landmark_log, bio, INT64_MIN)
        || !OSSL_MTC_CA_add_subtree_hash(ca, landmark_log, landmark_start,
            landmark_end, hash, sizeof(subtree_hash))) {
        BIO_free(bio);
        OSSL_MTC_CA_free(ca);
        return NULL;
    }
    BIO_free(bio);
    return ca;
}

/*
 * Load cert_name, trust ca, resolve the issuing CA and verify its proof, and
 * confirm the outcome is expect_ret with expect_error recorded.  ca is consumed.
 */
static int check(const char *cert_name, OSSL_MTC_CA *ca, int expect_ret,
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
        || !TEST_ptr(cas = sk_OSSL_MTC_CA_new(ossl_mtc_ca_cmp))
        || !TEST_int_eq(ossl_mtc_ca_stack_add(cas, ca), 1))
        goto err;
    X509_get0_signature(&sig, &alg, cert); /* the MTCProof is the signatureValue */
    found = ossl_mtc_ca_for_cert(cas, cert, &error);
    if (found != NULL)
        verified = ossl_mtc_verify(found, tbs, (size_t)tbs_len,
            ASN1_STRING_get0_data(sig), ASN1_STRING_get_length(sig), &error);
    if (!TEST_int_eq(verified, expect_ret) || !TEST_int_eq(error, expect_error))
        goto err;
    ret = 1;
err:
    sk_OSSL_MTC_CA_free(cas);
    OSSL_MTC_CA_free(ca);
    OPENSSL_free(tbs);
    X509_free(cert);
    OPENSSL_free(path);
    return ret;
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

/* A CA whose ID does not match the certificate issuer is not consulted. */
static int test_untrusted_ca(void)
{
    static const uint8_t other_id[] = { 0x81, 0xfd, 0x59, 0x02 };

    return check("mtc-leaf.pem",
        make_ca(other_id, sizeof(other_id), ca_seed, sizeof(ca_seed), NULL),
        0, X509_V_ERR_MTC_UNTRUSTED_CA);
}

int setup_tests(void)
{
    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_signatureless_trusted_subtree);
    ADD_TEST(test_signatureless_no_subtree);
    ADD_TEST(test_wrong_subtree_hash);
    ADD_TEST(test_standalone_cosignature);
    ADD_TEST(test_standalone_wrong_key);
    ADD_TEST(test_three_cosigners);
    ADD_TEST(test_no_ca_signer);
    ADD_TEST(test_duplicate_ca_signer);
    ADD_TEST(test_cosigner_wrong_order);
    ADD_TEST(test_untrusted_ca);
    return 1;
}
