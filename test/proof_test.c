/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Exercise the public OSSL_PROOF verification API against the same Merkle Tree
 * Certificates as mtc_verify_test (section 7.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/),
 * using only public headers.  The CA parameters mirror that fixture: CA ID
 * 32473.1, log 1, a 10-entry tree, and an
 * ML-DSA-44 CA cosigner keyed from the seed 00..1f.
 */

#include <openssl/core_names.h>
#include <openssl/proof.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

/* The libctx and property query the trust configurations use. */
static OSSL_LIB_CTX *libctx = NULL;
static const char *propq = NULL;

static const char *certs_dir;

/* The CA ID: the TrustAnchorID 32473.1 in relative-OID bytes. */
static const uint8_t ca_id[] = { 0x81, 0xfd, 0x59, 0x01 };

/* A CA ID that does not match the certificate issuer. */
static const uint8_t other_id[] = { 0x81, 0xfd, 0x59, 0x02 };

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

/* The CA cosigner seed (config 32473.1); its ML-DSA-44 key signs the subtree. */
static const uint8_t ca_seed[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
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

/*
 * Times within and past the landmark leaf's validity
 * (2020-01-01..2035-12-31); mtc-leaf.pem is valid 2020-01-01..2030-12-31, so
 * valid_time suits both.
 */
static const int64_t valid_time = 1609459200; /* 2021-01-01T00:00:00Z */
static const int64_t expired_time = 2082758400; /* 2036-01-01T00:00:00Z */

/*
 * The CRL fixtures (mtc-crl-*.pem) were issued on 2026-09-28;
 * mtc-crl-expired.pem runs one day from then, the others ten years.  Both
 * leaves are valid until 2030-12-31, so revocation_time lies within the
 * leaves and the ten-year CRLs, after the one-day CRL, and valid_time before
 * every CRL.  mtc-crl-indirect.pem and mtc-crl-shard.pem list the entry as
 * revoked, the first as an indirect CRL and the second as a partitioned CRL
 * naming a distribution point the leaves do not.
 */
static const int64_t revocation_time = 1798761600; /* 2027-01-01T00:00:00Z */

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
 * Build a trusted CA matching the fixture, keyed with the CA cosigner seed.  If
 * with_subtree is set the landmark leaf's log is given its active landmarks and
 * the vetted hash of the subtree that leaf proves into, which is what lets a
 * signatureless certificate verify.
 */
static OSSL_MTC_CA *make_ca(const uint8_t *id, size_t id_len, int with_subtree)
{
    EVP_PKEY *pkey = cosigner_key(ca_seed, sizeof(ca_seed));
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;

    if (pkey == NULL)
        return NULL;
    ca = OSSL_MTC_CA_new(id, id_len, EVP_sha256(), 0, pkey);
    EVP_PKEY_free(pkey); /* the CA holds its own reference */
    if (ca == NULL || !with_subtree)
        return ca;

    if ((bio = BIO_new_mem_buf(landmark_desc, -1)) == NULL
        || !OSSL_MTC_CA_load_landmarks(ca, landmark_log, bio, INT64_MIN)
        || !OSSL_MTC_CA_add_subtree_hash(ca, landmark_log, landmark_start,
            landmark_end, subtree_hash, sizeof(subtree_hash))) {
        BIO_free(bio);
        OSSL_MTC_CA_free(ca);
        return NULL;
    }
    BIO_free(bio);
    return ca;
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
 * The trusted cosigners of a trust configuration: kept for the test's lifetime,
 * as a store only borrows them (see X509_STORE_trust_mtc_cosigner(3)).
 */
static STACK_OF(OSSL_MTC_COSIGNER) *trusted_cosigners;

/*
 * Build a trust configuration trusting ca (NULL ca leaves it with no store),
 * holding the PEM CRL crl_name if given, and, when with_cosigners is set,
 * trusting the cosigners 32473.0 and 32473.2.  A trusted store only borrows ca
 * (see X509_STORE_trust_mtc_ca(3)), so the caller retains ca and must keep it
 * alive until after the trust is freed.
 */
static OSSL_PROOF_TRUST *build_trust(OSSL_MTC_CA *ca, const char *crl_name,
    int with_cosigners)
{
    X509_STORE *store = NULL;
    OSSL_PROOF_TRUST *trust = NULL;
    OSSL_MTC_COSIGNER *cosigner;
    char *path = NULL;
    BIO *in = NULL;
    X509_CRL *crl = NULL;

    if (!TEST_ptr(trust = OSSL_PROOF_TRUST_new(libctx, propq)))
        goto err;
    if (ca != NULL) {
        if (!TEST_ptr(store = X509_STORE_new())
            || !TEST_int_eq(X509_STORE_trust_mtc_ca(store, ca), 1)
            || !TEST_int_eq(OSSL_PROOF_TRUST_set1_x509_store(trust, store), 1))
            goto err;
    }
    if (crl_name != NULL) {
        if (!TEST_ptr(path = test_mk_file_path(certs_dir, crl_name))
            || !TEST_ptr(in = BIO_new_file(path, "r"))
            || !TEST_ptr(crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL))
            || !TEST_int_eq(X509_STORE_add_crl(store, crl), 1))
            goto err;
        X509_CRL_free(crl); /* the store holds its own reference */
        crl = NULL;
        BIO_free(in);
        in = NULL;
        OPENSSL_free(path);
        path = NULL;
    }
    if (with_cosigners) {
        if (!TEST_ptr(cosigner = make_cosigner(cosigner0_id, sizeof(cosigner0_id),
                          cosigner0_seed, sizeof(cosigner0_seed)))
            || !TEST_true(sk_OSSL_MTC_COSIGNER_push(trusted_cosigners, cosigner))
            || !TEST_int_eq(X509_STORE_trust_mtc_cosigner(store, cosigner), 1)
            || !TEST_ptr(cosigner = make_cosigner(cosigner2_id, sizeof(cosigner2_id),
                             cosigner2_seed, sizeof(cosigner2_seed)))
            || !TEST_true(sk_OSSL_MTC_COSIGNER_push(trusted_cosigners, cosigner))
            || !TEST_int_eq(X509_STORE_trust_mtc_cosigner(store, cosigner), 1))
            goto err;
    }
    X509_STORE_free(store); /* the trust holds its own reference */
    return trust;
err:
    X509_CRL_free(crl);
    BIO_free(in);
    OPENSSL_free(path);
    X509_STORE_free(store);
    OSSL_PROOF_TRUST_free(trust);
    return NULL;
}

/*
 * Build per-verification parameters with the optional host, time and cosigner
 * quorum.
 */
static OSSL_PROOF_PARAMS *build_params(const char *host, int64_t vtime,
    size_t quorum)
{
    OSSL_PROOF_PARAMS *params = NULL;
    X509_VERIFY_PARAM *param;

    if (!TEST_ptr(params = OSSL_PROOF_PARAMS_new()))
        return NULL;
    param = OSSL_PROOF_PARAMS_get0_x509_param(params);
    if (vtime != 0)
        X509_VERIFY_PARAM_set_time(param, (time_t)vtime);
    if (!TEST_int_eq(OSSL_PROOF_PARAMS_set_mtc_cosigner_quorum(params, quorum), 1)
        || !TEST_size_t_eq(OSSL_PROOF_PARAMS_get_mtc_cosigner_quorum(params),
            quorum)
        || (host != NULL
            && !TEST_int_eq(X509_VERIFY_PARAM_set1_host(param, host, 0), 1))) {
        OSSL_PROOF_PARAMS_free(params);
        return NULL;
    }
    return params;
}

/* Load cert_name into a proof. */
static OSSL_PROOF *load_proof(const char *cert_name)
{
    char *path = NULL;
    X509 *cert = NULL;
    OSSL_PROOF *proof = NULL;

    if (TEST_ptr(path = test_mk_file_path(certs_dir, cert_name))
        && TEST_ptr(cert = load_cert_pem(path, NULL)))
        proof = OSSL_PROOF_new_mtc(cert);
    X509_free(cert); /* the proof holds its own reference */
    OPENSSL_free(path);
    return proof;
}

/*
 * Confirm the X.509 outputs of a verification: the error code is expect_error
 * at depth 0 with the proof's certificate at fault; on success the verified
 * chain is that certificate alone and the matched name is expect_peername (NULL
 * for none), on failure there is no chain and no name.  The policy tree is
 * never set for a Merkle Tree Certificate.
 */
static int check_output(const OSSL_PROOF_OUTPUT *output, X509 *cert, int verified,
    int expect_error, const char *expect_peername)
{
    STACK_OF(X509) *chain = OSSL_PROOF_OUTPUT_get0_x509_chain(output);
    const char *peername = OSSL_PROOF_OUTPUT_get0_x509_peername(output);
    int code = X509_V_OK, depth = -1;

    if (!TEST_int_eq(OSSL_PROOF_OUTPUT_get_x509_error(output, &code), 1)
        || !TEST_int_eq(code, expect_error)
        || !TEST_int_eq(OSSL_PROOF_OUTPUT_get_x509_error_depth(output, &depth), 1)
        || !TEST_int_eq(depth, 0)
        || !TEST_ptr_null(OSSL_PROOF_OUTPUT_get0_x509_policy_tree(output)))
        return 0;
    if (!verified)
        return TEST_ptr_null(chain) && TEST_ptr_null(peername)
            && TEST_ptr_eq(OSSL_PROOF_OUTPUT_get0_x509_error_cert(output), cert);
    if (!TEST_ptr(chain) || !TEST_int_eq(sk_X509_num(chain), 1)
        || !TEST_ptr_eq(sk_X509_value(chain, 0), cert))
        return 0;
    if (expect_peername == NULL)
        return TEST_ptr_null(peername);
    return TEST_ptr(peername) && TEST_str_eq(peername, expect_peername);
}

/*
 * Verify cert_name against a trust configuration trusting ca (and, when
 * with_cosigners is set, the two trusted cosigners) and parameters with the
 * optional host, time and quorum, and confirm OSSL_PROOF_verify() returns
 * expect_ret and its output carries expect_error and expect_peername.  ca is
 * consumed.
 */
static int check(const char *cert_name, OSSL_MTC_CA *ca, int with_cosigners,
    const char *host, int64_t vtime, size_t quorum, int expect_ret,
    int expect_error, const char *expect_peername)
{
    OSSL_PROOF_TRUST *trust = build_trust(ca, NULL, with_cosigners);
    OSSL_PROOF_PARAMS *params = build_params(host, vtime, quorum);
    char *path = NULL;
    X509 *cert = NULL;
    OSSL_PROOF *proof = NULL;
    OSSL_PROOF_OUTPUT *output = NULL;
    int ret = 0;

    if (!TEST_ptr(trust) || !TEST_ptr(params)
        || !TEST_ptr(path = test_mk_file_path(certs_dir, cert_name))
        || !TEST_ptr(cert = load_cert_pem(path, NULL))
        || !TEST_ptr(proof = OSSL_PROOF_new_mtc(cert)))
        goto err;
    if (!TEST_int_eq(OSSL_PROOF_verify(trust, proof, params, &output), expect_ret)
        || !TEST_ptr(output)
        || !check_output(output, cert, expect_ret, expect_error, expect_peername))
        goto err;
    ret = 1;
err:
    OSSL_PROOF_OUTPUT_free(output);
    OSSL_PROOF_free(proof);
    X509_free(cert);
    OPENSSL_free(path);
    OSSL_PROOF_PARAMS_free(params);
    OSSL_PROOF_TRUST_free(trust); /* free the trust (and its store) before the CA */
    OSSL_MTC_CA_free(ca);
    return ret;
}

/*
 * Verify cert_name (with_subtree as for make_ca()) at vtime with the
 * verification flags set, against a store holding the CRL crl_name (which may
 * be NULL), and confirm OSSL_PROOF_verify() returns expect_ret with
 * expect_error in its output.
 */
static int check_revocation(const char *cert_name, int with_subtree,
    int64_t vtime, unsigned long flags, const char *crl_name, int expect_ret,
    int expect_error)
{
    OSSL_MTC_CA *ca = make_ca(ca_id, sizeof(ca_id), with_subtree);
    OSSL_PROOF_TRUST *trust = build_trust(ca, crl_name, 0);
    OSSL_PROOF_PARAMS *params = build_params(NULL, vtime, 0);
    char *path = NULL;
    X509 *cert = NULL;
    OSSL_PROOF *proof = NULL;
    OSSL_PROOF_OUTPUT *output = NULL;
    int ret = 0;

    if (!TEST_ptr(trust) || !TEST_ptr(params)
        || !TEST_true(X509_VERIFY_PARAM_set_flags(
            OSSL_PROOF_PARAMS_get0_x509_param(params), flags))
        || !TEST_ptr(path = test_mk_file_path(certs_dir, cert_name))
        || !TEST_ptr(cert = load_cert_pem(path, NULL))
        || !TEST_ptr(proof = OSSL_PROOF_new_mtc(cert)))
        goto err;
    if (!TEST_int_eq(OSSL_PROOF_verify(trust, proof, params, &output), expect_ret)
        || !TEST_ptr(output)
        || !check_output(output, cert, expect_ret, expect_error, NULL))
        goto err;
    ret = 1;
err:
    OSSL_PROOF_OUTPUT_free(output);
    OSSL_PROOF_free(proof);
    X509_free(cert);
    OPENSSL_free(path);
    OSSL_PROOF_PARAMS_free(params);
    OSSL_PROOF_TRUST_free(trust);
    OSSL_MTC_CA_free(ca);
    return ret;
}

/* A signatureless MTC verifies via a matching trusted subtree. */
static int test_verify_trusted_subtree(void)
{
    return check("mtc-landmark.pem", make_ca(ca_id, sizeof(ca_id), 1), 0, NULL,
        valid_time, 0, 1, X509_V_OK, NULL);
}

/* A standalone MTC verifies via the CA cosignature. */
static int test_verify_cosignature(void)
{
    return check("mtc-leaf-standalone.pem", make_ca(ca_id, sizeof(ca_id), 0), 0,
        NULL, valid_time, 0, 1, X509_V_OK, NULL);
}

/* A signatureless MTC with no trusted subtree is not trusted. */
static int test_not_trusted(void)
{
    return check("mtc-leaf.pem", make_ca(ca_id, sizeof(ca_id), 0), 0, NULL,
        valid_time, 0, 0, X509_V_ERR_MTC_NOT_TRUSTED, NULL);
}

/* A CA whose ID does not match the certificate issuer is not consulted. */
static int test_untrusted_ca(void)
{
    return check("mtc-leaf.pem", make_ca(other_id, sizeof(other_id), 0), 0, NULL,
        valid_time, 0, 0, X509_V_ERR_MTC_UNTRUSTED_CA, NULL);
}

/* A trust configuration with no store cannot trust the issuing CA. */
static int test_no_store(void)
{
    return check("mtc-leaf.pem", NULL, 0, NULL, valid_time, 0, 0,
        X509_V_ERR_MTC_UNTRUSTED_CA, NULL);
}

/* The leaf checks run once the proof verifies: a matching host is reported. */
static int test_host_match(void)
{
    return check("mtc-landmark.pem", make_ca(ca_id, sizeof(ca_id), 1), 0,
        "a.example", valid_time, 0, 1, X509_V_OK, "a.example");
}

/* A non-matching host is rejected. */
static int test_host_mismatch(void)
{
    return check("mtc-landmark.pem", make_ca(ca_id, sizeof(ca_id), 1), 0,
        "other.example", valid_time, 0, 0, X509_V_ERR_HOSTNAME_MISMATCH, NULL);
}

/* A verification time past notAfter is rejected. */
static int test_expired(void)
{
    return check("mtc-landmark.pem", make_ca(ca_id, sizeof(ca_id), 1), 0, NULL,
        expired_time, 0, 0, X509_V_ERR_CERT_HAS_EXPIRED, NULL);
}

/* Both trusted cosigners cosigned, so a quorum of two is met. */
static int test_quorum_met(void)
{
    return check("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), 0), 1, NULL, valid_time, 2, 1, X509_V_OK,
        NULL);
}

/* A quorum of three exceeds the two trusted cosigners that cosigned. */
static int test_quorum_short(void)
{
    return check("mtc-leaf-standalone-3cosigners.pem",
        make_ca(ca_id, sizeof(ca_id), 0), 1, NULL, valid_time, 3, 0,
        X509_V_ERR_MTC_COSIGNER_QUORUM, NULL);
}

/* CRL checking: a store CRL from the CA that does not list the entry passes it. */
static int test_crl_good_standalone(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time, X509_V_FLAG_CRL_CHECK,
        "mtc-crl-good.pem", 1, X509_V_OK);
}

static int test_crl_good_landmark(void)
{
    return check_revocation("mtc-landmark.pem", 1, revocation_time, X509_V_FLAG_CRL_CHECK,
        "mtc-crl-good.pem", 1, X509_V_OK);
}

/* A CRL listing the entry revokes every proof of it. */
static int test_crl_revoked_standalone(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time, X509_V_FLAG_CRL_CHECK,
        "mtc-crl-revoked.pem", 0, X509_V_ERR_CERT_REVOKED);
}

static int test_crl_revoked_landmark(void)
{
    return check_revocation("mtc-landmark.pem", 1, revocation_time, X509_V_FLAG_CRL_CHECK,
        "mtc-crl-revoked.pem", 0, X509_V_ERR_CERT_REVOKED);
}

/* CRL checking with no CRL available fails. */
static int test_crl_missing(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time, X509_V_FLAG_CRL_CHECK,
        NULL, 0, X509_V_ERR_UNABLE_TO_GET_CRL);
}

/* A CRL whose validity has not begun at the verification time is rejected. */
static int test_crl_not_yet_valid(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, valid_time,
        X509_V_FLAG_CRL_CHECK, "mtc-crl-good.pem", 0,
        X509_V_ERR_CRL_NOT_YET_VALID);
}

/* A CRL whose validity has ended at the verification time is rejected. */
static int test_crl_expired(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time,
        X509_V_FLAG_CRL_CHECK, "mtc-crl-expired.pem", 0,
        X509_V_ERR_CRL_HAS_EXPIRED);
}

/* An indirect CRL in the store is not used, though it lists the entry. */
static int test_crl_indirect_not_used(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time,
        X509_V_FLAG_CRL_CHECK, "mtc-crl-indirect.pem", 0,
        X509_V_ERR_UNABLE_TO_GET_CRL);
}

/*
 * A partitioned CRL applies only through a distribution point the certificate
 * names; these leaves name none, so it is not used, and with no other CRL the
 * check fails for want of one.
 */
static int test_crl_shard_not_covering(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time,
        X509_V_FLAG_CRL_CHECK, "mtc-crl-shard.pem", 0,
        X509_V_ERR_UNABLE_TO_GET_CRL);
}

/* Parameters requesting OCSP checking are refused: no verification, no output. */
static int test_ocsp_flag_refused(void)
{
    OSSL_MTC_CA *ca = make_ca(ca_id, sizeof(ca_id), 0);
    OSSL_PROOF_TRUST *trust = build_trust(ca, NULL, 0);
    OSSL_PROOF_PARAMS *params = build_params(NULL, valid_time, 0);
    OSSL_PROOF *proof = load_proof("mtc-leaf-standalone.pem");
    OSSL_PROOF_OUTPUT *output = NULL;
    int ret = 0;

    if (TEST_ptr(trust) && TEST_ptr(params) && TEST_ptr(proof)
        && TEST_true(X509_VERIFY_PARAM_set_flags(
            OSSL_PROOF_PARAMS_get0_x509_param(params),
            X509_V_FLAG_OCSP_RESP_CHECK))
        && TEST_int_eq(OSSL_PROOF_verify(trust, proof, params, &output), 0)
        && TEST_ptr_null(output))
        ret = 1;
    OSSL_PROOF_OUTPUT_free(output);
    OSSL_PROOF_free(proof);
    OSSL_PROOF_PARAMS_free(params);
    OSSL_PROOF_TRUST_free(trust);
    OSSL_MTC_CA_free(ca);
    return ret;
}

/* A store CRL is not consulted without CRL checking enabled. */
static int test_crl_not_checked(void)
{
    return check_revocation("mtc-leaf-standalone.pem", 0, revocation_time, 0,
        "mtc-crl-revoked.pem", 1, X509_V_OK);
}

/* OSSL_PROOF_verify() tolerates a NULL output out-parameter. */
static int test_null_output_out(void)
{
    OSSL_MTC_CA *ca = make_ca(ca_id, sizeof(ca_id), 0);
    OSSL_PROOF_TRUST *trust = build_trust(ca, NULL, 0);
    OSSL_PROOF_PARAMS *params = build_params(NULL, valid_time, 0);
    OSSL_PROOF *proof = load_proof("mtc-leaf.pem");
    int ret = 0;

    if (TEST_ptr(trust) && TEST_ptr(params) && TEST_ptr(proof))
        ret = TEST_int_eq(OSSL_PROOF_verify(trust, proof, params, NULL), 0);
    OSSL_PROOF_free(proof);
    OSSL_PROOF_PARAMS_free(params);
    OSSL_PROOF_TRUST_free(trust);
    OSSL_MTC_CA_free(ca);
    return ret;
}

/* A NULL proof is a hard error: verify fails and returns no output. */
static int test_null_proof(void)
{
    OSSL_PROOF_TRUST *trust = build_trust(NULL, NULL, 0);
    OSSL_PROOF_OUTPUT *output = NULL;
    int ret = 0;

    if (TEST_ptr(trust)
        && TEST_int_eq(OSSL_PROOF_verify(trust, NULL, NULL, &output), 0)
        && TEST_ptr_null(output))
        ret = 1;
    OSSL_PROOF_OUTPUT_free(output);
    OSSL_PROOF_TRUST_free(trust);
    return ret;
}

/* A NULL trust configuration (and NULL params) cannot trust the issuing CA. */
static int test_null_trust(void)
{
    OSSL_PROOF *proof = load_proof("mtc-leaf.pem");
    OSSL_PROOF_OUTPUT *output = NULL;
    int code = X509_V_OK, ret = 0;

    if (TEST_ptr(proof)
        && TEST_int_eq(OSSL_PROOF_verify(NULL, proof, NULL, &output), 0)
        && TEST_ptr(output)
        && TEST_int_eq(OSSL_PROOF_OUTPUT_get_x509_error(output, &code), 1)
        && TEST_int_eq(code, X509_V_ERR_MTC_UNTRUSTED_CA))
        ret = 1;
    OSSL_PROOF_OUTPUT_free(output);
    OSSL_PROOF_free(proof);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;
    if (!TEST_ptr(trusted_cosigners = sk_OSSL_MTC_COSIGNER_new_null()))
        return 0;

    ADD_TEST(test_verify_trusted_subtree);
    ADD_TEST(test_verify_cosignature);
    ADD_TEST(test_not_trusted);
    ADD_TEST(test_untrusted_ca);
    ADD_TEST(test_no_store);
    ADD_TEST(test_host_match);
    ADD_TEST(test_host_mismatch);
    ADD_TEST(test_expired);
    ADD_TEST(test_quorum_met);
    ADD_TEST(test_quorum_short);
    ADD_TEST(test_crl_good_standalone);
    ADD_TEST(test_crl_good_landmark);
    ADD_TEST(test_crl_revoked_standalone);
    ADD_TEST(test_crl_revoked_landmark);
    ADD_TEST(test_crl_missing);
    ADD_TEST(test_crl_not_yet_valid);
    ADD_TEST(test_crl_expired);
    ADD_TEST(test_crl_indirect_not_used);
    ADD_TEST(test_crl_shard_not_covering);
    ADD_TEST(test_crl_not_checked);
    ADD_TEST(test_ocsp_flag_refused);
    ADD_TEST(test_null_output_out);
    ADD_TEST(test_null_proof);
    ADD_TEST(test_null_trust);
    return 1;
}

void cleanup_tests(void)
{
    sk_OSSL_MTC_COSIGNER_pop_free(trusted_cosigners, OSSL_MTC_COSIGNER_free);
}
