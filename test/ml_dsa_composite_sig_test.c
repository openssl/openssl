/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "ml_dsa_composite_sig.inc"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static OSSL_LIB_CTX *lib_ctx = NULL;
static OSSL_PROVIDER *null_prov = NULL;
static OSSL_PROVIDER *lib_prov = NULL;

/* =========================================================================
 * Key helpers
 * ========================================================================= */

/*
 * Generate a ml dsa composite keypair using DRBG (no fixed seed).
 */
static EVP_PKEY *do_gen_key(const char *alg)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_generate(ctx, &pkey), 1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*
 * Load a ml dsa composite private key from raw DER bytes via EVP_PKEY_fromdata.
 * |priv| is the concatenated composite private key blob as exported by the
 * keymgmt (OSSL_PKEY_PARAM_PRIV_KEY).
 */
#if ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
static EVP_PKEY *ml_dsa_composite_key_from_priv(const char *alg,
    const uint8_t *priv, size_t priv_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
        (void *)priv, priv_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pkey,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                            params),
            1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
#endif /* ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT > 0 */

/*
 * Load a ml dsa composite public key from raw DER bytes via EVP_PKEY_fromdata.
 */
#if ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT > 0
static EVP_PKEY *ml_dsa_composite_key_from_pub(const char *alg,
    const uint8_t *pub, size_t pub_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        (void *)pub, pub_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pkey,
                            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                            params),
            1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
#endif /* ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT > 0 */

/* =========================================================================
 *  DRBG round-trip tests (keygen → sign → verify)
 * ========================================================================= */

/*
 * Sign |msg| with |key| using algorithm |alg|, verify the result.
 * Also checks the buffer-too-small path (sig_len - 1).
 */
static int do_sign_verify(EVP_PKEY *key, const char *alg,
    const uint8_t *msg, size_t msg_len)
{
    int ret = 0;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        /* query required buffer size */
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len, msg, msg_len), 1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len)))
        goto err;

    /* Sign with one byte too few — must fail */
    sig_len--;
    if (!TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, msg, msg_len), 0))
        goto err;
    sig_len++;

    /* Actual sign */
    if (!TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, msg, msg_len), 1))
        goto err;

    /* Verify the signature we just produced */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, msg, msg_len), 1))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/* Table of ml dsa composite algorithm names */
static const char *ml_dsa_composite_alg_names[] = {
    "ML-DSA-65-RSA3072-PKCS15-SHA512",
    "ML-DSA-65-ECDSA-P256-SHA512",
};
#define NUM_ML_DSA_COMPOSITE_ALGS (int)(sizeof(ml_dsa_composite_alg_names) / sizeof(ml_dsa_composite_alg_names[0]))

static uint8_t test_msg[] = "OpenSSL ml dsa composite signature test message";

/*
 * DRBG keygen + sign + verify for each of the 18 algorithms.
 * Parameterised by tst_id (0..17).
 */
static int ml_dsa_composite_drbg_sign_verify_test(int tst_id)
{
    int ret = 0;
    const char *alg = ml_dsa_composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif
    if (!TEST_ptr(key = do_gen_key(alg)))
        goto err;

    if (!TEST_true(do_sign_verify(key, alg, test_msg, sizeof(test_msg) - 1)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Two DRBG-generated keys of the same algorithm must not be equal.
 * Two keys of different algorithms must return -1 (incompatible types).
 * Checks EVP_PKEY_eq() and EVP_PKEY_dup() round-trips.
 */
static int ml_dsa_composite_keygen_drbg_test(void)
{
    int ret = 0;
    EVP_PKEY *k1 = NULL, *k2 = NULL, *k3 = NULL, *k1_dup = NULL;

    if (!TEST_ptr(k1 = do_gen_key("ML-DSA-65-RSA3072-PKCS15-SHA512"))
        || !TEST_ptr(k2 = do_gen_key("ML-DSA-65-RSA3072-PKCS15-SHA512"))
        /* same algorithm, different keys */
        || !TEST_int_eq(EVP_PKEY_eq(k1, k2), 0)
        /* dup must produce an equal key */
        || !TEST_ptr(k1_dup = EVP_PKEY_dup(k1))
        || !TEST_int_eq(EVP_PKEY_eq(k1, k1_dup), 1))
        goto err;

#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(k3 = do_gen_key("ML-DSA-65-ECDSA-P256-SHA512"))
        /* different algorithm must return -1 */
        || !TEST_int_eq(EVP_PKEY_eq(k1, k3), -1))
        goto err;
#endif

    ret = 1;
err:
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k3);
    EVP_PKEY_free(k1_dup);
    return ret;
}

/* =========================================================================
 * Deterministic vector tests (ml_dsa_composite_sig.inc)
 * ========================================================================= */

/*
 * siggen: load private key from vector, sign the fixed message, compare the
 * SHA-256 digest of the output signature against the stored reference.
 * (Same SHA-256-of-sig trick used by ml_dsa_siggen_test to keep the .inc
 * file small while still providing a complete bit-exact check.)
 */
#if ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
static int ml_dsa_composite_siggen_test(int tst_id)
{
    int ret = 0;
    const ML_DSA_COMPOSITE_SIG_GEN_TEST_DATA *td = &ml_dsa_composite_siggen_testdata[tst_id];
    EVP_PKEY_CTX *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM params[2], *p = params;
    uint8_t *psig = NULL;
    size_t psig_len = 0;
    uint8_t digest[32];
    size_t digest_len = sizeof(digest);

    if (td->add_random != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
            (void *)td->add_random, td->add_random_len);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(pkey = ml_dsa_composite_key_from_priv(td->alg, td->priv, td->priv_len)))
        goto err;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, params), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &psig_len,
                            td->msg, td->msg_len),
            1)
        || !TEST_ptr(psig = OPENSSL_zalloc(psig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, psig, &psig_len,
                            td->msg, td->msg_len),
            1)
        || !TEST_int_eq(EVP_Q_digest(lib_ctx, "SHA256", NULL,
                            psig, psig_len,
                            digest, &digest_len),
            1)
        || !TEST_mem_eq(digest, digest_len,
            td->sig_digest, td->sig_digest_len))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    OPENSSL_free(psig);
    return ret;
}
#endif /* ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT > 0 */

/*
 * sigver: load public key from vector, verify the stored signature.
 * td->expected == 1 for valid, 0 for deliberately invalid vectors.
 */
#if ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT > 0
static int ml_dsa_composite_sigver_test(int tst_id)
{
    int ret = 0;
    const ML_DSA_COMPOSITE_SIG_VER_TEST_DATA *td = &ml_dsa_composite_sigver_testdata[tst_id];
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;

    if (!TEST_ptr(pkey = ml_dsa_composite_key_from_pub(td->alg, td->pub, td->pub_len)))
        goto err;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, td->sig, td->sig_len,
                            td->msg, td->msg_len),
            td->expected))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}
#endif /* ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT > 0 */

/* =========================================================================
 * Negative tests
 * ========================================================================= */

/*
 * A signature produced by one ml dsa composite algorithm must not verify under a
 * different ml dsa composite algorithm that happens to share the same ML-DSA level
 * (cross-algorithm mismatch).
 */
static int ml_dsa_composite_cross_alg_mismatch_test(void)
{
    int ret = 0;
    EVP_PKEY *key_a = NULL, *key_b = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_a = NULL, *sig_b = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    const char *alg_a = "ML-DSA-65-RSA3072-PKCS15-SHA512";
    const char *alg_b = "ML-DSA-65-ECDSA-P256-SHA512";

#ifdef OPENSSL_NO_EC
    TEST_note("Skipping ml_dsa_composite_cross_alg_mismatch_test - requires EC (ECDSA-P256)");
    return 1;
#endif
    if (!TEST_ptr(key_a = do_gen_key(alg_a))
        || !TEST_ptr(key_b = do_gen_key(alg_b))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key_a, NULL))
        || !TEST_ptr(sig_a = EVP_SIGNATURE_fetch(lib_ctx, alg_a, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_a, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1))
        goto err;

    /*
     * Verify alg_a signature under alg_b key — must fail.
     * EVP_PKEY_verify returns 0 for "bad signature" (not -1).
     */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key_b, NULL))
        || !TEST_ptr(sig_b = EVP_SIGNATURE_fetch(lib_ctx, alg_b, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_b, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len,
                            test_msg, sizeof(test_msg) - 1),
            0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key_a);
    EVP_PKEY_free(key_b);
    EVP_SIGNATURE_free(sig_a);
    EVP_SIGNATURE_free(sig_b);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/*
 * A tampered signature (single bit flip) must not verify.
 */
static int ml_dsa_composite_tampered_sig_test(int tst_id)
{
    int ret = 0;
    const char *alg = ml_dsa_composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif
    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1))
        goto err;

    /* Tamper: flip a bit near the middle of the signature */
    sig[sig_len / 2] ^= 0x01;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len,
                            test_msg, sizeof(test_msg) - 1),
            0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/*
 * Encode the classic (RSA or EC) component of a key to its raw "type-specific"
 * wire format (RSAPublicKey/RSAPrivateKey DER, or ECPrivateKey DER), i.e. the
 * same on-the-wire encoding the composite provider itself produces/expects.
 */
static int encode_classic_component(EVP_PKEY *pkey, int selection,
    unsigned char **out, size_t *out_len)
{
    OSSL_ENCODER_CTX *ectx;
    int ok;

    *out = NULL;
    *out_len = 0;
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER",
        "type-specific", NULL);
    if (ectx == NULL)
        return 0;
    ok = OSSL_ENCODER_to_data(ectx, out, out_len);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

/*
 * Importing an ML-DSA-65-RSA3072-PKCS15-SHA512 public key whose embedded RSA
 * component is not actually 3072 bits must be rejected: modulus-size
 * downgrade / algorithm-confusion must be caught by the keymgmt import path.
 */
static int ml_dsa_composite_rsa_size_downgrade_test(void)
{
    int ret = 0;
    const char *alg = "ML-DSA-65-RSA3072-PKCS15-SHA512";
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *mldsa_key = NULL, *rsa_key = NULL, *bad_key = NULL;
    unsigned char *mldsa_pk = NULL, *rsa_pub = NULL, *blob = NULL;
    size_t mldsa_pk_len = 0, rsa_pub_len = 0, blob_len;
    unsigned int rsa_bits = 2048; /* wrong: this variant requires 3072 */
    OSSL_PARAM rsa_params[2], import_params[2];

    /* Real ML-DSA-65 public key bytes, to use as the (valid) PQ component */
    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(lib_ctx, "ML-DSA-65", NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(kctx), 1)
        || !TEST_int_eq(EVP_PKEY_generate(kctx, &mldsa_key), 1)
        || !TEST_int_eq(EVP_PKEY_get_octet_string_param(mldsa_key,
                            OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &mldsa_pk_len),
            1)
        || !TEST_ptr(mldsa_pk = OPENSSL_malloc(mldsa_pk_len))
        || !TEST_int_eq(EVP_PKEY_get_octet_string_param(mldsa_key,
                            OSSL_PKEY_PARAM_PUB_KEY, mldsa_pk, mldsa_pk_len,
                            &mldsa_pk_len),
            1))
        goto err;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* A real, but wrong-sized (2048-bit), RSA public key */
    rsa_params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &rsa_bits);
    rsa_params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(lib_ctx, "RSA", NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(kctx), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_params(kctx, rsa_params), 1)
        || !TEST_int_eq(EVP_PKEY_generate(kctx, &rsa_key), 1)
        || !TEST_true(encode_classic_component(rsa_key,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &rsa_pub, &rsa_pub_len)))
        goto err;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* mldsaPK(pk_len) || tradPK(raw) -- ml dsa composite public key wire format */
    blob_len = mldsa_pk_len + rsa_pub_len;
    if (!TEST_ptr(blob = OPENSSL_malloc(blob_len)))
        goto err;
    memcpy(blob, mldsa_pk, mldsa_pk_len);
    memcpy(blob + mldsa_pk_len, rsa_pub, rsa_pub_len);

    import_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        blob, blob_len);
    import_params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(kctx), 1))
        goto err;

    /* Must be rejected: the embedded RSA key is 2048 bits, not 3072 */
    if (!TEST_int_eq(EVP_PKEY_fromdata(kctx, &bad_key,
                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY, import_params),
            0)
        || !TEST_ptr_null(bad_key))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(mldsa_key);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(bad_key);
    OPENSSL_free(mldsa_pk);
    OPENSSL_free(rsa_pub);
    OPENSSL_free(blob);
    return ret;
}

/*
 * Importing an ML-DSA-65-ECDSA-P256-SHA512 private key whose embedded EC
 * component is on a different curve (P-384, not P-256) must be rejected:
 * curve confusion / downgrade must be caught by the keymgmt import path.
 */
static int ml_dsa_composite_ec_curve_downgrade_test(void)
{
    int ret = 0;
    const char *alg = "ML-DSA-65-ECDSA-P256-SHA512";
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *ec_key = NULL, *bad_key = NULL;
    unsigned char seed[32];
    unsigned char *ec_priv = NULL, *blob = NULL;
    size_t ec_priv_len = 0, blob_len;
    OSSL_PARAM import_params[2];

#ifdef OPENSSL_NO_EC
    TEST_note("Skipping ml_dsa_composite_ec_curve_downgrade_test - requires EC");
    return 1;
#endif

    if (!TEST_int_eq(RAND_bytes_ex(lib_ctx, seed, sizeof(seed), 0), 1))
        goto err;

    /* A real EC private key, but on the wrong curve (P-384, not P-256) */
    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(lib_ctx, "EC", NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(kctx), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_group_name(kctx, "P-384"), 1)
        || !TEST_int_eq(EVP_PKEY_generate(kctx, &ec_key), 1)
        || !TEST_true(encode_classic_component(ec_key,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY, &ec_priv, &ec_priv_len)))
        goto err;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* mldsaSeed(32) || tradSK(raw) -- ml dsa composite private key wire format */
    blob_len = sizeof(seed) + ec_priv_len;
    if (!TEST_ptr(blob = OPENSSL_malloc(blob_len)))
        goto err;
    memcpy(blob, seed, sizeof(seed));
    memcpy(blob + sizeof(seed), ec_priv, ec_priv_len);

    import_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
        blob, blob_len);
    import_params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(kctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(kctx), 1))
        goto err;

    /* Must be rejected: the embedded EC key is on P-384, not P-256 */
    if (!TEST_int_eq(EVP_PKEY_fromdata(kctx, &bad_key,
                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY, import_params),
            0)
        || !TEST_ptr_null(bad_key))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(bad_key);
    OPENSSL_free(ec_priv);
    OPENSSL_free(blob);
    return ret;
}

/* Locate |needle| (|needle_len| bytes) within |hay| (|hay_len| bytes); -1 if absent. */
static long find_bytes(const unsigned char *hay, long hay_len,
    const unsigned char *needle, long needle_len)
{
    long i;

    for (i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0)
            return i;
    }
    return -1;
}

/*
 * A SubjectPublicKeyInfo whose BIT STRING has a non-zero "unused bits" byte
 * is invalid DER for key material.  The hand-rolled composite SPKI parser
 * (ml_dsa_composite_spki_bitstring_body()) must reject it rather than silently
 * accept it and shift the decoded key material by one byte.
 */
static int ml_dsa_composite_spki_bad_unused_bits_test(void)
{
    int ret = 0;
    const char *alg = "ML-DSA-65-RSA3072-PKCS15-SHA512";
    EVP_PKEY *key = NULL, *decoded = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    unsigned char *der = NULL, *pub = NULL;
    const unsigned char *derp;
    size_t der_len = 0, pub_len = 0, len;
    long anchor;
#define ANCHOR_LEN 16

    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_int_eq(EVP_PKEY_get_octet_string_param(key,
                            OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len),
            1)
        || !TEST_ptr(pub = OPENSSL_malloc(pub_len))
        || !TEST_int_eq(EVP_PKEY_get_octet_string_param(key,
                            OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, &pub_len),
            1))
        goto err;

    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new_for_pkey(key,
                      OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                      "DER", "SubjectPublicKeyInfo", NULL))
        || !TEST_true(OSSL_ENCODER_to_data(ectx, &der, &der_len)))
        goto err;

    /* Locate the start of the ML-DSA public key within the encoded BIT STRING */
    anchor = find_bytes(der, (long)der_len, pub, ANCHOR_LEN);
    if (!TEST_int_ge(anchor, 1)
        || !TEST_uchar_eq(der[anchor - 1], 0)) /* unused-bits byte must be 0 */
        goto err;

    /* Sanity: the unmodified DER must decode successfully */
    derp = der;
    len = der_len;
    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&decoded, "DER",
                      "SubjectPublicKeyInfo", alg,
                      OSSL_KEYMGMT_SELECT_PUBLIC_KEY, lib_ctx, NULL))
        || !TEST_true(OSSL_DECODER_from_data(dctx, &derp, &len)))
        goto err;
    EVP_PKEY_free(decoded);
    decoded = NULL;
    OSSL_DECODER_CTX_free(dctx);
    dctx = NULL;

    /* Corrupt the unused-bits byte; decode must now fail */
    der[anchor - 1] = 0x01;
    derp = der;
    len = der_len;
    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&decoded, "DER",
                      "SubjectPublicKeyInfo", alg,
                      OSSL_KEYMGMT_SELECT_PUBLIC_KEY, lib_ctx, NULL))
        || !TEST_false(OSSL_DECODER_from_data(dctx, &derp, &len))
        || !TEST_ptr_null(decoded))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_PKEY_free(decoded);
    OSSL_ENCODER_CTX_free(ectx);
    OSSL_DECODER_CTX_free(dctx);
    OPENSSL_free(der);
    OPENSSL_free(pub);
    return ret;
#undef ANCHOR_LEN
}

/* =========================================================================
 * Streaming (sign/verify_message_update) tests
 * ========================================================================= */

/*
 * Feed the message in two chunks via the streaming API, then verify the
 * result both via the streaming API (EVP_PKEY_CTX_set_signature() +
 * verify_message_update()/_final()) and via the one-shot API, to confirm
 * both paths agree.
 */
static int ml_dsa_composite_streaming_sign_verify_test(int tst_id)
{
    int ret = 0;
    const char *alg = ml_dsa_composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    size_t msg_len = sizeof(test_msg) - 1;
    size_t half = msg_len / 2;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif

    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign_message_update(sctx, test_msg, half), 1)
        || !TEST_int_eq(EVP_PKEY_sign_message_update(sctx, test_msg + half,
                            msg_len - half),
            1)
        || !TEST_int_eq(EVP_PKEY_sign_message_final(sctx, NULL, &sig_len), 1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign_message_final(sctx, sig, &sig_len), 1))
        goto err;

    /* Verify via the streaming API, fed in different-size chunks */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_signature(vctx, sig, sig_len), 1)
        || !TEST_int_eq(EVP_PKEY_verify_message_update(vctx, test_msg, 1), 1)
        || !TEST_int_eq(EVP_PKEY_verify_message_update(vctx, test_msg + 1,
                            msg_len - 1),
            1)
        || !TEST_int_eq(EVP_PKEY_verify_message_final(vctx), 1))
        goto err;
    EVP_PKEY_CTX_free(vctx);
    vctx = NULL;

    /* The same signature must also verify via the one-shot API */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, test_msg, msg_len), 1))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/*
 * A tampered signature must not verify via the streaming API either.
 */
static int ml_dsa_composite_streaming_tampered_sig_test(int tst_id)
{
    int ret = 0;
    const char *alg = ml_dsa_composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif

    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign_message_update(sctx, test_msg,
                            sizeof(test_msg) - 1),
            1)
        || !TEST_int_eq(EVP_PKEY_sign_message_final(sctx, NULL, &sig_len), 1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign_message_final(sctx, sig, &sig_len), 1))
        goto err;

    sig[sig_len / 2] ^= 0x01;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_signature(vctx, sig, sig_len), 1)
        || !TEST_int_eq(EVP_PKEY_verify_message_update(vctx, test_msg,
                            sizeof(test_msg) - 1),
            1)
        || !TEST_int_eq(EVP_PKEY_verify_message_final(vctx), 0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/* =========================================================================
 * Externally pre-computed PH(M) tests (OSSL_SIGNATURE_PARAM_ML_DSA_COMPOSITE_PREHASH)
 * ========================================================================= */

/*
 * A caller may compute PH(M) itself (e.g. on another machine) and hand it
 * to sign()/verify() in place of the raw message, by setting
 * OSSL_SIGNATURE_PARAM_ML_DSA_COMPOSITE_PREHASH.  Every ml dsa composite algorithm
 * currently defined uses SHA-512 for PH(M).  This must produce a signature
 * that verifies both via the same flag and via a normal, independently
 * computed PH(M); it must also be interchangeable with a signature made the
 * ordinary way (raw message, no flag).
 */
static int ml_dsa_composite_external_prehash_test(int tst_id)
{
    int ret = 0;
    const char *alg = ml_dsa_composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL, *sig2 = NULL;
    size_t sig_len = 0, sig2_len = 0;
    uint8_t prehash[64];
    size_t prehash_len = sizeof(prehash);
    int have_prehash = 1;
    OSSL_PARAM params[2];

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif

    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_ML_DSA_COMPOSITE_PREHASH,
        &have_prehash);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_int_eq(EVP_Q_digest(lib_ctx, "SHA-512", NULL,
                            test_msg, sizeof(test_msg) - 1,
                            prehash, &prehash_len),
            1))
        goto err;

    /* Sign by feeding the pre-computed PH(M) directly, no raw message */
    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, params), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len, prehash, prehash_len), 1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, prehash, prehash_len), 1))
        goto err;

    /* Verify the same way, using only the pre-computed hash */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, params), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, prehash, prehash_len), 1))
        goto err;
    EVP_PKEY_CTX_free(vctx);
    vctx = NULL;

    /*
     * A signature made the ordinary way (raw message, no flag) must also
     * verify against the independently computed PH(M), confirming both
     * code paths build the same M'.
     */
    EVP_PKEY_CTX_free(sctx);
    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig2_len,
                            test_msg, sizeof(test_msg) - 1),
            1)
        || !TEST_ptr(sig2 = OPENSSL_zalloc(sig2_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig2, &sig2_len,
                            test_msg, sizeof(test_msg) - 1),
            1))
        goto err;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, params), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig2, sig2_len, prehash, prehash_len), 1))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    OPENSSL_free(sig2);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/* =========================================================================
 * Test registration
 * ========================================================================= */

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "config", OPT_CONFIG_FILE, '<',
            "The configuration file to use for the libctx" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;
    char *config_file = NULL;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        case OPT_TEST_CASES:
            break;
        default:
        case OPT_ERR:
            return 0;
        }
    }
    if (!test_get_libctx(&lib_ctx, &null_prov, config_file, &lib_prov, NULL))
        return 0;

    /* Strategy 1: DRBG round-trips for all 18 algorithms */
    ADD_ALL_TESTS(ml_dsa_composite_drbg_sign_verify_test, NUM_ML_DSA_COMPOSITE_ALGS);
    ADD_TEST(ml_dsa_composite_keygen_drbg_test);

    /* Strategy 2: deterministic vector tests from ml_dsa_composite_sig.inc */
#if ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
    ADD_ALL_TESTS(ml_dsa_composite_siggen_test, ML_DSA_COMPOSITE_SIGGEN_TESTDATA_COUNT);
#endif
#if ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT > 0
    ADD_ALL_TESTS(ml_dsa_composite_sigver_test, ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT);
#endif

    /* Negative tests */
    ADD_TEST(ml_dsa_composite_cross_alg_mismatch_test);
    ADD_ALL_TESTS(ml_dsa_composite_tampered_sig_test, NUM_ML_DSA_COMPOSITE_ALGS);
    ADD_TEST(ml_dsa_composite_rsa_size_downgrade_test);
    ADD_TEST(ml_dsa_composite_ec_curve_downgrade_test);
    ADD_TEST(ml_dsa_composite_spki_bad_unused_bits_test);

    /* Streaming (sign/verify_message_update) tests */
    ADD_ALL_TESTS(ml_dsa_composite_streaming_sign_verify_test, NUM_ML_DSA_COMPOSITE_ALGS);
    ADD_ALL_TESTS(ml_dsa_composite_streaming_tampered_sig_test, NUM_ML_DSA_COMPOSITE_ALGS);

    /* Externally pre-computed PH(M) tests */
    ADD_ALL_TESTS(ml_dsa_composite_external_prehash_test, NUM_ML_DSA_COMPOSITE_ALGS);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(null_prov);
    OSSL_PROVIDER_unload(lib_prov);
    OSSL_LIB_CTX_free(lib_ctx);
}
