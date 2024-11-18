/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include "crypto/rand.h"
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "self_test.h"
#include "self_test_data.inc"

static int set_kat_drbg(OSSL_LIB_CTX *ctx,
                        const unsigned char *entropy, size_t entropy_len,
                        const unsigned char *nonce, size_t nonce_len,
                        const unsigned char *persstr, size_t persstr_len);
static int reset_main_drbg(OSSL_LIB_CTX *ctx);

static int self_test_digest(const ST_KAT_DIGEST *t, OSSL_SELF_TEST *st,
                            OSSL_LIB_CTX *libctx)
{
    int ok = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(libctx, t->algorithm, NULL);

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST, t->desc);

    if (ctx == NULL
            || md == NULL
            || !EVP_DigestInit_ex(ctx, md, NULL)
            || !EVP_DigestUpdate(ctx, t->pt, t->pt_len)
            || !EVP_DigestFinal(ctx, out, &out_len))
        goto err;

    /* Optional corruption */
    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (out_len != t->expected_len
            || memcmp(out, t->expected, out_len) != 0)
        goto err;
    ok = 1;
err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ok);
    return ok;
}

/*
 * Helper function to setup a EVP_CipherInit
 * Used to hide the complexity of Authenticated ciphers.
 */
static int cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       const ST_KAT_CIPHER *t, int enc)
{
    unsigned char *in_tag = NULL;
    int pad = 0, tmp;

    /* Flag required for Key wrapping */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (t->tag == NULL) {
        /* Use a normal cipher init */
        return EVP_CipherInit_ex(ctx, cipher, NULL, t->key, t->iv, enc)
               && EVP_CIPHER_CTX_set_padding(ctx, pad);
    }

    /* The authenticated cipher init */
    if (!enc)
        in_tag = (unsigned char *)t->tag;

    return EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)
           && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t->iv_len, NULL) > 0)
           && (in_tag == NULL
               || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t->tag_len,
                                      in_tag) > 0)
           && EVP_CipherInit_ex(ctx, NULL, NULL, t->key, t->iv, enc)
           && EVP_CIPHER_CTX_set_padding(ctx, pad)
           && EVP_CipherUpdate(ctx, NULL, &tmp, t->aad, t->aad_len);
}

/* Test a single KAT for encrypt/decrypt */
static int self_test_cipher(const ST_KAT_CIPHER *t, OSSL_SELF_TEST *st,
                            OSSL_LIB_CTX *libctx)
{
    int ret = 0, encrypt = 1, len = 0, ct_len = 0, pt_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char ct_buf[256] = { 0 };
    unsigned char pt_buf[256] = { 0 };

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_CIPHER, t->base.desc);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;
    cipher = EVP_CIPHER_fetch(libctx, t->base.algorithm, NULL);
    if (cipher == NULL)
        goto err;

    /* Encrypt plain text message */
    if ((t->mode & CIPHER_MODE_ENCRYPT) != 0) {
        if (!cipher_init(ctx, cipher, t, encrypt)
                || !EVP_CipherUpdate(ctx, ct_buf, &len, t->base.pt,
                                     t->base.pt_len)
                || !EVP_CipherFinal_ex(ctx, ct_buf + len, &ct_len))
            goto err;

        OSSL_SELF_TEST_oncorrupt_byte(st, ct_buf);
        ct_len += len;
        if (ct_len != (int)t->base.expected_len
            || memcmp(t->base.expected, ct_buf, ct_len) != 0)
            goto err;

        if (t->tag != NULL) {
            unsigned char tag[16] = { 0 };

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t->tag_len,
                                     tag) <= 0
                || memcmp(tag, t->tag, t->tag_len) != 0)
                goto err;
        }
    }

    /* Decrypt cipher text */
    if ((t->mode & CIPHER_MODE_DECRYPT) != 0) {
        if (!(cipher_init(ctx, cipher, t, !encrypt)
              && EVP_CipherUpdate(ctx, pt_buf, &len,
                                  t->base.expected, t->base.expected_len)
              && EVP_CipherFinal_ex(ctx, pt_buf + len, &pt_len)))
            goto err;
        OSSL_SELF_TEST_oncorrupt_byte(st, pt_buf);
        pt_len += len;
        if (pt_len != (int)t->base.pt_len
                || memcmp(pt_buf, t->base.pt, pt_len) != 0)
            goto err;
    }

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

static int add_params(OSSL_PARAM_BLD *bld, const ST_KAT_PARAM *params,
                      BN_CTX *ctx)
{
    int ret = 0;
    const ST_KAT_PARAM *p;

    if (params == NULL)
        return 1;
    for (p = params; p->data != NULL; ++p) {
        switch (p->type) {
        case OSSL_PARAM_UNSIGNED_INTEGER: {
            BIGNUM *bn = BN_CTX_get(ctx);

            if (bn == NULL
                || (BN_bin2bn(p->data, p->data_len, bn) == NULL)
                || !OSSL_PARAM_BLD_push_BN(bld, p->name, bn))
                goto err;
            break;
        }
        case OSSL_PARAM_UTF8_STRING: {
            if (!OSSL_PARAM_BLD_push_utf8_string(bld, p->name, p->data,
                                                 p->data_len))
                goto err;
            break;
        }
        case OSSL_PARAM_OCTET_STRING: {
            if (!OSSL_PARAM_BLD_push_octet_string(bld, p->name, p->data,
                                                  p->data_len))
                goto err;
            break;
        }
        case OSSL_PARAM_INTEGER: {
            if (!OSSL_PARAM_BLD_push_int(bld, p->name, *(int *)p->data))
                goto err;
            break;
        }
        default:
            break;
        }
    }
    ret = 1;
err:
    return ret;
}

static int self_test_kdf(const ST_KAT_KDF *t, OSSL_SELF_TEST *st,
                         OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    unsigned char out[128];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    BN_CTX *bnctx = NULL;
    OSSL_PARAM *params  = NULL;
    OSSL_PARAM_BLD *bld = NULL;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KDF, t->desc);

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        goto err;

    kdf = EVP_KDF_fetch(libctx, t->algorithm, "");
    if (kdf == NULL)
        goto err;

    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    if (!add_params(bld, t->params, bnctx))
        goto err;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    if (t->expected_len > sizeof(out))
        goto err;
    if (EVP_KDF_derive(ctx, out, t->expected_len, params) <= 0)
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (memcmp(out, t->expected,  t->expected_len) != 0)
        goto err;

    ret = 1;
err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    BN_CTX_free(bnctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

static int self_test_drbg(const ST_KAT_DRBG *t, OSSL_SELF_TEST *st,
                          OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    unsigned char out[256];
    EVP_RAND *rand;
    EVP_RAND_CTX *test = NULL, *drbg = NULL;
    unsigned int strength = 256;
    int prediction_resistance = 1; /* Causes a reseed */
    OSSL_PARAM drbg_params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_DRBG, t->desc);

    rand = EVP_RAND_fetch(libctx, "TEST-RAND", NULL);
    if (rand == NULL)
        goto err;

    test = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (test == NULL)
        goto err;

    drbg_params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
                                               &strength);
    if (!EVP_RAND_CTX_set_params(test, drbg_params))
        goto err;

    rand = EVP_RAND_fetch(libctx, t->algorithm, NULL);
    if (rand == NULL)
        goto err;

    drbg = EVP_RAND_CTX_new(rand, test);
    EVP_RAND_free(rand);
    if (drbg == NULL)
        goto err;

    strength = EVP_RAND_get_strength(drbg);

    drbg_params[0] = OSSL_PARAM_construct_utf8_string(t->param_name,
                                                      t->param_value, 0);
    /* This is only used by HMAC-DRBG but it is ignored by the others */
    drbg_params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "HMAC", 0);
    if (!EVP_RAND_CTX_set_params(drbg, drbg_params))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                          (void *)t->entropyin,
                                          t->entropyinlen);
    drbg_params[1] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE,
                                          (void *)t->nonce, t->noncelen);
    if (!EVP_RAND_instantiate(test, strength, 0, NULL, 0, drbg_params))
        goto err;
    if (!EVP_RAND_instantiate(drbg, strength, 0, t->persstr, t->persstrlen,
                              NULL))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                          (void *)t->entropyinpr1,
                                          t->entropyinpr1len);
    if (!EVP_RAND_CTX_set_params(test, drbg_params))
        goto err;

    if (!EVP_RAND_generate(drbg, out, t->expectedlen, strength,
                           prediction_resistance,
                           t->entropyaddin1, t->entropyaddin1len))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                         (void *)t->entropyinpr2,
                                         t->entropyinpr2len);
    if (!EVP_RAND_CTX_set_params(test, drbg_params))
        goto err;

    /*
     * This calls ossl_prov_drbg_reseed() internally when
     * prediction_resistance = 1
     */
    if (!EVP_RAND_generate(drbg, out, t->expectedlen, strength,
                           prediction_resistance,
                           t->entropyaddin2, t->entropyaddin2len))
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (memcmp(out, t->expected, t->expectedlen) != 0)
        goto err;

    if (!EVP_RAND_uninstantiate(drbg))
        goto err;
    /*
     * Check that the DRBG data has been zeroized after
     * ossl_prov_drbg_uninstantiate.
     */
    if (!EVP_RAND_verify_zeroization(drbg))
        goto err;

    ret = 1;
err:
    EVP_RAND_CTX_free(drbg);
    EVP_RAND_CTX_free(test);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
static int self_test_ka(const ST_KAT_KAS *t,
                        OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    EVP_PKEY_CTX *kactx = NULL, *dctx = NULL;
    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *params_peer = NULL;
    unsigned char secret[256];
    size_t secret_len = t->expected_len;
    OSSL_PARAM_BLD *bld = NULL;
    BN_CTX *bnctx = NULL;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KA, t->desc);

    if (secret_len > sizeof(secret))
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        goto err;

    if (!add_params(bld, t->key_group, bnctx)
        || !add_params(bld, t->key_host_data, bnctx))
        goto err;
    params = OSSL_PARAM_BLD_to_param(bld);

    if (!add_params(bld, t->key_group, bnctx)
        || !add_params(bld, t->key_peer_data, bnctx))
        goto err;

    params_peer = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL || params_peer == NULL)
        goto err;

    /* Create a EVP_PKEY_CTX to load the DH keys into */
    kactx = EVP_PKEY_CTX_new_from_name(libctx, t->algorithm, "");
    if (kactx == NULL)
        goto err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        goto err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &peerkey, EVP_PKEY_KEYPAIR, params_peer) <= 0)
        goto err;

    /* Create a EVP_PKEY_CTX to perform key derivation */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (dctx == NULL)
        goto err;

    if (EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peerkey) <= 0
        || EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, secret);

    if (secret_len != t->expected_len
        || memcmp(secret, t->expected, t->expected_len) != 0)
        goto err;
    ret = 1;
err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(kactx);
    EVP_PKEY_CTX_free(dctx);
    OSSL_PARAM_free(params_peer);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}
#endif /* !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC) */

static int self_test_digest_sign(const ST_KAT_SIGN *t,
                                 OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    OSSL_PARAM *paramskey = NULL, *paramsinit = NULL;
    OSSL_PARAM_BLD *bldkey = NULL, *bldinit = NULL;
    EVP_SIGNATURE *sigalg = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *fromctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char sig[256];
    BN_CTX *bnctx = NULL;
    size_t siglen = sizeof(sig);
    int digested = 0;
    const char *typ = OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;

    if (t->sig_expected_len > sizeof(sig))
        goto err;

    if (t->sig_expected == NULL)
        typ = OSSL_SELF_TEST_TYPE_PCT_SIGNATURE;

    OSSL_SELF_TEST_onbegin(st, typ, t->desc);

    if (t->entropy != NULL) {
        if (!set_kat_drbg(libctx, t->entropy, t->entropy_len,
                          t->nonce, t->nonce_len, t->persstr, t->persstr_len))
            goto err;
    }

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;

    bldkey = OSSL_PARAM_BLD_new();
    bldinit = OSSL_PARAM_BLD_new();
    if (bldkey == NULL || bldinit == NULL)
        goto err;

    if (!add_params(bldkey, t->key, bnctx)
            || !add_params(bldinit, t->init, bnctx))
        goto err;
    paramskey = OSSL_PARAM_BLD_to_param(bldkey);
    paramsinit = OSSL_PARAM_BLD_to_param(bldinit);

    fromctx = EVP_PKEY_CTX_new_from_name(libctx, t->keytype, NULL);
    if (fromctx == NULL
            || paramskey == NULL
            || paramsinit == NULL)
        goto err;
    if (EVP_PKEY_fromdata_init(fromctx) <= 0
            || EVP_PKEY_fromdata(fromctx, &pkey, EVP_PKEY_KEYPAIR, paramskey) <= 0)
        goto err;

    sigalg = EVP_SIGNATURE_fetch(libctx, t->sigalgorithm, NULL);
    if (sigalg == NULL)
        goto err;
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (ctx == NULL)
        goto err;

    digested = ((t->mode & SIGNATURE_MODE_DIGESTED) != 0);

    if ((t->mode & SIGNATURE_MODE_VERIFY_ONLY) != 0) {
        memcpy(sig, t->sig_expected, t->sig_expected_len);
        siglen = t->sig_expected_len;
    } else {
        if (digested) {
            if (EVP_PKEY_sign_init_ex2(ctx, sigalg, paramsinit) <= 0)
                goto err;
        } else {
            if (EVP_PKEY_sign_message_init(ctx, sigalg, paramsinit) <= 0)
                goto err;
        }
        if (EVP_PKEY_sign(ctx, sig, &siglen, t->msg, t->msg_len) <= 0)
            goto err;

        if (t->sig_expected != NULL
                && (siglen != t->sig_expected_len
                    || memcmp(sig, t->sig_expected, t->sig_expected_len) != 0))
            goto err;
    }

    if ((t->mode & SIGNATURE_MODE_SIGN_ONLY) == 0) {
        if (digested) {
            if (EVP_PKEY_verify_init_ex2(ctx, sigalg, NULL) <= 0)
                goto err;
        } else {
            if (EVP_PKEY_verify_message_init(ctx, sigalg, NULL) <= 0)
                goto err;
        }
        OSSL_SELF_TEST_oncorrupt_byte(st, sig);
        if (EVP_PKEY_verify(ctx, sig, siglen, t->msg, t->msg_len) <= 0)
            goto err;
    }
    ret = 1;
err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(fromctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(sigalg);
    OSSL_PARAM_free(paramskey);
    OSSL_PARAM_free(paramsinit);
    OSSL_PARAM_BLD_free(bldkey);
    OSSL_PARAM_BLD_free(bldinit);
    if (t->entropy != NULL) {
        if (!reset_main_drbg(libctx))
            ret = 0;
    }
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

/*
 * Test a data driven list of KAT's for digest algorithms.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_digests(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_digest_tests); ++i) {
        if (!self_test_digest(&st_kat_digest_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_ciphers(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_cipher_tests); ++i) {
        if (!self_test_cipher(&st_kat_cipher_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_kdfs(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kdf_tests); ++i) {
        if (!self_test_kdf(&st_kat_kdf_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_drbgs(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_drbg_tests); ++i) {
        if (!self_test_drbg(&st_kat_drbg_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_kas(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int ret = 1;
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
    int i;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kas_tests); ++i) {
        if (!self_test_ka(&st_kat_kas_tests[i], st, libctx))
            ret = 0;
    }
#endif

    return ret;
}

static int self_test_signatures(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_sign_tests); ++i) {
        if (!self_test_digest_sign(&st_kat_sign_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

/*
 * Swap the library context DRBG for KAT testing
 *
 * In FIPS 140-3, the asymmetric POST must be a KAT, not a PCT.  For DSA and ECDSA,
 * the sign operation includes the random value 'k'.  For a KAT to work, we
 * have to have control of the DRBG to make sure it is in a "test" state, where
 * its output is truly deterministic.
 *
 */

/*
 * Replacement "random" sources
 * main_rand is used for most tests and it's set to generate mode.
 * kat_rand is used for KATs where specific input is mandated.
 */
static EVP_RAND_CTX *kat_rand = NULL;
static EVP_RAND_CTX *main_rand = NULL;

static int set_kat_drbg(OSSL_LIB_CTX *ctx,
                        const unsigned char *entropy, size_t entropy_len,
                        const unsigned char *nonce, size_t nonce_len,
                        const unsigned char *persstr, size_t persstr_len) {
    EVP_RAND *rand;
    unsigned int strength = 256;
    EVP_RAND_CTX *parent_rand = NULL;
    OSSL_PARAM drbg_params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    /* If not NULL, we didn't cleanup from last call: BAD */
    if (kat_rand != NULL)
        return 0;

    rand = EVP_RAND_fetch(ctx, "TEST-RAND", NULL);
    if (rand == NULL)
        return 0;

    parent_rand = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (parent_rand == NULL)
        goto err;

    drbg_params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
                                               &strength);
    if (!EVP_RAND_CTX_set_params(parent_rand, drbg_params))
        goto err;

    rand = EVP_RAND_fetch(ctx, "HASH-DRBG", NULL);
    if (rand == NULL)
        goto err;

    kat_rand = EVP_RAND_CTX_new(rand, parent_rand);
    EVP_RAND_free(rand);
    if (kat_rand == NULL)
        goto err;

    drbg_params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    if (!EVP_RAND_CTX_set_params(kat_rand, drbg_params))
        goto err;

    /* Instantiate the RNGs */
    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                          (void *)entropy, entropy_len);
    drbg_params[1] =
        OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE,
                                          (void *)nonce, nonce_len);
    if (!EVP_RAND_instantiate(parent_rand, strength, 0, NULL, 0, drbg_params))
        goto err;

    EVP_RAND_CTX_free(parent_rand);
    parent_rand = NULL;

    if (!EVP_RAND_instantiate(kat_rand, strength, 0, persstr, persstr_len, NULL))
        goto err;

    /* When we set the new private generator this one is freed, so upref it */
    if (!EVP_RAND_CTX_up_ref(main_rand))
        goto err;

    /* Update the library context DRBG */
    if (RAND_set0_private(ctx, kat_rand) > 0) {
        /* Keeping a copy to verify zeroization */
        if (EVP_RAND_CTX_up_ref(kat_rand))
            return 1;
        RAND_set0_private(ctx, main_rand);
    }

 err:
    EVP_RAND_CTX_free(parent_rand);
    EVP_RAND_CTX_free(kat_rand);
    kat_rand = NULL;
    return 0;
}

static int reset_main_drbg(OSSL_LIB_CTX *ctx) {
    int ret = 1;

    if (!RAND_set0_private(ctx, main_rand))
        ret = 0;
    if (kat_rand != NULL) {
        if (!EVP_RAND_uninstantiate(kat_rand)
                || !EVP_RAND_verify_zeroization(kat_rand))
            ret = 0;
        EVP_RAND_CTX_free(kat_rand);
        kat_rand = NULL;
    }
    return ret;
}

static int setup_main_random(OSSL_LIB_CTX *libctx)
{
    OSSL_PARAM drbg_params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };
    unsigned int strength = 256, generate = 1;
    EVP_RAND *rand;

    rand = EVP_RAND_fetch(libctx, "TEST-RAND", NULL);
    if (rand == NULL)
        return 0;

    main_rand = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (main_rand == NULL)
        goto err;

    drbg_params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_GENERATE,
                                               &generate);
    drbg_params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
                                               &strength);

    if (!EVP_RAND_instantiate(main_rand, strength, 0, NULL, 0, drbg_params))
        goto err;
    return 1;
 err:
    EVP_RAND_CTX_free(main_rand);
    return 0;
}

/*
 * Run the algorithm KAT's.
 * Return 1 is successful, otherwise return 0.
 * This runs all the tests regardless of if any fail.
 */
int SELF_TEST_kats(OSSL_SELF_TEST *st, OSSL_LIB_CTX *libctx)
{
    EVP_RAND_CTX *saved_rand = ossl_rand_get0_private_noncreating(libctx);
    int ret = 1;

    if (saved_rand != NULL && !EVP_RAND_CTX_up_ref(saved_rand))
        return 0;
    if (!setup_main_random(libctx)
            || !RAND_set0_private(libctx, main_rand)) {
        /* Decrement saved_rand reference counter */
        EVP_RAND_CTX_free(saved_rand);
        EVP_RAND_CTX_free(main_rand);
        return 0;
    }

    if (!self_test_digests(st, libctx))
        ret = 0;
    if (!self_test_ciphers(st, libctx))
        ret = 0;
    if (!self_test_signatures(st, libctx))
        ret = 0;
    if (!self_test_kdfs(st, libctx))
        ret = 0;
    if (!self_test_drbgs(st, libctx))
        ret = 0;
    if (!self_test_kas(st, libctx))
        ret = 0;

    RAND_set0_private(libctx, saved_rand);
    return ret;
}

