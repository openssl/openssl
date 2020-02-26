/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand_drbg.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "self_test.h"
#include "self_test_data.inc"
#include "../../crypto/rand/rand_local.h"

#define DRBG_PARAM_ENTROPY "DRBG-ENTROPY"
#define DRBG_PARAM_NONCE   "DRBG-NONCE"

static int self_test_digest(const ST_KAT_DIGEST *t, OSSL_SELF_TEST *st,
                            OPENSSL_CTX *libctx)
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
    OSSL_SELF_TEST_onend(st, ok);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

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
           && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t->iv_len, NULL)
           && (in_tag == NULL
               || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t->tag_len,
                                      in_tag))
           && EVP_CipherInit_ex(ctx, NULL, NULL, t->key, t->iv, enc)
           && EVP_CIPHER_CTX_set_padding(ctx, pad)
           && EVP_CipherUpdate(ctx, NULL, &tmp, t->aad, t->aad_len);
}

/* Test a single KAT for encrypt/decrypt */
static int self_test_cipher(const ST_KAT_CIPHER *t, OSSL_SELF_TEST *st,
                            OPENSSL_CTX *libctx)
{
    int ret = 0, encrypt = 1, len, ct_len = 0, pt_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char ct_buf[256] = { 0 };
    unsigned char pt_buf[256] = { 0 };

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_CIPHER, t->base.desc);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;
    cipher = EVP_CIPHER_fetch(libctx, t->base.algorithm, "");
    if (cipher == NULL)
        goto err;

    /* Encrypt plain text message */
    if (!cipher_init(ctx, cipher, t, encrypt)
            || !EVP_CipherUpdate(ctx, ct_buf, &len, t->base.pt, t->base.pt_len)
            || !EVP_CipherFinal_ex(ctx, ct_buf + len, &ct_len))
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, ct_buf);
    ct_len += len;
    if (ct_len != (int)t->base.expected_len
        || memcmp(t->base.expected, ct_buf, ct_len) != 0)
        goto err;

    if (t->tag != NULL) {
        unsigned char tag[16] = { 0 };

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t->tag_len, tag)
            || memcmp(tag, t->tag, t->tag_len) != 0)
            goto err;
    }

    if (!(cipher_init(ctx, cipher, t, !encrypt)
          && EVP_CipherUpdate(ctx, pt_buf, &len, ct_buf, ct_len)
          && EVP_CipherFinal_ex(ctx, pt_buf + len, &pt_len)))
        goto err;
    pt_len += len;

    if (pt_len != (int)t->base.pt_len
            || memcmp(pt_buf, t->base.pt, pt_len) != 0)
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

static int self_test_kdf(const ST_KAT_KDF *t, OSSL_SELF_TEST *st,
                         OPENSSL_CTX *libctx)
{
    int ret = 0;
    int i, numparams;
    unsigned char out[64];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[16];
    const OSSL_PARAM *settables = NULL;

    numparams = OSSL_NELEM(params);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KDF, t->desc);

    /* Zeroize the params array to avoid mem leaks on error */
    for (i = 0; i < numparams; ++i)
        params[i] = OSSL_PARAM_construct_end();

    kdf = EVP_KDF_fetch(libctx, t->algorithm, "");
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto err;

    settables = EVP_KDF_settable_ctx_params(kdf);
    for (i = 0; t->ctrls[i].name != NULL; ++i) {
        if (!ossl_assert(i < (numparams - 1)))
            goto err;
        if (!OSSL_PARAM_allocate_from_text(&params[i], settables,
                                           t->ctrls[i].name,
                                           t->ctrls[i].value,
                                           strlen(t->ctrls[i].value), NULL))
            goto err;
    }
    if (!EVP_KDF_CTX_set_params(ctx, params))
        goto err;

    if (t->expected_len > sizeof(out))
        goto err;
    if (EVP_KDF_derive(ctx, out, t->expected_len) <= 0)
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (memcmp(out, t->expected,  t->expected_len) != 0)
        goto err;

    ret = 1;
err:
    for (i = 0; params[i].key != NULL; ++i)
        OPENSSL_free(params[i].data);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

static size_t drbg_kat_entropy_cb(RAND_DRBG *drbg, unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len,
                                  int prediction_resistance)
{
    OSSL_PARAM *drbg_params = RAND_DRBG_get_callback_data(drbg);
    OSSL_PARAM *p = OSSL_PARAM_locate(drbg_params, DRBG_PARAM_ENTROPY);

    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    *pout = (unsigned char *)p->data;
    return p->data_size;
}

static size_t drbg_kat_nonce_cb(RAND_DRBG *drbg, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
{
    OSSL_PARAM *drbg_params = RAND_DRBG_get_callback_data(drbg);
    OSSL_PARAM *p = OSSL_PARAM_locate(drbg_params, DRBG_PARAM_NONCE);

    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    *pout = (unsigned char *)p->data;
    return p->data_size;
}

static int self_test_drbg(const ST_KAT_DRBG *t, OSSL_SELF_TEST *st,
                          OPENSSL_CTX *libctx)
{
    int ret = 0;
    unsigned char out[256];
    RAND_DRBG *drbg = NULL;
    unsigned int flags = 0;
    int prediction_resistance = 1; /* Causes a reseed */
    OSSL_PARAM drbg_params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };
    static const unsigned char zero[sizeof(drbg->data)] = { 0 };

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_DRBG, t->desc);

    if (strcmp(t->desc, OSSL_SELF_TEST_DESC_DRBG_HMAC) == 0)
        flags |= RAND_DRBG_FLAG_HMAC;

    drbg = RAND_DRBG_new_ex(libctx, t->nid, flags, NULL);
    if (drbg == NULL)
        goto err;

    if (!RAND_DRBG_set_callback_data(drbg, drbg_params))
        goto err;

    if (!RAND_DRBG_set_callbacks(drbg, drbg_kat_entropy_cb, NULL,
                                 drbg_kat_nonce_cb, NULL))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(DRBG_PARAM_ENTROPY,
                                          (void *)t->entropyin, t->entropyinlen);
    drbg_params[1] =
        OSSL_PARAM_construct_octet_string(DRBG_PARAM_NONCE,
                                          (void *)t->nonce, t->noncelen);

    if (!RAND_DRBG_instantiate(drbg, t->persstr, t->persstrlen))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(DRBG_PARAM_ENTROPY,
                                          (void *)t->entropyinpr1,
                                          t->entropyinpr1len);

    if (!RAND_DRBG_generate(drbg, out, t->expectedlen, prediction_resistance,
                            t->entropyaddin1, t->entropyaddin1len))
        goto err;

    drbg_params[0] =
        OSSL_PARAM_construct_octet_string(DRBG_PARAM_ENTROPY,
                                         (void *)t->entropyinpr2,
                                         t->entropyinpr2len);
    /* This calls RAND_DRBG_reseed() internally when prediction_resistance = 1 */
    if (!RAND_DRBG_generate(drbg, out,  t->expectedlen, prediction_resistance,
                            t->entropyaddin2, t->entropyaddin2len))
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (memcmp(out, t->expected, t->expectedlen) != 0)
        goto err;

    if (!RAND_DRBG_uninstantiate(drbg))
        goto err;
    /*
     * Check that the DRBG data has been zeroized after RAND_DRBG_uninstantiate.
     */
    if (memcmp((unsigned char *)&drbg->data, zero, sizeof(drbg->data)) != 0)
        goto err;

    ret = 1;
err:
    RAND_DRBG_free(drbg);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

/*
 * Test a data driven list of KAT's for digest algorithms.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_digests(OSSL_SELF_TEST *st, OPENSSL_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_digest_tests); ++i) {
        if (!self_test_digest(&st_kat_digest_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_ciphers(OSSL_SELF_TEST *st, OPENSSL_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_cipher_tests); ++i) {
        if (!self_test_cipher(&st_kat_cipher_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_kdfs(OSSL_SELF_TEST *st, OPENSSL_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kdf_tests); ++i) {
        if (!self_test_kdf(&st_kat_kdf_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

static int self_test_drbgs(OSSL_SELF_TEST *st, OPENSSL_CTX *libctx)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_drbg_tests); ++i) {
        if (!self_test_drbg(&st_kat_drbg_tests[i], st, libctx))
            ret = 0;
    }
    return ret;
}

/*
 * Run the algorithm KAT's.
 * Return 1 is successful, otherwise return 0.
 * This runs all the tests regardless of if any fail.
 *
 * TODO(3.0) Add self tests for KA, Sign/Verify when they become available
 */
int SELF_TEST_kats(OSSL_SELF_TEST *st, OPENSSL_CTX *libctx)
{
    int ret = 1;

    if (!self_test_digests(st, libctx))
        ret = 0;
    if (!self_test_ciphers(st, libctx))
        ret = 0;
    if (!self_test_kdfs(st, libctx))
        ret = 0;
    if (!self_test_drbgs(st, libctx))
        ret = 0;

    return ret;
}
