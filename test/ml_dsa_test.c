/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "internal/nelem.h"
#include "testutil.h"
#include "ml_dsa.inc"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static OSSL_LIB_CTX *lib_ctx = NULL;
static OSSL_PROVIDER *null_prov = NULL;
static OSSL_PROVIDER *lib_prov = NULL;

static EVP_PKEY *do_gen_key(const char *alg,
                            const uint8_t *seed, size_t seed_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;

    if (seed_len != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                 (char *)seed, seed_len);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
            || !TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
            || !TEST_int_eq(EVP_PKEY_CTX_set_params(ctx, params), 1)
            || !TEST_int_eq(EVP_PKEY_generate(ctx, &pkey), 1))
        goto err;
err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int ml_dsa_create_keypair(EVP_PKEY **pkey, const char *name,
                                 const uint8_t *priv, size_t priv_len,
                                 const uint8_t *pub, size_t pub_len)
{
    int ret = 0, selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3], *p = params;

    if (priv != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                 (uint8_t *)priv, priv_len);
        selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }
    if (pub != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                 (uint8_t *)pub, pub_len);
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, name, NULL))
            || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
            || !TEST_int_eq(EVP_PKEY_fromdata(ctx, pkey, selection,
                                              params), 1))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int ml_dsa_keygen_test(int tst_id)
{
    int ret = 0;
    const ML_DSA_KEYGEN_TEST_DATA *tst = &ml_dsa_keygen_testdata[tst_id];
    EVP_PKEY *pkey = NULL;
    uint8_t priv[5 * 1024], pub[3 * 1024];
    size_t priv_len, pub_len;

    if (!TEST_ptr(pkey = do_gen_key(tst->name, tst->seed, tst->seed_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                   priv, sizeof(priv), &priv_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, sizeof(pub), &pub_len)))
        goto err;
    if (!TEST_mem_eq(pub, pub_len, tst->pub, tst->pub_len))
        goto err;
    if (!TEST_mem_eq(priv, priv_len, tst->priv, tst->priv_len))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int ml_dsa_siggen_test(int tst_id)
{
    int ret = 0;
    ML_DSA_SIG_TEST_DATA *td = &ml_dsa_siggen_testdata[tst_id];
    EVP_PKEY_CTX *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM params[4], *p = params;
    uint8_t *psig = NULL;
    size_t psig_len = 0, sig_len2 = 0;
    uint8_t digest[32];
    size_t digest_len = sizeof(digest);
    int encode = 0, deterministic = 1;

    *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    if (td->add_random != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
                                                 (char *)td->add_random,
                                                 td->add_random_len);
    *p = OSSL_PARAM_construct_end();

    /*
     * This just uses from data here, but keygen also works.
     * The keygen path is tested via ml_dsa_keygen_test
     */
    if (!ml_dsa_create_keypair(&pkey, td->alg, td->priv, td->priv_len,
                               NULL, 0))
        goto err;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL)))
        goto err;
    if (!TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL)))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, params), 1)
            || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &psig_len,
                                          td->msg, td->msg_len), 1)
            || !TEST_true(EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_MAX_SIZE,
                                                    &sig_len2))
            || !TEST_int_eq(sig_len2, psig_len)
            || !TEST_ptr(psig = OPENSSL_zalloc(psig_len))
            || !TEST_int_eq(EVP_PKEY_sign(sctx, psig, &psig_len,
                                          td->msg, td->msg_len), 1))
        goto err;
    if (!TEST_int_eq(EVP_Q_digest(lib_ctx, "SHA256", NULL, psig, psig_len,
                                  digest, &digest_len), 1))
        goto err;
    if (!TEST_mem_eq(digest, digest_len, td->sig_digest, td->sig_digest_len))
        goto err;

    if (!TEST_int_eq(EVP_PKEY_verify_message_init(sctx, sig_alg, params), 1)
            || !TEST_int_eq(EVP_PKEY_verify(sctx, psig, psig_len,
                                            td->msg, td->msg_len), 1))
        goto err;
    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    OPENSSL_free(psig);
    return ret;
}

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

    ADD_ALL_TESTS(ml_dsa_keygen_test, OSSL_NELEM(ml_dsa_keygen_testdata));
    ADD_ALL_TESTS(ml_dsa_siggen_test, OSSL_NELEM(ml_dsa_siggen_testdata));
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(null_prov);
    OSSL_PROVIDER_unload(lib_prov);
    OSSL_LIB_CTX_free(lib_ctx);
}
