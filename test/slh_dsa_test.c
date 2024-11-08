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
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include "crypto/slh_dsa.h"
#include "internal/nelem.h"
#include "testutil.h"
#include "slh_dsa.inc"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static OSSL_LIB_CTX *lib_ctx = NULL;
static OSSL_PROVIDER *null_prov = NULL;
static OSSL_PROVIDER *lib_prov = NULL;

static EVP_PKEY *slh_dsa_pubkey_from_data(const char *alg,
                                          const unsigned char *data, size_t datalen)
{
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (unsigned char *)data, datalen);
    params[1] = OSSL_PARAM_construct_end();
    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        && TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        && (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) == 1);
    if (ret == 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int slh_dsa_create_keypair(EVP_PKEY **pkey, const char *name,
                                  const uint8_t *priv, size_t priv_len,
                                  const uint8_t *pub, size_t pub_len)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *pub_name = OSSL_PKEY_PARAM_PUB_KEY;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
            || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                           OSSL_PKEY_PARAM_PRIV_KEY,
                                                           priv, priv_len) > 0)
            || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                           pub_name,
                                                           pub, pub_len) > 0)
            || !TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, name, NULL))
            || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
            || !TEST_int_eq(EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_KEYPAIR,
                                              params), 1))
        goto err;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int slh_dsa_bad_pub_len_test(void)
{
    int ret = 0;
    SLH_DSA_SIG_TEST_DATA *td = &slh_dsa_sig_testdata[0];
    EVP_PKEY *pkey = NULL;
    size_t pub_len = 0;
    unsigned char pubdata[64 + 1];

    if (!TEST_size_t_le(td->pub_len, sizeof(pubdata)))
        goto end;

    OPENSSL_cleanse(pubdata, sizeof(pubdata));
    memcpy(pubdata, td->pub, td->pub_len);

    if (!TEST_ptr_null(pkey = slh_dsa_pubkey_from_data(td->alg, pubdata,
                                                       td->pub_len - 1))
            || !TEST_ptr_null(pkey = slh_dsa_pubkey_from_data(td->alg, pubdata,
                                                              td->pub_len + 1)))
        goto end;

    ret = 1;
end:
    if (ret == 0)
        TEST_note("Incorrectly accepted public key of length %u (expected %u)",
                  (unsigned)pub_len, (unsigned)td->pub_len);
    EVP_PKEY_free(pkey);
    return ret == 1;
}

static int slh_dsa_key_eq_test(void)
{
    int ret = 0;
    EVP_PKEY *key[3] = { NULL, NULL, NULL };
    SLH_DSA_SIG_TEST_DATA *td1 = &slh_dsa_sig_testdata[0];
    SLH_DSA_SIG_TEST_DATA *td2 = &slh_dsa_sig_testdata[1];
#ifndef OPENSSL_NO_EC
    EVP_PKEY *eckey = NULL;
#endif

    if (!TEST_ptr(key[0] = slh_dsa_pubkey_from_data(td1->alg, td1->pub, td1->pub_len))
            || !TEST_ptr(key[1] = slh_dsa_pubkey_from_data(td1->alg, td1->pub, td1->pub_len))
            || !TEST_ptr(key[2] = slh_dsa_pubkey_from_data(td2->alg, td2->pub, td2->pub_len)))
        goto end;

    if (!TEST_int_eq(EVP_PKEY_eq(key[0], key[1]), 1)
            || !TEST_int_ne(EVP_PKEY_eq(key[0], key[2]), 1))
        goto end;

#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(eckey = EVP_PKEY_Q_keygen(lib_ctx, NULL, "EC", "P-256")))
        goto end;
    ret = TEST_int_ne(EVP_PKEY_eq(key[0], eckey), 1);
    EVP_PKEY_free(eckey);
#else
    ret = 1;
#endif
end:
    EVP_PKEY_free(key[2]);
    EVP_PKEY_free(key[1]);
    EVP_PKEY_free(key[0]);
    return ret;
}

static int slh_dsa_key_validate_test(void)
{
    int ret = 0;
    SLH_DSA_SIG_TEST_DATA *td = &slh_dsa_sig_testdata[0];
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(key = slh_dsa_pubkey_from_data(td->alg, td->pub, td->pub_len)))
        return 0;
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL)))
        goto end;
    ret = TEST_int_eq(EVP_PKEY_check(vctx), 1);
    EVP_PKEY_CTX_free(vctx);
end:
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Rather than having to store the full signature into a file, we just do a
 * verify using the output of a sign. The sign test already does a Known answer
 * test (KAT) using the digest of the signature, so this should be sufficient to
 * run as a KAT for the verify.
 */
static int do_slh_dsa_verify(const SLH_DSA_SIG_TEST_DATA *td,
                             uint8_t *sig, size_t sig_len)
{
    int ret = 0;
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM params[2], *p = params;
    int encode = 0;

    *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(key = slh_dsa_pubkey_from_data(td->alg, td->pub, td->pub_len)))
        return 0;
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL)))
        goto err;
    if (!TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL)))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_verify_init_ex2(vctx, sig_alg, params), 1)
            || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len,
                                            td->msg, td->msg_len), 1))
        goto err;
    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

static int slh_dsa_sign_verify_test(int tst_id)
{
    int ret = 0;
    SLH_DSA_SIG_TEST_DATA *td = &slh_dsa_sig_testdata[tst_id];
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
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ADD_RANDOM,
                                                 (char *)td->add_random,
                                                 td->add_random_len);
    *p = OSSL_PARAM_construct_end();

    /*
     * This just uses from data here, but keygen also works.
     * The keygen path is tested via slh_dsa_keygen_test
     */
    if (!slh_dsa_create_keypair(&pkey, td->alg, td->priv, td->priv_len,
                                td->pub, td->pub_len))
        goto err;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL)))
        goto err;
    if (!TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL)))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_sign_init_ex2(sctx, sig_alg, params), 1)
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
    if (!do_slh_dsa_verify(td, psig, psig_len))
        goto err;
    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    OPENSSL_free(psig);
    return ret;
}

static EVP_PKEY *do_gen_key(const char *alg,
                            const uint8_t *entropy, size_t entropy_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;

    if (entropy_len != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_ENTROPY,
                                                 (char *)entropy, entropy_len);
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

static int slh_dsa_keygen_test(int tst_id)
{
    int ret = 0;
    const SLH_DSA_KEYGEN_TEST_DATA *tst = &slh_dsa_keygen_testdata[tst_id];
    EVP_PKEY *pkey = NULL;
    uint8_t priv[32 * 2], pub[32 * 2];
    size_t priv_len, pub_len;
    size_t key_len = tst->priv_len / 2;
    size_t n = key_len / 2;
    int bits = 0, sec_bits = 0, sig_len = 0;

    if (!TEST_ptr(pkey = do_gen_key(tst->name, tst->priv, key_len + n)))
        goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                   priv, sizeof(priv), &priv_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, sizeof(pub), &pub_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_BITS, &bits))
            || !TEST_int_eq(bits, 8 * key_len)
            || !TEST_true(EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_SECURITY_BITS,
                                                 &sec_bits))
            || !TEST_int_eq(sec_bits, 8 * n)
            || !TEST_true(EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_MAX_SIZE,
                                                 &sig_len))
            || !TEST_int_ge(sig_len, 7856)
            || !TEST_int_le(sig_len, 49856))
        goto err;

    if (!TEST_size_t_eq(priv_len, key_len)
            || !TEST_size_t_eq(pub_len, key_len))
        goto err;
    if (!TEST_mem_eq(pub, pub_len, tst->priv + key_len, key_len))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pkey);
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

    ADD_TEST(slh_dsa_bad_pub_len_test);
    ADD_TEST(slh_dsa_key_validate_test);
    ADD_TEST(slh_dsa_key_eq_test);
    ADD_ALL_TESTS(slh_dsa_sign_verify_test, OSSL_NELEM(slh_dsa_sig_testdata));
    ADD_ALL_TESTS(slh_dsa_keygen_test, OSSL_NELEM(slh_dsa_keygen_testdata));
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(null_prov);
    OSSL_PROVIDER_unload(lib_prov);
    OSSL_LIB_CTX_free(lib_ctx);
}
