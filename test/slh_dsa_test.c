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

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *fake_rand = NULL;

static size_t entropy_pos = 0;
static size_t entropy_sz = 0;
static uint8_t entropy[128];

static int set_entropy(const uint8_t *ent1, size_t ent1_len,
                       const uint8_t *ent2, size_t ent2_len)
{
    if ((ent1_len + ent2_len) > sizeof(entropy))
        return 0;
    entropy_pos = 0;
    entropy_sz += (ent1_len + ent2_len);
    memcpy(entropy, ent1, ent1_len);
    if (ent2 != NULL)
        memcpy(entropy + ent1_len, ent2, ent2_len);
    return 1;
}

static int fake_rand_cb(unsigned char *buf, size_t num,
                        ossl_unused const char *name, EVP_RAND_CTX *ctx)
{
    if ((entropy_pos + num) > entropy_sz)
        return 0;
    memcpy(buf, entropy + entropy_pos, num);
    entropy_pos += num;
    return 1;
}

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
    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, alg, NULL))
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

    if (pub_len != priv_len)
        pub_name = OSSL_PKEY_PARAM_SLH_DSA_PUB_SEED;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
            || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                           OSSL_PKEY_PARAM_PRIV_KEY,
                                                           priv, priv_len) > 0)
            || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
                                                           pub_name,
                                                           pub, pub_len) > 0)
            || !TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, name, NULL))
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
    EVP_PKEY *key[2] = { NULL, NULL };
    SLH_DSA_SIG_TEST_DATA *td1 = &slh_dsa_sig_testdata[0];
#ifndef OPENSSL_NO_EC
    EVP_PKEY *eckey = NULL;
#endif

    if (!TEST_ptr(key[0] = slh_dsa_pubkey_from_data(td1->alg, td1->pub, td1->pub_len))
            || !TEST_ptr(key[1] = slh_dsa_pubkey_from_data(td1->alg, td1->pub, td1->pub_len)))
        goto end;

    ret = TEST_int_eq(EVP_PKEY_eq(key[0], key[1]), 1);
    if (ret == 0)
        goto end;

#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(eckey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256")))
        goto end;
    ret = TEST_int_ne(EVP_PKEY_eq(key[0], eckey), 1);
    EVP_PKEY_free(eckey);
#endif
end:
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
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL)))
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
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL)))
        goto err;
    if (!TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(libctx, td->alg, NULL)))
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

static int slh_dsa_sign_verify_test(void)
{
    int ret = 0;
    SLH_DSA_SIG_TEST_DATA *td = &slh_dsa_sig_testdata[0];
    EVP_PKEY_CTX *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM params[3], *p = params;
    uint8_t sig[64 * 1024];
    size_t sig_len = sizeof(sig);
    uint8_t digest[32];
    size_t digest_len = sizeof(digest);
    int encode = 0, deterministic = 1;

    *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    *p = OSSL_PARAM_construct_end();

    /*
     * This just uses from data here, but keygen also works.
     * The keygen path is tested via slh_dsa_keygen_test
     */
    if (!slh_dsa_create_keypair(&pkey, td->alg, td->priv, td->priv_len,
                                td->pub, td->pub_len))
        goto err;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL)))
        goto err;
    if (!TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(libctx, td->alg, NULL)))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_sign_init_ex2(sctx, sig_alg, params), 1)
            || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len,
                                          td->msg, td->msg_len), 1))
        goto err;

    if (!TEST_int_eq(EVP_Q_digest(libctx, "SHA256", NULL, sig, sig_len,
                                  digest, &digest_len), 1))
        goto err;
    if (!TEST_mem_eq(digest, digest_len, td->sig_digest, td->sig_digest_len))
        goto err;
    if (!do_slh_dsa_verify(td, sig, sig_len))
        goto err;
    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    return ret;
}

static int slh_dsa_keygen_test(void)
{
    int ret = 0;
    const SLH_DSA_KEYGEN_TEST_DATA *tst = &slh_dsa_keygen_testdata[0];
    EVP_PKEY *pkey = NULL;
    uint8_t priv[32 * 2], pub[32 * 2];
    size_t priv_len, pub_len;

    if (!TEST_true(set_entropy(tst->priv, tst->priv_len,
                               tst->pub_seed, tst->pub_seed_len)))
        goto err;

    fake_rand_set_callback(RAND_get0_private(NULL), &fake_rand_cb);
    fake_rand_set_callback(RAND_get0_public(NULL), &fake_rand_cb);

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(libctx, NULL, tst->name)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                   priv, sizeof(priv), &priv_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, sizeof(pub), &pub_len)))
        goto err;
    if (!TEST_size_t_eq(priv_len, tst->priv_len)
            || !TEST_size_t_eq(pub_len, tst->priv_len))
        goto err;
    ret = 1;
err:
    fake_rand_set_callback(RAND_get0_public(NULL), NULL);
    fake_rand_set_callback(RAND_get0_private(NULL), NULL);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * Given raw values for the private key + public key seed
 * generate the public root using from data.
 */
static int slh_dsa_pub_root_from_data_test(void)
{
    int ret = 0;
    uint8_t priv[64], pub[64];
    size_t priv_len = 0, pub_len = 0;
    EVP_PKEY *pkey = NULL;
    const SLH_DSA_KEYGEN_TEST_DATA *tst = &slh_dsa_keygen_testdata[0];

    if (!slh_dsa_create_keypair(&pkey, tst->name, tst->priv, tst->priv_len,
                                tst->pub_seed, tst->pub_seed_len))
        goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                   priv, sizeof(priv), &priv_len)))
        goto err;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, sizeof(pub), &pub_len)))
        goto err;
    if (!TEST_mem_eq(pub, pub_len, tst->pub_expected, tst->pub_expected_len))
        goto err;
    ret = 1;
err:
    OPENSSL_cleanse(priv, priv_len);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    fake_rand = fake_rand_start(NULL);
    if (fake_rand == NULL)
        return 0;

    ADD_TEST(slh_dsa_bad_pub_len_test);
    ADD_TEST(slh_dsa_key_validate_test);
    ADD_TEST(slh_dsa_key_eq_test);
    ADD_TEST(slh_dsa_sign_verify_test);
    ADD_TEST(slh_dsa_keygen_test);
    ADD_TEST(slh_dsa_pub_root_from_data_test);
    return 1;
}

void cleanup_tests(void)
{
    fake_rand_finish(fake_rand);
}
