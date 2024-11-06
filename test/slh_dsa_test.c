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
#include "crypto/slh_dsa.h"
#include "internal/nelem.h"
#include "testutil.h"
#include "slh_dsa.inc"

static OSSL_LIB_CTX *libctx = NULL;

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

static int slh_dsa_bad_pub_len_test(void)
{
    int ret = 0;
    SLH_DSA_ACVP_TEST_DATA *td = &slh_dsa_testdata[0];
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
    SLH_DSA_ACVP_TEST_DATA *td1 = &slh_dsa_testdata[0];
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
    SLH_DSA_ACVP_TEST_DATA *td = &slh_dsa_testdata[0];
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

static int slh_dsa_sig_verify_test(void)
{
    int ret = 0;
    SLH_DSA_ACVP_TEST_DATA *td = &slh_dsa_testdata[0];
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
            || !TEST_int_eq(EVP_PKEY_verify(vctx, td->sig, td->sig_len,
                                            td->msg, td->msg_len), 1))
        goto err;
    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(slh_dsa_bad_pub_len_test);
    ADD_TEST(slh_dsa_key_validate_test);
    ADD_TEST(slh_dsa_key_eq_test);
    ADD_TEST(slh_dsa_sig_verify_test);
    return 1;
}
