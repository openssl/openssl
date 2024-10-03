/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "crypto/lms.h"
#include "internal/nelem.h"
#include "testutil.h"
#include "lms.inc"

static OSSL_LIB_CTX *libctx = NULL;

static EVP_PKEY *lms_pubkey_from_data(const unsigned char *data, size_t datalen)
{
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                  (unsigned char *)data, datalen);
    params[1] = OSSL_PARAM_construct_end();
    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "LMS", NULL))
        && TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        && (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) == 1);
    if (ret == 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int lms_bad_pub_len_test(void)
{
    int ret = 0;
    LMS_ACVP_TEST_DATA *td = &lms_testdata[1];
    EVP_PKEY *pkey = NULL;
    size_t publen = 0;
    unsigned char pubdata[128];

    if (!TEST_size_t_le(td->publen + 16, sizeof(pubdata)))
        goto end;

    OPENSSL_cleanse(pubdata, sizeof(pubdata));
    memcpy(pubdata, td->pub, td->publen);

    for (publen = 0; publen <= td->publen + 16; publen += 3) {
        if (publen == td->publen)
            continue;
        if (!TEST_ptr_null(pkey = lms_pubkey_from_data(pubdata, publen)))
            goto end;
    }
    ret = 1;
end:
    if (ret == 0)
        TEST_note("Incorrectly accepted public key of length %u (expected %u)",
                  (unsigned)publen, (unsigned)td->publen);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

static int lms_key_eq_test(void)
{
    int ret = 0;
    EVP_PKEY *key[3] = { NULL, NULL, NULL };
    LMS_ACVP_TEST_DATA *td1 = &lms_testdata[0];
    LMS_ACVP_TEST_DATA *td2 = &lms_testdata[1];
#ifndef OPENSSL_NO_EC
    EVP_PKEY *eckey = NULL;
#endif

    if (!TEST_ptr(key[0] = lms_pubkey_from_data(td1->pub, td1->publen))
            || !TEST_ptr(key[1] = lms_pubkey_from_data(td1->pub, td1->publen))
            || !TEST_ptr(key[2] = lms_pubkey_from_data(td2->pub, td2->publen)))
        goto end;

    ret = TEST_int_eq(EVP_PKEY_eq(key[0], key[1]), 1)
        && TEST_int_ne(EVP_PKEY_eq(key[0], key[2]), 1);
    if (ret == 0)
        goto end;

#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(eckey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256")))
        goto end;
    ret = TEST_int_ne(EVP_PKEY_eq(key[0], eckey), 1);
    EVP_PKEY_free(eckey);
#endif
end:
    EVP_PKEY_free(key[2]);
    EVP_PKEY_free(key[1]);
    EVP_PKEY_free(key[0]);
    return ret;
}

static int lms_key_validate_test(void)
{
    int ret = 0;
    LMS_ACVP_TEST_DATA *td = &lms_testdata[0];
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(key = lms_pubkey_from_data(td->pub, td->publen)))
        return 0;
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL)))
        goto end;
    ret = TEST_int_eq(EVP_PKEY_check(vctx), 1);
    EVP_PKEY_CTX_free(vctx);
end:
    EVP_PKEY_free(key);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(lms_bad_pub_len_test);
    ADD_TEST(lms_key_validate_test);
    ADD_TEST(lms_key_eq_test);
    return 1;
}
