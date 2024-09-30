/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/decoder.h>
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

static int lms_pubkey_decoder_fail_test(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection = 0;
    LMS_ACVP_TEST_DATA *td = &lms_testdata[0];
    const unsigned char *pdata;
    size_t pdatalen;
    static const unsigned char pub_bad_LMSType[] = {
        0x00, 0x00, 0x00, 0xAA
    };
    static const unsigned char pub_bad_OTSType[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xAA
    };

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, NULL, NULL, "LMS",
                                                       selection,
                                                       libctx, NULL)))
        return 0;

    pdata = td->pub;
    pdatalen = 3;
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdatalen = SIZE_MAX;
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdata = pub_bad_LMSType;
    pdatalen = sizeof(pub_bad_LMSType);
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdata = pub_bad_OTSType;
    pdatalen = sizeof(pub_bad_OTSType);
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);
    return ret;
}

static EVP_PKEY *key_decode_from_bio(BIO *bio, const char *keytype)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection = 0;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, NULL, NULL,
                                                       keytype,
                                                       selection,
                                                       libctx, NULL)))
        return NULL;

    if (!TEST_true(OSSL_DECODER_from_bio(dctx, bio))) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

static EVP_PKEY *key_decode_from_data(const unsigned char *data, size_t datalen,
                                      const char *keytype)
{
    BIO *bio;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(bio = BIO_new_mem_buf(data, datalen)))
        return NULL;
    key = key_decode_from_bio(bio, keytype);
    BIO_free(bio);
    return key;
}

static int lms_key_decode_test(void)
{
    int ret = 0;
    LMS_ACVP_TEST_DATA *td1 = &lms_testdata[0];
    EVP_PKEY *key = NULL;

    ret = TEST_ptr(key = key_decode_from_data(td1->pub, td1->publen, NULL));
    EVP_PKEY_free(key);
    return ret;
}

static int lms_pubkey_decoder_test(void)
{
    int ret = 0;
    LMS_ACVP_TEST_DATA *td = &lms_testdata[0];
    EVP_PKEY *pub = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const unsigned char *data;
    size_t data_len;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pub, "xdr", NULL,
                                                       "LMS",
                                                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                                       libctx, NULL)))
        goto err;
    data = td->pub;
    data_len = td->publen;
    if (!TEST_true(OSSL_DECODER_from_data(dctx, &data, &data_len)))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pub);
    OSSL_DECODER_CTX_free(dctx);
    return ret;
}

static int lms_key_eq_test(void)
{
    int ret = 0;
    EVP_PKEY *key[4] = { NULL, NULL, NULL };
    LMS_ACVP_TEST_DATA *td1 = &lms_testdata[0];
    LMS_ACVP_TEST_DATA *td2 = &lms_testdata[1];
#ifndef OPENSSL_NO_EC
    EVP_PKEY *eckey = NULL;
#endif

    if (!TEST_ptr(key[0] = lms_pubkey_from_data(td1->pub, td1->publen))
            || !TEST_ptr(key[1] = lms_pubkey_from_data(td1->pub, td1->publen))
            || !TEST_ptr(key[2] = lms_pubkey_from_data(td2->pub, td2->publen))
            || !TEST_ptr(key[3] = key_decode_from_data(td1->pub, td1->publen,
                                                       NULL)))
        goto end;

    ret = TEST_int_eq(EVP_PKEY_eq(key[0], key[1]), 1)
        && TEST_int_ne(EVP_PKEY_eq(key[0], key[2]), 1)
        && TEST_int_eq(EVP_PKEY_eq(key[0], key[3]), 1);
    if (ret == 0)
        goto end;

#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(eckey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256")))
        goto end;
    ret = TEST_int_ne(EVP_PKEY_eq(key[0], eckey), 1);
    EVP_PKEY_free(eckey);
#endif
end:
    EVP_PKEY_free(key[3]);
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
    ADD_TEST(lms_key_decode_test);
    ADD_TEST(lms_pubkey_decoder_test);
    ADD_TEST(lms_pubkey_decoder_fail_test);
    return 1;
}
