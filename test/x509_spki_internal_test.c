/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "crypto/x509.h"
#include "internal/bytestring.h"
#include "testutil.h"

static const struct {
    const char *type;
    const char *group;
    int explicit_params;
} keys[] = {
    { "RSA", NULL, 0 },
    { "RSA-PSS", NULL, 0 },
#ifndef OPENSSL_NO_EC
    { "EC", "P-256", 0 },
    { "EC", "P-384", 0 },
    { "EC", "P-256", 1 },
#endif
#ifndef OPENSSL_NO_ECX
    { "ED25519", NULL, 0 },
    { "ED448", NULL, 0 },
    { "X25519", NULL, 0 },
    { "X448", NULL, 0 },
#endif
};

static EVP_PKEY *make_key(size_t i)
{
    EVP_PKEY *pkey;

    if (strcmp(keys[i].type, "EC") == 0)
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", keys[i].group);
    else if (strncmp(keys[i].type, "RSA", 3) == 0)
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, keys[i].type, (size_t)2048);
    else
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, keys[i].type);
    if (pkey != NULL && keys[i].explicit_params
        && !EVP_PKEY_set_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_ENCODING,
            OSSL_PKEY_EC_ENCODING_EXPLICIT)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

static int test_spki_to_pkey(int i)
{
    EVP_PKEY *pkey = NULL, *got = NULL;
    unsigned char *der = NULL, *got_der = NULL;
    int der_len, got_der_len, ret = 0;
    CBS spki;

    if (!TEST_ptr(pkey = make_key(i))
        || !TEST_int_gt(der_len = i2d_PUBKEY(pkey, &der), 0))
        goto err;
    CBS_init(&spki, der, (size_t)der_len);
    if (!TEST_ptr(got = ossl_x509_spki_to_pkey(&spki))
        || !TEST_true(EVP_PKEY_is_a(got, keys[i].type))
        || !TEST_int_eq(EVP_PKEY_eq(got, pkey), 1)
        || !TEST_int_gt(got_der_len = i2d_PUBKEY(got, &got_der), 0)
        || !TEST_mem_eq(got_der, got_der_len, der, der_len))
        goto err;
    ret = 1;
err:
    OPENSSL_free(der);
    OPENSSL_free(got_der);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(got);
    return ret;
}

static int test_spki_malformed(void)
{
    EVP_PKEY *pkey = NULL, *got = NULL;
    unsigned char *der = NULL;
    int der_len, ret = 0;
    CBS spki;

    if (!TEST_ptr(pkey = make_key(0))
        || !TEST_int_gt(der_len = i2d_PUBKEY(pkey, &der), 0))
        goto err;
    CBS_init(&spki, der, (size_t)der_len - 1);
    if (!TEST_ptr_null(got = ossl_x509_spki_to_pkey(&spki)))
        goto err;
    ret = 1;
err:
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(got);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_spki_to_pkey, OSSL_NELEM(keys));
    ADD_TEST(test_spki_malformed);
    return 1;
}
