/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "crypto/x509.h"
#include "internal/pool.h"
#include "testutil.h"

static X509 *make_cert(EVP_PKEY *pkey)
{
    X509 *x = NULL, *ret = NULL;
    X509_NAME *name = NULL;

    if (!TEST_ptr(x = X509_new())
        || !TEST_ptr_null(x->der)
        || !TEST_true(X509_set_version(x, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(x), 1))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 3600))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"x509_buffer_test", -1, -1, 0))
        || !TEST_true(X509_set_subject_name(x, name))
        || !TEST_true(X509_set_issuer_name(x, name))
        || !TEST_true(X509_set_pubkey(x, pkey))
        || !TEST_ptr_null(x->der)
        || !TEST_int_gt(X509_sign(x, pkey, EVP_sha256()), 0)
        || !TEST_ptr(x->der))
        goto err;
    ret = x;
    x = NULL;

err:
    X509_NAME_free(name);
    X509_free(x);
    return ret;
}

static int der_matches(const X509 *x, const unsigned char *der, int der_len)
{
    return TEST_ptr(x->der)
        && TEST_mem_eq(CRYPTO_BUFFER_data(x->der), CRYPTO_BUFFER_len(x->der),
            der, (size_t)der_len);
}

static int test_x509_buffer(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL, *y = NULL, *z = NULL;
    unsigned char *der = NULL, *p = NULL;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey)))
        goto err;

    /* The signed certificate's der is its encoding. */
    if (!TEST_int_gt(der_len = i2d_X509(x, &der), 0)
        || !der_matches(x, der, der_len))
        goto err;

    /* d2i_X509 copies the bytes it consumed into der. */
    q = der;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len))
        || !der_matches(y, der, der_len)
        || !TEST_ptr_ne(CRYPTO_BUFFER_data(y->der), der))
        goto err;

    /* d2i_X509 into an existing certificate replaces its der. */
    q = der;
    if (!TEST_ptr(d2i_X509(&y, &q, der_len))
        || !der_matches(y, der, der_len))
        goto err;

    /* X509_dup of a decoded certificate shares its der. */
    if (!TEST_ptr(z = X509_dup(y))
        || !TEST_ptr_eq(z->der, y->der))
        goto err;
    X509_free(z);
    z = NULL;

    /* X509_dup of a signed certificate shares its der. */
    if (!TEST_ptr(z = X509_dup(x))
        || !TEST_ptr_eq(z->der, x->der))
        goto err;
    X509_free(z);
    z = NULL;

    /* A setter drops der. */
    if (!TEST_true(X509_set_version(y, X509_VERSION_2))
        || !TEST_ptr_null(y->der))
        goto err;

    /* X509_dup of a modified certificate has no der. */
    if (!TEST_ptr(z = X509_dup(y))
        || !TEST_ptr_null(z->der))
        goto err;
    X509_free(z);
    z = NULL;
    X509_free(y);
    y = NULL;

    /* der holds only the certificate, not what follows it. */
    if (!TEST_ptr(p = OPENSSL_zalloc((size_t)der_len + 1)))
        goto err;
    memcpy(p, der, (size_t)der_len);
    q = p;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len + 1))
        || !TEST_ptr_eq(q, p + der_len)
        || !der_matches(y, der, der_len))
        goto err;
    X509_free(y);
    y = NULL;

    /*
     * An outer SEQUENCE with a non-minimal length is decoded without der:
     * the two length octets after 0x82 are re-encoded after 0x83 0x00.
     */
    if (!TEST_int_eq(der[1], 0x82))
        goto err;
    p[0] = 0x30;
    p[1] = 0x83;
    p[2] = 0x00;
    memcpy(p + 3, der + 2, (size_t)der_len - 2);
    q = p;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len + 1))
        || !TEST_ptr_eq(q, p + der_len + 1)
        || !TEST_ptr_null(y->der))
        goto err;

    /* Decoding it into a certificate with der drops the der. */
    q = der;
    if (!TEST_ptr(z = d2i_X509(NULL, &q, der_len))
        || !TEST_ptr(z->der))
        goto err;
    q = p;
    if (!TEST_ptr(d2i_X509(&z, &q, der_len + 1))
        || !TEST_ptr_null(z->der))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    X509_free(y);
    X509_free(z);
    OPENSSL_free(der);
    OPENSSL_free(p);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_x509_buffer);
    return 1;
}
