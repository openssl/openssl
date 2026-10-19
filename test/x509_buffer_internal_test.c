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
#include "crypto/x509_view.h"
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

/* Whether x has a view whose TBSCertificate lies in x's der. */
static int view_of_der(const X509 *x)
{
    const struct x509_view *view;
    const unsigned char *start;
    CBS tbs;

    if (!TEST_ptr(x->der) || !TEST_ptr(view = x509_get0_view(x))
        || !TEST_true(x509_view_get_tbs(view, &tbs)))
        return 0;
    start = CRYPTO_BUFFER_data(x->der);

    return TEST_true(CBS_data(&tbs) > start)
        && TEST_true(CBS_data(&tbs) + CBS_len(&tbs)
            < start + CRYPTO_BUFFER_len(x->der));
}

static int test_x509_view(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL, *y = NULL, *z = NULL;
    unsigned char *der = NULL;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey)))
        goto err;

    /* A signed, a decoded and a duplicated certificate have a view. */
    if (!view_of_der(x)
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;
    q = der;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len))
        || !view_of_der(y)
        || !TEST_ptr(z = X509_dup(y))
        || !view_of_der(z)
        || !TEST_mem_eq(&z->view, sizeof(z->view), &y->view, sizeof(y->view)))
        goto err;
    X509_free(z);
    z = NULL;

    /* A modified certificate has none. */
    if (!TEST_true(X509_set_version(y, X509_VERSION_2))
        || !TEST_ptr_null(x509_get0_view(y)))
        goto err;

    /* A certificate with der the view rejects has none: an encoded v1. */
    if (!TEST_ptr(x->cert_info->version = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(x->cert_info->version, 0))
        || !TEST_int_gt(X509_sign(x, pkey, EVP_sha256()), 0)
        || !TEST_ptr(x->der)
        || !TEST_ptr_null(x509_get0_view(x)))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    X509_free(y);
    X509_free(z);
    OPENSSL_free(der);
    return ret;
}

static int test_x509_cmp(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL, *y = NULL, *z = NULL, *w = NULL;
    unsigned char *der = NULL;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey))
        || !TEST_ptr(w = make_cert(pkey))
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;
    q = der;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len)))
        goto err;
    q = der;
    if (!TEST_ptr(z = d2i_X509(NULL, &q, der_len)))
        goto err;

    /* Certificates with DER compare by it, without the extension cache. */
    if (!TEST_int_eq(X509_cmp(y, z), 0)
        || !TEST_int_eq(X509_cmp(x, y), 0)
        || !TEST_int_ne(X509_cmp(y, w), 0)
        || !TEST_int_eq(X509_cmp(y, w), -X509_cmp(w, y))
        || !TEST_int_eq(y->ex_cached, 0)
        || !TEST_int_eq(z->ex_cached, 0))
        goto err;

    /* A certificate with DER equals the same certificate without. */
    if (!TEST_true(ossl_x509_decode(z)))
        goto err;
    ossl_x509_set0_der(z, NULL);
    if (!TEST_int_eq(X509_cmp(y, z), 0)
        || !TEST_int_eq(X509_cmp(z, y), 0))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    X509_free(y);
    X509_free(z);
    X509_free(w);
    OPENSSL_free(der);
    return ret;
}

static int test_x509_pubkey(void)
{
    EVP_PKEY *pkey = NULL, *other = NULL, *got = NULL;
    X509 *x = NULL, *y = NULL, *z = NULL;
    unsigned char *der = NULL;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey))
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;

    /* A signed and a decoded X509 cache the key from the view. */
    q = der;
    if (!TEST_ptr(x->pkey)
        || !TEST_ptr_eq(X509_get0_pubkey(x), x->pkey)
        || !TEST_int_eq(EVP_PKEY_eq(x->pkey, pkey), 1)
        || !TEST_ptr(y = d2i_X509(NULL, &q, der_len))
        || !TEST_ptr(y->pkey)
        || !TEST_ptr_eq(X509_get0_pubkey(y), y->pkey)
        || !TEST_int_eq(EVP_PKEY_eq(y->pkey, pkey), 1)
        || !TEST_ptr(got = X509_get_pubkey(y))
        || !TEST_ptr_eq(got, y->pkey))
        goto err;

    /* X509_dup shares the key. */
    if (!TEST_ptr(z = X509_dup(y))
        || !TEST_ptr_eq(z->pkey, y->pkey))
        goto err;

    /* A modified X509 caches none, and returns the key it was given. */
    if (!TEST_true(X509_set_pubkey(z, other))
        || !TEST_ptr_null(z->pkey)
        || !TEST_int_eq(EVP_PKEY_eq(X509_get0_pubkey(z), other), 1))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(other);
    EVP_PKEY_free(got);
    X509_free(x);
    X509_free(y);
    X509_free(z);
    OPENSSL_free(der);
    return ret;
}

static int test_i2d_x509(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL, *y = NULL;
    unsigned char *der = NULL, *out = NULL, *buf = NULL, *p;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey))
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;
    q = der;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len))
        || !TEST_true(ossl_x509_decode(y)))
        goto err;

    /* A certificate with DER encodes as its DER, not from its fields. */
    y->signature.data[0] ^= 1;
    if (!TEST_int_eq(i2d_X509(y, NULL), der_len)
        || !TEST_int_eq(i2d_X509(y, &out), der_len)
        || !TEST_mem_eq(out, der_len, der, der_len)
        || !TEST_ptr(buf = OPENSSL_malloc(der_len)))
        goto err;
    p = buf;
    if (!TEST_int_eq(i2d_X509(y, &p), der_len)
        || !TEST_ptr_eq(p, buf + der_len)
        || !TEST_mem_eq(buf, der_len, der, der_len))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    X509_free(y);
    OPENSSL_free(der);
    OPENSSL_free(out);
    OPENSSL_free(buf);
    return ret;
}

static int test_lazy_decode(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL, *y = NULL, *z = NULL, *w = NULL;
    unsigned char *der = NULL, *out = NULL;
    const unsigned char *q;
    int der_len, ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = make_cert(pkey))
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;

    /* A decoded certificate has no cert_info until a reader needs it. */
    q = der;
    if (!TEST_ptr(y = d2i_X509(NULL, &q, der_len))
        || !TEST_ptr_null(y->cert_info)
        || !TEST_ptr(X509_get0_pubkey(y))
        || !TEST_int_eq(X509_cmp(x, y), 0)
        || !TEST_int_eq(i2d_X509(y, &out), der_len)
        || !TEST_mem_eq(out, der_len, der, der_len)
        || !TEST_ptr_null(y->cert_info))
        goto err;

    /*
     * Decoding into an existing certificate reuses it undecoded and keeps
     * its property query.
     */
    q = der;
    if (!TEST_ptr(w = X509_new_ex(NULL, "provider=default"))
        || !TEST_ptr_eq(d2i_X509(&w, &q, der_len), w)
        || !TEST_true(w->undecoded)
        || !TEST_str_eq(w->propq, "provider=default")
        || !TEST_ptr(X509_get_subject_name(w))
        || !TEST_false(w->undecoded)
        || !TEST_int_eq(X509_cmp(w, x), 0))
        goto err;

    /* X509_dup shares its DER, view and key without decoding. */
    if (!TEST_ptr(z = X509_dup(y))
        || !TEST_ptr_null(z->cert_info)
        || !TEST_ptr_eq(z->der, y->der)
        || !TEST_ptr_eq(z->pkey, y->pkey))
        goto err;

    /* A reader decodes it. */
    if (!TEST_ptr(X509_get_subject_name(y))
        || !TEST_ptr(y->cert_info)
        || !TEST_int_eq(X509_NAME_cmp(X509_get_subject_name(y),
                            X509_get_subject_name(x)),
            0)
        || !TEST_int_eq(X509_get_signature_nid(z), X509_get_signature_nid(x))
        || !TEST_ptr(z->cert_info))
        goto err;
    ret = 1;

err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    X509_free(y);
    X509_free(z);
    X509_free(w);
    OPENSSL_free(der);
    OPENSSL_free(out);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_lazy_decode);
    ADD_TEST(test_i2d_x509);
    ADD_TEST(test_x509_buffer);
    ADD_TEST(test_x509_view);
    ADD_TEST(test_x509_cmp);
    ADD_TEST(test_x509_pubkey);
    return 1;
}
