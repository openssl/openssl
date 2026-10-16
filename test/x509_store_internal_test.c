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
#include <openssl/x509v3.h>

#include "crypto/x509.h"
#include "crypto/x509_view.h"
#include "testutil.h"

/*
 * A self-signed CA certificate for the common name given, valid over the
 * times given, decoded from its encoding so that it has DER and a view.
 */
static X509 *make_cert(const char *cn, const char *not_before,
    const char *not_after)
{
    X509 *cert = NULL, *ret = NULL;
    EVP_PKEY *pkey = NULL;
    X509_NAME *name = NULL;
    BASIC_CONSTRAINTS *bc = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int der_len;

    if (!TEST_ptr(cert = X509_new())
        || !TEST_true(X509_set_version(cert, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0))
        || !TEST_true(X509_set_issuer_name(cert, name))
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(ASN1_TIME_set_string(X509_getm_notBefore(cert),
            not_before))
        || !TEST_true(ASN1_TIME_set_string(X509_getm_notAfter(cert),
            not_after))
        || !TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))
        || !TEST_true(X509_set_pubkey(cert, pkey))
        || !TEST_ptr(bc = BASIC_CONSTRAINTS_new()))
        goto err;
    bc->ca = 0xff;
    if (!TEST_true(X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 1, 0))
        || !TEST_int_gt(X509_sign(cert, pkey, NULL), 0)
        || !TEST_int_gt(der_len = i2d_X509(cert, &der), 0))
        goto err;
    p = der;
    ret = d2i_X509(NULL, &p, der_len);

err:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    X509_NAME_free(name);
    BASIC_CONSTRAINTS_free(bc);
    OPENSSL_free(der);
    return ret;
}

static int subject_of(const X509 *cert, CBS *out)
{
    const struct x509_view *view;

    return TEST_ptr(view = x509_get0_view(cert))
        && TEST_true(x509_view_get_subject(view, out));
}

/* Whether certs holds exactly the certificates in want, in order. */
static int certs_are(STACK_OF(X509) *certs, X509 **want, int want_num)
{
    int i;

    if (want_num == 0)
        return TEST_ptr_null(certs);
    if (!TEST_ptr(certs) || !TEST_int_eq(sk_X509_num(certs), want_num))
        return 0;
    for (i = 0; i < want_num; i++) {
        if (!TEST_ptr_eq(sk_X509_value(certs, i), want[i]))
            return 0;
    }
    return 1;
}

static int test_store_subjects(void)
{
    X509_STORE *store = NULL;
    X509 *current = NULL, *expired = NULL, *other = NULL, *no_view = NULL;
    X509 *want[2];
    STACK_OF(X509) *certs = NULL, *all = NULL;
    CBS subject;
    unsigned char *name = NULL;
    int64_t check_time;
    int name_len, ret = 0;

    if (!TEST_ptr(current = make_cert("store test", "210101000000Z",
                      "310101000000Z"))
        || !TEST_ptr(expired = make_cert("store test", "100101000000Z",
                         "200101000000Z"))
        || !TEST_ptr(other = make_cert("other", "210101000000Z",
                         "310101000000Z"))
        || !TEST_ptr(no_view = make_cert("no view", "210101000000Z",
                         "310101000000Z"))
        || !TEST_true(X509_set_serialNumber(no_view,
            X509_get_serialNumber(current)))
        || !TEST_ptr_null(x509_get0_view(no_view)))
        goto err;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, current))
        || !TEST_true(X509_STORE_add_cert(store, expired))
        || !TEST_true(X509_STORE_add_cert(store, other))
        || !TEST_true(X509_STORE_add_cert(store, no_view))
        || !TEST_true(X509_STORE_add_cert(store, current))
        || !TEST_ptr(all = X509_STORE_get1_all_certs(store))
        || !TEST_int_eq(sk_X509_num(all), 4))
        goto err;

    /* Both certificates with the subject, in insertion order. */
    want[0] = current;
    want[1] = expired;
    if (!subject_of(current, &subject)
        || !certs_are(certs = ossl_x509_store_get1_certs_by_subject(store,
                          &subject, NULL),
            want, 2))
        goto err;
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    /* The one valid at the time first. */
    check_time = 1735689600; /* 2025-01-01 */
    if (!certs_are(certs = ossl_x509_store_get1_certs_by_subject(store,
                       &subject, &check_time),
            want, 2))
        goto err;
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    check_time = 1420070400; /* 2015-01-01 */
    want[0] = expired;
    want[1] = current;
    if (!certs_are(certs = ossl_x509_store_get1_certs_by_subject(store,
                       &subject, &check_time),
            want, 2))
        goto err;
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    want[0] = other;
    if (!subject_of(other, &subject)
        || !certs_are(certs = ossl_x509_store_get1_certs_by_subject(store,
                          &subject, NULL),
            want, 1))
        goto err;
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    /* A certificate without a view is in the store but not found. */
    if (!TEST_int_gt(name_len = i2d_X509_NAME(X509_get_subject_name(no_view),
                         &name),
            0))
        goto err;
    CBS_init(&subject, name, (size_t)name_len);
    if (!certs_are(ossl_x509_store_get1_certs_by_subject(store, &subject,
                       NULL),
            NULL, 0))
        goto err;
    ret = 1;

err:
    sk_X509_pop_free(certs, X509_free);
    sk_X509_pop_free(all, X509_free);
    X509_STORE_free(store);
    X509_free(current);
    X509_free(expired);
    X509_free(other);
    X509_free(no_view);
    OPENSSL_free(name);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_store_subjects);
    return 1;
}
