/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "crypto/x509.h"
#include "crypto/x509_view.h"
#include "testutil.h"

static const char *certs_dir;

static X509 *load_cert(const char *name)
{
    char *path;
    BIO *bio = NULL;
    X509 *x = NULL;

    if (!TEST_ptr(path = test_mk_file_path(certs_dir, name))
        || !TEST_ptr(bio = BIO_new_file(path, "r")))
        goto err;
    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);

err:
    BIO_free(bio);
    OPENSSL_free(path);
    return x;
}

/*
 * Verifies leaf against root-cert.pem with ca-cert.pem untrusted, as a
 * server certificate, and returns the verification error.
 */
static int verify(X509 *leaf, unsigned long flags)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *root = NULL, *ca = NULL;
    STACK_OF(X509) *untrusted = NULL;
    int ret = -1;

    if (!TEST_ptr(root = load_cert("root-cert.pem"))
        || !TEST_ptr(ca = load_cert("ca-cert.pem"))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, root))
        || !TEST_ptr(untrusted = sk_X509_new_null())
        || !TEST_true(sk_X509_push(untrusted, ca)))
        goto err;
    ca = NULL;
    if (!TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, leaf, untrusted)))
        goto err;
    X509_STORE_CTX_set_flags(ctx, flags);
    X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
    (void)X509_verify_cert(ctx);
    ret = X509_STORE_CTX_get_error(ctx);

err:
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, X509_free);
    X509_STORE_free(store);
    X509_free(root);
    X509_free(ca);
    return ret;
}

static int test_strict_chain(void)
{
    X509 *leaf;
    int ret;

    ret = TEST_ptr(leaf = load_cert("ee-cert.pem"))
        && TEST_int_eq(verify(leaf, 0), X509_V_OK)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT), X509_V_OK);
    X509_free(leaf);
    return ret;
}

/*
 * A setter leaves the certificate without a view even when it changes
 * nothing, so its signature still verifies.
 */
static int test_strict_no_view(void)
{
    X509 *leaf;
    ASN1_INTEGER *serial = NULL;
    int ret = 0;

    if (!TEST_ptr(leaf = load_cert("ee-cert.pem"))
        || !TEST_ptr(serial = ASN1_INTEGER_dup(X509_get0_serialNumber(leaf)))
        || !TEST_true(X509_set_serialNumber(leaf, serial))
        || !TEST_ptr_null(x509_get0_view(leaf))
        || !TEST_int_eq(verify(leaf, 0), X509_V_OK)
        || !TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT),
            X509_V_ERR_UNSPECIFIED))
        goto err;
    ret = 1;

err:
    ASN1_INTEGER_free(serial);
    X509_free(leaf);
    return ret;
}

/*
 * ee-pathlen.pem has a pathLenConstraint without cA, which its view finds
 * malformed and which a non-strict verification accepts.
 */
static int test_strict_malformed_extension(void)
{
    X509 *leaf;
    int ret;

    ret = TEST_ptr(leaf = load_cert("ee-pathlen.pem"))
        && TEST_ptr(x509_get0_view(leaf))
        && TEST_true(x509_view_has_malformed_extension(x509_get0_view(leaf)))
        && TEST_int_eq(verify(leaf, 0), X509_V_OK)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT),
            X509_V_ERR_INVALID_EXTENSION);
    X509_free(leaf);
    return ret;
}

OPT_TEST_DECLARE_USAGE("certs-dir\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_strict_chain);
    ADD_TEST(test_strict_no_view);
    ADD_TEST(test_strict_malformed_extension);
    return 1;
}
