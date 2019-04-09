/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "testutil.h"

static const char *roots_f;
static const char *untrusted_f;
static const char *bad_f;

static STACK_OF(X509) *load_certs_from_file(const char *filename)
{
    STACK_OF(X509) *certs;
    BIO *bio;
    X509 *x;

    bio = BIO_new_file(filename, "r");

    if (bio == NULL) {
        return NULL;
    }

    certs = sk_X509_new_null();
    if (certs == NULL) {
        BIO_free(bio);
        return NULL;
    }

    ERR_set_mark();
    do {
        x = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if (x != NULL && !sk_X509_push(certs, x)) {
            sk_X509_pop_free(certs, X509_free);
            BIO_free(bio);
            return NULL;
        } else if (x == NULL) {
            /*
             * We probably just ran out of certs, so ignore any errors
             * generated
             */
            ERR_pop_to_mark();
        }
    } while (x != NULL);

    BIO_free(bio);

    return certs;
}

/*
 * Test for CVE-2015-1793 (Alternate Chains Certificate Forgery)
 *
 * Chain is as follows:
 *
 * rootCA (self-signed)
 *   |
 * interCA
 *   |
 * subinterCA       subinterCA (self-signed)
 *   |                   |
 * leaf ------------------
 *   |
 * bad
 *
 * rootCA, interCA, subinterCA, subinterCA (ss) all have CA=TRUE
 * leaf and bad have CA=FALSE
 *
 * subinterCA and subinterCA (ss) have the same subject name and keys
 *
 * interCA (but not rootCA) and subinterCA (ss) are in the trusted store
 * (roots.pem)
 * leaf and subinterCA are in the untrusted list (untrusted.pem)
 * bad is the certificate being verified (bad.pem)
 *
 * Versions vulnerable to CVE-2015-1793 will fail to detect that leaf has
 * CA=FALSE, and will therefore incorrectly verify bad
 *
 */
static int test_alt_chains_cert_forgery(void)
{
    int ret = 0;
    int i;
    X509 *x = NULL;
    STACK_OF(X509) *untrusted = NULL;
    BIO *bio = NULL;
    X509_STORE_CTX *sctx = NULL;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (store == NULL)
        goto err;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto err;
    if (!X509_LOOKUP_load_file(lookup, roots_f, X509_FILETYPE_PEM))
        goto err;

    untrusted = load_certs_from_file(untrusted_f);

    if ((bio = BIO_new_file(bad_f, "r")) == NULL)
        goto err;

    if ((x = PEM_read_bio_X509(bio, NULL, 0, NULL)) == NULL)
        goto err;

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        goto err;

    if (!X509_STORE_CTX_init(sctx, store, x, untrusted))
        goto err;

    i = X509_verify_cert(sctx);

    if (i == 0 && X509_STORE_CTX_get_error(sctx) == X509_V_ERR_INVALID_CA) {
        /* This is the result we were expecting: Test passed */
        ret = 1;
    }
 err:
    X509_STORE_CTX_free(sctx);
    X509_free(x);
    BIO_free(bio);
    sk_X509_pop_free(untrusted, X509_free);
    X509_STORE_free(store);
    return ret;
}

static int test_store_ctx(void)
{
    X509_STORE_CTX *sctx = NULL;
    X509 *x = NULL;
    BIO *bio = NULL;
    int testresult = 0, ret;

    bio = BIO_new_file(bad_f, "r");
    if (bio == NULL)
        goto err;

    x = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (x == NULL)
        goto err;

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        goto err;

    if (!X509_STORE_CTX_init(sctx, NULL, x, NULL))
        goto err;

    /* Verifying a cert where we have no trusted certs should fail */
    ret = X509_verify_cert(sctx);

    if (ret == 0) {
        /* This is the result we were expecting: Test passed */
        testresult = 1;
    }

 err:
    X509_STORE_CTX_free(sctx);
    X509_free(x);
    BIO_free(bio);
    return testresult;
}

static int custom_get_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                 X509_NAME *name, X509_OBJECT *obj)
{
    X509 *x = X509_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    int ret = 0;

    if (!TEST_ptr(x)
            || !TEST_ptr(serial)
            || !TEST_true(ASN1_INTEGER_set_uint64(serial, (uint64_t)999))
            || !TEST_true(X509_set_serialNumber(x, serial))
            || !TEST_true(X509_OBJECT_set1_X509(obj, x)))
        goto err;

    ret = 1;
 err:
    X509_free(x);
    ASN1_INTEGER_free(serial);
    return ret;
}

static int test_custom_lookup(void)
{
    X509_LOOKUP_METHOD *meth = X509_LOOKUP_meth_new("custom");
    X509_STORE *store = X509_STORE_new();
    X509_NAME *name = X509_NAME_new();
    X509_OBJECT *obj = X509_OBJECT_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509 *x = NULL;
    const ASN1_INTEGER *serial = NULL;
    int testresult = 0;

    if (!TEST_ptr(store)
            || !TEST_ptr(meth)
            || !TEST_ptr(name)
            || !TEST_ptr(obj)
            || !TEST_ptr(ctx))
        goto err;

    if (!TEST_true(X509_LOOKUP_meth_set_get_by_subject(meth,
                                                       custom_get_by_subject))
            || !TEST_ptr(X509_STORE_add_lookup(store, meth))
            || !TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL))
            || !TEST_true(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, name,
                                                        obj))
            || !TEST_true(X509_OBJECT_get_type(obj) == X509_LU_X509)
            || !TEST_ptr(x = X509_OBJECT_get0_X509(obj))
            || !TEST_ptr(serial = X509_get0_serialNumber(x))
            || !TEST_long_eq(ASN1_INTEGER_get(serial), 999))
        goto err;

    testresult = 1;
 err:
    X509_LOOKUP_meth_free(meth);
    X509_STORE_free(store);
    X509_NAME_free(name);
    X509_OBJECT_free(obj);
    X509_STORE_CTX_free(ctx);
    return testresult;
}

#ifndef OPENSSL_NO_SM2
static int test_sm2_id(void)
{
    /* we only need an X509 structure, no matter if it's a real SM2 cert */
    X509 *x = NULL;
    BIO *bio = NULL;
    int ret = 0;
    ASN1_OCTET_STRING *v = NULL, *v2 = NULL;
    char *sm2id = "this is an ID";

    bio = BIO_new_file(bad_f, "r");
    if (bio == NULL)
        goto err;

    x = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (x == NULL)
        goto err;

    v = ASN1_OCTET_STRING_new();
    if (v == NULL)
        goto err;

    if (!ASN1_OCTET_STRING_set(v, (unsigned char *)sm2id, (int)strlen(sm2id))) {
        ASN1_OCTET_STRING_free(v);
        goto err;
    }

    X509_set0_sm2_id(x, v);

    v2 = X509_get0_sm2_id(x);
    if (!TEST_ptr(v2)
            || !TEST_int_eq(ASN1_OCTET_STRING_cmp(v, v2), 0))
        goto err;

    ret = 1;
 err:
    X509_free(x);
    BIO_free(bio);
    return ret;
}
#endif

OPT_TEST_DECLARE_USAGE("roots.pem untrusted.pem bad.pem\n")

int setup_tests(void)
{
    if (!TEST_ptr(roots_f = test_get_argument(0))
            || !TEST_ptr(untrusted_f = test_get_argument(1))
            || !TEST_ptr(bad_f = test_get_argument(2)))
        return 0;

    ADD_TEST(test_alt_chains_cert_forgery);
    ADD_TEST(test_store_ctx);
#ifndef OPENSSL_NO_SM2
    ADD_TEST(test_sm2_id);
#endif
    ADD_TEST(test_custom_lookup);

    return 1;
}
