/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

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
 * Verifies leaf against root-cert.pem with ca-cert.pem and
 * ca-cert-ec-named.pem untrusted, as a
 * server certificate, at check_time when it is not NULL, for host with
 * X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT when it is not NULL, and returns
 * the verification error.
 */
static int verify(X509 *leaf, unsigned long flags, const int64_t *check_time,
    const char *host)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *root = NULL, *ca = NULL, *ec_ca = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_VERIFY_PARAM *param;
    int ret = -1;

    if (!TEST_ptr(root = load_cert("root-cert.pem"))
        || !TEST_ptr(ca = load_cert("ca-cert.pem"))
        || !TEST_ptr(ec_ca = load_cert("ca-cert-ec-named.pem"))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, root))
        || !TEST_ptr(untrusted = sk_X509_new_null())
        || !TEST_true(sk_X509_push(untrusted, ca)))
        goto err;
    ca = NULL;
    if (!TEST_true(sk_X509_push(untrusted, ec_ca)))
        goto err;
    ec_ca = NULL;
    if (!TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, leaf, untrusted)))
        goto err;
    if (host != NULL) {
        param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_hostflags(param,
            X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(param, host, 0)))
            goto err;
    }
    X509_STORE_CTX_set_flags(ctx, flags);
    if (check_time != NULL)
        ossl_x509_verify_param_set_time_posix(X509_STORE_CTX_get0_param(ctx),
            *check_time);
    X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
    (void)X509_verify_cert(ctx);
    ret = X509_STORE_CTX_get_error(ctx);

err:
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, X509_free);
    X509_STORE_free(store);
    X509_free(root);
    X509_free(ca);
    X509_free(ec_ca);
    return ret;
}

static int test_strict_chain(void)
{
    X509 *leaf;
    int ret;

    ret = TEST_ptr(leaf = load_cert("ee-cert.pem"))
        && TEST_int_eq(verify(leaf, 0, NULL, NULL), X509_V_OK)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, NULL, NULL), X509_V_OK);
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
        || !TEST_int_eq(verify(leaf, 0, NULL, NULL), X509_V_OK)
        || !TEST_int_ne(verify(leaf, X509_V_FLAG_X509_STRICT, NULL, NULL), X509_V_OK))
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
        && TEST_int_eq(verify(leaf, 0, NULL, NULL), X509_V_OK)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, NULL, NULL),
            X509_V_ERR_INVALID_EXTENSION);
    X509_free(leaf);
    return ret;
}

static int test_strict_times(void)
{
    X509 *leaf;
    int64_t before = 0, after = INT64_C(253402300799);
    int ret;

    ret = TEST_ptr(leaf = load_cert("ee-cert.pem"))
        && TEST_int_eq(verify(leaf, 0, &before, NULL), X509_V_ERR_CERT_NOT_YET_VALID)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, &before, NULL),
            X509_V_ERR_CERT_NOT_YET_VALID)
        && TEST_int_eq(verify(leaf, 0, &after, NULL), X509_V_ERR_CERT_HAS_EXPIRED)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, &after, NULL),
            X509_V_ERR_CERT_HAS_EXPIRED);
    X509_free(leaf);
    return ret;
}

/*
 * ee-cert-ec-sha3-256.pem names server.example in its subject alone,
 * ee-cert.pem in its subjectAltName as well.
 */
static int test_strict_host(void)
{
    X509 *leaf = NULL, *cn_only = NULL;
    int ret;

    ret = TEST_ptr(leaf = load_cert("ee-cert.pem"))
        && TEST_ptr(cn_only = load_cert("ee-cert-ec-sha3-256.pem"))
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, NULL,
                           "server.example"),
            X509_V_OK)
        && TEST_int_eq(verify(leaf, X509_V_FLAG_X509_STRICT, NULL,
                           "other.example"),
            X509_V_ERR_HOSTNAME_MISMATCH)
        && TEST_int_eq(verify(cn_only, 0, NULL, "server.example"), X509_V_OK)
        && TEST_int_eq(verify(cn_only, X509_V_FLAG_X509_STRICT, NULL,
                           "server.example"),
            X509_V_ERR_HOSTNAME_MISMATCH);
    X509_free(leaf);
    X509_free(cn_only);
    return ret;
}

/* ee-cert.pem with the last octet of its signature changed. */
static X509 *load_bad_signature(void)
{
    X509 *x, *bad = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int der_len;

    if (!TEST_ptr(x = load_cert("ee-cert.pem"))
        || !TEST_int_gt(der_len = i2d_X509(x, &der), 0))
        goto err;
    der[der_len - 1] ^= 0x01;
    p = der;
    if (!TEST_ptr(bad = d2i_X509(NULL, &p, der_len))
        || !TEST_ptr(x509_get0_view(bad))) {
        X509_free(bad);
        bad = NULL;
    }

err:
    OPENSSL_free(der);
    X509_free(x);
    return bad;
}

static int test_strict_signature(void)
{
    X509 *pss = NULL, *bad = NULL;
    int ret;

    ret = TEST_ptr(pss = load_cert("ee-pss-sha256-cert.pem"))
        && TEST_int_eq(verify(pss, X509_V_FLAG_X509_STRICT, NULL, NULL),
            X509_V_OK)
        && TEST_ptr(bad = load_bad_signature())
        && TEST_int_eq(verify(bad, 0, NULL, NULL),
            X509_V_ERR_CERT_SIGNATURE_FAILURE)
        && TEST_int_eq(verify(bad, X509_V_FLAG_X509_STRICT, NULL, NULL),
            X509_V_ERR_CERT_SIGNATURE_FAILURE);
    X509_free(pss);
    X509_free(bad);
    return ret;
}

static X509_NAME *make_name(const char *cn, int type)
{
    X509_NAME *name;

    if (!TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", type,
            (const unsigned char *)cn, -1, -1, 0))) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

/*
 * A certificate for key with the names given, signed by sign_key, and a CA
 * certificate when ca is set.
 */
static X509 *make_cert(const X509_NAME *subject, const X509_NAME *issuer,
    EVP_PKEY *key, EVP_PKEY *sign_key, int ca)
{
    BASIC_CONSTRAINTS *bc = NULL;
    X509 *x;

    if (ca) {
        if (!TEST_ptr(bc = BASIC_CONSTRAINTS_new()))
            return NULL;
        bc->ca = 0xff;
    }
    if (!TEST_ptr(x = X509_new())
        || !TEST_true(X509_set_version(x, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(x), 1))
        || !TEST_true(X509_set_subject_name(x, subject))
        || !TEST_true(X509_set_issuer_name(x, issuer))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), -3600))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 3600))
        || !TEST_true(X509_set_pubkey(x, key))
        || (bc != NULL
            && !TEST_true(X509_add1_ext_i2d(x, NID_basic_constraints, bc, 1,
                0)))
        || !TEST_int_gt(X509_sign(x, sign_key, NULL), 0)) {
        X509_free(x);
        x = NULL;
    }
    BASIC_CONSTRAINTS_free(bc);
    return x;
}

static int verify_with_root(X509 *root, X509 *leaf, unsigned long flags)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int ret = -1;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, root))
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    X509_STORE_CTX_set_flags(ctx, flags);
    (void)X509_verify_cert(ctx);
    ret = X509_STORE_CTX_get_error(ctx);

err:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ret;
}

/*
 * The leaf names its issuer as a UTF8String, the root its subject as a
 * PrintableString with the same characters: equal as canonical names, not
 * as bytes.
 */
static int test_strict_issuer_bytes(void)
{
    EVP_PKEY *root_key = NULL, *leaf_key = NULL;
    X509_NAME *root_name = NULL, *utf8_name = NULL, *leaf_name = NULL;
    X509 *root = NULL, *leaf = NULL;
    int ret = 0;

    if (!TEST_ptr(root_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))
        || !TEST_ptr(leaf_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))
        || !TEST_ptr(root_name = make_name("View Root",
                         V_ASN1_PRINTABLESTRING))
        || !TEST_ptr(utf8_name = make_name("View Root", V_ASN1_UTF8STRING))
        || !TEST_ptr(leaf_name = make_name("View Leaf", V_ASN1_UTF8STRING))
        || !TEST_ptr(root = make_cert(root_name, root_name, root_key,
                         root_key, 1))
        || !TEST_ptr(leaf = make_cert(leaf_name, utf8_name, leaf_key,
                         root_key, 0))
        || !TEST_int_eq(verify_with_root(root, leaf, 0), X509_V_OK)
        || !TEST_int_eq(verify_with_root(root, leaf, X509_V_FLAG_X509_STRICT),
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
        goto err;
    ret = 1;

err:
    X509_free(root);
    X509_free(leaf);
    X509_NAME_free(root_name);
    X509_NAME_free(utf8_name);
    X509_NAME_free(leaf_name);
    EVP_PKEY_free(root_key);
    EVP_PKEY_free(leaf_key);
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
    ADD_TEST(test_strict_times);
    ADD_TEST(test_strict_host);
    ADD_TEST(test_strict_signature);
    ADD_TEST(test_strict_issuer_bytes);
    return 1;
}
