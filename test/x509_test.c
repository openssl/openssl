/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED /* EVP_PKEY_get1/set1_RSA */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include "crypto/x509.h" /* x509_st definition */
#include "testutil.h"

static EVP_PKEY *pubkey = NULL;
static EVP_PKEY *privkey = NULL;
static EVP_MD *signmd = NULL;

/* EC key pair used for signing */
static const unsigned char privkeydata[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x7d, 0x2b, 0xfe, 0x5c, 0xcb, 0xcb, 0x27, 0xd6, 0x28,
    0xfe, 0x98, 0x34, 0x84, 0x4a, 0x13, 0x6f, 0x70, 0xc4, 0x1a, 0x0b, 0xfc, 0xde, 0xb0, 0xb2, 0x32,
    0xb1, 0xdd, 0x4f, 0x0e, 0xbc, 0xdf, 0x89, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b, 0x19, 0x43,
    0x45, 0x6b, 0xd4, 0x50, 0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23, 0x7a, 0x3b,
    0x48, 0x23, 0xe2, 0x2a, 0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e, 0x7c, 0x8d,
    0xfc, 0x08, 0x46, 0x37, 0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a, 0x6b, 0x7a,
    0x0b, 0xe4, 0xe8, 0x9c, 0x4a, 0xbb, 0xbf, 0x09, 0x4d
};

static const unsigned char pubkeydata[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b,
    0x19, 0x43, 0x45, 0x6b, 0xd4, 0x50, 0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23,
    0x7a, 0x3b, 0x48, 0x23, 0xe2, 0x2a, 0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e,
    0x7c, 0x8d, 0xfc, 0x08, 0x46, 0x37, 0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a,
    0x6b, 0x7a, 0x0b, 0xe4, 0xe8, 0x9c, 0x4a, 0xbb, 0xbf, 0x09, 0x4d
};

/* Self signed cert using ECDSA-SHA256 with the keypair listed above */
static const unsigned char certdata[] = {
    0x30, 0x82, 0x01, 0x86, 0x30, 0x82, 0x01, 0x2d, 0x02, 0x14, 0x75, 0xd6, 0x04, 0xd2, 0x80, 0x61,
    0xd3, 0x32, 0xbc, 0xae, 0x38, 0x58, 0xfe, 0x12, 0x42, 0x81, 0x7a, 0xdd, 0x0b, 0x99, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74,
    0x64, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x31, 0x30, 0x31, 0x32, 0x30, 0x37, 0x32, 0x37, 0x35,
    0x35, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x35, 0x30, 0x30, 0x32, 0x32, 0x37, 0x30, 0x37, 0x32, 0x37,
    0x35, 0x35, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d,
    0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69,
    0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b, 0x19, 0x43, 0x45, 0x6b, 0xd4, 0x50,
    0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23, 0x7a, 0x3b, 0x48, 0x23, 0xe2, 0x2a,
    0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e, 0x7c, 0x8d, 0xfc, 0x08, 0x46, 0x37,
    0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a, 0x6b, 0x7a, 0x0b, 0xe4, 0xe8, 0x9c,
    0x4a, 0xbb, 0xbf, 0x09, 0x4d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x5f, 0x45, 0x7f, 0xa4, 0x6a, 0x03, 0xfd, 0xe7,
    0xf3, 0x42, 0x43, 0x38, 0x5b, 0x81, 0x08, 0x1a, 0x47, 0x8e, 0x59, 0x3a, 0x28, 0x5b, 0x97, 0x67,
    0x47, 0x66, 0x2a, 0x16, 0xf5, 0xce, 0xf5, 0x92, 0x02, 0x20, 0x22, 0x0e, 0xab, 0x35, 0xdf, 0x49,
    0xb1, 0x86, 0xa3, 0x3b, 0x26, 0xda, 0x7e, 0x8b, 0x44, 0x45, 0xc6, 0x46, 0x14, 0x04, 0x22, 0x2b,
    0xe5, 0x2a, 0x62, 0x84, 0xc5, 0x94, 0xa0, 0x1b, 0xaa, 0xa9
};

/* Some simple CRL data */
static const unsigned char crldata[] = {
    0x30, 0x81, 0x8B, 0x30, 0x31, 0x02, 0x01, 0x01, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x54, 0x65, 0x73, 0x74, 0x17, 0x0D, 0x32, 0x32, 0x31, 0x30, 0x31, 0x32, 0x30,
    0x35, 0x33, 0x34, 0x30, 0x31, 0x5A, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x75, 0xAC, 0xA9, 0xB5, 0xFE,
    0x63, 0x09, 0x8B, 0x57, 0x4F, 0xBB, 0xC6, 0x0C, 0xA9, 0x9A, 0x7C, 0x55, 0x89, 0xF9, 0x9C, 0x48,
    0xE9, 0xF3, 0xED, 0xE5, 0xC2, 0x88, 0xCE, 0xEC, 0xB1, 0x51, 0xF1, 0x02, 0x21, 0x00, 0x8B, 0x93,
    0xC5, 0xA6, 0x28, 0x48, 0x5A, 0x4E, 0x10, 0x52, 0x82, 0x12, 0x2F, 0xC4, 0x62, 0x2D, 0x3F, 0x5A,
    0x62, 0x7F, 0x9D, 0x1B, 0x12, 0xC5, 0x36, 0x25, 0x73, 0x03, 0xF4, 0xDE, 0x62, 0x24
};

/*
 * Test for Regression discussed in PR #19388
 * In order for this simple test to fail, it requires the digest used for
 * signing to be different from the alg within the loaded cert.
 */
static int test_x509_tbs_cache(void)
{
    int ret;
    X509 *x = NULL;
    const unsigned char *p = certdata;

    ret = TEST_ptr(x = d2i_X509(NULL, &p, sizeof(certdata)))
        && TEST_int_gt(X509_sign(x, privkey, signmd), 0)
        && TEST_int_eq(X509_verify(x, pubkey), 1);
    X509_free(x);
    return ret;
}

static int test_x509_verify_with_new(void)
{
    int ret;
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL;

    ret = TEST_ptr(x = X509_new())
        && TEST_ptr(pkey = EVP_PKEY_new())
        && TEST_int_eq(X509_verify(x, pkey), -1)
        && TEST_int_eq(X509_verify(x, pubkey), -1);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ret;
}

static int add_name_entry(X509_NAME *name, int nid, const char *value)
{
    return X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
        (const unsigned char *)value,
        -1, -1, 0);
}

static X509_NAME *make_store_test_name(const char *common_name)
{
    X509_NAME *name = NULL;

    if (!TEST_ptr(name = X509_NAME_new())
        || !TEST_true(add_name_entry(name, NID_commonName, common_name))) {
        X509_NAME_free(name);
        return NULL;
    }

    return name;
}

static X509 *make_store_test_cert(const X509_NAME *name, long serial)
{
    X509 *x = NULL;

    if (!TEST_ptr(x = X509_new())
        || !TEST_int_eq(X509_set_version(x, X509_VERSION_3), 1)
        || !TEST_int_eq(ASN1_INTEGER_set(X509_get_serialNumber(x), serial), 1)
        || !TEST_int_eq(X509_set_subject_name(x, name), 1)
        || !TEST_int_eq(X509_set_issuer_name(x, name), 1)
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600))
        || !TEST_int_eq(X509_set_pubkey(x, pubkey), 1)
        || !TEST_int_gt(X509_sign(x, privkey, signmd), 0)) {
        X509_free(x);
        return NULL;
    }

    return x;
}

static X509_CRL *roundtrip_crl(X509_CRL *crl)
{
    unsigned char *der = NULL;
    const unsigned char *q = NULL;
    int derlen;
    X509_CRL *ret = NULL;

    derlen = i2d_X509_CRL(crl, &der);
    if (derlen <= 0 || der == NULL)
        goto end;

    q = der;
    ret = d2i_X509_CRL(NULL, &q, derlen);

end:
    OPENSSL_free(der);
    X509_CRL_free(crl);
    return ret;
}

/*
 * Build and sign a CRL without serializing it: no cached DER encoding and
 * no cached SHA1 fingerprint.
 */
static X509_CRL *make_store_test_crl_raw(const X509_NAME *issuer, int number)
{
    X509_CRL *crl = NULL, *ret = NULL;
    ASN1_INTEGER *crl_number = NULL;
    ASN1_TIME *last_update = NULL;
    ASN1_TIME *next_update = NULL;

    if (!TEST_ptr(crl = X509_CRL_new())
        || !TEST_ptr(crl_number = ASN1_INTEGER_new())
        || !TEST_ptr(last_update = ASN1_TIME_new())
        || !TEST_ptr(next_update = ASN1_TIME_new())
        || !TEST_int_eq(ASN1_INTEGER_set(crl_number, number), 1)
        || !TEST_int_eq(ASN1_TIME_set_string(last_update, "20240101000000Z"), 1)
        || !TEST_int_eq(ASN1_TIME_set_string(next_update, "20250101000000Z"), 1)
        || !TEST_int_eq(X509_CRL_set_version(crl, X509_CRL_VERSION_2), 1)
        || !TEST_int_eq(X509_CRL_set_issuer_name(crl, issuer), 1)
        || !TEST_int_eq(X509_CRL_set1_lastUpdate(crl, last_update), 1)
        || !TEST_int_eq(X509_CRL_set1_nextUpdate(crl, next_update), 1)
        || !TEST_int_eq(X509_CRL_add1_ext_i2d(crl, NID_crl_number,
                            crl_number, 0, 0),
            1)
        || !TEST_int_gt(X509_CRL_sign(crl, privkey, signmd), 0))
        goto err;

    ret = crl;
    crl = NULL;

err:
    X509_CRL_free(crl);
    ASN1_INTEGER_free(crl_number);
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    return ret;
}

static X509_CRL *make_store_test_crl(const X509_NAME *issuer, int number)
{
    X509_CRL *crl = make_store_test_crl_raw(issuer, number);

    return crl != NULL ? roundtrip_crl(crl) : NULL;
}

static int check_store_object_count(X509_STORE *store, int expected_certs,
    int expected_crls)
{
    int i, certs = 0, crls = 0, ret = 0;
    STACK_OF(X509_OBJECT) *objs = NULL;

    if (!TEST_ptr(objs = X509_STORE_get1_objects(store))
        || !TEST_true(sk_X509_OBJECT_is_sorted(objs)))
        goto err;

    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        const X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);

        switch (X509_OBJECT_get_type(obj)) {
        case X509_LU_X509:
            certs++;
            break;
        case X509_LU_CRL:
            crls++;
            break;
        default:
            break;
        }
    }

    ret = TEST_int_eq(certs, expected_certs)
        && TEST_int_eq(crls, expected_crls)
        && TEST_int_eq(sk_X509_OBJECT_num(objs), expected_certs + expected_crls);

err:
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    return ret;
}

static int test_x509_store_add_duplicate_crls(void)
{
    int i, ret = 0;
    X509_STORE *store = NULL;
    X509_NAME *issuer = NULL;
    X509 *cert = NULL;
    X509_CRL *crls[4] = { NULL, NULL, NULL, NULL };

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(issuer = make_store_test_name("Store Test Issuer"))
        || !TEST_ptr(cert = make_store_test_cert(issuer, 1)))
        goto err;

    for (i = 0; i < 4; i++)
        if (!TEST_ptr(crls[i] = make_store_test_crl(issuer, i + 1)))
            goto err;

    if (!TEST_true(X509_STORE_add_crl(store, crls[0]))
        || !TEST_true(X509_STORE_add_cert(store, cert))
        || !TEST_true(X509_STORE_add_crl(store, crls[1]))
        || !TEST_true(X509_STORE_add_crl(store, crls[2]))
        || !TEST_true(X509_STORE_add_crl(store, crls[3]))
        || !check_store_object_count(store, 1, 4))
        goto err;

    for (i = 0; i < 4; i++) {
        if (!TEST_true(X509_STORE_add_crl(store, crls[i]))
            || !check_store_object_count(store, 1, 4))
            goto err;
    }

    ret = 1;

err:
    X509_STORE_free(store);
    X509_NAME_free(issuer);
    X509_free(cert);
    for (i = 0; i < 4; i++)
        X509_CRL_free(crls[i]);
    return ret;
}

/*
 * A cert taken straight from the builder carries no cached DER encoding, while
 * the same cert decoded from its DER does. Both live in the default,
 * SHA1-capable library context, so they are fingerprinted and X509_cmp() folds
 * them. The store must fold them too, regardless of add order: its content
 * ordering must not treat encoding availability as a key, or one genuine cert
 * ends up stored as two objects.
 */
static int test_x509_store_dup_cert_cached_vs_uncached(void)
{
    int ret = 0;
    X509 *built = NULL, *decoded = NULL;
    X509_NAME *name = NULL;
    X509_STORE *store = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen;

    if (!TEST_ptr(name = make_store_test_name("Store Test Subject"))
        || !TEST_ptr(built = make_store_test_cert(name, 1))
        || !TEST_int_gt(derlen = i2d_X509(built, &der), 0))
        goto err;
    p = der;
    if (!TEST_ptr(decoded = d2i_X509(NULL, &p, derlen)))
        goto err;

    (void)X509_check_purpose(built, -1, 0);
    (void)X509_check_purpose(decoded, -1, 0);

    /* Both are fingerprinted and identical: OpenSSL's canonical cmp folds them. */
    if (!TEST_int_eq(built->ex_flags & EXFLAG_NO_FINGERPRINT, 0)
        || !TEST_int_eq(decoded->ex_flags & EXFLAG_NO_FINGERPRINT, 0)
        || !TEST_int_eq(X509_cmp(built, decoded), 0))
        goto err;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, built))
        || !TEST_true(X509_STORE_add_cert(store, decoded))
        || !check_store_object_count(store, 1, 0))
        goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    X509_free(decoded);
    X509_free(built);
    OPENSSL_free(der);
    X509_NAME_free(name);
    return ret;
}

/*
 * CRLs that were never DER-serialized have no cached SHA1 fingerprint (and
 * no EXFLAG_NO_FINGERPRINT either) and no cached encoding. The store must
 * still tell distinct CRLs apart via their signature bits instead of
 * silently dropping them as duplicates, while re-adding the same object is
 * still detected as a duplicate.
 */
static int test_x509_store_distinct_crls_no_enc_cache(void)
{
    int i, ret = 0;
    X509_STORE *store = NULL;
    X509_NAME *issuer = NULL;
    X509_CRL *crls[3] = { NULL, NULL, NULL };

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(issuer = make_store_test_name("Store Test Issuer")))
        goto err;

    for (i = 0; i < 3; i++)
        if (!TEST_ptr(crls[i] = make_store_test_crl_raw(issuer, i + 1))
            || !TEST_true(X509_STORE_add_crl(store, crls[i])))
            goto err;

    if (!check_store_object_count(store, 0, 3))
        goto err;

    for (i = 0; i < 3; i++)
        if (!TEST_true(X509_STORE_add_crl(store, crls[i]))
            || !check_store_object_count(store, 0, 3))
            goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    X509_NAME_free(issuer);
    for (i = 0; i < 3; i++)
        X509_CRL_free(crls[i]);
    return ret;
}

/*
 * Two X509 objects with identical DER but living in different library
 * contexts: one in the default (SHA1-capable) context and one in a context
 * with only the "base" provider loaded, so its SHA1 fingerprint cannot be
 * computed and EXFLAG_NO_FINGERPRINT is set.
 */
static int test_x509_store_dup_cert_mixed_libctx(void)
{
    int ret = 0;
    OSSL_LIB_CTX *no_sha1_ctx = NULL;
    OSSL_PROVIDER *base = NULL;
    X509 *normal = NULL, *no_sha1 = NULL;
    X509_STORE *store = NULL;
    const unsigned char *p;

    if (!TEST_ptr(no_sha1_ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(base = OSSL_PROVIDER_load(no_sha1_ctx, "base")))
        goto err;

    p = certdata;
    if (!TEST_ptr(normal = d2i_X509(NULL, &p, sizeof(certdata)))
        || !TEST_ptr(no_sha1 = X509_new_ex(no_sha1_ctx, NULL)))
        goto err;
    p = certdata;
    if (!TEST_ptr(d2i_X509(&no_sha1, &p, sizeof(certdata))))
        goto err;

    /* Populate the extension/fingerprint cache in each object's libctx. */
    (void)X509_check_purpose(no_sha1, -1, 0);
    (void)X509_check_purpose(normal, -1, 0);

    /*
     * The base-only context cannot hash, so no fingerprint is cached for
     * no_sha1, whereas normal has one.
     */
    if (!TEST_int_ne(no_sha1->ex_flags & EXFLAG_NO_FINGERPRINT, 0)
        || !TEST_int_eq(normal->ex_flags & EXFLAG_NO_FINGERPRINT, 0))
        goto err;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, no_sha1))
        || !TEST_true(X509_STORE_add_cert(store, normal))
        || !check_store_object_count(store, 1, 0))
        goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    X509_free(no_sha1);
    X509_free(normal);
    OSSL_PROVIDER_unload(base);
    OSSL_LIB_CTX_free(no_sha1_ctx);
    return ret;
}

/*
 * As test_x509_store_dup_cert_mixed_libctx, but with a per-name object list
 * deep enough for the binary-search duplicate detection to actually branch.
 *
 * X509_cmp() orders two fingerprinted certs by their SHA1 hash yet falls back
 * to the DER encoding as soon as one cert lacks a fingerprint. Mixing the two
 * orderings is not transitive: a fingerprinted cert A and its fingerprint-less
 * duplicate A' encode identically (A == A'), while a third fingerprinted cert B
 * can satisfy A < B by hash but B < A' by encoding. With only two objects the
 * search never compares against a third cert and the inconsistency stays
 * hidden; here many certs share one subject name, so the sorted bucket is deep
 * enough that a fingerprint-less duplicate can be stepped past and added twice.
 * Regression test for PR #31909.
 */
static int test_x509_store_dup_cert_mixed_libctx_bucket(void)
{
#define STORE_MIXED_CERTS 48
    int i, ret = 0;
    OSSL_LIB_CTX *no_sha1_ctx = NULL;
    OSSL_PROVIDER *base = NULL;
    X509_NAME *name = NULL;
    X509 *normal[STORE_MIXED_CERTS] = { NULL };
    X509 *no_sha1[STORE_MIXED_CERTS] = { NULL };
    X509_STORE *store = NULL;

    if (!TEST_ptr(no_sha1_ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(base = OSSL_PROVIDER_load(no_sha1_ctx, "base"))
        || !TEST_ptr(name = make_store_test_name("Store Test Subject")))
        goto err;

    /*
     * All certs share one subject name (only the serial differs) so they land
     * in a single per-name object list, but each has distinct DER. Decode a
     * fingerprinted copy in the default context and a fingerprint-less copy in
     * the base-only context from the same DER.
     */
    for (i = 0; i < STORE_MIXED_CERTS; i++) {
        X509 *tmp = NULL;
        unsigned char *der = NULL;
        const unsigned char *p;
        int derlen = 0, ok;

        ok = TEST_ptr(tmp = make_store_test_cert(name, i + 1))
            && TEST_int_gt(derlen = i2d_X509(tmp, &der), 0);
        if (ok) {
            p = der;
            ok = TEST_ptr(normal[i] = d2i_X509(NULL, &p, derlen))
                && TEST_ptr(no_sha1[i] = X509_new_ex(no_sha1_ctx, NULL));
        }
        if (ok) {
            p = der;
            ok = TEST_ptr(d2i_X509(&no_sha1[i], &p, derlen));
        }
        X509_free(tmp);
        OPENSSL_free(der);
        if (!ok)
            goto err;

        (void)X509_check_purpose(normal[i], -1, 0);
        (void)X509_check_purpose(no_sha1[i], -1, 0);
        if (!TEST_int_eq(normal[i]->ex_flags & EXFLAG_NO_FINGERPRINT, 0)
            || !TEST_int_ne(no_sha1[i]->ex_flags & EXFLAG_NO_FINGERPRINT, 0))
            goto err;
    }

    /* Fill the bucket with the fingerprinted certs. */
    if (!TEST_ptr(store = X509_STORE_new()))
        goto err;
    for (i = 0; i < STORE_MIXED_CERTS; i++)
        if (!TEST_true(X509_STORE_add_cert(store, normal[i])))
            goto err;
    if (!check_store_object_count(store, STORE_MIXED_CERTS, 0))
        goto err;

    /*
     * Each fingerprint-less copy duplicates a cert already in the bucket, so
     * the object count must stay unchanged. A duplicate that slips past the
     * search is still added (X509_STORE_add_cert() reports success either way),
     * so only the count exposes the miss.
     */
    for (i = 0; i < STORE_MIXED_CERTS; i++)
        if (!TEST_true(X509_STORE_add_cert(store, no_sha1[i])))
            goto err;
    if (!check_store_object_count(store, STORE_MIXED_CERTS, 0))
        goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    for (i = 0; i < STORE_MIXED_CERTS; i++) {
        X509_free(normal[i]);
        X509_free(no_sha1[i]);
    }
    X509_NAME_free(name);
    OSSL_PROVIDER_unload(base);
    OSSL_LIB_CTX_free(no_sha1_ctx);
    return ret;
#undef STORE_MIXED_CERTS
}

/*
 * The CRL counterpart of test_x509_store_dup_cert_mixed_libctx: the same CRL
 * DER decoded in the default (SHA1-capable) context and in a base-only context
 * that cannot compute its SHA1 fingerprint (EXFLAG_NO_FINGERPRINT). Unlike
 * X509_cmp(), X509_CRL_match() does not fall back and reports -2 when a
 * fingerprint is missing, so the store's ordering must use the cached encoding
 * to still fold the two identical CRLs into a single object. Regression test
 * for PR #31909.
 */
static int test_x509_store_dup_crl_mixed_libctx(void)
{
    int ret = 0;
    OSSL_LIB_CTX *no_sha1_ctx = NULL;
    OSSL_PROVIDER *base = NULL;
    X509_NAME *issuer = NULL;
    X509_CRL *raw = NULL, *sha1_crl = NULL, *no_sha1_crl = NULL;
    X509_STORE *store = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen;

    if (!TEST_ptr(no_sha1_ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(base = OSSL_PROVIDER_load(no_sha1_ctx, "base"))
        || !TEST_ptr(issuer = make_store_test_name("Store Test Issuer"))
        || !TEST_ptr(raw = make_store_test_crl_raw(issuer, 1))
        || !TEST_int_gt(derlen = i2d_X509_CRL(raw, &der), 0))
        goto err;

    p = der;
    if (!TEST_ptr(sha1_crl = d2i_X509_CRL(NULL, &p, derlen))
        || !TEST_ptr(no_sha1_crl = X509_CRL_new_ex(no_sha1_ctx, NULL)))
        goto err;
    p = der;
    if (!TEST_ptr(d2i_X509_CRL(&no_sha1_crl, &p, derlen)))
        goto err;
    ERR_clear_error();

    /*
     * The fingerprint is cached at decode time, so the base-only context
     * leaves no_sha1_crl without one whereas sha1_crl has one.
     */
    if (!TEST_int_ne(no_sha1_crl->flags & EXFLAG_NO_FINGERPRINT, 0)
        || !TEST_int_eq(sha1_crl->flags & EXFLAG_NO_FINGERPRINT, 0))
        goto err;

    /* X509_CRL_match() cannot compare them and returns its error value. */
    if (!TEST_int_eq(X509_CRL_match(no_sha1_crl, sha1_crl), -2))
        goto err;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_crl(store, sha1_crl))
        || !TEST_true(X509_STORE_add_crl(store, no_sha1_crl))
        || !check_store_object_count(store, 0, 1))
        goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    X509_CRL_free(no_sha1_crl);
    X509_CRL_free(sha1_crl);
    X509_CRL_free(raw);
    OPENSSL_free(der);
    X509_NAME_free(issuer);
    OSSL_PROVIDER_unload(base);
    OSSL_LIB_CTX_free(no_sha1_ctx);
    return ret;
}

#ifndef OPENSSL_NO_DEPRECATED_4_0
/*
 * X509_STORE_get0_objects() switches the store to the legacy global object
 * stack. Verify get1_certs/get1_crls still filter by subject/issuer there and
 * do not return objects with other names.
 */
static int test_x509_store_get1_by_name_after_get0_objects(void)
{
    int ret = 0;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_NAME *name1 = NULL, *name2 = NULL;
    X509 *cert1 = NULL, *cert2 = NULL;
    X509_CRL *crl1 = NULL, *crl2 = NULL;
    STACK_OF(X509_OBJECT) *objs = NULL;
    STACK_OF(X509) *certs = NULL;
    STACK_OF(X509_CRL) *crls = NULL;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_ptr(name1 = make_store_test_name("A Store Test Issuer"))
        || !TEST_ptr(name2 = make_store_test_name("Z Store Test Issuer"))
        || !TEST_ptr(cert1 = make_store_test_cert(name1, 11))
        || !TEST_ptr(cert2 = make_store_test_cert(name2, 12))
        || !TEST_ptr(crl1 = make_store_test_crl(name1, 11))
        || !TEST_ptr(crl2 = make_store_test_crl(name2, 12)))
        goto err;

    /* Force the deprecated global-stack representation. */
    if (!TEST_ptr(objs = X509_STORE_get0_objects(store))
        || !TEST_int_eq(sk_X509_OBJECT_num(objs), 0)
        || !TEST_true(X509_STORE_add_cert(store, cert1))
        || !TEST_true(X509_STORE_add_cert(store, cert2))
        || !TEST_true(X509_STORE_add_crl(store, crl1))
        || !TEST_true(X509_STORE_add_crl(store, crl2))
        || !TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL))
        || !TEST_ptr(certs = X509_STORE_CTX_get1_certs(ctx, name1))
        || !TEST_int_eq(sk_X509_num(certs), 1)
        || !TEST_ptr(crls = X509_STORE_CTX_get1_crls(ctx, name1))
        || !TEST_int_eq(sk_X509_CRL_num(crls), 1))
        goto err;

    ret = 1;

err:
    OSSL_STACK_OF_X509_free(certs);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_NAME_free(name1);
    X509_NAME_free(name2);
    X509_free(cert1);
    X509_free(cert2);
    X509_CRL_free(crl1);
    X509_CRL_free(crl2);
    return ret;
}

/*
 * X509_STORE_get0_objects() merges the per-name object lists into the legacy
 * global stack and re-sorts it with the (type, name) comparator. Duplicate
 * detection on later additions must still work on that stack, in particular
 * within runs of objects sharing a subject name, whose relative order the
 * re-sort need not preserve. Use several names, each with several certs, so
 * the merged stack is not already sorted and the re-sort actually runs.
 */
static int test_x509_store_no_dups_after_get0_objects(void)
{
#define STORE_TEST_NAMES 8
#define STORE_TEST_CERTS_PER_NAME 8
#define STORE_TEST_CERTS (STORE_TEST_NAMES * STORE_TEST_CERTS_PER_NAME)
    int i, j, ret = 0;
    char cn[sizeof("Store Test Subject 00")];
    X509_STORE *store = NULL;
    X509_NAME *names[STORE_TEST_NAMES] = { NULL };
    X509 *certs[STORE_TEST_CERTS] = { NULL };

    if (!TEST_ptr(store = X509_STORE_new()))
        goto err;

    for (i = 0; i < STORE_TEST_NAMES; i++) {
        BIO_snprintf(cn, sizeof(cn), "Store Test Subject %02d", i);
        if (!TEST_ptr(names[i] = make_store_test_name(cn)))
            goto err;
        for (j = 0; j < STORE_TEST_CERTS_PER_NAME; j++) {
            X509 **cert = &certs[i * STORE_TEST_CERTS_PER_NAME + j];

            if (!TEST_ptr(*cert = make_store_test_cert(names[i],
                              i * 1000 + j + 1))
                || !TEST_true(X509_STORE_add_cert(store, *cert)))
                goto err;
        }
    }
    if (!check_store_object_count(store, STORE_TEST_CERTS, 0))
        goto err;

    /* Switch to the global-stack representation. */
    if (!TEST_ptr(X509_STORE_get0_objects(store)))
        goto err;

    /* Re-adding every cert must be detected as a duplicate. */
    for (i = 0; i < STORE_TEST_CERTS; i++)
        if (!TEST_true(X509_STORE_add_cert(store, certs[i])))
            goto err;

    ret = check_store_object_count(store, STORE_TEST_CERTS, 0);

err:
    X509_STORE_free(store);
    for (i = 0; i < STORE_TEST_NAMES; i++)
        X509_NAME_free(names[i]);
    for (i = 0; i < STORE_TEST_CERTS; i++)
        X509_free(certs[i]);
    return ret;
}
#endif

/*
 * Test for Regression discussed in PR #19388
 * In order for this simple test to fail, it requires the digest used for
 * signing to be different from the alg within the loaded cert.
 */
static int test_x509_crl_tbs_cache(void)
{
    int ret;
    X509_CRL *crl = NULL;
    const unsigned char *p = crldata;

    ret = TEST_ptr(crl = d2i_X509_CRL(NULL, &p, sizeof(crldata)))
        && TEST_int_gt(X509_CRL_sign(crl, privkey, signmd), 0)
        && TEST_int_eq(X509_CRL_verify(crl, pubkey), 1);

    X509_CRL_free(crl);
    return ret;
}

static int test_asn1_item_verify(void)
{
    int ret = 0;
    BIO *bio = NULL;
    X509 *x509 = NULL;
    const char *certfile;
    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *alg = NULL;
    EVP_PKEY *pkey;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    RSA *rsa = NULL;
#endif

    if (!TEST_ptr(certfile = test_get_argument(0))
        || !TEST_ptr(bio = BIO_new_file(certfile, "r"))
        || !TEST_ptr(x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL))
        || !TEST_ptr(pkey = X509_get0_pubkey(x509)))
        goto err;

#ifndef OPENSSL_NO_DEPRECATED_3_0
    /* Issue #24575 requires legacy key but the test is useful anyway */
    if (!TEST_ptr(rsa = EVP_PKEY_get1_RSA(pkey)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_set1_RSA(pkey, rsa), 0))
        goto err;
#endif

    X509_get0_signature(&sig, &alg, x509);

    if (!TEST_int_gt(ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF),
                         alg, sig,
                         &x509->cert_info, pkey),
            0))
        goto err;

    ERR_set_mark();
    if (!TEST_int_lt(ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF),
                         alg, sig,
                         NULL, pkey),
            0)) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    ret = 1;

err:
#ifndef OPENSSL_NO_DEPRECATED_3_0
    RSA_free(rsa);
#endif
    X509_free(x509);
    BIO_free(bio);
    return ret;
}

static int test_x509_delete_last_extension(void)
{
    int ret = 0;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;

    if (!TEST_ptr((x509 = X509_new()))
        /* Initially, there are no extensions and thus no extension list. */
        || !TEST_ptr_null(X509_get0_extensions(x509))
        /* Add an extension. */
        || !TEST_ptr((ext = X509_EXTENSION_new()))
        || !TEST_ptr((obj = OBJ_nid2obj(NID_subject_key_identifier)))
        || !TEST_int_eq(X509_EXTENSION_set_object(ext, obj), 1)
        || !TEST_int_eq(X509_add_ext(x509, ext, -1), 1)
        /* There should now be an extension list. */
        || !TEST_ptr(X509_get0_extensions(x509))
        || !TEST_int_eq(sk_X509_EXTENSION_num(X509_get0_extensions(x509)), 1))
        goto err;

    /* Delete the extension. */
    X509_EXTENSION_free(X509_delete_ext(x509, 0));

    /* The extension list should be NULL again. */
    if (!TEST_ptr_null(X509_get0_extensions(x509)))
        goto err;

    ret = 1;

err:
    X509_free(x509);
    X509_EXTENSION_free(ext);
    return ret;
}

static int test_x509_crl_delete_last_extension(void)
{
    int ret = 0;
    X509_CRL *crl = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;

    if (!TEST_ptr((crl = X509_CRL_new()))
        /* Initially, there are no extensions and thus no extension list. */
        || !TEST_ptr_null(X509_CRL_get0_extensions(crl))
        /* Add an extension. */
        || !TEST_ptr((ext = X509_EXTENSION_new()))
        || !TEST_ptr((obj = OBJ_nid2obj(NID_subject_key_identifier)))
        || !TEST_int_eq(X509_EXTENSION_set_object(ext, obj), 1)
        || !TEST_int_eq(X509_CRL_add_ext(crl, ext, -1), 1)
        /* There should now be an extension list. */
        || !TEST_ptr(X509_CRL_get0_extensions(crl))
        || !TEST_int_eq(sk_X509_EXTENSION_num(X509_CRL_get0_extensions(crl)),
            1))
        goto err;

    /* Delete the extension. */
    X509_EXTENSION_free(X509_CRL_delete_ext(crl, 0));

    /* The extension list should be NULL again. */
    if (!TEST_ptr_null(X509_CRL_get0_extensions(crl)))
        goto err;

    ret = 1;

err:
    X509_CRL_free(crl);
    X509_EXTENSION_free(ext);
    return ret;
}

static int test_x509_revoked_delete_last_extension(void)
{
    int ret = 0;
    X509_REVOKED *rev = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;

    if (!TEST_ptr((rev = X509_REVOKED_new()))
        /* Initially, there are no extensions and thus no extension list. */
        || !TEST_ptr_null(X509_REVOKED_get0_extensions(rev))
        /* Add an extension. */
        || !TEST_ptr((ext = X509_EXTENSION_new()))
        || !TEST_ptr((obj = OBJ_nid2obj(NID_subject_key_identifier)))
        || !TEST_int_eq(X509_EXTENSION_set_object(ext, obj), 1)
        || !TEST_int_eq(X509_REVOKED_add_ext(rev, ext, -1), 1)
        /* There should now be an extension list. */
        || !TEST_ptr(X509_REVOKED_get0_extensions(rev))
        || !TEST_int_eq(sk_X509_EXTENSION_num(X509_REVOKED_get0_extensions(rev)), 1))
        goto err;

    /* Delete the extension. */
    X509_EXTENSION_free(X509_REVOKED_delete_ext(rev, 0));

    /* The extension list should be NULL again. */
    if (!TEST_ptr_null(X509_REVOKED_get0_extensions(rev)))
        goto err;

    ret = 1;

err:
    X509_REVOKED_free(rev);
    X509_EXTENSION_free(ext);
    return ret;
}

static int test_drop_empty_cert_keyids(void)
{
    static const unsigned char commonName[] = "test";
    BIO *bio = NULL;
    CONF *conf = NULL;
    X509 *x = NULL;
    X509_NAME *subject = NULL;
    X509_NAME_ENTRY *name_entry = NULL;
    X509_EXTENSION *ext = NULL;
    const STACK_OF(X509_EXTENSION) *exts;
    X509V3_CTX ctx;
    int ret = 0;

    if (!TEST_ptr(x = X509_new())
        || !TEST_int_eq(X509_set_version(x, X509_VERSION_3), 1)
        || !TEST_int_eq(ASN1_INTEGER_set(X509_get_serialNumber(x), 1), 1)
        || !TEST_ptr(subject = X509_NAME_new()))
        goto err;

    name_entry = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
        MBSTRING_ASC, commonName, -1);
    if (!TEST_ptr(name_entry)
        || !TEST_int_eq(X509_NAME_add_entry(subject, name_entry, -1, 0), 1)
        || !TEST_int_eq(X509_set_subject_name(x, subject), 1)
        || !TEST_int_eq(X509_set_issuer_name(x, subject), 1)
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600))
        || !TEST_int_eq(X509_set_pubkey(x, pubkey), 1))
        goto err;

    /*
     * Check that X509_add_ext() does not create non-NULL empty stack when
     * adding an ignored extension (from initial NULL state).
     */
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, X509V3_CTX_REPLACE);
    if (!TEST_ptr(ext = X509V3_EXT_conf(NULL, &ctx, "subjectKeyIdentifier", "none"))
        || !TEST_int_eq(X509_add_ext(x, ext, -1), 1)
        || !TEST_ptr_null(X509_get0_extensions(x)))
        goto err;

    /* Add non-empty SKID */
    if (!TEST_ptr(bio = BIO_new(BIO_s_mem()))
        || !TEST_int_ge(BIO_printf(bio, "subjectKeyIdentifier = hash\n"), 0)
        || !TEST_ptr(conf = NCONF_new(NULL))
        || !TEST_int_gt(NCONF_load_bio(conf, bio, NULL), 0))
        goto err;
    (void)BIO_reset(bio);

    X509V3_set_nconf(&ctx, conf);
    if (!TEST_true(X509V3_EXT_add_nconf(conf, &ctx, "default", x))
        || !TEST_ptr(exts = X509_get0_extensions(x))
        || !TEST_int_eq(sk_X509_EXTENSION_num(exts), 1))
        goto err;

    /* Request "empty" SKID in order to drop any previous value */
    NCONF_free(conf);
    if (!TEST_ptr(conf = NCONF_new(NULL))
        || !TEST_int_ge(BIO_printf(bio, "subjectKeyIdentifier = none\n"), 0)
        || !TEST_int_gt(NCONF_load_bio(conf, bio, NULL), 0))
        goto err;

    X509V3_set_nconf(&ctx, conf);
    if (!TEST_true(X509V3_EXT_add_nconf(conf, &ctx, "default", x))
        || !TEST_int_gt(X509_sign(x, privkey, signmd), 0)
        || !TEST_ptr_null(X509_get0_extensions(x)))
        goto err;

    /*
     * Now check that a non-empty extension is actually added via
     * X509_add_ext().
     */
    X509_EXTENSION_free(ext);
    if (!TEST_ptr(ext = X509V3_EXT_conf(NULL, &ctx, "subjectKeyIdentifier", "hash"))
        || !TEST_int_eq(X509_add_ext(x, ext, -1), 1)
        || !TEST_int_gt(X509_sign(x, privkey, signmd), 0)
        || !TEST_ptr(exts = X509_get0_extensions(x))
        || !TEST_int_eq(sk_X509_EXTENSION_num(exts), 1))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    NCONF_free(conf);
    X509_NAME_ENTRY_free(name_entry);
    X509_NAME_free(subject);
    X509_EXTENSION_free(ext);
    X509_free(x);
    return ret;
}

static int test_drop_empty_csr_keyids(void)
{
    static const unsigned char commonName[] = "test";
    BIO *bio = NULL;
    CONF *conf = NULL;
    X509_REQ *x = NULL;
    X509_NAME *subject = NULL;
    X509_NAME_ENTRY *name_entry = NULL;
    X509_EXTENSION *ext = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509V3_CTX ctx;
    int ret = 0;

    if (!TEST_ptr(x = X509_REQ_new())
        || !TEST_int_eq(X509_REQ_set_version(x, X509_REQ_VERSION_1), 1)
        || !TEST_ptr(subject = X509_NAME_new()))
        goto err;

    name_entry = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
        MBSTRING_ASC, commonName, -1);
    if (!TEST_ptr(name_entry)
        || !TEST_int_eq(X509_NAME_add_entry(subject, name_entry, -1, 0), 1)
        || !TEST_int_eq(X509_REQ_set_subject_name(x, subject), 1)
        || !TEST_int_eq(X509_REQ_set_pubkey(x, pubkey), 1))
        goto err;

    /* Add non-empty SKID, CSRs have no issuer, so no AKID */
    if (!TEST_ptr(bio = BIO_new(BIO_s_mem()))
        || !TEST_int_ge(BIO_printf(bio, "subjectKeyIdentifier = hash\n"), 0)
        || !TEST_ptr(conf = NCONF_new(NULL))
        || !TEST_int_gt(NCONF_load_bio(conf, bio, NULL), 0))
        goto err;
    (void)BIO_reset(bio);

    X509V3_set_ctx(&ctx, NULL, NULL, x, NULL, X509V3_CTX_REPLACE);
    X509V3_set_nconf(&ctx, conf);
    if (!TEST_true(X509V3_EXT_REQ_add_nconf(conf, &ctx, "default", x))
        || !TEST_int_eq(X509_REQ_get_attr_count(x), 1)
        || !TEST_ptr(exts = X509_REQ_get_extensions(x))
        || !TEST_int_eq(sk_X509_EXTENSION_num(exts), 1))
        goto err;
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    exts = NULL;

    /* Request an "empty" SKID in order to drop the previous SKID */
    NCONF_free(conf);
    if (!TEST_ptr(conf = NCONF_new(NULL))
        || !TEST_int_ge(BIO_printf(bio, "subjectKeyIdentifier = none\n"), 0)
        || !TEST_int_gt(NCONF_load_bio(conf, bio, NULL), 0))
        goto err;

    X509V3_set_nconf(&ctx, conf);
    if (!TEST_true(X509V3_EXT_REQ_add_nconf(conf, &ctx, "default", x))
        || !TEST_int_gt(X509_REQ_sign(x, privkey, signmd), 0)
        || !TEST_int_eq(X509_REQ_get_attr_count(x), 0))
        goto err;

    ret = 1;

err:
    BIO_free(bio);
    NCONF_free(conf);
    X509_NAME_ENTRY_free(name_entry);
    X509_NAME_free(subject);
    X509_EXTENSION_free(ext);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(x);
    return ret;
}

/*
 * TPM 1.2 Endorsement Key certificate with a NID_rsaesOaep
 * SubjectPublicKeyInfo AlgorithmIdentifier (per TCG Credential
 * Profiles V1.2 section 3.2.7).  The AlgorithmIdentifier carries
 * a TCG-specific pSourceAlgorithm ("TCPA") in its parameters,
 * which we deliberately do not interpret.  The key body itself
 * is a standard RSAPublicKey.
 */
static const char *kRsaesOaepCert[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDhDCCAmygAwIBAgIUBchBXcXPAWxNMJEsLXEXHv/eVZswDQYJKoZIhvcNAQEL\n",
    "BQAwVTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBO\n",
    "VjEmMCQGA1UEAxMdU1RNIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDIwHhcNMjEw\n",
    "OTA0MDAwMDAwWhcNMzEwOTA0MDAwMDAwWjAAMIIBNzAiBgkqhkiG9w0BAQcwFaIT\n",
    "MBEGCSqGSIb3DQEBCQQEVENQQQOCAQ8AMIIBCgKCAQEAxpd3DnecpD87acEsYp4J\n",
    "stM2q5Ss3CkjAP2Ei8yGjbO6DG/6WBIZjTdI5RfIcInoqN4QMso94vm8VqijdRI+\n",
    "Zo5hLTCPLKXYwa6UG5yIPZ3ENQdhgZWeEPWe+pp9VUwz8wi78Ifk+CCV6Xp/5kQi\n",
    "DCsR+RYbOVb9QgR6kjq+cx1z8YFp5u+k3Pl9tMq9xgIp5E6hT2MaS12KnoN8+hYI\n",
    "mfCYVnpzBeQaHDp1KUoyDK6xGt86VxB0QyRbniHI38qgQL6qhO7z96aQ0pNGoQde\n",
    "QUxFf/sETurQ5zSf+3btnS8afjxdVBKzj3isv5BaQrt0mdB7+3XWD+ASda33SY12\n",
    "6wIDAQABo4GLMIGIMB8GA1UdIwQYMBaAFFcfgGtHzOeb+jWUfO2IuNEAWuCeMEIG\n",
    "A1UdIAQ7MDkwNwYEVR0gADAvMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3LnN0LmNv\n",
    "bS9UUE0vcmVwb3NpdG9yeS8wDAYDVR0TAQH/BAIwADATBgNVHSUBAf8ECTAHBgVn\n",
    "gQUIATANBgkqhkiG9w0BAQsFAAOCAQEAMOhFPNcebyCRFOBztlWhmDb2DHTCD0nC\n",
    "DVobH4WZJXGf4bkYNO3mOLyWtHEVzb36kiq7enh3f/eGhDPwKB8axlozpR5KAvER\n",
    "szKNO8iLGOjuYzI2A4DazkttczFfzSB9QDgJrwTNEfIJtwRm2HQSiL0zzuEQOnaS\n",
    "UWyt/iKn4/34BjEeaw4/Ld7+f06LXqSr18SUr0LTB2kk+Zzf0Och1C+G1CNLgJMM\n",
    "MNQikAv0xdaOMX3HzA+phFlLbw/x8sboMlzmrbr92a/4Fp5WvmOSHH3ciwTtbAQn\n",
    "A2TfExNOaKD2BG5FnB7c66puw2/yVxhveocQYgmT9XtMrNX00vEZJQ==\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

/*
 * Verify that a SubjectPublicKeyInfo with an id-RSAES-OAEP
 * AlgorithmIdentifier decodes to an RSA EVP_PKEY via both the
 * provider decoder path (exercised by X509_from_strings() +
 * X509_get0_pubkey()) and the legacy type-specific path
 * (exercised by d2i_RSA_PUBKEY() when available).
 */
static int test_rsaesoaep_spki(void)
{
    int ret = 0;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const X509_PUBKEY *xpk = NULL;
    unsigned char *spki_der = NULL, *q;
    const unsigned char *p;
    int spki_len;
    RSA *rsa = NULL;
#endif

    /* Provider / OSSL_DECODER path. */
    if (!TEST_ptr(cert = X509_from_strings(kRsaesOaepCert))
        || !TEST_ptr(pkey = X509_get0_pubkey(cert))
        || !TEST_int_eq(EVP_PKEY_get_base_id(pkey), EVP_PKEY_RSA)
        || !TEST_int_ge(EVP_PKEY_get_bits(pkey), 2048))
        goto err;

#ifndef OPENSSL_NO_DEPRECATED_3_0
    /*
     * Legacy path: d2i_RSA_PUBKEY() routes through
     * ossl_d2i_PUBKEY_legacy() which sets flag_force_legacy=1,
     * so this exercises the NID_rsaesOaep -> NID_rsaEncryption
     * remap in x509_pubkey_decode().
     */
    if (!TEST_ptr(xpk = X509_get_X509_PUBKEY(cert))
        || !TEST_int_gt((spki_len = i2d_X509_PUBKEY(xpk, NULL)), 0)
        || !TEST_ptr(spki_der = OPENSSL_malloc(spki_len)))
        goto err;
    q = spki_der;
    if (!TEST_int_eq(i2d_X509_PUBKEY(xpk, &q), spki_len))
        goto err;
    p = spki_der;
    if (!TEST_ptr(rsa = d2i_RSA_PUBKEY(NULL, &p, spki_len))
        || !TEST_int_ge(RSA_bits(rsa), 2048))
        goto err;
#endif

    ret = 1;
err:
#ifndef OPENSSL_NO_DEPRECATED_3_0
    RSA_free(rsa);
    OPENSSL_free(spki_der);
#endif
    X509_free(cert);
    return ret;
}

/*
 * nameConstraints extnValue contents with one empty directoryName subtree.
 * Empty X509_NAME has canon_enc == NULL / canon_enclen == 0.
 *
 *   SEQUENCE { [0|1] { SEQUENCE { [4] { SEQUENCE {} } } } }
 */
static const unsigned char nc_excluded_empty_dirname[] = {
    0x30, 0x08, 0xa1, 0x06, 0x30, 0x04, 0xa4, 0x02, 0x30, 0x00
};
static const unsigned char nc_permitted_empty_dirname[] = {
    0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0xa4, 0x02, 0x30, 0x00
};

/* Decode a raw nameConstraints extnValue into a NAME_CONSTRAINTS object. */
static NAME_CONSTRAINTS *nc_empty_dirname_from_der(const unsigned char *der,
    unsigned int der_len)
{
    NAME_CONSTRAINTS *nc = NULL;
    ASN1_OCTET_STRING *os = NULL;
    X509_EXTENSION *ext = NULL;

    os = ASN1_OCTET_STRING_new();
    if (!TEST_ptr(os)
        || !TEST_true(ASN1_OCTET_STRING_set(os, der, der_len)))
        goto end;
    ext = X509_EXTENSION_create_by_NID(NULL, NID_name_constraints,
        1 /* critical */, os);
    if (!TEST_ptr(ext))
        goto end;
    nc = X509V3_EXT_d2i(ext);

end:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(os);
    return nc;
}

/* Build a minimal certificate with a non-empty subject DN. */
static X509 *nc_empty_dirname_subject(const char *cn)
{
    X509 *x = NULL;
    X509_NAME *nm = NULL;

    if (!TEST_ptr(x = X509_new()))
        goto err;
    nm = X509_NAME_new();
    if (!TEST_ptr(nm)
        || !TEST_true(X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0))
        || !TEST_true(X509_set_subject_name(x, nm)))
        goto err;
    X509_NAME_free(nm);
    return x;

err:
    X509_NAME_free(nm);
    X509_free(x);
    return NULL;
}

/* Check an empty directoryName constraint against a non-empty subject DN. */
static int nc_check_empty_dirname(const unsigned char *der, unsigned int der_len,
    int expected)
{
    int ok = 0;
    NAME_CONSTRAINTS *nc = NULL;
    X509 *x = NULL;

    if (!TEST_ptr(nc = nc_empty_dirname_from_der(der, der_len))
        || !TEST_ptr(x = nc_empty_dirname_subject("leaf.example"))
        || !TEST_int_eq(NAME_CONSTRAINTS_check(x, nc), expected))
        goto end;

    ok = 1;

end:
    X509_free(x);
    NAME_CONSTRAINTS_free(nc);
    return ok;
}

/* Empty excluded directoryName matches the subject DN: excluded violation. */
static int test_nc_empty_dirname_excluded(void)
{
    return nc_check_empty_dirname(nc_excluded_empty_dirname,
        sizeof(nc_excluded_empty_dirname), X509_V_ERR_EXCLUDED_VIOLATION);
}

/* Empty permitted directoryName matches the subject DN: permitted. */
static int test_nc_empty_dirname_permitted(void)
{
    return nc_check_empty_dirname(nc_permitted_empty_dirname,
        sizeof(nc_permitted_empty_dirname), X509_V_OK);
}

OPT_TEST_DECLARE_USAGE("<pss-self-signed-cert.pem>\n")

int setup_tests(void)
{
    const unsigned char *p;
    size_t cnt;

    cnt = test_get_argument_count();
    if (cnt != 1) {
        TEST_error("Must specify a certificate file self-signed with RSA-PSS.\n");
        return 0;
    }

    p = pubkeydata;
    pubkey = d2i_PUBKEY(NULL, &p, sizeof(pubkeydata));

    p = privkeydata;
    privkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(privkeydata));

    if (pubkey == NULL || privkey == NULL) {
        BIO_printf(bio_err, "Failed to create keys\n");
        return 0;
    }

    /* Note this digest is different from the certificate digest */
    signmd = EVP_MD_fetch(NULL, "SHA384", NULL);
    if (signmd == NULL) {
        BIO_printf(bio_err, "Failed to fetch digest\n");
        return 0;
    }

    ADD_TEST(test_x509_tbs_cache);
    ADD_TEST(test_x509_crl_tbs_cache);
    ADD_TEST(test_asn1_item_verify);
    ADD_TEST(test_x509_delete_last_extension);
    ADD_TEST(test_x509_crl_delete_last_extension);
    ADD_TEST(test_x509_revoked_delete_last_extension);
    ADD_TEST(test_drop_empty_cert_keyids);
    ADD_TEST(test_drop_empty_csr_keyids);
    ADD_TEST(test_rsaesoaep_spki);
    ADD_TEST(test_x509_verify_with_new);
    ADD_TEST(test_nc_empty_dirname_excluded);
    ADD_TEST(test_nc_empty_dirname_permitted);
    ADD_TEST(test_x509_store_add_duplicate_crls);
    ADD_TEST(test_x509_store_dup_cert_cached_vs_uncached);
    ADD_TEST(test_x509_store_distinct_crls_no_enc_cache);
    ADD_TEST(test_x509_store_dup_cert_mixed_libctx);
    ADD_TEST(test_x509_store_dup_cert_mixed_libctx_bucket);
    ADD_TEST(test_x509_store_dup_crl_mixed_libctx);
#ifndef OPENSSL_NO_DEPRECATED_4_0
    ADD_TEST(test_x509_store_get1_by_name_after_get0_objects);
    ADD_TEST(test_x509_store_no_dups_after_get0_objects);
#endif
    return 1;
}

void cleanup_tests(void)
{
    EVP_MD_free(signmd);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
}
