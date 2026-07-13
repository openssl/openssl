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
                         (X509_ALGOR *)alg, (ASN1_BIT_STRING *)sig,
                         &x509->cert_info, pkey),
            0))
        goto err;

    ERR_set_mark();
    if (!TEST_int_lt(ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF),
                         (X509_ALGOR *)alg, (ASN1_BIT_STRING *)sig,
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

static int add_name_entry(X509_NAME *name, const char *field,
    const char *value)
{
    return X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
        (const unsigned char *)value, -1, -1, 0);
}

static X509_NAME *make_store_test_name(void)
{
    X509_NAME *name = X509_NAME_new();

    if (name == NULL)
        return NULL;
    if (!add_name_entry(name, "C", "CN")
        || !add_name_entry(name, "O", "OpenSSL X509_STORE Test")
        || !add_name_entry(name, "CN", "Shared Test Issuer")) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

static X509 *make_store_test_cert(X509_NAME *name)
{
    X509 *cert = X509_new();

    if (cert == NULL)
        return NULL;
    if (!X509_set_version(cert, 2)
        || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
        || !X509_set_subject_name(cert, name)
        || !X509_set_issuer_name(cert, name)
        || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 24 * 60 * 60) == NULL
        || !X509_set_pubkey(cert, privkey)
        || !X509_sign(cert, privkey, signmd)) {
        X509_free(cert);
        return NULL;
    }
    return cert;
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

static X509_CRL *make_store_test_crl(X509_NAME *issuer, int number)
{
    X509_CRL *crl = NULL;
    ASN1_INTEGER *crl_number = NULL;
    ASN1_TIME *last_update = NULL;
    ASN1_TIME *next_update = NULL;

    crl = X509_CRL_new();
    crl_number = ASN1_INTEGER_new();
    last_update = ASN1_TIME_new();
    next_update = ASN1_TIME_new();
    if (crl == NULL || crl_number == NULL || last_update == NULL
        || next_update == NULL)
        goto err;

    if (!ASN1_INTEGER_set(crl_number, number)
        || !ASN1_TIME_set_string(last_update, "20240101000000Z")
        || !ASN1_TIME_set_string(next_update, "20250101000000Z")
        || !X509_CRL_set_version(crl, 1)
        || !X509_CRL_set_issuer_name(crl, issuer)
        || !X509_CRL_set1_lastUpdate(crl, last_update)
        || !X509_CRL_set1_nextUpdate(crl, next_update)
        || !X509_CRL_add1_ext_i2d(crl, NID_crl_number, crl_number, 0, 0)
        || !X509_CRL_sign(crl, privkey, signmd))
        goto err;

    ASN1_INTEGER_free(crl_number);
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);

    return roundtrip_crl(crl);

err:
    X509_CRL_free(crl);
    ASN1_INTEGER_free(crl_number);
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    return NULL;
}

static int count_store_objects(X509_STORE *store, X509_LOOKUP_TYPE type)
{
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get1_objects(store);
    int i, count = 0;

    if (objs == NULL)
        return -1;

    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);

        if (type == X509_LU_NONE || X509_OBJECT_get_type(obj) == type)
            count++;
    }
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    return count;
}

static int test_x509_store_add_duplicate_crls(void)
{
    int ret = 0, i;
    X509_STORE *store = NULL;
    X509_NAME *name = NULL;
    X509 *cert = NULL;
    X509_CRL *crls[4] = { NULL, NULL, NULL, NULL };

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(name = make_store_test_name())
        || !TEST_ptr(cert = make_store_test_cert(name)))
        goto err;

    for (i = 0; i < 4; i++) {
        if (!TEST_ptr(crls[i] = make_store_test_crl(name, i + 1)))
            goto err;
    }

    if (!TEST_true(X509_STORE_add_crl(store, crls[0]))
        || !TEST_true(X509_STORE_add_cert(store, cert))
        || !TEST_true(X509_STORE_add_crl(store, crls[1]))
        || !TEST_true(X509_STORE_add_crl(store, crls[2]))
        || !TEST_true(X509_STORE_add_crl(store, crls[3]))
        || !TEST_int_eq(count_store_objects(store, X509_LU_NONE), 5)
        || !TEST_int_eq(count_store_objects(store, X509_LU_X509), 1)
        || !TEST_int_eq(count_store_objects(store, X509_LU_CRL), 4))
        goto err;

    for (i = 0; i < 4; i++) {
        if (!TEST_true(X509_STORE_add_crl(store, crls[i]))
            || !TEST_int_eq(count_store_objects(store, X509_LU_NONE), 5)
            || !TEST_int_eq(count_store_objects(store, X509_LU_X509), 1)
            || !TEST_int_eq(count_store_objects(store, X509_LU_CRL), 4))
            goto err;
    }

    ret = 1;

err:
    for (i = 0; i < 4; i++)
        X509_CRL_free(crls[i]);
    X509_free(cert);
    X509_NAME_free(name);
    X509_STORE_free(store);
    return ret;
}

OPT_TEST_DECLARE_USAGE("<pss-self-signed-cert.pem>\n")

int setup_tests(void)
{
    const unsigned char *p;
    int cnt;

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
    ADD_TEST(test_x509_verify_with_new);
    ADD_TEST(test_x509_store_add_duplicate_crls);
    return 1;
}

void cleanup_tests(void)
{
    EVP_MD_free(signmd);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
}
