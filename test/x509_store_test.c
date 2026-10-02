/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
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
 * no cached SHA-1 fingerprint.
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

    if (!TEST_ptr(objs = X509_STORE_get1_objects(store)))
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

#ifndef OPENSSL_NO_DEPRECATED_4_0
static const X509_NAME *store_object_name(const X509_OBJECT *obj)
{
    switch (X509_OBJECT_get_type(obj)) {
    case X509_LU_X509:
        return X509_get_subject_name(X509_OBJECT_get0_X509(obj));
    case X509_LU_CRL:
        return X509_CRL_get_issuer(X509_OBJECT_get0_X509_CRL(obj));
    case X509_LU_NONE:
    default:
        return NULL;
    }
}

static int check_store_object_total_order(const STACK_OF(X509_OBJECT) *objs)
{
    int i;

    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        const X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);

        if (!TEST_true(obj->store_hash_valid))
            return 0;
        if (i > 0) {
            const X509_OBJECT *prev = sk_X509_OBJECT_value(objs, i - 1);
            int cmp = X509_OBJECT_get_type(prev) - X509_OBJECT_get_type(obj);

            if (cmp == 0)
                cmp = X509_NAME_cmp(store_object_name(prev),
                    store_object_name(obj));
            if (cmp == 0)
                cmp = memcmp(prev->store_hash, obj->store_hash,
                    sizeof(prev->store_hash));
            if (!TEST_int_le(cmp, 0))
                return 0;
        }
    }
    return 1;
}

/**
 * @brief Verify a store hash collision does not fold distinct encodings.
 * @returns 1 on success or 0 on failure
 */
static int test_x509_store_hash_collision(void)
{
    int ret = 0;
    unsigned int mdlen = 0;
    X509_STORE *store = NULL;
    X509_NAME *name = NULL;
    X509 *cert1 = NULL, *cert2 = NULL;
    X509_OBJECT *stored = NULL;
    STACK_OF(X509_OBJECT) *objs = NULL;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(name = make_store_test_name("Store Test Subject"))
        || !TEST_ptr(cert1 = make_store_test_cert(name, 1))
        || !TEST_ptr(cert2 = make_store_test_cert(name, 2))
        || !TEST_true(X509_STORE_add_cert(store, cert1))
        || !TEST_ptr(objs = X509_STORE_get0_objects(store))
        || !TEST_int_eq(sk_X509_OBJECT_num(objs), 1)
        || !TEST_ptr(stored = sk_X509_OBJECT_value(objs, 0))
        || !TEST_true(X509_digest(cert2, EVP_sha1(), stored->store_hash,
            &mdlen))
        || !TEST_size_t_eq((size_t)mdlen, sizeof(stored->store_hash)))
        goto err;

    /* cert1 now has cert2's index key, while their DER encodings differ. */
    if (!TEST_true(X509_STORE_add_cert(store, cert2))
        || !check_store_object_count(store, 2, 0)
        || !TEST_true(X509_STORE_add_cert(store, cert2))
        || !check_store_object_count(store, 2, 0))
        goto err;

    ret = 1;

err:
    X509_STORE_free(store);
    X509_free(cert1);
    X509_free(cert2);
    X509_NAME_free(name);
    return ret;
}
#endif

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
 * SHA-1-capable library context, so they are fingerprinted and X509_cmp() folds
 * them. The store must fold them too.
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
 * CRLs that were never DER-serialized have no cached SHA-1 fingerprint (and
 * no EXFLAG_NO_FINGERPRINT either) and no cached encoding. The store must
 * still tell distinct CRLs instead of silently dropping them as duplicates,
 * while re-adding the same object is still detected as a duplicate.
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
 * global stack and sorts it by (type, name, fingerprint). Duplicate detection
 * on later additions must still work on that stack. Use several names, each
 * with several certs and CRLs, so all parts of the order are exercised and the
 * merged stack is not already sorted.
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
    X509_CRL *crls[STORE_TEST_CERTS] = { NULL };
    STACK_OF(X509_OBJECT) *objs = NULL;

    if (!TEST_ptr(store = X509_STORE_new()))
        goto err;

    for (i = 0; i < STORE_TEST_NAMES; i++) {
        BIO_snprintf(cn, sizeof(cn), "Store Test Subject %02d", i);
        if (!TEST_ptr(names[i] = make_store_test_name(cn)))
            goto err;
        for (j = 0; j < STORE_TEST_CERTS_PER_NAME; j++) {
            int n = i * STORE_TEST_CERTS_PER_NAME + j;
            X509 **cert = &certs[n];
            X509_CRL **crl = &crls[n];

            if (!TEST_ptr(*cert = make_store_test_cert(names[i],
                              i * 1000 + j + 1))
                || !TEST_ptr(*crl = make_store_test_crl(names[i],
                                 i * 1000 + j + 1))
                || !TEST_true(X509_STORE_add_cert(store, *cert))
                || !TEST_true(X509_STORE_add_crl(store, *crl)))
                goto err;
        }
    }
    if (!check_store_object_count(store, STORE_TEST_CERTS, STORE_TEST_CERTS))
        goto err;

    /* Switch to the global-stack representation. */
    if (!TEST_ptr(objs = X509_STORE_get0_objects(store))
        || !check_store_object_total_order(objs))
        goto err;

    /* Re-adding every object must be detected as a duplicate. */
    for (i = 0; i < STORE_TEST_CERTS; i++)
        if (!TEST_true(X509_STORE_add_cert(store, certs[i]))
            || !TEST_true(X509_STORE_add_crl(store, crls[i])))
            goto err;

    ret = check_store_object_count(store, STORE_TEST_CERTS, STORE_TEST_CERTS);

err:
    X509_STORE_free(store);
    for (i = 0; i < STORE_TEST_NAMES; i++)
        X509_NAME_free(names[i]);
    for (i = 0; i < STORE_TEST_CERTS; i++)
        X509_free(certs[i]);
    for (i = 0; i < STORE_TEST_CERTS; i++)
        X509_CRL_free(crls[i]);
    return ret;
}
#endif

int setup_tests(void)
{
    const unsigned char *p;

    p = pubkeydata;
    pubkey = d2i_PUBKEY(NULL, &p, sizeof(pubkeydata));

    p = privkeydata;
    privkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(privkeydata));

    if (pubkey == NULL || privkey == NULL) {
        BIO_printf(bio_err, "Failed to create keys\n");
        return 0;
    }

    signmd = EVP_MD_fetch(NULL, "SHA384", NULL);
    if (signmd == NULL) {
        BIO_printf(bio_err, "Failed to fetch digest\n");
        return 0;
    }

    ADD_TEST(test_x509_store_add_duplicate_crls);
    ADD_TEST(test_x509_store_dup_cert_cached_vs_uncached);
    ADD_TEST(test_x509_store_distinct_crls_no_enc_cache);
#ifndef OPENSSL_NO_DEPRECATED_4_0
    ADD_TEST(test_x509_store_hash_collision);
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
