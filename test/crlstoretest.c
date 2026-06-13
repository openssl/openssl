/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "testutil.h"

typedef struct test_chain_st {
    EVP_PKEY *root_key;
    X509 *root;
    EVP_PKEY *leaf_key;
    X509 *leaf;
} TEST_CHAIN;

typedef struct crl_spec_st {
    long crl_number;
    long base_crl_number;
    long this_update_offset;
    long revoked_serial;
    int revoked_reason;
    int idp_reason_bit;
    const char *idp_uri;
    int custom_akid_byte;
    int add_freshest_crl;
} CRL_SPEC;

static void test_chain_free(TEST_CHAIN *chain)
{
    X509_free(chain->leaf);
    EVP_PKEY_free(chain->leaf_key);
    X509_free(chain->root);
    EVP_PKEY_free(chain->root_key);
    memset(chain, 0, sizeof(*chain));
}

static EVP_PKEY *make_test_key(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
}

static int add_cert_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext;
    int ok;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!TEST_ptr(ext))
        return 0;
    ok = TEST_true(X509_add_ext(cert, ext, -1));
    X509_EXTENSION_free(ext);
    return ok;
}

static int set_name(X509_NAME *name, const char *cn)
{
    return TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)cn,
        -1, -1, 0));
}

static X509 *make_cert(EVP_PKEY *subject_key, const char *subject_cn,
    X509 *issuer, EVP_PKEY *issuer_key, long serial,
    int is_ca)
{
    X509 *cert = X509_new();
    X509_NAME *name = NULL;
    const char *bc;
    const char *ku;

    if (!TEST_ptr(cert))
        return NULL;
    if (!TEST_true(X509_set_version(cert, 2))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(cert),
            serial))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(cert),
            -60 * 60))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(cert),
            60 * 60 * 24))
        || !TEST_true(X509_set_pubkey(cert, subject_key)))
        goto err;

    name = X509_NAME_new();
    if (!TEST_ptr(name)
        || !set_name(name, subject_cn)
        || !TEST_true(X509_set_subject_name(cert, name)))
        goto err;
    if (issuer != NULL) {
        if (!TEST_true(X509_set_issuer_name(cert,
                X509_get_subject_name(issuer))))
            goto err;
    } else {
        if (!TEST_true(X509_set_issuer_name(cert, name)))
            goto err;
        issuer = cert;
        issuer_key = subject_key;
    }

    bc = is_ca ? "critical,CA:TRUE,pathlen:4" : "critical,CA:FALSE";
    ku = is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature";
    if (!add_cert_ext(cert, issuer, NID_basic_constraints, bc)
        || !add_cert_ext(cert, issuer, NID_key_usage, ku)
        || !add_cert_ext(cert, issuer, NID_subject_key_identifier, "hash"))
        goto err;
    if (issuer != cert
        && !add_cert_ext(cert, issuer, NID_authority_key_identifier,
            "keyid:always"))
        goto err;

    if (!TEST_int_ne(X509_sign(cert, issuer_key, EVP_sha256()), 0))
        goto err;
    X509_NAME_free(name);
    return cert;

err:
    X509_NAME_free(name);
    X509_free(cert);
    return NULL;
}

static int make_chain(TEST_CHAIN *chain, const char *leaf_cn)
{
    memset(chain, 0, sizeof(*chain));
    chain->root_key = make_test_key();
    chain->leaf_key = make_test_key();
    if (!TEST_ptr(chain->root_key) || !TEST_ptr(chain->leaf_key))
        goto err;
    chain->root = make_cert(chain->root_key, "CRL Store Test Root",
        NULL, NULL, 1, 1);
    chain->leaf = make_cert(chain->leaf_key, leaf_cn, chain->root,
        chain->root_key, 2, 0);
    if (!TEST_ptr(chain->root) || !TEST_ptr(chain->leaf))
        goto err;
    return 1;

err:
    test_chain_free(chain);
    return 0;
}

static int add_ext_i2d_to_crl(X509_CRL *crl, int nid, int critical,
    void *value)
{
    X509_EXTENSION *ext = X509V3_EXT_i2d(nid, critical, value);
    int ok;

    if (!TEST_ptr(ext))
        return 0;
    ok = TEST_true(X509_CRL_add_ext(crl, ext, -1));
    X509_EXTENSION_free(ext);
    return ok;
}

static int add_integer_crl_ext(X509_CRL *crl, int nid, long value)
{
    ASN1_INTEGER *integer = ASN1_INTEGER_new();
    int ok = 0;

    if (!TEST_ptr(integer))
        return 0;
    if (!TEST_true(ASN1_INTEGER_set(integer, value)))
        goto end;
    ok = add_ext_i2d_to_crl(crl, nid, 0, integer);

end:
    ASN1_INTEGER_free(integer);
    return ok;
}

static int add_issuer_akid(X509_CRL *crl, X509 *issuer)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext;
    int ok;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, NULL, NULL, crl, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier,
        "keyid:always");
    if (!TEST_ptr(ext))
        return 0;
    ok = TEST_true(X509_CRL_add_ext(crl, ext, -1));
    X509_EXTENSION_free(ext);
    return ok;
}

static int add_custom_akid(X509_CRL *crl, int value)
{
    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    X509_EXTENSION *ext = NULL;
    unsigned char keyid[4];
    int ok = 0;

    if (!TEST_ptr(akid))
        goto end;
    akid->keyid = ASN1_OCTET_STRING_new();
    if (!TEST_ptr(akid->keyid))
        goto end;
    keyid[0] = (unsigned char)value;
    keyid[1] = (unsigned char)(value + 1);
    keyid[2] = (unsigned char)(value + 2);
    keyid[3] = (unsigned char)(value + 3);
    if (!TEST_true(ASN1_OCTET_STRING_set(akid->keyid, keyid,
            sizeof(keyid))))
        goto end;
    ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
    if (!TEST_ptr(ext))
        goto end;
    ok = TEST_true(X509_CRL_add_ext(crl, ext, -1));

end:
    X509_EXTENSION_free(ext);
    AUTHORITY_KEYID_free(akid);
    return ok;
}

static GENERAL_NAME *make_uri_general_name(const char *uri)
{
    GENERAL_NAME *name = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();

    if (!TEST_ptr(name) || !TEST_ptr(ia5))
        goto err;
    if (!TEST_true(ASN1_STRING_set(ia5, uri, (int)strlen(uri))))
        goto err;
    name->type = GEN_URI;
    name->d.uniformResourceIdentifier = ia5;
    return name;

err:
    GENERAL_NAME_free(name);
    ASN1_IA5STRING_free(ia5);
    return NULL;
}

static DIST_POINT_NAME *make_uri_dpname(const char *uri)
{
    DIST_POINT_NAME *dpn = DIST_POINT_NAME_new();
    GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *name = NULL;

    if (!TEST_ptr(dpn) || !TEST_ptr(names))
        goto err;
    name = make_uri_general_name(uri);
    if (!TEST_ptr(name))
        goto err;
    if (!TEST_true(sk_GENERAL_NAME_push(names, name)))
        goto err;
    name = NULL;
    dpn->type = 0;
    dpn->name.fullname = names;
    return dpn;

err:
    GENERAL_NAME_free(name);
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    DIST_POINT_NAME_free(dpn);
    return NULL;
}

static ASN1_BIT_STRING *make_reason_bits(int bit)
{
    ASN1_BIT_STRING *bits = ASN1_BIT_STRING_new();

    if (!TEST_ptr(bits))
        return NULL;
    if (!TEST_true(ASN1_BIT_STRING_set_bit(bits, bit, 1))) {
        ASN1_BIT_STRING_free(bits);
        return NULL;
    }
    return bits;
}

static int add_idp(X509_CRL *crl, const char *uri, int reason_bit)
{
    ISSUING_DIST_POINT *idp = ISSUING_DIST_POINT_new();
    int ok = 0;

    if (!TEST_ptr(idp))
        goto end;
    if (uri != NULL) {
        idp->distpoint = make_uri_dpname(uri);
        if (!TEST_ptr(idp->distpoint))
            goto end;
    }
    if (reason_bit >= 0) {
        idp->onlysomereasons = make_reason_bits(reason_bit);
        if (!TEST_ptr(idp->onlysomereasons))
            goto end;
    }
    ok = add_ext_i2d_to_crl(crl, NID_issuing_distribution_point, 0, idp);

end:
    ISSUING_DIST_POINT_free(idp);
    return ok;
}

static CRL_DIST_POINTS *make_crldp(const char *uri)
{
    CRL_DIST_POINTS *points = sk_DIST_POINT_new_null();
    DIST_POINT *point = DIST_POINT_new();

    if (!TEST_ptr(points) || !TEST_ptr(point))
        goto err;
    point->distpoint = make_uri_dpname(uri);
    if (!TEST_ptr(point->distpoint))
        goto err;
    if (!TEST_true(sk_DIST_POINT_push(points, point)))
        goto err;
    point = NULL;
    return points;

err:
    DIST_POINT_free(point);
    sk_DIST_POINT_pop_free(points, DIST_POINT_free);
    return NULL;
}

static int add_freshest_crl(X509_CRL *crl, const char *uri)
{
    CRL_DIST_POINTS *points = make_crldp(uri);
    int ok = 0;

    if (!TEST_ptr(points))
        return 0;
    ok = add_ext_i2d_to_crl(crl, NID_freshest_crl, 0, points);
    sk_DIST_POINT_pop_free(points, DIST_POINT_free);
    return ok;
}

static int add_revoked_reason(X509_REVOKED *revoked, int reason)
{
    ASN1_ENUMERATED *asn1_reason = ASN1_ENUMERATED_new();
    X509_EXTENSION *ext = NULL;
    int ok = 0;

    if (!TEST_ptr(asn1_reason))
        goto end;
    if (!TEST_true(ASN1_ENUMERATED_set(asn1_reason, reason)))
        goto end;
    ext = X509V3_EXT_i2d(NID_crl_reason, 0, asn1_reason);
    if (!TEST_ptr(ext))
        goto end;
    ok = TEST_true(X509_REVOKED_add_ext(revoked, ext, -1));

end:
    X509_EXTENSION_free(ext);
    ASN1_ENUMERATED_free(asn1_reason);
    return ok;
}

static X509_CRL *roundtrip_crl(X509_CRL *crl)
{
    unsigned char *der = NULL;
    unsigned char *p;
    const unsigned char *q;
    int len;
    X509_CRL *decoded = NULL;

    len = i2d_X509_CRL(crl, NULL);
    if (!TEST_int_gt(len, 0))
        return NULL;
    der = OPENSSL_malloc((size_t)len);
    if (!TEST_ptr(der))
        return NULL;
    p = der;
    if (!TEST_int_eq(i2d_X509_CRL(crl, &p), len))
        goto end;
    q = der;
    decoded = d2i_X509_CRL(NULL, &q, len);
    TEST_ptr(decoded);

end:
    OPENSSL_free(der);
    return decoded;
}

static X509_CRL *make_crl(X509 *issuer, EVP_PKEY *issuer_key,
    const CRL_SPEC *spec)
{
    X509_CRL *crl = X509_CRL_new();
    X509_CRL *decoded = NULL;
    X509_REVOKED *revoked = NULL;
    ASN1_INTEGER *serial = NULL;
    ASN1_TIME *last = ASN1_TIME_new();
    ASN1_TIME *next = ASN1_TIME_new();

    if (!TEST_ptr(crl) || !TEST_ptr(last) || !TEST_ptr(next))
        goto err;
    if (!TEST_true(X509_CRL_set_version(crl, 1))
        || !TEST_true(X509_CRL_set_issuer_name(crl,
            X509_get_subject_name(issuer)))
        || !TEST_ptr(X509_gmtime_adj(last, spec->this_update_offset))
        || !TEST_ptr(X509_gmtime_adj(next, 60 * 60 * 24))
        || !TEST_true(X509_CRL_set1_lastUpdate(crl, last))
        || !TEST_true(X509_CRL_set1_nextUpdate(crl, next))
        || !add_integer_crl_ext(crl, NID_crl_number, spec->crl_number))
        goto err;
    if (spec->base_crl_number >= 0
        && !add_integer_crl_ext(crl, NID_delta_crl,
            spec->base_crl_number))
        goto err;
    if (spec->custom_akid_byte >= 0) {
        if (!add_custom_akid(crl, spec->custom_akid_byte))
            goto err;
    } else if (!add_issuer_akid(crl, issuer)) {
        goto err;
    }
    if ((spec->idp_uri != NULL || spec->idp_reason_bit >= 0)
        && !add_idp(crl, spec->idp_uri, spec->idp_reason_bit))
        goto err;
    if (spec->add_freshest_crl
        && !add_freshest_crl(crl, "http://crlstore.test/delta.crl"))
        goto err;

    if (spec->revoked_serial >= 0) {
        revoked = X509_REVOKED_new();
        serial = ASN1_INTEGER_new();
        if (!TEST_ptr(revoked) || !TEST_ptr(serial))
            goto err;
        if (!TEST_true(ASN1_INTEGER_set(serial, spec->revoked_serial))
            || !TEST_true(X509_REVOKED_set_serialNumber(revoked, serial))
            || !TEST_true(X509_REVOKED_set_revocationDate(revoked, last)))
            goto err;
        if (spec->revoked_reason >= 0
            && !add_revoked_reason(revoked, spec->revoked_reason))
            goto err;
        if (!TEST_true(X509_CRL_add0_revoked(crl, revoked)))
            goto err;
        revoked = NULL;
    }

    if (!TEST_true(X509_CRL_sort(crl))
        || !TEST_int_ne(X509_CRL_sign(crl, issuer_key,
                            EVP_sha256()),
            0))
        goto err;
    decoded = roundtrip_crl(crl);

err:
    X509_REVOKED_free(revoked);
    ASN1_INTEGER_free(serial);
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    X509_CRL_free(crl);
    return decoded;
}

static long crl_number(X509_CRL *crl)
{
    ASN1_INTEGER *number;
    long value = -1;

    number = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);
    if (number != NULL)
        value = ASN1_INTEGER_get(number);
    ASN1_INTEGER_free(number);
    return value;
}

static int store_count(X509_STORE *store, X509_CRL *sample, int *count)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509_CRL) *crls = NULL;
    int ok = 0;

    *count = 0;
    if (!TEST_ptr(ctx))
        goto end;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL)))
        goto end;
    crls = X509_STORE_CTX_get1_crls(ctx, X509_CRL_get_issuer(sample));
    if (crls != NULL)
        *count = sk_X509_CRL_num(crls);
    ok = 1;

end:
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_STORE_CTX_free(ctx);
    return ok;
}

static int expect_store_count(X509_STORE *store, X509_CRL *sample,
    int expected)
{
    int count;

    return TEST_true(store_count(store, sample, &count))
        && TEST_int_eq(count, expected);
}

static int expect_only_crl_number(X509_STORE *store, X509_CRL *sample,
    long expected_number,
    int expected_revoked_count)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(X509_REVOKED) *revoked;
    int ok = 0;

    if (!TEST_ptr(ctx))
        goto end;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL)))
        goto end;
    crls = X509_STORE_CTX_get1_crls(ctx, X509_CRL_get_issuer(sample));
    if (!TEST_ptr(crls) || !TEST_int_eq(sk_X509_CRL_num(crls), 1))
        goto end;
    crl = sk_X509_CRL_value(crls, 0);
    revoked = X509_CRL_get_REVOKED(crl);
    ok = TEST_long_eq(crl_number(crl), expected_number)
        && TEST_int_eq(revoked != NULL ? sk_X509_REVOKED_num(revoked) : 0,
            expected_revoked_count);

end:
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_STORE_CTX_free(ctx);
    return ok;
}

static int verify_leaf(TEST_CHAIN *chain, X509_CRL **crls, size_t crl_count,
    unsigned long flags, int expected_err)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    size_t i;
    int verify_ret, verify_err;
    int ok = 0;

    if (!TEST_ptr(store) || !TEST_ptr(ctx))
        goto end;
    if (!TEST_true(X509_STORE_add_cert(store, chain->root)))
        goto end;
    for (i = 0; i < crl_count; i++) {
        if (!TEST_true(X509_STORE_add_crl(store, crls[i])))
            goto end;
    }
    if (flags != 0 && !TEST_true(X509_STORE_set_flags(store, flags)))
        goto end;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, chain->leaf, NULL)))
        goto end;

    verify_ret = X509_verify_cert(ctx);
    verify_err = X509_STORE_CTX_get_error(ctx);
    ok = TEST_int_eq(verify_ret, expected_err == X509_V_OK ? 1 : 0)
        && TEST_int_eq(verify_err, expected_err);

end:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ok;
}

/*
 * Scenario: an older empty full CRL is already cached, then a newer
 * equivalent same-scope full CRL arrives revoking the leaf certificate. The
 * newer CRL must replace the older one and certificate verification must use
 * the newer revocation state.
 */
static int test_same_scope_newer_replaces(void)
{
    TEST_CHAIN chain;
    X509_CRL *older = NULL, *newer = NULL;
    X509_STORE *store = X509_STORE_new();
    long leaf_serial;
    X509_CRL *verify_crls[2];
    int ok = 0;

    if (!TEST_true(make_chain(&chain, "same-scope-newer.test"))
        || !TEST_ptr(store))
        goto end;
    leaf_serial = ASN1_INTEGER_get(X509_get_serialNumber(chain.leaf));
    older = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 1, -1, -2 * 60 * 60, -1, -1, -1,
            NULL, -1, 0 });
    newer = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 2, -1, -60 * 60, leaf_serial, -1, -1,
            NULL, -1, 0 });
    verify_crls[0] = older;
    verify_crls[1] = newer;
    if (!TEST_ptr(older) || !TEST_ptr(newer)
        || !TEST_true(X509_STORE_add_crl(store, older))
        || !TEST_true(X509_STORE_add_crl(store, newer)))
        goto end;

    ok = expect_only_crl_number(store, older, 2, 1)
        && verify_leaf(&chain, verify_crls, 2, X509_V_FLAG_CRL_CHECK,
            X509_V_ERR_CERT_REVOKED);

end:
    X509_STORE_free(store);
    X509_CRL_free(older);
    X509_CRL_free(newer);
    test_chain_free(&chain);
    return ok;
}

/*
 * Scenario: a newer same-scope CRL is cached, then an older equivalent CRL
 * arrives later. The store must treat this as a successful no-op and must not
 * downgrade the cached revocation state.
 */
static int test_same_scope_older_does_not_downgrade(void)
{
    TEST_CHAIN chain;
    X509_CRL *newer = NULL, *older = NULL;
    X509_STORE *store = X509_STORE_new();
    long leaf_serial;
    X509_CRL *verify_crls[2];
    int ok = 0;

    if (!TEST_true(make_chain(&chain, "same-scope-no-downgrade.test"))
        || !TEST_ptr(store))
        goto end;
    leaf_serial = ASN1_INTEGER_get(X509_get_serialNumber(chain.leaf));
    newer = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 2, -1, -60 * 60, leaf_serial, -1, -1,
            NULL, -1, 0 });
    older = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 1, -1, -2 * 60 * 60, -1, -1, -1,
            NULL, -1, 0 });
    verify_crls[0] = newer;
    verify_crls[1] = older;
    if (!TEST_ptr(newer) || !TEST_ptr(older)
        || !TEST_true(X509_STORE_add_crl(store, newer))
        || !TEST_true(X509_STORE_add_crl(store, older)))
        goto end;

    ok = expect_only_crl_number(store, newer, 2, 1)
        && verify_leaf(&chain, verify_crls, 2, X509_V_FLAG_CRL_CHECK,
            X509_V_ERR_CERT_REVOKED);

end:
    X509_STORE_free(store);
    X509_CRL_free(newer);
    X509_CRL_free(older);
    test_chain_free(&chain);
    return ok;
}

/*
 * Scenario: two CRLs have the same issuer but different
 * issuingDistributionPoint URI scopes. They are distinct CRL partitions and
 * must coexist in the store.
 */
static int test_distinct_idp_scopes_coexist(void)
{
    TEST_CHAIN chain;
    X509_CRL *dp_a = NULL, *dp_b = NULL;
    X509_STORE *store = X509_STORE_new();
    int ok = 0;

    if (!TEST_true(make_chain(&chain, "distinct-idp.test"))
        || !TEST_ptr(store))
        goto end;
    dp_a = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 10, -1, -2 * 60 * 60, -1, -1, -1,
            "http://crlstore.test/scope-a.crl", -1,
            0 });
    dp_b = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 11, -1, -60 * 60, -1, -1, -1,
            "http://crlstore.test/scope-b.crl", -1,
            0 });
    if (!TEST_ptr(dp_a) || !TEST_ptr(dp_b)
        || !TEST_true(X509_STORE_add_crl(store, dp_a))
        || !TEST_true(X509_STORE_add_crl(store, dp_b)))
        goto end;

    ok = expect_store_count(store, dp_a, 2);

end:
    X509_STORE_free(store);
    X509_CRL_free(dp_a);
    X509_CRL_free(dp_b);
    test_chain_free(&chain);
    return ok;
}

/*
 * Scenario: two CRLs have the same issuer but different IDP onlySomeReasons
 * scopes. They are distinct reason partitions. Verification with extended CRL
 * support must still find the revocation in the applicable reason partition.
 */
static int test_distinct_reason_scopes_coexist(void)
{
    TEST_CHAIN chain;
    X509_CRL *key_compromise = NULL, *ca_compromise = NULL;
    X509_STORE *store = X509_STORE_new();
    long leaf_serial;
    X509_CRL *verify_crls[2];
    int ok = 0;

    if (!TEST_true(make_chain(&chain, "distinct-reason.test"))
        || !TEST_ptr(store))
        goto end;
    leaf_serial = ASN1_INTEGER_get(X509_get_serialNumber(chain.leaf));
    key_compromise = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 20, -1, -2 * 60 * 60,
            leaf_serial,
            CRL_REASON_KEY_COMPROMISE, 1,
            NULL, -1, 0 });
    ca_compromise = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 21, -1, -60 * 60, -1, -1, 2,
            NULL, -1, 0 });
    verify_crls[0] = key_compromise;
    verify_crls[1] = ca_compromise;
    if (!TEST_ptr(key_compromise) || !TEST_ptr(ca_compromise)
        || !TEST_true(X509_STORE_add_crl(store, key_compromise))
        || !TEST_true(X509_STORE_add_crl(store, ca_compromise)))
        goto end;

    ok = expect_store_count(store, key_compromise, 2)
        && verify_leaf(&chain, verify_crls, 2,
            X509_V_FLAG_CRL_CHECK
                | X509_V_FLAG_EXTENDED_CRL_SUPPORT,
            X509_V_ERR_CERT_REVOKED);

end:
    X509_STORE_free(store);
    X509_CRL_free(key_compromise);
    X509_CRL_free(ca_compromise);
    test_chain_free(&chain);
    return ok;
}

/*
 * Scenario: two CA certificates share the same issuer subject name but have
 * different key identifiers. CRLs from those authorities must coexist because
 * subject name alone does not identify the CRL authority.
 */
static int test_same_issuer_different_akid_coexist(void)
{
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    X509 *ca1 = NULL, *ca2 = NULL;
    X509_CRL *crl1 = NULL, *crl2 = NULL;
    X509_STORE *store = X509_STORE_new();
    int ok = 0;

    key1 = make_test_key();
    key2 = make_test_key();
    if (!TEST_ptr(key1) || !TEST_ptr(key2) || !TEST_ptr(store))
        goto end;
    ca1 = make_cert(key1, "Shared Subject CRL Authority", NULL, NULL, 101, 1);
    ca2 = make_cert(key2, "Shared Subject CRL Authority", NULL, NULL, 102, 1);
    crl1 = make_crl(ca1, key1,
        &(CRL_SPEC) { 30, -1, -2 * 60 * 60, -1, -1, -1,
            NULL, 1, 0 });
    crl2 = make_crl(ca2, key2,
        &(CRL_SPEC) { 31, -1, -60 * 60, -1, -1, -1,
            NULL, 20, 0 });
    if (!TEST_ptr(ca1) || !TEST_ptr(ca2)
        || !TEST_ptr(crl1) || !TEST_ptr(crl2)
        || !TEST_true(X509_STORE_add_crl(store, crl1))
        || !TEST_true(X509_STORE_add_crl(store, crl2)))
        goto end;

    ok = expect_store_count(store, crl1, 2);

end:
    X509_STORE_free(store);
    X509_CRL_free(crl1);
    X509_CRL_free(crl2);
    X509_free(ca1);
    X509_free(ca2);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ok;
}

/*
 * Scenario: a base full CRL and a compatible delta CRL have the same issuer
 * and AKID but different delta/baseCRL state. They must coexist so revocation
 * checking with X509_V_FLAG_USE_DELTAS can apply the delta CRL.
 */
static int test_full_plus_delta_coexist(void)
{
    TEST_CHAIN chain;
    X509_CRL *base = NULL, *delta = NULL;
    X509_STORE *store = X509_STORE_new();
    long leaf_serial;
    X509_CRL *verify_crls[2];
    int ok = 0;

    if (!TEST_true(make_chain(&chain, "delta-crl.test"))
        || !TEST_ptr(store))
        goto end;
    leaf_serial = ASN1_INTEGER_get(X509_get_serialNumber(chain.leaf));
    base = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 40, -1, -2 * 60 * 60, -1, -1, -1,
            NULL, -1, 1 });
    delta = make_crl(chain.root, chain.root_key,
        &(CRL_SPEC) { 41, 40, -60 * 60, leaf_serial, -1, -1,
            NULL, -1, 0 });
    verify_crls[0] = base;
    verify_crls[1] = delta;
    if (!TEST_ptr(base) || !TEST_ptr(delta)
        || !TEST_true(X509_STORE_add_crl(store, base))
        || !TEST_true(X509_STORE_add_crl(store, delta)))
        goto end;

    ok = expect_store_count(store, base, 2)
        && verify_leaf(&chain, verify_crls, 2,
            X509_V_FLAG_CRL_CHECK | X509_V_FLAG_USE_DELTAS,
            X509_V_ERR_CERT_REVOKED);

end:
    X509_STORE_free(store);
    X509_CRL_free(base);
    X509_CRL_free(delta);
    test_chain_free(&chain);
    return ok;
}

OPT_TEST_DECLARE_USAGE("crlstoretest\n")

int setup_tests(void)
{
    ADD_TEST(test_same_scope_newer_replaces);
    ADD_TEST(test_same_scope_older_does_not_downgrade);
    ADD_TEST(test_distinct_idp_scopes_coexist);
    ADD_TEST(test_distinct_reason_scopes_coexist);
    ADD_TEST(test_same_issuer_different_akid_coexist);
    ADD_TEST(test_full_plus_delta_coexist);
    return 1;
}
