/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/posix_time.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/x509.h"
#include "crypto/x509_view.h"
#include "internal/bytestring.h"
#include "internal/nelem.h"
#include "internal/o_dir.h"
#include "testutil.h"

static X509 *make_cert(int ca)
{
    X509 *cert = NULL, *ret = NULL;
    EVP_PKEY *pkey = NULL;
    X509_NAME *name = NULL;
    BASIC_CONSTRAINTS *bc = NULL;
    ASN1_BIT_STRING *ku = NULL;
    EXTENDED_KEY_USAGE *eku = NULL;
    GENERAL_NAMES *san = NULL;
    GENERAL_NAME *gen;
    ASN1_OCTET_STRING *skid = NULL;
    static const struct {
        int type;
        const char *value;
    } names[] = {
        { GEN_DNS, "a.example" },
        { GEN_DNS, "*.wild.example" },
        { GEN_EMAIL, "user@example" },
        { GEN_IPADD, "192.0.2.1" }
    };
    size_t i;

    if (!TEST_ptr(cert = X509_new())
        || !TEST_true(X509_set_version(cert, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(cert), 256))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"x509_view test", -1, -1, 0))
        || !TEST_true(X509_set_issuer_name(cert, name))
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(ASN1_TIME_set_string(X509_getm_notBefore(cert),
            "210101000000Z"))
        || !TEST_true(ASN1_TIME_set_string(X509_getm_notAfter(cert),
            "310101000000Z"))
        || !TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))
        || !TEST_true(X509_set_pubkey(cert, pkey)))
        goto err;

    if (!TEST_ptr(bc = BASIC_CONSTRAINTS_new()))
        goto err;
    bc->ca = ca ? 0xff : 0;
    if (!TEST_true(X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 1, 0)))
        goto err;

    if (!TEST_ptr(ku = ASN1_BIT_STRING_new())
        || !TEST_true(ASN1_BIT_STRING_set_bit(ku, 0, 1))
        || !TEST_true(X509_add1_ext_i2d(cert, NID_key_usage, ku, 1, 0)))
        goto err;

    if (!TEST_ptr(eku = sk_ASN1_OBJECT_new_null())
        || !TEST_true(sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_server_auth)))
        || !TEST_true(X509_add1_ext_i2d(cert, NID_ext_key_usage, eku, 0, 0)))
        goto err;

    if (!TEST_ptr(san = sk_GENERAL_NAME_new_null()))
        goto err;
    for (i = 0; i < OSSL_NELEM(names); i++) {
        if (!TEST_ptr(gen = a2i_GENERAL_NAME(NULL, NULL, NULL, names[i].type,
                          names[i].value, 0)))
            goto err;
        if (!TEST_true(sk_GENERAL_NAME_push(san, gen))) {
            GENERAL_NAME_free(gen);
            goto err;
        }
    }
    if (!TEST_true(X509_add1_ext_i2d(cert, NID_subject_alt_name, san, 0, 0)))
        goto err;

    if (!TEST_ptr(skid = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(skid,
            (const unsigned char *)"skid", 4))
        || !TEST_true(X509_add1_ext_i2d(cert, NID_subject_key_identifier,
            skid, 0, 0))
        || !TEST_int_gt(X509_sign(cert, pkey, NULL), 0))
        goto err;

    ret = cert;
    cert = NULL;

err:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    X509_NAME_free(name);
    BASIC_CONSTRAINTS_free(bc);
    ASN1_BIT_STRING_free(ku);
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    GENERAL_NAMES_free(san);
    ASN1_OCTET_STRING_free(skid);
    return ret;
}

static uint8_t *cert_der(X509 *cert, size_t *out_len)
{
    uint8_t *der = NULL;
    int len;

    *out_len = 0;
    if (!TEST_int_gt(len = i2d_X509(cert, &der), 0))
        return NULL;
    *out_len = (size_t)len;
    return der;
}

static int set_raw_extension(X509 *x509, int nid, const uint8_t *bytes,
    size_t len)
{
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *value = NULL;
    int idx, ret = 0;

    if ((idx = X509_get_ext_by_NID(x509, nid, -1)) >= 0)
        X509_EXTENSION_free(X509_delete_ext(x509, idx));
    if (!TEST_ptr(value = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(value, bytes, (int)len))
        || !TEST_ptr(ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, value))
        || !TEST_true(X509_add_ext(x509, ext, -1)))
        goto err;
    ret = 1;

err:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(value);
    return ret;
}

/* Leaves x509 with no Extensions field. */
static void delete_extensions(X509 *x509)
{
    sk_X509_EXTENSION_pop_free(x509->cert_info.extensions,
        X509_EXTENSION_free);
    x509->cert_info.extensions = NULL;
    x509->cert_info.enc.modified = 1;
}

/* Encodes version in the version field when present, else omits it. */
static int set_version_field(X509 *x509, int present, long version)
{
    ASN1_INTEGER_free(x509->cert_info.version);
    x509->cert_info.version = NULL;
    x509->cert_info.enc.modified = 1;
    if (!present)
        return 1;

    return TEST_ptr(x509->cert_info.version = ASN1_INTEGER_new())
        && TEST_true(ASN1_INTEGER_set(x509->cert_info.version, version));
}

/* Whether the view holds any field of the extension with the given NID. */
static int view_has_extension(const struct x509_view *view, int nid)
{
    CBS cbs;
    uint32_t usage;

    switch (nid) {
    case NID_basic_constraints:
        return view->has_basic_constraints;
    case NID_key_usage:
        return x509_view_key_usage(view, &usage);
    case NID_ext_key_usage:
        return x509_view_ext_key_usage(view, &usage);
    case NID_subject_alt_name:
        return x509_view_get_san(view, &cbs);
    case NID_subject_key_identifier:
        return x509_view_get_skid(view, &cbs);
    case NID_name_constraints:
        return x509_view_get_name_constraints(view, &cbs);
    case NID_authority_key_identifier:
        return view->has_akid || x509_view_get_akid_keyid(view, &cbs)
            || x509_view_get_akid_issuer(view, &cbs)
            || x509_view_get_akid_serial(view, &cbs);
    }
    return -1;
}

static int test_fixture(void)
{
    X509 *x509;
    struct x509_view cert;
    CBS cbs;
    uint8_t *der = NULL;
    size_t der_len;
    uint32_t usage;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int_eq(x509_view_version(&cert), 2)
        || !TEST_true(x509_view_get_serial(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs), "\x02\x02\x01\x00", 4)
        || !TEST_true(x509_view_get_not_before(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs),
            "\x17\x0d"
            "210101000000Z",
            15)
        || !TEST_true(cert.has_basic_constraints)
        || !TEST_false(x509_view_is_ca(&cert))
        || !TEST_true(x509_view_key_usage(&cert, &usage))
        || !TEST_uint_eq(usage, KU_DIGITAL_SIGNATURE)
        || !TEST_true(x509_view_ext_key_usage(&cert, &usage))
        || !TEST_uint_eq(usage, XKU_SSL_SERVER)
        || !TEST_true(x509_view_get_san(&cert, &cbs))
        || !TEST_size_t_eq(cert.san_count, 4)
        || !TEST_false(x509_view_has_unhandled_critical(&cert))
        || !TEST_false(x509_view_has_malformed_extension(&cert))
        || !TEST_false(x509_view_get_issuer_uid(&cert, &cbs))
        || !TEST_false(x509_view_get_subject_uid(&cert, &cbs))
        || !TEST_true(x509_view_get_signature(&cert, &cbs))
        || !TEST_size_t_eq(CBS_len(&cbs), 67)
        || !TEST_mem_eq(CBS_data(&cbs), 3, "\x03\x41\x00", 3)
        || !TEST_true(x509_view_sig_algs_match(&cert))
        || !TEST_int_eq(x509_view_sig_nid(&cert), NID_ED25519)
        || !TEST_true(x509_view_get_tbs(&cert, &cbs))
        || !TEST_ptr_eq(CBS_data(&cbs), der + 4)
        || !TEST_true(CBS_peek_asn1_tag(&cbs, CBS_ASN1_SEQUENCE))
        || !TEST_true(CBS_data(&cert.extensions) >= CBS_data(&cbs))
        || !TEST_ptr_eq(CBS_data(&cert.extensions) + CBS_len(&cert.extensions),
            CBS_data(&cbs) + CBS_len(&cbs))
        || !TEST_true(CBS_peek_asn1_tag(&cert.extensions, CBS_ASN1_SEQUENCE)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int test_truncation(void)
{
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len, i;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len)))
        goto err;
    for (i = 0; i < der_len; i++) {
        if (!TEST_false(x509_view_parse(der, i, &cert))) {
            TEST_info("%zu of %zu bytes accepted", i, der_len);
            goto err;
        }
    }
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int test_trailing_octet(void)
{
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL, *copy = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_ptr(copy = OPENSSL_zalloc(der_len + 1)))
        goto err;
    memcpy(copy, der, der_len);
    if (!TEST_false(x509_view_parse(copy, der_len + 1, &cert)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(copy);
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/*
 * A byte patch: the one occurrence of pattern in the fixture's DER is
 * replaced by the same number of bytes from replacement.  The result is
 * rejected unless want_accept is set.
 */
static const uint8_t serial[] = { 0x02, 0x02, 0x01, 0x00 };
static const uint8_t serial_padded[] = { 0x02, 0x02, 0x00, 0x00 };
static const uint8_t serial_padded_negative[] = { 0x02, 0x02, 0xff, 0x80 };
static const uint8_t serial_negative[] = { 0x02, 0x02, 0x80, 0x00 };
static const uint8_t critical[] = { 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff };
static const uint8_t critical_ber[] = { 0x55, 0x1d, 0x13, 0x01, 0x01, 0x01 };
static const uint8_t ca[] = { 0x30, 0x03, 0x01, 0x01, 0xff };
static const uint8_t ca_ber[] = { 0x30, 0x03, 0x01, 0x01, 0x01 };
static const uint8_t key_usage[] = { 0x03, 0x02, 0x07, 0x80 };
static const uint8_t key_usage_unused_bit[] = { 0x03, 0x02, 0x07, 0x81 };
static const uint8_t dns[] = { 0x82, 0x09, 'a', '.', 'e' };
static const uint8_t dns_constructed[] = { 0xa2, 0x09, 'a', '.', 'e' };
static const uint8_t time_utc[] = "\x17\x0d"
                                  "210101000000Z";
static const uint8_t time_bad_day[] = "\x17\x0d"
                                      "210230000000Z";
static const uint8_t time_bad_hour[] = "\x17\x0d"
                                       "210101240000Z";
static const uint8_t time_bad_second[] = "\x17\x0d"
                                         "210101000060Z";
static const uint8_t time_no_z[] = "\x17\x0d"
                                   "2101010000000";
static const uint8_t time_not_digit[] = "\x17\x0d"
                                        "2101010000a0Z";

static const struct patch_test {
    const char *name;
    int ca;
    const uint8_t *pattern;
    const uint8_t *replacement;
    size_t len;
    int want_accept;
    int want_malformed;
} patch_tests[] = {
    { "padded serial", 0, serial, serial_padded, sizeof(serial), 0, 0 },
    { "padded negative serial", 0, serial, serial_padded_negative,
        sizeof(serial), 0, 0 },
    { "negative serial", 0, serial, serial_negative, sizeof(serial), 1, 0 },
    { "BER critical", 0, critical, critical_ber, sizeof(critical), 0, 0 },
    { "BER cA", 1, ca, ca_ber, sizeof(ca), 1, 1 },
    { "keyUsage unused bit set", 0, key_usage, key_usage_unused_bit,
        sizeof(key_usage), 1, 1 },
    { "constructed dNSName", 0, dns, dns_constructed, sizeof(dns), 1, 1 },
    { "notBefore February 30", 0, time_utc, time_bad_day,
        sizeof(time_utc) - 1, 0, 0 },
    { "notBefore hour 24", 0, time_utc, time_bad_hour, sizeof(time_utc) - 1,
        0, 0 },
    { "notBefore second 60", 0, time_utc, time_bad_second,
        sizeof(time_utc) - 1, 0, 0 },
    { "notBefore without Z", 0, time_utc, time_no_z, sizeof(time_utc) - 1, 0,
        0 },
    { "notBefore non-digit", 0, time_utc, time_not_digit,
        sizeof(time_utc) - 1, 0, 0 }
};

static int test_patch(int idx)
{
    const struct patch_test *pt = &patch_tests[idx];
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len, off, found = 0, count = 0;
    int ret = 0;

    TEST_info("%s", pt->name);
    if (!TEST_ptr(x509 = make_cert(pt->ca))
        || !TEST_ptr(der = cert_der(x509, &der_len)))
        goto err;
    for (off = 0; off + pt->len <= der_len; off++) {
        if (memcmp(der + off, pt->pattern, pt->len) == 0) {
            found = off;
            count++;
        }
    }
    if (!TEST_size_t_eq(count, 1))
        goto err;
    memcpy(der + found, pt->replacement, pt->len);
    if (!pt->want_accept) {
        if (!TEST_false(x509_view_parse(der, der_len, &cert)))
            goto err;
    } else if (!TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int_eq(x509_view_has_malformed_extension(&cert),
            pt->want_malformed)) {
        goto err;
    }
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/* An extension of the fixture replaced by one with a given extnValue. */
static const uint8_t path_len_no_ca[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
static const uint8_t path_len_negative[] = {
    0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0xff
};
static const uint8_t ca_path_len[] = {
    0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00
};
static const uint8_t eku_empty[] = { 0x30, 0x00 };
static const uint8_t skid_trailing[] = { 0x04, 0x04, 's', 'k', 'i', 'd', 0x00 };
static const uint8_t akid_trailing[] = {
    0x30, 0x06, 0x80, 0x04, 'a', 'k', 'i', 'd', 0x00
};
static const uint8_t san_empty[] = { 0x30, 0x00 };

static const struct raw_extension_test {
    const char *name;
    int nid;
    const uint8_t *value;
    size_t len;
    int want_malformed;
    int want_ca;
} raw_extension_tests[] = {
    { "pathLen without cA", NID_basic_constraints, path_len_no_ca,
        sizeof(path_len_no_ca), 1, 0 },
    { "negative pathLen", NID_basic_constraints, path_len_negative,
        sizeof(path_len_negative), 1, 0 },
    { "cA with pathLen", NID_basic_constraints, ca_path_len,
        sizeof(ca_path_len), 0, 1 },
    { "empty extendedKeyUsage", NID_ext_key_usage, eku_empty,
        sizeof(eku_empty), 1, 0 },
    { "subjectKeyIdentifier trailing octet", NID_subject_key_identifier,
        skid_trailing, sizeof(skid_trailing), 1, 0 },
    { "authorityKeyIdentifier trailing octet", NID_authority_key_identifier,
        akid_trailing, sizeof(akid_trailing), 1, 0 },
    { "empty subjectAltName", NID_subject_alt_name, san_empty,
        sizeof(san_empty), 0, 0 }
};

static int test_raw_extension(int idx)
{
    const struct raw_extension_test *rt = &raw_extension_tests[idx];
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    TEST_info("%s", rt->name);
    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_true(set_raw_extension(x509, rt->nid, rt->value, rt->len))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int_eq(x509_view_has_malformed_extension(&cert),
            rt->want_malformed)
        || !TEST_int_ne(view_has_extension(&cert, rt->nid), rt->want_malformed)
        || !TEST_int_eq(x509_view_is_ca(&cert), rt->want_ca))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/* A version field as encoded, and the version x509_view reports. */
static const struct version_test {
    const char *name;
    int present;
    long encoded;
    int extensions;
    int want_accept;
    int want_version;
} version_tests[] = {
    { "v1", 0, 0, 0, 1, 0 },
    { "encoded v1", 1, 0, 0, 0, 0 },
    { "v2", 1, 1, 0, 1, 1 },
    { "v3 without extensions", 1, 2, 0, 1, 2 },
    { "v4", 1, 3, 0, 0, 0 },
    { "negative version", 1, -1, 0, 0, 0 },
    { "v1 with extensions", 0, 0, 1, 0, 0 },
    { "v2 with extensions", 1, 1, 1, 0, 0 }
};

static int test_version(int idx)
{
    const struct version_test *vt = &version_tests[idx];
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    TEST_info("%s", vt->name);
    if (!TEST_ptr(x509 = make_cert(0)))
        goto err;
    if (!vt->extensions)
        delete_extensions(x509);
    if (!TEST_true(set_version_field(x509, vt->present, vt->encoded))
        || !TEST_ptr(der = cert_der(x509, &der_len)))
        goto err;
    if (!vt->want_accept) {
        if (!TEST_false(x509_view_parse(der, der_len, &cert)))
            goto err;
    } else if (!TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int_eq(x509_view_version(&cert), vt->want_version)) {
        goto err;
    }
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/* Serials of 20 and 21 octets, the RFC 5280 limit and one over. */
static int set_serial_bit(X509 *x509, BIGNUM *bn, int bit)
{
    ASN1_INTEGER *aint;
    int ret;

    if (!TEST_true(BN_set_bit(bn, bit))
        || !TEST_ptr(aint = BN_to_ASN1_INTEGER(bn, NULL)))
        return 0;
    ret = TEST_true(X509_set_serialNumber(x509, aint));
    ASN1_INTEGER_free(aint);
    return ret;
}

static int test_serial_length(void)
{
    X509 *x509;
    struct x509_view cert;
    BIGNUM *bn = NULL;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(bn = BN_new())
        || !set_serial_bit(x509, bn, 20 * 8 - 2)
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_size_t_eq(CBS_len(&cert.serial), 22))
        goto err;
    OPENSSL_free(der);
    der = NULL;
    if (!set_serial_bit(x509, bn, 21 * 8 - 2)
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_size_t_eq(CBS_len(&cert.serial), 23))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    BN_free(bn);
    X509_free(x509);
    return ret;
}

static int test_unique_ids(void)
{
    X509 *x509;
    struct x509_view cert;
    ASN1_BIT_STRING *uid = NULL;
    CBS cbs;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(uid = ASN1_BIT_STRING_new())
        || !TEST_true(ASN1_BIT_STRING_set_bit(uid, 1, 1))
        || !TEST_true(ASN1_BIT_STRING_set_bit(uid, 2, 1))
        || !TEST_true(ASN1_BIT_STRING_set_bit(uid, 3, 1))
        || !TEST_true(ASN1_BIT_STRING_set_bit(uid, 5, 1))
        || !TEST_true(ASN1_BIT_STRING_set_bit(uid, 7, 1)))
        goto err;

    x509->cert_info.issuerUID = uid;
    x509->cert_info.enc.modified = 1;
    if (!TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_get_issuer_uid(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs), "\x81\x02\x00u", 4)
        || !TEST_false(x509_view_get_subject_uid(&cert, &cbs)))
        goto err;
    OPENSSL_free(der);
    der = NULL;
    x509->cert_info.issuerUID = NULL;

    x509->cert_info.subjectUID = uid;
    x509->cert_info.enc.modified = 1;
    if (!TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_get_subject_uid(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs), "\x82\x02\x00u", 4)
        || !TEST_false(x509_view_get_issuer_uid(&cert, &cbs)))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    delete_extensions(x509);
    if (!TEST_true(set_version_field(x509, 1, 1))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert)))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    if (!TEST_true(set_version_field(x509, 0, 0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_false(x509_view_parse(der, der_len, &cert)))
        goto err;
    ret = 1;

err:
    if (x509 != NULL) {
        x509->cert_info.issuerUID = NULL;
        x509->cert_info.subjectUID = NULL;
    }
    OPENSSL_free(der);
    ASN1_BIT_STRING_free(uid);
    X509_free(x509);
    return ret;
}

static int test_duplicate_extension(void)
{
    X509 *x509;
    struct x509_view cert;
    const X509_EXTENSION *ext;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(ext = X509_get_ext(x509,
                         X509_get_ext_by_NID(x509, NID_subject_key_identifier,
                             -1)))
        || !TEST_true(X509_add_ext(x509, ext, -1))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_has_malformed_extension(&cert))
        || !TEST_false(view_has_extension(&cert, NID_subject_key_identifier))
        || !TEST_true(view_has_extension(&cert, NID_subject_alt_name)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static X509_EXTENSION *make_extension(const char *oid, int crit)
{
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *value = NULL;

    if (TEST_ptr(obj = OBJ_txt2obj(oid, 1))
        && TEST_ptr(value = ASN1_OCTET_STRING_new())
        && TEST_true(ASN1_OCTET_STRING_set(value,
            (const unsigned char *)"\x05\x00", 2)))
        ext = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, value);
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(value);
    return ext;
}

static int parse_with_extension(const char *oid, int crit,
    struct x509_view *cert)
{
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(ext = make_extension(oid, crit))
        || !TEST_ptr(x509 = make_cert(0))
        || !TEST_true(X509_add_ext(x509, ext, -1))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, cert)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    X509_EXTENSION_free(ext);
    return ret;
}

static int test_unknown_extension(void)
{
    struct x509_view cert;

    return parse_with_extension("1.3.6.1.4.1.32473.99", 0, &cert)
        && TEST_false(cert.has_unhandled_critical)
        && parse_with_extension("1.3.6.1.4.1.32473.99", 1, &cert)
        && TEST_true(cert.has_unhandled_critical);
}

#define X509_VIEW_EXT_ALL                                  \
    (X509_VIEW_EXT_NAME_CONSTRAINTS | X509_VIEW_EXT_POLICY \
        | X509_VIEW_EXT_IP_ADDR_BLOCKS | X509_VIEW_EXT_AUTONOMOUS_SYS_IDS)

static const struct extensions_present_test {
    const char *name;
    const char *oid;
    uint32_t bit;
    int parsed;
} extensions_present_tests[] = {
    { "nameConstraints", "2.5.29.30", X509_VIEW_EXT_NAME_CONSTRAINTS, 1 },
    { "certificatePolicies", "2.5.29.32", X509_VIEW_EXT_CERTIFICATE_POLICIES,
        0 },
    { "policyMappings", "2.5.29.33", X509_VIEW_EXT_POLICY_MAPPINGS, 0 },
    { "policyConstraints", "2.5.29.36", X509_VIEW_EXT_POLICY_CONSTRAINTS, 0 },
    { "inhibitAnyPolicy", "2.5.29.54", X509_VIEW_EXT_INHIBIT_ANY_POLICY, 0 },
    { "ipAddrBlocks", "1.3.6.1.5.5.7.1.7", X509_VIEW_EXT_IP_ADDR_BLOCKS, 0 },
    { "autonomousSysIds", "1.3.6.1.5.5.7.1.8",
        X509_VIEW_EXT_AUTONOMOUS_SYS_IDS, 0 }
};

/*
 * Checks the X509_VIEW_EXT_ bit, criticality and malformed handling of the
 * extension in extensions_present_tests[idx].
 */
static int test_extensions_present(int idx)
{
    const struct extensions_present_test *et = &extensions_present_tests[idx];
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len;
    int crit, ret = 0;

    TEST_info("%s", et->name);
    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_uint_eq(x509_view_extensions_present(&cert, X509_VIEW_EXT_ALL),
            0))
        goto err;
    for (crit = 0; crit <= 1; crit++) {
        if (!parse_with_extension(et->oid, crit, &cert)
            || !TEST_uint_eq(x509_view_extensions_present(&cert,
                                 X509_VIEW_EXT_ALL),
                et->bit)
            || !TEST_false(x509_view_has_unhandled_critical(&cert))
            || !TEST_int_eq(x509_view_has_malformed_extension(&cert),
                et->parsed))
            goto err;
    }
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/*
 * The fixture with every occurrence of the Ed25519 OID, in the signature
 * algorithms and the key, replaced by replacement.
 */
static int parse_with_sig_oid(const uint8_t *replacement)
{
    static const uint8_t ed25519_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len, off, count = 0;
    int ret = -1;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len)))
        goto err;
    for (off = 0; off + sizeof(ed25519_oid) <= der_len; off++) {
        if (memcmp(der + off, ed25519_oid, sizeof(ed25519_oid)) == 0) {
            memcpy(der + off, replacement, sizeof(ed25519_oid));
            count++;
        }
    }
    if (!TEST_size_t_eq(count, 3))
        goto err;
    ret = x509_view_parse(der, der_len, &cert);

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int test_sig_oid(void)
{
    static const uint8_t unknown[] = { 0x06, 0x03, 0x2b, 0x65, 0x7f };
    static const uint8_t last_continued[] = { 0x06, 0x03, 0x2b, 0x65, 0xf0 };
    static const uint8_t leading_0x80[] = { 0x06, 0x03, 0x2b, 0x80, 0x70 };

    return TEST_int_eq(parse_with_sig_oid(unknown), 1)
        && TEST_int_eq(parse_with_sig_oid(last_continued), 0)
        && TEST_int_eq(parse_with_sig_oid(leading_0x80), 0);
}

static int test_no_extensions(void)
{
    X509 *x509;
    struct x509_view cert;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0)))
        goto err;
    delete_extensions(x509);
    if (!TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_false(x509_view_has_malformed_extension(&cert))
        || !TEST_false(view_has_extension(&cert, NID_basic_constraints)))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    if (!TEST_ptr(x509->cert_info.extensions = sk_X509_EXTENSION_new_null()))
        goto err;
    x509->cert_info.enc.modified = 1;
    if (!TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_has_malformed_extension(&cert)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int test_times(void)
{
    X509 *x509;
    struct x509_view cert;
    CBS cbs;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int64_t_eq(x509_view_not_before_posix(&cert), 1609459200)
        || !TEST_int64_t_eq(x509_view_not_after_posix(&cert), 1924992000))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    if (!TEST_true(ASN1_TIME_set_string(X509_getm_notBefore(x509),
            "20210101000000Z"))
        || !TEST_true(ASN1_TIME_set_string(X509_getm_notAfter(x509),
            "20310101000000Z")))
        goto err;
    x509->cert_info.enc.modified = 1;
    if (!TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_get_not_before(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs),
            "\x18\x0f"
            "20210101000000Z",
            17)
        || !TEST_true(x509_view_get_not_after(&cert, &cbs))
        || !TEST_mem_eq(CBS_data(&cbs), CBS_len(&cbs),
            "\x18\x0f"
            "20310101000000Z",
            17)
        || !TEST_int64_t_eq(x509_view_not_before_posix(&cert), 1609459200)
        || !TEST_int64_t_eq(x509_view_not_after_posix(&cert), 1924992000))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/* A nameConstraints with the given extnValue added to the CA fixture. */
static const uint8_t nc_permitted[] = {
    0x30, 0x0d, 0xa0, 0x0b, 0x30, 0x09,
    0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'
};
static const uint8_t nc_excluded_bounds[] = {
    0x30, 0x10, 0xa1, 0x0e, 0x30, 0x0c,
    0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x80, 0x01, 0x00
};
static const uint8_t nc_empty[] = { 0x30, 0x00 };
static const uint8_t nc_no_name[] = {
    0x30, 0x07, 0xa0, 0x05, 0x30, 0x03, 0x80, 0x01, 0x00
};
static const uint8_t nc_out_of_order[] = {
    0x30, 0x1a,
    0xa1, 0x0b, 0x30, 0x09, 0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0xa0, 0x0b, 0x30, 0x09, 0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'
};
static const uint8_t nc_bad_bound[] = {
    0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0c,
    0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x82, 0x01, 0x00
};
static const uint8_t nc_trailing[] = {
    0x30, 0x0d, 0xa0, 0x0b, 0x30, 0x09,
    0x82, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00
};

static const struct name_constraints_test {
    const char *name;
    const uint8_t *value;
    size_t len;
    int want_malformed;
} name_constraints_tests[] = {
    { "nameConstraints permitted", nc_permitted, sizeof(nc_permitted), 0 },
    { "nameConstraints excluded with minimum", nc_excluded_bounds,
        sizeof(nc_excluded_bounds), 0 },
    { "nameConstraints empty", nc_empty, sizeof(nc_empty), 0 },
    { "nameConstraints subtree without name", nc_no_name, sizeof(nc_no_name),
        1 },
    { "nameConstraints excluded before permitted", nc_out_of_order,
        sizeof(nc_out_of_order), 1 },
    { "nameConstraints bound with tag 2", nc_bad_bound, sizeof(nc_bad_bound),
        1 },
    { "nameConstraints trailing octet", nc_trailing, sizeof(nc_trailing), 1 }
};

static int test_name_constraints(int idx)
{
    const struct name_constraints_test *nt = &name_constraints_tests[idx];
    X509 *x509;
    struct x509_view cert;
    CBS nc;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    TEST_info("%s", nt->name);
    if (!TEST_ptr(x509 = make_cert(1))
        || !TEST_true(set_raw_extension(x509, NID_name_constraints, nt->value,
            nt->len))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_int_eq(x509_view_has_malformed_extension(&cert),
            nt->want_malformed))
        goto err;
    if (nt->want_malformed) {
        if (!TEST_false(x509_view_get_name_constraints(&cert, &nc)))
            goto err;
    } else if (!TEST_true(x509_view_get_name_constraints(&cert, &nc))
        || !TEST_mem_eq(CBS_data(&nc), CBS_len(&nc), nt->value, nt->len)) {
        goto err;
    }
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int test_no_name_constraints(void)
{
    X509 *x509;
    struct x509_view cert;
    CBS nc;
    uint8_t *der = NULL;
    size_t der_len;
    int ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_false(x509_view_get_name_constraints(&cert, &nc)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

static int next_name_is(CBS *names, int want_type, const void *want,
    size_t want_len)
{
    CBS name;
    int type;

    return TEST_true(x509_view_next_general_name(names, &type, &name))
        && TEST_int_eq(type, want_type)
        && TEST_mem_eq(CBS_data(&name), CBS_len(&name), want, want_len);
}

static int test_general_names(void)
{
    static const uint8_t ip_example[] = { 192, 0, 2, 1 };
    X509 *x509;
    struct x509_view cert;
    CBS san, names, name;
    uint8_t *der = NULL;
    size_t der_len;
    int type, ret = 0;

    if (!TEST_ptr(x509 = make_cert(0))
        || !TEST_ptr(der = cert_der(x509, &der_len))
        || !TEST_true(x509_view_parse(der, der_len, &cert))
        || !TEST_true(x509_view_get_san(&cert, &san))
        || !TEST_true(CBS_get_asn1(&san, &names, CBS_ASN1_SEQUENCE))
        || !next_name_is(&names, GEN_DNS, "a.example", 9)
        || !next_name_is(&names, GEN_DNS, "*.wild.example", 14)
        || !next_name_is(&names, GEN_EMAIL, "user@example", 12)
        || !next_name_is(&names, GEN_IPADD, ip_example, sizeof(ip_example))
        || !TEST_false(x509_view_next_general_name(&names, &type, &name))
        || !TEST_size_t_eq(CBS_len(&names), 0))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    X509_free(x509);
    return ret;
}

/*
 * The extensions x509_view parses, by NID; a critical extension outside
 * this set is unhandled for x509_view whether or not X509 supports it.
 */
static const int handled_nids[] = {
    NID_basic_constraints,
    NID_key_usage,
    NID_ext_key_usage,
    NID_subject_alt_name,
    NID_subject_key_identifier,
    NID_authority_key_identifier,
    NID_name_constraints
};

static int has_unhandled_critical(const X509 *x509)
{
    const X509_EXTENSION *ext;
    size_t j;
    int i, nid;

    for (i = 0; i < X509_get_ext_count(x509); i++) {
        ext = X509_get_ext(x509, i);
        if (!X509_EXTENSION_get_critical(ext))
            continue;
        nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
        for (j = 0; j < OSSL_NELEM(handled_nids); j++) {
            if (nid == handled_nids[j])
                break;
        }
        if (j == OSSL_NELEM(handled_nids))
            return 1;
    }
    return 0;
}

/* Compares a getter's field with an encoding of the X509 field. */
static int compare_element(const char *what, int got, const CBS *field,
    const uint8_t *der, int der_len)
{
    if (!TEST_true(got) || der_len < 0
        || !TEST_mem_eq(CBS_data(field), CBS_len(field), der,
            (size_t)der_len)) {
        TEST_info("%s differs from X509", what);
        return 0;
    }
    return 1;
}

/*
 * Compares the contents of a getter's field, which has the given tag,
 * with the bytes of the X509 field.
 */
static int compare_bytes(const char *what, int got, const CBS *field,
    unsigned int tag, const ASN1_STRING *want)
{
    CBS cbs, contents;

    if (!TEST_int_eq(got, want != NULL)) {
        TEST_info("%s presence differs", what);
        return 0;
    }
    if (!got)
        return 1;
    CBS_dup(field, &cbs);
    if (!TEST_true(CBS_get_asn1(&cbs, &contents, tag))
        || !TEST_size_t_eq(CBS_len(&cbs), 0)
        || !TEST_mem_eq(CBS_data(&contents), CBS_len(&contents),
            ASN1_STRING_get0_data(want), ASN1_STRING_get_length(want))) {
        TEST_info("%s differs from X509", what);
        return 0;
    }
    return 1;
}

/*
 * Walks the names, a SEQUENCE OF GeneralName, alongside X509's decoding of
 * them, comparing type and, for the string forms, value.
 */
static int compare_general_names(const CBS *general_names,
    const GENERAL_NAMES *gens)
{
    const GENERAL_NAME *gen;
    const ASN1_STRING *str;
    CBS seq, cbs, name;
    int type, i = 0;

    CBS_dup(general_names, &seq);
    if (!TEST_true(CBS_get_asn1(&seq, &cbs, CBS_ASN1_SEQUENCE)))
        return 0;
    while (CBS_len(&cbs) > 0) {
        if (!TEST_true(x509_view_next_general_name(&cbs, &type, &name))
            || !TEST_ptr(gen = sk_GENERAL_NAME_value(gens, i))
            || !TEST_int_eq(type, gen->type))
            return 0;
        switch (type) {
        case GEN_EMAIL:
        case GEN_DNS:
        case GEN_URI:
            str = gen->d.ia5;
            break;
        case GEN_IPADD:
            str = gen->d.ip;
            break;
        default:
            str = NULL;
            break;
        }
        if (str != NULL
            && !TEST_mem_eq(CBS_data(&name), CBS_len(&name),
                ASN1_STRING_get0_data(str), ASN1_STRING_get_length(str)))
            return 0;
        i++;
    }
    return TEST_int_eq(i, sk_GENERAL_NAME_num(gens));
}

/*
 * Walks the extensions slice alongside X509's decoding of the extensions,
 * comparing OID, criticality and value.
 */
static int compare_extensions(const X509 *x509, const struct x509_view *cert)
{
    const X509_EXTENSION *ext;
    const ASN1_OBJECT *want_oid;
    const ASN1_OCTET_STRING *want_value;
    CBS extensions, cbs, oid, value;
    int is_critical, i = 0;

    if (CBS_len(&cert->extensions) == 0)
        return TEST_int_eq(X509_get_ext_count(x509), 0);
    CBS_dup(&cert->extensions, &extensions);
    if (!TEST_true(CBS_get_asn1(&extensions, &cbs, CBS_ASN1_SEQUENCE)))
        return 0;
    while (CBS_len(&cbs) > 0) {
        if (!TEST_true(x509_view_next_extension(&cbs, &oid, &is_critical,
                &value))
            || !TEST_ptr(ext = X509_get_ext(x509, i)))
            return 0;
        want_oid = X509_EXTENSION_get_object(ext);
        want_value = X509_EXTENSION_get_data(ext);
        if (!TEST_mem_eq(CBS_data(&oid), CBS_len(&oid),
                OBJ_get0_data(want_oid), OBJ_length(want_oid))
            || !TEST_int_eq(is_critical, X509_EXTENSION_get_critical(ext))
            || !TEST_mem_eq(CBS_data(&value), CBS_len(&value),
                ASN1_STRING_get0_data(want_value),
                ASN1_STRING_get_length(want_value)))
            return 0;
        i++;
    }
    return TEST_int_eq(i, X509_get_ext_count(x509));
}

/* Compares each getter with the X509 accessor it stands in for. */
static int compare_getters(X509 *x509, const struct x509_view *view)
{
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *tbs_alg, *alg;
    GENERAL_NAMES *san = NULL;
    NAME_CONSTRAINTS *nc = NULL;
    ASN1_OCTET_STRING *skid = NULL;
    AUTHORITY_KEYID *akid = NULL;
    CBS cbs, issuer_contents, want_contents;
    uint8_t *der = NULL, *der2 = NULL;
    int64_t path_len;
    int len, len2, got, ret = 0;

    len = i2d_X509_CINF(&x509->cert_info, &der);
    if (!compare_element("tbs", x509_view_get_tbs(view, &cbs), &cbs, der, len))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    len = i2d_ASN1_INTEGER(X509_get0_serialNumber(x509), &der);
    if (!compare_element("serial", x509_view_get_serial(view, &cbs), &cbs, der,
            len))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    X509_get0_signature(&sig, &alg, x509);
    tbs_alg = X509_get0_tbs_sigalg(x509);
    len = i2d_X509_ALGOR(tbs_alg, &der);
    len2 = i2d_X509_ALGOR(alg, &der2);
    if (!compare_element("tbs signature algorithm",
            x509_view_get_tbs_sig_alg(view, &cbs), &cbs, der, len)
        || !compare_element("signature algorithm",
            x509_view_get_sig_alg(view, &cbs), &cbs, der2, len2)
        || !TEST_int_eq(x509_view_sig_algs_match(view),
            len == len2 && memcmp(der, der2, (size_t)len) == 0)
        || !TEST_int_eq(x509_view_sig_nid(view), X509_get_signature_nid(x509)))
        goto err;
    OPENSSL_free(der);
    OPENSSL_free(der2);
    der = der2 = NULL;

    len = i2d_ASN1_BIT_STRING(sig, &der);
    if (!compare_element("signature", x509_view_get_signature(view, &cbs), &cbs,
            der, len))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    len = i2d_X509_NAME(X509_get_issuer_name(x509), &der);
    len2 = i2d_X509_NAME(X509_get_subject_name(x509), &der2);
    if (!compare_element("issuer", x509_view_get_issuer(view, &cbs), &cbs, der,
            len)
        || !compare_element("subject", x509_view_get_subject(view, &cbs), &cbs,
            der2, len2)
        || !TEST_int_eq(x509_view_is_self_issued(view),
            len == len2 && memcmp(der, der2, (size_t)len) == 0))
        goto err;
    OPENSSL_free(der);
    OPENSSL_free(der2);
    der = der2 = NULL;

    len = i2d_ASN1_TIME(X509_get0_notBefore(x509), &der);
    len2 = i2d_ASN1_TIME(X509_get0_notAfter(x509), &der2);
    if (!compare_element("notBefore", x509_view_get_not_before(view, &cbs),
            &cbs, der, len)
        || !compare_element("notAfter", x509_view_get_not_after(view, &cbs),
            &cbs, der2, len2))
        goto err;
    OPENSSL_free(der);
    OPENSSL_free(der2);
    der = der2 = NULL;

    len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), &der);
    if (!compare_element("spki", x509_view_get_spki(view, &cbs), &cbs, der,
            len))
        goto err;
    OPENSSL_free(der);
    der = NULL;

    got = x509_view_get_san(view, &cbs);
    san = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (!TEST_int_eq(got, san != NULL))
        goto err;
    if (san != NULL) {
        len = i2d_GENERAL_NAMES(san, &der);
        if (!compare_element("subjectAltName", got, &cbs, der, len)
            || !compare_general_names(&cbs, san))
            goto err;
        OPENSSL_free(der);
        der = NULL;
    }

    got = x509_view_get_name_constraints(view, &cbs);
    nc = X509_get_ext_d2i(x509, NID_name_constraints, NULL, NULL);
    if (!TEST_int_eq(got, nc != NULL))
        goto err;
    if (nc != NULL) {
        len = ASN1_item_i2d((ASN1_VALUE *)nc, &der,
            ASN1_ITEM_rptr(NAME_CONSTRAINTS));
        if (!compare_element("nameConstraints", got, &cbs, der, len))
            goto err;
        OPENSSL_free(der);
        der = NULL;
    }

    got = x509_view_path_len(view, &path_len);
    if (!TEST_int_eq(got, X509_get_pathlen(x509) >= 0)
        || (got && !TEST_true(path_len == X509_get_pathlen(x509))))
        goto err;

    skid = X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
    if (!compare_bytes("subjectKeyIdentifier", x509_view_get_skid(view, &cbs),
            &cbs, CBS_ASN1_OCTETSTRING, skid))
        goto err;
    akid = X509_get_ext_d2i(x509, NID_authority_key_identifier, NULL, NULL);
    if (!compare_bytes("authorityKeyIdentifier keyid",
            x509_view_get_akid_keyid(view, &cbs), &cbs,
            CBS_ASN1_CONTEXT_SPECIFIC | 0, akid != NULL ? akid->keyid : NULL)
        || !compare_bytes("authorityKeyIdentifier serial",
            x509_view_get_akid_serial(view, &cbs), &cbs,
            CBS_ASN1_CONTEXT_SPECIFIC | 2, akid != NULL ? akid->serial : NULL))
        goto err;
    got = x509_view_get_akid_issuer(view, &cbs);
    if (!TEST_int_eq(got, akid != NULL && akid->issuer != NULL))
        goto err;
    if (got) {
        CBS want;

        len = i2d_GENERAL_NAMES(akid->issuer, &der);
        if (!TEST_int_gt(len, 0)
            || !TEST_true(CBS_get_asn1(&cbs, &issuer_contents,
                CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1)))
            goto err;
        CBS_init(&want, der, (size_t)len);
        if (!TEST_true(CBS_get_asn1(&want, &want_contents, CBS_ASN1_SEQUENCE))
            || !TEST_mem_eq(CBS_data(&issuer_contents),
                CBS_len(&issuer_contents), CBS_data(&want_contents),
                CBS_len(&want_contents)))
            goto err;
    }
    ret = 1;

err:
    OPENSSL_free(der);
    OPENSSL_free(der2);
    GENERAL_NAMES_free(san);
    NAME_CONSTRAINTS_free(nc);
    ASN1_OCTET_STRING_free(skid);
    AUTHORITY_KEYID_free(akid);
    return ret;
}

/* Compares a unique identifier with X509's. */
static int compare_uid(const char *what, int got, const CBS *field,
    unsigned int tag, const ASN1_BIT_STRING *uid)
{
    CBS cbs, contents;
    uint8_t *der = NULL;
    CBS want, want_contents;
    int len, ret = 0;

    if (!TEST_int_eq(got, uid != NULL)) {
        TEST_info("%s presence differs", what);
        return 0;
    }
    if (!got)
        return 1;
    len = i2d_ASN1_BIT_STRING(uid, &der);
    CBS_dup(field, &cbs);
    if (!TEST_int_gt(len, 0)
        || !TEST_true(CBS_get_asn1(&cbs, &contents, tag)))
        goto err;
    CBS_init(&want, der, (size_t)len);
    if (!TEST_true(CBS_get_asn1(&want, &want_contents, CBS_ASN1_BITSTRING))
        || !TEST_mem_eq(CBS_data(&contents), CBS_len(&contents),
            CBS_data(&want_contents), CBS_len(&want_contents)))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    return ret;
}

/* Compares a POSIX time with X509's conversion of the time. */
static int compare_time(const char *what, int64_t got, const ASN1_TIME *want)
{
    struct tm tm;
    int64_t want_posix;

    if (!TEST_true(ASN1_TIME_to_tm(want, &tm))
        || !TEST_true(OPENSSL_tm_to_posix(&tm, &want_posix))
        || !TEST_int64_t_eq(got, want_posix)) {
        TEST_info("%s differs from X509", what);
        return 0;
    }
    return 1;
}

/*
 * Compares x509_view's view of a certificate with X509's.  Rejection by
 * x509_view is expected exactly when the version is encoded as v1 or is
 * past v3, a v1 certificate has unique identifiers, or a v1 or v2
 * certificate has extensions.  Extension fields are compared only when
 * X509 finds the extensions valid and x509_view finds none malformed; a
 * malformed one must be invalid for X509 too, where a pathLenConstraint
 * without cA counts as invalid.
 */
static int compare_cert(X509 *x509)
{
    struct x509_view cert;
    const ASN1_BIT_STRING *issuer_uid, *subject_uid;
    GENERAL_NAMES *san;
    CBS cbs;
    uint8_t *der = NULL;
    size_t der_len;
    uint32_t flags, usage;
    long version;
    int accept, want_accept, valid, got, san_count = -1, ret = 0;

    if (!TEST_ptr(der = cert_der(x509, &der_len)))
        return 0;

    X509_get0_uids(x509, &issuer_uid, &subject_uid);
    version = X509_get_version(x509);
    want_accept = version >= 0 && version <= 2
        && !(x509->cert_info.version != NULL && version == 0)
        && !(version == 0 && (issuer_uid != NULL || subject_uid != NULL))
        && !(version != 2 && x509->cert_info.extensions != NULL);
    accept = x509_view_parse(der, der_len, &cert);
    if (!TEST_int_eq(accept, want_accept))
        goto err;
    if (!accept) {
        ret = 1;
        goto err;
    }

    if (!TEST_long_eq(x509_view_version(&cert), version)
        || !compare_uid("issuerUID", x509_view_get_issuer_uid(&cert, &cbs),
            &cbs, CBS_ASN1_CONTEXT_SPECIFIC | 1, issuer_uid)
        || !compare_uid("subjectUID", x509_view_get_subject_uid(&cert, &cbs),
            &cbs, CBS_ASN1_CONTEXT_SPECIFIC | 2, subject_uid))
        goto err;
    if (!compare_time("notBefore", x509_view_not_before_posix(&cert),
            X509_get0_notBefore(x509))
        || !compare_time("notAfter", x509_view_not_after_posix(&cert),
            X509_get0_notAfter(x509)))
        goto err;

    flags = X509_get_extension_flags(x509);
    valid = (flags & EXFLAG_INVALID) == 0;
    /* A pathLenConstraint without cA is malformed (RFC 5280 4.2.1.9). */
    if ((flags & EXFLAG_CA) == 0 && X509_get_pathlen(x509) >= 0)
        valid = 0;
    if (x509_view_has_malformed_extension(&cert)) {
        if (!TEST_false(valid)) {
            TEST_info("malformed extension valid for X509");
            goto err;
        }
        ret = 1;
        goto err;
    }
    if (!valid) {
        ret = 1;
        goto err;
    }

    if (!TEST_int_eq(cert.has_basic_constraints, (flags & EXFLAG_BCONS) != 0)
        || !TEST_int_eq(x509_view_is_ca(&cert), (flags & EXFLAG_CA) != 0))
        goto err;
    got = x509_view_key_usage(&cert, &usage);
    if (!TEST_int_eq(got, (flags & EXFLAG_KUSAGE) != 0)
        || (got && !TEST_uint_eq(usage, X509_get_key_usage(x509))))
        goto err;
    got = x509_view_ext_key_usage(&cert, &usage);
    if (!TEST_int_eq(got, (flags & EXFLAG_XKUSAGE) != 0)
        || (got && !TEST_uint_eq(usage, X509_get_extended_key_usage(x509))))
        goto err;

    if ((san = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL))
        != NULL) {
        san_count = sk_GENERAL_NAME_num(san);
        GENERAL_NAMES_free(san);
    }
    if (cert.has_san && !TEST_int_eq((int)cert.san_count, san_count))
        goto err;

    if (!TEST_int_eq(x509_view_has_unhandled_critical(&cert),
            has_unhandled_critical(x509))
        || !compare_getters(x509, &cert)
        || !compare_extensions(x509, &cert))
        goto err;
    ret = 1;

err:
    OPENSSL_free(der);
    return ret;
}

static STACK_OF(OPENSSL_STRING) *cert_files;

static int string_cmp(const char *const *a, const char *const *b)
{
    return strcmp(*a, *b);
}

static void string_free(char *s)
{
    OPENSSL_free(s);
}

static int test_compare_file(int idx)
{
    const char *file = sk_OPENSSL_STRING_value(cert_files, idx);
    BIO *bio = NULL;
    X509 *x509;
    int index = 0, ret = 1;

    if (!TEST_ptr(file) || !TEST_ptr(bio = BIO_new_file(file, "r")))
        return 0;
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (!compare_cert(x509)) {
            TEST_info("%s: certificate %d", file, index);
            ret = 0;
        }
        index++;
        X509_free(x509);
    }
    ERR_clear_error();
    BIO_free(bio);
    return ret;
}

/* Collects the .pem files in dir into cert_files, in sorted order. */
static int collect_cert_files(const char *dir)
{
    OPENSSL_DIR_CTX *ctx = NULL;
    const char *name;
    char *path;
    size_t len;

    if (!TEST_ptr(cert_files = sk_OPENSSL_STRING_new(string_cmp)))
        return 0;
    while ((name = OPENSSL_DIR_read(&ctx, dir)) != NULL) {
        len = strlen(name);
        if (len < 4 || strcmp(name + len - 4, ".pem") != 0)
            continue;
        if (!TEST_ptr(path = test_mk_file_path(dir, name)))
            break;
        if (!TEST_int_gt(sk_OPENSSL_STRING_push(cert_files, path), 0)) {
            OPENSSL_free(path);
            break;
        }
    }
    OPENSSL_DIR_end(&ctx);
    sk_OPENSSL_STRING_sort(cert_files);
    return name == NULL;
}

OPT_TEST_DECLARE_USAGE("[certs-dir]\n")

int setup_tests(void)
{
    const char *dir;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_TEST(test_fixture);
    ADD_TEST(test_truncation);
    ADD_TEST(test_trailing_octet);
    ADD_ALL_TESTS(test_patch, OSSL_NELEM(patch_tests));
    ADD_ALL_TESTS(test_raw_extension, OSSL_NELEM(raw_extension_tests));
    ADD_ALL_TESTS(test_version, OSSL_NELEM(version_tests));
    ADD_TEST(test_serial_length);
    ADD_TEST(test_unique_ids);
    ADD_TEST(test_duplicate_extension);
    ADD_TEST(test_unknown_extension);
    ADD_ALL_TESTS(test_extensions_present,
        OSSL_NELEM(extensions_present_tests));
    ADD_TEST(test_sig_oid);
    ADD_TEST(test_no_extensions);
    ADD_TEST(test_times);
    ADD_ALL_TESTS(test_name_constraints, OSSL_NELEM(name_constraints_tests));
    ADD_TEST(test_no_name_constraints);
    ADD_TEST(test_general_names);
    if ((dir = test_get_argument(0)) != NULL) {
        if (!collect_cert_files(dir))
            return 0;
        ADD_ALL_TESTS(test_compare_file, sk_OPENSSL_STRING_num(cert_files));
    }
    return 1;
}

void cleanup_tests(void)
{
    sk_OPENSSL_STRING_pop_free(cert_files, string_free);
}
