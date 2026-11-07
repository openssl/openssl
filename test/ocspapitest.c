/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

#include "testutil.h"

static const char *certstr;
static const char *privkeystr;
static const char *eecertstr;
static const char *eekeystr;
static const char *cacertstr;

#ifndef OPENSSL_NO_OCSP
static int get_cert_and_key(X509 **cert_out, EVP_PKEY **key_out)
{
    BIO *certbio, *keybio;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(certbio = BIO_new_file(certstr, "r")))
        return 0;
    cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    BIO_free(certbio);
    if (!TEST_ptr(keybio = BIO_new_file(privkeystr, "r")))
        goto end;
    key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    if (!TEST_ptr(cert) || !TEST_ptr(key))
        goto end;
    *cert_out = cert;
    *key_out = key;
    return 1;
end:
    X509_free(cert);
    EVP_PKEY_free(key);
    return 0;
}

static int get_cert(X509 **cert_out)
{
    BIO *certbio;
    X509 *cert = NULL;

    if (!TEST_ptr(certbio = BIO_new_file(certstr, "r")))
        return 0;
    cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    BIO_free(certbio);
    if (!TEST_ptr(cert))
        goto end;
    *cert_out = cert;
    return 1;
end:
    X509_free(cert);
    return 0;
}

static OCSP_BASICRESP *make_dummy_resp(void)
{
    const unsigned char namestr[] = "openssl.example.com";
    unsigned char keybytes[128] = { 7 };
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_BASICRESP *bs_out = NULL;
    OCSP_CERTID *cid = NULL;
    ASN1_TIME *thisupd = ASN1_TIME_set(NULL, time(NULL));
    ASN1_TIME *nextupd = ASN1_TIME_set(NULL, time(NULL) + 200);
    X509_NAME *name = X509_NAME_new();
    ASN1_BIT_STRING *key = ASN1_BIT_STRING_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();

    if (!TEST_ptr(name)
        || !TEST_ptr(key)
        || !TEST_ptr(serial)
        || !TEST_true(X509_NAME_add_entry_by_NID(name, NID_commonName,
            MBSTRING_ASC,
            namestr, -1, -1, 1))
        || !TEST_true(ASN1_BIT_STRING_set1(key, keybytes, sizeof(keybytes), 0))
        || !TEST_true(ASN1_INTEGER_set_uint64(serial, (uint64_t)1)))
        goto err;
    cid = OCSP_cert_id_new(EVP_sha256(), name, key, serial);
    if (!TEST_ptr(bs)
        || !TEST_ptr(thisupd)
        || !TEST_ptr(nextupd)
        || !TEST_ptr(cid)
        || !TEST_true(OCSP_basic_add1_status(bs, cid,
            V_OCSP_CERTSTATUS_UNKNOWN,
            0, NULL, thisupd, nextupd)))
        goto err;
    bs_out = bs;
    bs = NULL;
err:
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    ASN1_BIT_STRING_free(key);
    ASN1_INTEGER_free(serial);
    OCSP_CERTID_free(cid);
    OCSP_BASICRESP_free(bs);
    X509_NAME_free(name);
    return bs_out;
}

static int test_resp_signer(void)
{
    OCSP_BASICRESP *bs = NULL;
    X509 *signer = NULL, *tmp;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *extra_certs = NULL;
    int ret = 0;

    /*
     * Test a response with no certs at all; get the signer from the
     * extra certs given to OCSP_resp_get0_signer().
     */
    bs = make_dummy_resp();
    extra_certs = sk_X509_new_null();
    if (!TEST_ptr(bs)
        || !TEST_ptr(extra_certs)
        || !TEST_true(get_cert_and_key(&signer, &key))
        || !TEST_true(sk_X509_push(extra_certs, signer))
        || !TEST_true(OCSP_basic_sign(bs, signer, key, EVP_sha1(),
            NULL, OCSP_NOCERTS)))
        goto err;
    if (!TEST_true(OCSP_resp_get0_signer(bs, &tmp, extra_certs))
        || !TEST_int_eq(X509_cmp(tmp, signer), 0))
        goto err;
    OCSP_BASICRESP_free(bs);

    /* Do it again but include the signer cert */
    bs = make_dummy_resp();
    tmp = NULL;
    if (!TEST_ptr(bs)
        || !TEST_true(OCSP_basic_sign(bs, signer, key, EVP_sha1(),
            NULL, 0)))
        goto err;
    if (!TEST_true(OCSP_resp_get0_signer(bs, &tmp, NULL))
        || !TEST_int_eq(X509_cmp(tmp, signer), 0))
        goto err;
    ret = 1;
err:
    OCSP_BASICRESP_free(bs);
    sk_X509_free(extra_certs);
    X509_free(signer);
    EVP_PKEY_free(key);
    return ret;
}

static const struct {
    const char *name;
    int count;
    int ids[4];
    int statuses[4];
} find_status_tests[] = {
    { "empty response", 0, { 0 }, { 0 } },
    { "missing CertID", 1, { 1 }, { V_OCSP_CERTSTATUS_GOOD } },
    { "unique good", 1, { 0 }, { V_OCSP_CERTSTATUS_GOOD } },
    { "unique revoked", 1, { 0 }, { V_OCSP_CERTSTATUS_REVOKED } },
    { "unique unknown", 1, { 0 }, { V_OCSP_CERTSTATUS_UNKNOWN } },
    { "good then revoked", 2, { 0, 0 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "revoked then good", 2, { 0, 0 },
        { V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_GOOD } },
    { "identical good", 2, { 0, 0 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_GOOD } },
    { "identical revoked", 2, { 0, 0 },
        { V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_REVOKED } },
    { "unknown then good", 2, { 0, 0 },
        { V_OCSP_CERTSTATUS_UNKNOWN, V_OCSP_CERTSTATUS_GOOD } },
    { "different serial", 2, { 0, 1 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "match after unrelated entries", 3, { 1, 1, 0 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED,
            V_OCSP_CERTSTATUS_REVOKED } },
    { "match before unrelated duplicates", 3, { 0, 1, 1 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_GOOD,
            V_OCSP_CERTSTATUS_REVOKED } },
    { "separated duplicates", 4, { 1, 0, 1, 0 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_GOOD,
            V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "missing with unrelated duplicates", 2, { 1, 1 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "different issuer name hash", 2, { 0, 2 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "different issuer key hash", 2, { 0, 3 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } },
    { "different hash algorithm", 2, { 0, 4 },
        { V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED } }
};

static int test_resp_find_status(int idx)
{
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *ids[5] = { NULL };
    OCSP_SINGLERESP *single;
    X509 *cert = NULL;
    ASN1_INTEGER *serial;
    ASN1_OCTET_STRING *name_hash, *key_hash, *hash;
    ASN1_TIME *now = NULL;
    ASN1_GENERALIZEDTIME *marker = NULL;
    ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;
    ASN1_GENERALIZEDTIME *expected_revtime, *expected_thisupd, *expected_nextupd;
    unsigned char hash_bytes[EVP_MAX_MD_SIZE];
    const char *error_data;
    unsigned long previous_error;
    size_t hash_len;
    int i, mask, matches = 0, last = -1;
    int status, reason, error_flags;
    int expected_status = -99, expected_reason = -99, ret = 0;

    TEST_info("%s", find_status_tests[idx].name);
    if (!TEST_true(get_cert(&cert))
        || !TEST_ptr(bs = OCSP_BASICRESP_new())
        || !TEST_ptr(now = ASN1_TIME_set(NULL, 1700000000))
        || !TEST_ptr(marker = ASN1_GENERALIZEDTIME_new())
        || !TEST_ptr(ids[0] = OCSP_cert_to_id(EVP_sha256(), cert, cert)))
        goto end;
    for (i = 1; i < 4; i++) {
        if (!TEST_ptr(ids[i] = OCSP_CERTID_dup(ids[0])))
            goto end;
    }
    if (!TEST_true(OCSP_id_get0_info(NULL, NULL, NULL, &serial, ids[1]))
        || !TEST_true(ASN1_INTEGER_set(serial, 999999))
        || !TEST_true(OCSP_id_get0_info(&name_hash, NULL, NULL, NULL, ids[2]))
        || !TEST_true(OCSP_id_get0_info(NULL, NULL, &key_hash, NULL, ids[3]))
        || !TEST_ptr(ids[4] = OCSP_cert_to_id(EVP_sha3_256(), cert, cert)))
        goto end;
    for (i = 2; i < 4; i++) {
        hash = i == 2 ? name_hash : key_hash;
        hash_len = ASN1_STRING_get_length(hash);
        if (!TEST_size_t_gt(hash_len, 0)
            || !TEST_size_t_le(hash_len, sizeof(hash_bytes)))
            goto end;
        memcpy(hash_bytes, ASN1_STRING_get0_data(hash), hash_len);
        hash_bytes[0] ^= 1;
        if (!TEST_true(ASN1_OCTET_STRING_set(hash, hash_bytes, (int)hash_len)))
            goto end;
    }
    /* Isolate the algorithm field by keeping the two hash values equal. */
    if (!TEST_true(OCSP_id_get0_info(&name_hash, NULL, &key_hash, NULL, ids[0]))
        || !TEST_true(OCSP_id_get0_info(&hash, NULL, NULL, NULL, ids[4]))
        || !TEST_true(ASN1_STRING_copy(hash, name_hash))
        || !TEST_true(OCSP_id_get0_info(NULL, NULL, &hash, NULL, ids[4]))
        || !TEST_true(ASN1_STRING_copy(hash, key_hash)))
        goto end;
    for (i = 1; i < 5; i++) {
        if (!TEST_int_ne(OCSP_id_cmp(ids[0], ids[i]), 0))
            goto end;
    }

    expected_revtime = expected_thisupd = expected_nextupd = marker;
    for (i = 0; i < find_status_tests[idx].count; i++) {
        if (!TEST_ptr(single = OCSP_basic_add1_status(bs,
                          ids[find_status_tests[idx].ids[i]],
                          find_status_tests[idx].statuses[i],
                          OCSP_REVOKED_STATUS_KEYCOMPROMISE, now, now, now)))
            goto end;
        if (find_status_tests[idx].ids[i] == 0) {
            matches++;
            expected_status = OCSP_single_get0_status(single, &expected_reason,
                &expected_revtime, &expected_thisupd, &expected_nextupd);
        }
    }
    if (!TEST_int_eq(OCSP_resp_count(bs), find_status_tests[idx].count))
        goto end;

    /* The enumeration API must still return every matching entry. */
    for (i = 0; i < find_status_tests[idx].count; i++) {
        if (find_status_tests[idx].ids[i] == 0) {
            last = OCSP_resp_find(bs, ids[0], last);
            if (!TEST_int_eq(last, i))
                goto end;
        }
    }
    if (!TEST_int_eq(OCSP_resp_find(bs, ids[0], last), -1))
        goto end;

    /* Exercise all combinations of optional output parameters. */
    for (mask = 0; mask < 32; mask++) {
        status = reason = -99;
        revtime = thisupd = nextupd = marker;
        ERR_clear_error();
        ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
        previous_error = ERR_peek_last_error();
        if (!TEST_int_eq(OCSP_resp_find_status(bs, ids[0],
                             (mask & 1) != 0 ? &status : NULL,
                             (mask & 2) != 0 ? &reason : NULL,
                             (mask & 4) != 0 ? &revtime : NULL,
                             (mask & 8) != 0 ? &thisupd : NULL,
                             (mask & 16) != 0 ? &nextupd : NULL),
                matches == 1)
            || !TEST_int_eq(status,
                matches == 1 && (mask & 1) != 0 ? expected_status : -99)
            || !TEST_int_eq(reason,
                matches == 1 && (mask & 2) != 0 ? expected_reason : -99)
            || !TEST_ptr_eq(revtime,
                matches == 1 && (mask & 4) != 0 ? expected_revtime : marker)
            || !TEST_ptr_eq(thisupd,
                matches == 1 && (mask & 8) != 0 ? expected_thisupd : marker)
            || !TEST_ptr_eq(nextupd,
                matches == 1 && (mask & 16) != 0 ? expected_nextupd : marker)
            || !TEST_ulong_eq(ERR_get_error(), previous_error))
            goto end;
        if (matches > 1) {
            if (!TEST_int_eq(ERR_GET_LIB(ERR_peek_last_error()), ERR_LIB_OCSP)
                || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
                    ERR_R_PASSED_INVALID_ARGUMENT))
                goto end;
            ERR_peek_last_error_all(NULL, NULL, NULL, &error_data, &error_flags);
            if (!TEST_true((error_flags & ERR_TXT_STRING) != 0)
                || !TEST_str_eq(error_data, "multiple responses for the same CertID"))
                goto end;
            ERR_get_error();
        }
        if (!TEST_ulong_eq(ERR_peek_error(), 0))
            goto end;
    }
    ret = 1;
end:
    ERR_clear_error();
    for (i = 0; i < 5; i++)
        OCSP_CERTID_free(ids[i]);
    OCSP_BASICRESP_free(bs);
    ASN1_TIME_free(now);
    ASN1_GENERALIZEDTIME_free(marker);
    X509_free(cert);
    return ret;
}

static int test_access_description(int testcase)
{
    ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
    int ret = 0;

    if (!TEST_ptr(ad))
        goto err;

    switch (testcase) {
    case 0: /* no change */
        break;
    case 1: /* check and release current location */
        if (!TEST_ptr(ad->location))
            goto err;
        GENERAL_NAME_free(ad->location);
        ad->location = NULL;
        break;
    case 2: /* replace current location */
        GENERAL_NAME_free(ad->location);
        ad->location = GENERAL_NAME_new();
        if (!TEST_ptr(ad->location))
            goto err;
        break;
    }
    ACCESS_DESCRIPTION_free(ad);
    ret = 1;
err:
    return ret;
}

static int test_ocsp_url_svcloc_new(void)
{
    static const char *urls[] = {
        "www.openssl.org",
        "www.openssl.net",
        NULL
    };

    X509 *issuer = NULL;
    X509_EXTENSION *ext = NULL;
    int ret = 0;

    if (!TEST_true(get_cert(&issuer)))
        goto err;

    /*
     * Test calling this ocsp method to catch any memory leak
     */
    ext = OCSP_url_svcloc_new(X509_get_issuer_name(issuer), urls);
    if (!TEST_ptr(ext))
        goto err;

    X509_EXTENSION_free(ext);
    ret = 1;
err:
    X509_free(issuer);
    return ret;
}

/*
 * A request whose signer and issuer are decoded in their own library
 * context verifies while the default library context can fetch nothing.
 */
static int test_req_verify_signer_libctx(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    X509 *signer = NULL, *ca = NULL;
    EVP_PKEY *key = NULL;
    X509_STORE *store = NULL;
    OCSP_REQUEST *req = NULL;
    int ret = 0;

    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(prov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(signer = load_cert_pem(eecertstr, libctx))
        || !TEST_ptr(ca = load_cert_pem(cacertstr, libctx))
        || !TEST_ptr(key = load_pkey_pem(eekeystr, libctx))
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, ca))
        || !TEST_ptr(req = OCSP_REQUEST_new())
        || !TEST_true(OCSP_request_sign(req, signer, key, EVP_sha256(), NULL, 0))
        || !TEST_true(EVP_set_default_properties(NULL, "provider=absent")))
        goto end;
    ret = TEST_int_gt(OCSP_request_verify(req, NULL, store, OCSP_PARTIAL_CHAIN), 0);
    EVP_set_default_properties(NULL, "");
end:
    OCSP_REQUEST_free(req);
    X509_STORE_free(store);
    EVP_PKEY_free(key);
    X509_free(ca);
    X509_free(signer);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

#endif /* OPENSSL_NO_OCSP */

OPT_TEST_DECLARE_USAGE("certfile privkeyfile eecertfile eekeyfile cacertfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certstr = test_get_argument(0))
        || !TEST_ptr(privkeystr = test_get_argument(1))
        || !TEST_ptr(eecertstr = test_get_argument(2))
        || !TEST_ptr(eekeystr = test_get_argument(3))
        || !TEST_ptr(cacertstr = test_get_argument(4)))
        return 0;
#ifndef OPENSSL_NO_OCSP
    ADD_TEST(test_resp_signer);
    ADD_ALL_TESTS(test_resp_find_status, OSSL_NELEM(find_status_tests));
    ADD_ALL_TESTS(test_access_description, 3);
    ADD_TEST(test_ocsp_url_svcloc_new);
    ADD_TEST(test_req_verify_signer_libctx);
#endif
    return 1;
}
