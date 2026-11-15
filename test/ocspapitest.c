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
    ADD_ALL_TESTS(test_access_description, 3);
    ADD_TEST(test_ocsp_url_svcloc_new);
    ADD_TEST(test_req_verify_signer_libctx);
#endif
    return 1;
}
