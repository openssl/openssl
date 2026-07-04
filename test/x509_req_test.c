/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "testutil.h"

static char *certsDir = NULL;

/*
 * Test for the missing X509 version check discussed in issue #5738 and
 * added in PR #24677.
 * This test tries to verify a malformed CSR with the X509 version set
 * version 6, instead of 1. As this request is malformed, even its
 * signature is valid, the verification must fail.
 */
static int test_x509_req_detect_invalid_version(void)
{
    char *certFilePath;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    int ret = 0;

    certFilePath = test_mk_file_path(certsDir, "x509-req-detect-invalid-version.pem");
    if (certFilePath == NULL)
        goto err;
    if (!TEST_ptr(bio = BIO_new_file(certFilePath, "r")))
        goto err;
    req = PEM_read_bio_X509_REQ(bio, NULL, 0, NULL);
    if (req == NULL) {
        ret = 1; /* success, reading PEM with invalid CSR data is allowed to fail. */
        goto err;
    }
    if (!TEST_ptr(pkey = X509_REQ_get_pubkey(req)))
        goto err;
    /* Verification MUST fail at this point. ret != 1. */
    if (!TEST_int_ne(X509_REQ_verify(req, pkey), 1))
        goto err;
    ret = 1; /* success */
err:
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    BIO_free(bio);
    OPENSSL_free(certFilePath);
    return ret;
}

static int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    if (sk_X509_EXTENSION_push(sk, ex) <= 0)
        return 0;

    return 1;
}

static int test_x509_req_add_exts(void)
{
    X509_REQ *x = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;
    int nid = NID_undef;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0
        || (x = X509_REQ_new()) == NULL
        || X509_REQ_set_pubkey(x, pkey) <= 0)
        goto err;

    exts = sk_X509_EXTENSION_new_null();
    if (!TEST_ptr(exts))
        goto err;

    /*
     * For request extensions they are all packed in a single attribute. We
     * save them in a STACK and add them all at once later...
     */

    if (!TEST_int_eq(add_ext(exts, NID_netscape_cert_type, "client,email"), 1)
        || !TEST_int_eq(add_ext(exts, NID_subject_alt_name, "email:steve@openssl.org"), 1)
        || !TEST_int_eq(add_ext(exts, NID_crl_distribution_points, "URI:http://example.org"), 1)
        /* These tests require some underlying config but we just check that we don't crash */
        || !TEST_int_eq(add_ext(exts, NID_proxyCertInfo, "text:xxx"), 0)
        || !TEST_int_eq(add_ext(exts, NID_certificate_policies, "xxx:yyy"), 0)
        /* Some Netscape specific extensions */
        || !TEST_int_eq(add_ext(exts, NID_netscape_cert_type, "client,email"), 1))
        goto err;

    /* Maybe even add our own extension based on existing */
    nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
    if (!TEST_int_ne(nid, NID_undef)
        || !TEST_int_gt(X509V3_EXT_add_alias(nid, NID_netscape_comment), 0)
        || !TEST_int_eq(add_ext(exts, nid, "example comment alias"), 1)
        || !TEST_int_eq(X509_REQ_add_extensions(x, exts), 1))
        goto err;

    if (!X509_REQ_sign(x, pkey, EVP_sha256()))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);

    X509_REQ_free(x);
    EVP_PKEY_free(pkey);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return ret;
}
OPT_TEST_DECLARE_USAGE("certdir\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(certsDir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_x509_req_detect_invalid_version);
    ADD_TEST(test_x509_req_add_exts);
    return 1;
}

void cleanup_tests(void)
{
}
