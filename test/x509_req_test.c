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

#include "testutil.h"

static const char bad_csr_version_6[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICoTCCAYkCAQUwXDELMAkGA1UEBhMCQ0gxDTALBgNVBAgMBEJlcm4xDTALBgNV\n"
    "BAcMBEJlcm4xFDASBgNVBAoMC0VyYnNsYW5kREVWMRkwFwYDVQQDDBB0ZXN0Lm9w\n"
    "ZW5zc2wub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgnKT31X7\n"
    "GG1doZXQ0cHY32OjExJT5z/AhZNHt44AdZmrGDwcANBa68mK1pJ4zbLStsa0ABfC\n"
    "clPnoq4jqPcoMqPu5SNGR29lBWSQr8AzzHFOalHfYmdsTwRxy2fM56WVfrmi/HY5\n"
    "8pZ0LgAuF7Kb8hjUkqBbWzAo0GJaYqWitkrDdproLMLz65GJYYlxXcPd79yt+SHk\n"
    "TdfRANcjinRK/EKgkWYVu5yE/lqWl9lwgxY9YAeDp6/WZ7K5wGueiMNYsKoud0MP\n"
    "al00AgaBgicIBMfVPdN19p8ZC4u2BuJlM1oq2eZbaP35rAlB1InbPtFIGL0c0h0o\n"
    "6prLD6FgYHd1PQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBADQIUWrf2wnUlKK4\n"
    "Q2kuK6EtC2CYblmUqV8kUx/sWkfaG2zD7ekyTVJg80IhnsrVJ3VQwOUtbWltgskF\n"
    "ZzrwXbIIVkHzeI51jrt/jUXzskCjyDkxjeRgCxSJ1bIlN+OkIeXf/jjDJ+ebyeJl\n"
    "oRgg/KtbaJVb9niFjbxdyMNEI5qZAmocFpE2t5S9GlosTEIPNbowZAe8+AeUXGJB\n"
    "7SPJZ3U+Rk7Yx6cW2Hc5litIDzJlIN8D86v26lgJ1VEoYGD81wPEhIjHTkRBWhp6\n"
    "kGV0EojP8ntSjDFHIH184MQAJYyr6YlEM3DcCYPwydLN/rkEHQVAxKKuSCrpcUMH\n"
    "hfcdPO4=\n"
    "-----END CERTIFICATE REQUEST-----";

/*
 * Test for the missing X509 version check discussed in issue #5738 and
 * added in PR #24677.
 * This test tries to verify a malformed CSR with the X509 version set
 * version 6, instead of 1. As this request is malformed, even its
 * signature is valid, the verification must fail.
 */
static int test_x509_req_detect_invalid_version(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    int ret = 0;

    if (!TEST_ptr(bio = BIO_new_mem_buf(bad_csr_version_6, sizeof(bad_csr_version_6) - 1)))
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
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_x509_req_detect_invalid_version);
    return 1;
}

void cleanup_tests(void)
{
}
