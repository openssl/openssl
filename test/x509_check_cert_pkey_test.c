/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include "testutil.h"

/*
 * c: path of a cert in PEM format
 * k: path of a key in PEM format
 * t: API type, "cert" for X509_ and "req" for X509_REQ_ APIs.
 * e: expected, "ok" for success, "failed" for what should fail.
 */
static int test_x509_check_cert_pkey(const char *c, const char *k,
    const char *t, const char *e)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;
    X509_REQ *x509_req = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0, type = 0, expected = 0, result = 0;

    /*
     * we check them first thus if fails we don't need to do
     * those PEM parsing operations.
     */
    if (strcmp(t, "cert") == 0) {
        type = 1;
    } else if (strcmp(t, "req") == 0) {
        type = 2;
    } else {
        TEST_error("invalid 'type'");
        goto failed;
    }

    if (strcmp(e, "ok") == 0) {
        expected = 1;
    } else if (strcmp(e, "failed") == 0) {
        expected = 2;
    } else {
        TEST_error("invalid 'expected'");
        goto failed;
    }

    /* process private key */
    bio = BIO_new_file(k, "r");
    if (bio == NULL) {
        TEST_error("create BIO for private key failed");
        goto failed;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        TEST_error("read PEM private key failed");
        goto failed;
    }

    BIO_free(bio);

    /* process cert or cert request, use the same local var */
    bio = BIO_new_file(c, "r");
    if (bio == NULL) {
        TEST_error("create BIO for cert or cert req failed");
        goto failed;
    }

    switch (type) {
        case 1:
            x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if (x509 == NULL) {
                TEST_error("read PEM x509 failed");
                goto failed;
            }

            result = X509_check_private_key(x509, pkey);
            break;
        case 2:
            x509_req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
            if (x509_req == NULL) {
                TEST_error("read PEM x509 req failed");
                goto failed;
            }

            result = X509_REQ_check_private_key(x509_req, pkey);
            break;
        default:
            /* should never be here */
            break;
    }

    if (expected == 1) {
        /* expected == 1 means we expect an "ok" */
        if (!TEST_int_eq(result, 1)) {
            TEST_error("check private key: expected: 1, got: %d", result);
            goto failed;
        }
    } else {
        if (!TEST_int_eq(result, 0)) {
            TEST_error("check private key: expected: 0, got: %d", result);
            goto failed;
        }
    }

out:
    if (bio)
        BIO_free(bio);
    if (x509)
        X509_free(x509);
    if (x509_req)
        X509_REQ_free(x509_req);
    if (pkey)
        EVP_PKEY_free(pkey);
    return ret;

failed:
    ret = 1;
    goto out;
}

int test_main(int argc, char **argv)
{
    if (!TEST_int_eq(argc, 5)) {
        TEST_info("usage: x509_check_cert_pkey cert.pem|cert.req"
                  " key.pem cert|req <expected>");
        return 1;
    }

    return test_x509_check_cert_pkey(argv[1], argv[2], argv[3], argv[4]);
}
