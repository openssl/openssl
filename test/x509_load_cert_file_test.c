/*
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

static const char *chain;
static const char *crl;

static const char *cn_cert1[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIC9DCCAdygAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQd3d3\n",
    "LmV4YW1wbGUudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0yNTAxMTAwMDAwMDBaMBsx\n",
    "GTAXBgNVBAMMEHd3dy5leGFtcGxlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n",
    "DwAwggEKAoIBAQDPwPv+vSWbbNI+EUMH162Srn88C2ywadFWgBdnVikBJ10LcwQK\n",
    "6zrTC+TzVafEhWUJDujnhJlTCc0ASIIJti2adwJODgbf2lk4n4mXcT4BFYvJbWaW\n",
    "BjSRPnfwKyQyHoXDyCtLZGtwB295mNcF1sGOS7SmpM4n4hbzTx/o3mxCEd/CGEzh\n",
    "hiljQIr6VtwVxcGoaI5AIW/gbKZB4tYrCeiqVDITZFx5kp0BQ4aPIr+1ws4Y9qta\n",
    "1ljZgf/E3uaQK2CFAWYv6Zz2QYfjkoTZ2wq3PBj1DVWT0nJs/rezKA6R1iyePiFa\n",
    "nqlNyjNKFDi/oVVmgsDgllVXoWaDoTncXQGzAgMBAAGjQjBAMB0GA1UdDgQWBBTl\n",
    "aFbHpg5r2p4B6MyRy3MG9cwBijAfBgNVHSMEGDAWgBQIA+YPQEiawtPX3vt3hpGo\n",
    "Wo+/3zANBgkqhkiG9w0BAQsFAAOCAQEAmx1N72vdZLCaMXkZapz5j9NND0cvDjXu\n",
    "YvUfGU+Y9dTTX4+RmrWuLWgLlk7Unq5DPAQahE4Kc7+JsyMtSXQnOyTZAEmy+1qN\n",
    "DG42aPiRtfm2Og0mmTrIml3n/tZzmYPU+hC4f9M6qtpI9S0IaqAXFZdup45o6uZj\n",
    "Wt7oiIfnbj3UIf7Bc3k/0jUvCZavppH9yKdd70cpkxRXBfqSpift7YqH6RCpKp/P\n",
    "jiDYR27N7qUmfe60AHCBhPA1A1fTUXmhRfl8mRm2wiUelKUZ77wRkk5VpbsAA/JW\n",
    "07vUu3WC2773pUT/68MED5h26Mr6xjKxG8v8SfeMpri5R74P1TnJpQ==\n",
    "-----END CERTIFICATE-----\n",
    NULL,
};
static const char *cn_cert2[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIC9DCCAdygAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQd3d3\n",
    "LmV4YW1wbGUudGVzdDAeFw0yNTAxMTEwMDAwMDBaFw0yNTAxMjAwMDAwMDBaMBsx\n",
    "GTAXBgNVBAMMEHd3dy5leGFtcGxlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n",
    "DwAwggEKAoIBAQDPwPv+vSWbbNI+EUMH162Srn88C2ywadFWgBdnVikBJ10LcwQK\n",
    "6zrTC+TzVafEhWUJDujnhJlTCc0ASIIJti2adwJODgbf2lk4n4mXcT4BFYvJbWaW\n",
    "BjSRPnfwKyQyHoXDyCtLZGtwB295mNcF1sGOS7SmpM4n4hbzTx/o3mxCEd/CGEzh\n",
    "hiljQIr6VtwVxcGoaI5AIW/gbKZB4tYrCeiqVDITZFx5kp0BQ4aPIr+1ws4Y9qta\n",
    "1ljZgf/E3uaQK2CFAWYv6Zz2QYfjkoTZ2wq3PBj1DVWT0nJs/rezKA6R1iyePiFa\n",
    "nqlNyjNKFDi/oVVmgsDgllVXoWaDoTncXQGzAgMBAAGjQjBAMB0GA1UdDgQWBBTl\n",
    "aFbHpg5r2p4B6MyRy3MG9cwBijAfBgNVHSMEGDAWgBQIA+YPQEiawtPX3vt3hpGo\n",
    "Wo+/3zANBgkqhkiG9w0BAQsFAAOCAQEAH+hviFeMZc55/H5AZG4p3VdOQ5ZxsHJF\n",
    "NTkxY/0wGcKJhelyNN39rnlhUFLKlEhbWE/LlTBCU9ILLiFeSAaFiNgufqFEBefL\n",
    "cjqcfQUeB2vUHNnrWy6QPCc0SNSdholTelEgf8eXPBrJWS/iazcKTLfBrFbs6K++\n",
    "F/Efn1p7+DutFpgaTdupuonsJOMM33Nw3MfAz6bw5Hjd17ritjRW0g58OsLfv9Ac\n",
    "Dbw2bEzZDvkkH5yDlHOl/dyyhDdcMs6bRsoM+LC0PuZ3dAUQhlnQ8SlPojm5qUjA\n",
    "0hyy4w4tmYFCzdUxR6vnQie4a/D0o5cLuecIIemozKONMZo+FVGjFQ==\n",
    "-----END CERTIFICATE-----\n",
    NULL,
};
static const char *cn_crl2[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBtjCBnwIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBB3d3cuZXhhbXBs\n",
    "ZS50ZXN0Fw0yNTA5MTExMzA0MTZaFw0yNTEyMjAxMzA0MTZaMD8wEwICEAAXDTI1\n",
    "MDkxMTExNTcxMFowEwICEAEXDTI1MDkxMTExNTgwNVowEwICEAIXDTI1MDkxMTEz\n",
    "MDM1MVqgDzANMAsGA1UdFAQEAgIQATANBgkqhkiG9w0BAQsFAAOCAQEAZUUsIeXL\n",
    "zTwpa2bwAg0xUIm/ARnoHlZSxMoWPsQnIkrQreCTvc9QpTo+IrS+SDaBJqu8V+DM\n",
    "Z4rNqreQG1wNNgkSTEOAFMjQPOmvtePyYGxNgM4MdpKaejdZSk22rccaAQVhSjGp\n",
    "AYprwbWqyfAq7JUYLUZ1EjsIoRQIKMQa79bzF7S4oNN6sMq6icJueFmd55ufmv27\n",
    "1amhUpJh5YJ8BNpLZGicujYm8TVCZqSjVI0JsXAQYhm1u/pUrcydRfc7c5PMkpIj\n",
    "uByPkdYLVgpKJH6Y5Q9Kx5MR+p85JM31ePlSobft+wZh/WMV0Id6PZ8/56oOhV3V\n",
    "bVxU+BlQ5ZKmYw==\n"
    "-----END X509 CRL-----\n",
    NULL,
};

static int test_load_cert_file(void)
{
    int ret = 0, i;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    STACK_OF(X509) *certs = NULL;
    STACK_OF(X509_OBJECT) *objs = NULL;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_ptr(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))
        || !TEST_true(X509_load_cert_file(lookup, chain, X509_FILETYPE_PEM))
        || !TEST_ptr(certs = X509_STORE_get1_all_certs(store))
        || !TEST_int_eq(sk_X509_num(certs), 4)
#ifndef OPENSSL_NO_DEPRECATED_4_0
        || !TEST_ptr(objs = X509_STORE_get0_objects(store))
        || !TEST_int_eq(sk_X509_OBJECT_num(objs), 4)
#endif
        || !TEST_ptr(objs = X509_STORE_get1_objects(store))
        || !TEST_int_eq(sk_X509_OBJECT_num(objs), 4))
        goto err;

    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        const X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        if (!TEST_int_eq(X509_OBJECT_get_type(obj), X509_LU_X509))
            goto err;
    }

    if (crl != NULL && !TEST_true(X509_load_crl_file(lookup, crl, X509_FILETYPE_PEM)))
        goto err;

    ret = 1;

err:
    OSSL_STACK_OF_X509_free(certs);
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    X509_STORE_free(store);
    return ret;
}

static int check_get1_certs(X509_STORE_CTX *ctx, const X509_NAME *name,
    X509 *cert1, X509 *cert2)
{
    STACK_OF(X509) *certs = NULL;
    X509 *got1, *got2;
    int ret = 0;

    if (!TEST_ptr(certs = X509_STORE_CTX_get1_certs(ctx, name))
        || !TEST_int_eq(sk_X509_num(certs), cert2 == NULL ? 1 : 2))
        goto err;

    got1 = sk_X509_value(certs, 0);
    if (cert2 == NULL) {
        if (!TEST_ptr_eq(got1, cert1))
            goto err;
    } else {
        got2 = sk_X509_value(certs, 1);
        if (!TEST_true((got1 == cert1 && got2 == cert2)
                || (got1 == cert2 && got2 == cert1)))
            goto err;
    }
    ret = 1;

err:
    OSSL_STACK_OF_X509_free(certs);
    return ret;
}

static int check_get1_crls(X509_STORE_CTX *ctx, const X509_NAME *name,
    X509_CRL *crl1, X509_CRL *crl2)
{
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *got1, *got2;
    int ret = 0;

    if (!TEST_ptr(crls = X509_STORE_CTX_get1_crls(ctx, name))
        || !TEST_int_eq(sk_X509_CRL_num(crls), crl2 == NULL ? 1 : 2))
        goto err;

    got1 = sk_X509_CRL_value(crls, 0);
    if (crl2 == NULL) {
        if (!TEST_ptr_eq(got1, crl1))
            goto err;
    } else {
        got2 = sk_X509_CRL_value(crls, 1);
        if (!TEST_true((got1 == crl1 && got2 == crl2)
                || (got1 == crl2 && got2 == crl1)))
            goto err;
    }
    ret = 1;

err:
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return ret;
}

static int check_store_get1_by_name(X509_STORE_CTX *ctx, const X509_NAME *name1,
    const X509_NAME *nameA, X509 *cert1, X509 *cert2, X509 *certA,
    X509_CRL *crl1, X509_CRL *crl2, X509_CRL *crlA)
{
    return check_get1_certs(ctx, name1, cert1, cert2)
        && check_get1_certs(ctx, nameA, certA, NULL)
        && check_get1_crls(ctx, name1, crl1, crl2)
        && check_get1_crls(ctx, nameA, crlA, NULL);
}

/* Check exact lookup results in hash table and flat store representations. */
static int test_load_same_cn_certs(void)
{
    X509 *cert1 = NULL, *cert2 = NULL, *certA = NULL;
    X509_CRL *crl1 = NULL, *crl2 = NULL, *crlA = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    const X509_NAME *name1;
    X509_NAME *nameA = NULL;
    int ret = 0;

    if (!TEST_ptr(cert1 = X509_from_strings(cn_cert1))
        || !TEST_ptr(cert2 = X509_from_strings(cn_cert2))
        || !TEST_ptr(crl1 = CRL_from_strings(cn_crl2))
        || !TEST_ptr(name1 = X509_get_subject_name(cert1))
        || !TEST_ptr(nameA = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(nameA, "CN", MBSTRING_ASC,
            (unsigned char *)"alpha.test", -1, -1, 0))
        || !TEST_ptr(certA = X509_dup(cert1))
        || !TEST_true(X509_set_subject_name(certA, nameA))
        || !TEST_ptr(crl2 = X509_CRL_new())
        || !TEST_true(X509_CRL_set_issuer_name(crl2, name1))
        || !TEST_ptr(crlA = X509_CRL_new())
        || !TEST_true(X509_CRL_set_issuer_name(crlA, nameA))
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL))
        || !TEST_true(X509_STORE_add_cert(store, cert1))
        || !TEST_true(X509_STORE_add_crl(store, crl1))
        || !TEST_true(X509_STORE_add_cert(store, cert2))
        || !TEST_true(X509_STORE_add_crl(store, crl2))
        || !TEST_true(X509_STORE_add_cert(store, certA))
        || !TEST_true(X509_STORE_add_crl(store, crlA))
        || !check_store_get1_by_name(ctx, name1, nameA, cert1, cert2, certA,
            crl1, crl2, crlA))
        goto err;

#ifndef OPENSSL_NO_DEPRECATED_4_0
    /* Exercise conversion of an already populated store. */
    if (!TEST_ptr(X509_STORE_get0_objects(store))
        || !check_store_get1_by_name(ctx, name1, nameA, cert1, cert2, certA,
            crl1, crl2, crlA))
        goto err;

    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(store);
    store = NULL;

    /* Put a foreign object between the two matching objects of each type. */
    if (!TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, NULL, NULL))
        /* Deliberately single-threaded: this call exposes internal state. */
        || !TEST_ptr(X509_STORE_get0_objects(store))
        || !TEST_true(X509_STORE_add_cert(store, cert1))
        || !TEST_true(X509_STORE_add_cert(store, certA))
        || !TEST_true(X509_STORE_add_cert(store, cert2))
        || !TEST_true(X509_STORE_add_crl(store, crl1))
        || !TEST_true(X509_STORE_add_crl(store, crlA))
        || !TEST_true(X509_STORE_add_crl(store, crl2))
        || !check_store_get1_by_name(ctx, name1, nameA, cert1, cert2, certA,
            crl1, crl2, crlA))
        goto err;
#endif

    ret = 1;

err:
    X509_NAME_free(nameA);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert1);
    X509_free(cert2);
    X509_free(certA);
    X509_CRL_free(crl1);
    X509_CRL_free(crl2);
    X509_CRL_free(crlA);
    return ret;
}

/*
 * Test to trigger memory failures in X509_STORE_add_cert.
 */
static int test_x509_store_add_mfail(void)
{
    X509 *cert = NULL;
    X509_STORE *store = NULL;
    int ret = 0;

    cert = X509_from_strings(cn_cert1);
    if (!TEST_ptr(cert))
        goto err;
    store = X509_STORE_new();
    if (!TEST_ptr(store))
        goto err;

    MFAIL_start();
    ret = X509_STORE_add_cert(store, cert);
    MFAIL_end();

err:
    X509_STORE_free(store);
    X509_free(cert);
    return ret;
}

static int test_x509_get1_objects_mfail(void)
{
    X509 *cert1 = NULL, *cert2 = NULL;
    X509_STORE *store = NULL;
    STACK_OF(X509_OBJECT) *objs = NULL;
    int ret = 0;

    if (!TEST_ptr(cert1 = X509_from_strings(cn_cert1))
        || !TEST_ptr(cert2 = X509_from_strings(cn_cert2)))
        goto err;

    store = X509_STORE_new();
    if (!TEST_ptr(store))
        goto err;
    if (!TEST_true(X509_STORE_add_cert(store, cert1))
        || !TEST_true(X509_STORE_add_cert(store, cert2)))
        goto err;

    MFAIL_start();
    objs = X509_STORE_get1_objects(store);
    MFAIL_end();

    ret = (objs != NULL);

err:
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    X509_STORE_free(store);
    X509_free(cert1);
    X509_free(cert2);
    return ret;
}

/* Trigger memory failures while parsing a PEM certificate. */
static int test_x509_pem_read_mfail(void)
{
    X509 *cert;

    MFAIL_start();
    cert = X509_from_strings(cn_cert1);
    MFAIL_end();

    X509_free(cert);
    return 1;
}

OPT_TEST_DECLARE_USAGE("cert.pem [crl.pem]\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    chain = test_get_argument(0);
    if (chain == NULL)
        return 0;

    crl = test_get_argument(1);

    ADD_TEST(test_load_cert_file);
    ADD_TEST(test_load_same_cn_certs);
    ADD_MFAIL_NO_CHECK_TEST(test_x509_pem_read_mfail);
    ADD_MFAIL_TEST(test_x509_store_add_mfail);
    ADD_MFAIL_TEST(test_x509_get1_objects_mfail);

    return 1;
}
