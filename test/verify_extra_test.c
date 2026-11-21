/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "testutil.h"

static const char *certs_dir;
static char *root_f = NULL;
static char *roots_f = NULL;
static char *untrusted_f = NULL;
static char *bad_f = NULL;
static char *req_f = NULL;
static char *sroot_cert = NULL;
static char *ca_cert = NULL;
static char *ee_cert = NULL;

#define load_cert_from_file(file) load_cert_pem(file, NULL)

/*-
 * Test for CVE-2015-1793 (Alternate Chains Certificate Forgery)
 *
 * Chain is as follows:
 *
 * rootCA (self-signed)
 *   |
 * interCA
 *   |
 * subinterCA       subinterCA (self-signed)
 *   |                   |
 * leaf ------------------
 *   |
 * bad
 *
 * rootCA, interCA, subinterCA, subinterCA (ss) all have CA=TRUE
 * leaf and bad have CA=FALSE
 *
 * subinterCA and subinterCA (ss) have the same subject name and keys
 *
 * interCA (but not rootCA) and subinterCA (ss) are in the trusted store
 * (roots.pem)
 * leaf and subinterCA are in the untrusted list (untrusted.pem)
 * bad is the certificate being verified (bad.pem)
 *
 * Versions vulnerable to CVE-2015-1793 will fail to detect that leaf has
 * CA=FALSE, and will therefore incorrectly verify bad
 *
 */
static int test_alt_chains_cert_forgery(void)
{
    int ret = 0;
    int i;
    X509 *x = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE_CTX *sctx = NULL;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (store == NULL)
        goto err;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto err;
    if (X509_LOOKUP_load_file(lookup, roots_f, X509_FILETYPE_PEM) <= 0)
        goto err;

    untrusted = load_certs_pem(untrusted_f);

    if ((x = load_cert_from_file(bad_f)) == NULL)
        goto err;

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        goto err;

    if (!X509_STORE_CTX_init(sctx, store, x, untrusted))
        goto err;

    i = X509_verify_cert(sctx);

    if (i == 0 && X509_STORE_CTX_get_error(sctx) == X509_V_ERR_INVALID_CA) {
        /* This is the result we were expecting: Test passed */
        ret = 1;
    }
err:
    X509_STORE_CTX_free(sctx);
    X509_free(x);
    OSSL_STACK_OF_X509_free(untrusted);
    X509_STORE_free(store);
    return ret;
}

static int test_distinguishing_id(void)
{
    X509 *x = NULL;
    int ret = 0;
    ASN1_OCTET_STRING *v = NULL;
    const ASN1_OCTET_STRING *v2 = NULL;
    char *distid = "this is an ID";

    x = load_cert_from_file(bad_f);
    if (x == NULL)
        goto err;

    v = ASN1_OCTET_STRING_new();
    if (v == NULL)
        goto err;

    if (!ASN1_OCTET_STRING_set(v, (unsigned char *)distid,
            (int)strlen(distid))) {
        ASN1_OCTET_STRING_free(v);
        goto err;
    }

    X509_set0_distinguishing_id(x, v);

    v2 = X509_get0_distinguishing_id(x);
    if (!TEST_ptr(v2)
        || !TEST_int_eq(ASN1_OCTET_STRING_cmp(v, v2), 0))
        goto err;

    ret = 1;
err:
    X509_free(x);
    return ret;
}

static int test_req_distinguishing_id(void)
{
    X509_REQ *x = NULL;
    BIO *bio = NULL;
    int ret = 0;
    ASN1_OCTET_STRING *v = NULL, *v2 = NULL;
    char *distid = "this is an ID";

    bio = BIO_new_file(req_f, "r");
    if (bio == NULL)
        goto err;

    x = PEM_read_bio_X509_REQ(bio, NULL, 0, NULL);
    if (x == NULL)
        goto err;

    v = ASN1_OCTET_STRING_new();
    if (v == NULL)
        goto err;

    if (!ASN1_OCTET_STRING_set(v, (unsigned char *)distid,
            (int)strlen(distid))) {
        ASN1_OCTET_STRING_free(v);
        goto err;
    }

    X509_REQ_set0_distinguishing_id(x, v);

    v2 = X509_REQ_get0_distinguishing_id(x);
    if (!TEST_ptr(v2)
        || !TEST_int_eq(ASN1_OCTET_STRING_cmp(v, v2), 0))
        goto err;

    ret = 1;
err:
    X509_REQ_free(x);
    BIO_free(bio);
    return ret;
}

static int test_self_signed(const char *filename, int use_trusted, int expected)
{
    X509 *cert = load_cert_from_file(filename); /* may result in NULL */
    STACK_OF(X509) *trusted = sk_X509_new_null();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ret;

    ret = TEST_int_eq(X509_self_signed(cert, 1), expected);

    if (cert != NULL) {
        if (use_trusted)
            ret = ret && TEST_true(sk_X509_push(trusted, cert));
        ret = ret && TEST_true(X509_STORE_CTX_init(ctx, NULL, cert, NULL));
        X509_STORE_CTX_set0_trusted_stack(ctx, trusted);
        ret = ret && TEST_int_eq(X509_verify_cert(ctx), expected);
    }

    X509_STORE_CTX_free(ctx);
    sk_X509_free(trusted);
    X509_free(cert);
    return ret;
}

static const char *multiname_cert[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFnDCCBISgAwIBAgIUTgfdSQm2hjgUZoA8jeQX7sDPAoowDQYJKoZIhvcNAQEL\n"
    "BQAwgYUxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdBbGJlcnRhMREwDwYDVQQHDAhF\n"
    "ZG1vbnRvbjERMA8GA1UECgwITXVwcGV0cnkxITAfBgNVBAsMGFN0YXRsZXIgYW5k\n"
    "IFdhbGRvcmYgUiBVUzEbMBkGA1UEAwwSYmVha2VyLm11cHBldHJ5LmNhMB4XDTI2\n"
    "MDExMjIwNTUwOVoXDTI3MDExMjIwNTUwOVowgYUxCzAJBgNVBAYTAkNBMRAwDgYD\n"
    "VQQIDAdBbGJlcnRhMREwDwYDVQQHDAhFZG1vbnRvbjERMA8GA1UECgwITXVwcGV0\n"
    "cnkxITAfBgNVBAsMGFN0YXRsZXIgYW5kIFdhbGRvcmYgUiBVUzEbMBkGA1UEAwwS\n"
    "YmVha2VyLm11cHBldHJ5LmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
    "AQEA+EsGQCX4YyZF3QbVcFUcWpYDp8MJHr5vF0cosvj9afGPhpLREWR7EmnNA8Gf\n"
    "wb+ef/jNrDg8W81uDD3N29PvbM+hHAQPaHrRupQZ+W+uIVEAu/lpI359jIRS1Sey\n"
    "IcU2vIgn3Tlnv4UX3o3QMyH8+RcCvSNrWu4+f9ipMAy/xq3PWBm+fHi/+bI03eDy\n"
    "0xNm8kpXbhqZQiZ1tAhsTa3V2pIufqAnctDgl2GUHtfmKO095OHimjhQXHxO8Ctk\n"
    "R+vFv0nleJoAAfkmaMdtdTd1O8m3AtQv6xQC4X5Tu/+FKKQOXjf/8OtqW2lrlxxR\n"
    "pbFuy66I9HVyf+gGWEbZyqbCpwIDAQABo4ICADCCAfwwggG3BgNVHREEggGuMIIB\n"
    "qoILbXVwcGV0cnkuY2GCD3d3dy5tdXBwZXRyeS5jYYITc3RhdGxlci5tdXBwZXRy\n"
    "eS5jYYITd2FsZG9yZi5tdXBwZXRyeS5jYYETc3RhdGxlckBtdXBwdGVyeS5jYYET\n"
    "d2FsZG9yZkBtdXBwdGVyeS5jYYcExikABIcQIAEFA7o+AAAAAAAAAAIAMIcEqveq\n"
    "AocQKAEBuAAQAAAAAAAAAAAAC4cEwCEEDIcQIAEFAAACAAAAAAAAAAAADIcExwdb\n"
    "DYcQIAEFAAAtAAAAAAAAAAAADYcEwMvmCocQIAEFAACoAAAAAAAAAAAADocEwAUF\n"
    "8YcQIAEFAAAvAAAAAAAAAAAAD4cEwHAkBIcQIAEFAAASAAAAAAAAAAANDYcExmG+\n"
    "NYcQIAEFAAABAAAAAAAAAAAAU4cEwCSUEYcQIAEH/gAAAAAAAAAAAAAAU4cEwDqA\n"
    "HocQIAEFAwwnAAAAAAAAAAIAMIcEwQAOgYcQIAEH/QAAAAAAAAAAAAAAAYcExwdT\n"
    "KocQIAEFAACfAAAAAAAAAAAAQocEygwbIYcQIAENwwAAAAAAAAAAAAAANTALBgNV\n"
    "HQ8EBAMCBDAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFCutBN63ufhB\n"
    "IY4dOuFcYfC3p+mMMA0GCSqGSIb3DQEBCwUAA4IBAQBBWfTvwxV1s3xaS5Ko6T7B\n"
    "vS7TPih0MO8auv0mvZXG3jy/LfAfgu05PbGIf0dzFhBpoZD0VrrugmdemLkJd+u6\n"
    "pbEttGFZtcGb//MtjUAYQnEq6fYgDeT0dGU0upwQPWGgh5LpFSab+71C6Ofc3YFM\n"
    "WPH7UaRBUV2mqNtUokOce6kYtl97St7p6cGpQW9Q1uFQODvAm3ZPq/YNGnTJAOdb\n"
    "9UX8Td1T5fH86H0hb6qB0AEhVdgjPUgs33zYNWRPg8fYleT6w1MpE2HaUqqhld3B\n"
    "ZtVZ5IznkY+8qH0rua89m4TV3qzUqNVUL0uxkWnQI3W8g3Adin7QN3EA6ZYrTD3q\n"
    "-----END CERTIFICATE-----\n",
    NULL,
};

static const time_t multiname_valid_at = 1768253189;

static const char *multiname_dnsnames[] = {
    "muppetry.ca",
    "www.muppetry.ca",
    "statler.muppetry.ca",
    "waldorf.muppetry.ca",
    NULL,
};

static const char *multiname_emails[] = {
    "statler@mupptery.ca",
    "waldorf@mupptery.ca",
    NULL,
};

static const char *multiname_ips[] = {
    "198.41.0.4",
    "2001:503:ba3e::2:30",
    "170.247.170.2",
    "2801:1b8:10::b",
    "192.33.4.12",
    "2001:500:2::c",
    "199.7.91.13",
    "2001:500:2d::d",
    "192.203.230.10",
    "2001:500:a8::e",
    "192.5.5.241",
    "2001:500:2f::f",
    "192.112.36.4",
    "2001:500:12::d0d",
    "198.97.190.53",
    "2001:500:1::53",
    "192.36.148.17",
    "2001:7fe::53",
    "192.58.128.30",
    "2001:503:c27::2:30",
    "193.0.14.129",
    "2001:7fd::1",
    "199.7.83.42",
    "2001:500:9f::42",
    "202.12.27.33",
    "2001:dc3::35",
    NULL,
};

static int test_multiname_selfsigned(void)
{
    X509 *cert = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    int fails = 0;
    int ret = 0;

    if (!TEST_ptr((cert = X509_from_strings(multiname_cert))))
        goto err;

    if (!TEST_true(X509_self_signed(cert, 1)))
        goto err;

    if (!TEST_ptr(store = X509_STORE_new()))
        goto err;

    if (!TEST_true(X509_STORE_add_cert(store, cert)))
        goto err;

    if (!TEST_ptr((vpm = X509_STORE_get0_param(store))))
        goto err;

    if (!TEST_ptr(ctx = X509_STORE_CTX_new()))
        goto err;

    X509_VERIFY_PARAM_set_time(vpm, multiname_valid_at);

    for (size_t i = 0; multiname_dnsnames[i] != NULL; i++) {
        /* Try one not in the certificate */
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, "bunsen.muppetry.ca", 0)))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_false(X509_verify_cert(ctx))) {
            TEST_info("Verify succeeded for non-present name bunsen.muppetry.ca\n");
            goto err;
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, NULL, 0)))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx)))
            goto err;
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, multiname_dnsnames[i], strlen(multiname_dnsnames[i]))))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx))) {
            TEST_info("Verify failed for initial name %s\n", multiname_dnsnames[i]);
            fails++;
        }
        X509_STORE_CTX_cleanup(ctx);
        for (size_t j = 0; multiname_dnsnames[j] != NULL; j++) {
            if (j != i) {
                if (!TEST_true(X509_VERIFY_PARAM_add1_host(vpm, multiname_dnsnames[j], 0)))
                    goto err;
                if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
                    goto err;
                if (!TEST_true(X509_verify_cert(ctx))) {
                    TEST_info("Verify failed with added name %s\n", multiname_dnsnames[j]);
                    fails++;
                }
                X509_STORE_CTX_cleanup(ctx);
            }
        }
        /* Try the CN */
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, "beaker.muppetry.ca", 0)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx))) {
            TEST_info("Verify failed for CN name beaker.muppetry.ca\n");
            fails++;
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, NULL, 0)))
            goto err;
        /* Try the domain with . */
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, ".muppetry.ca", 0)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx))) {
            TEST_info("Verify failed for domain name .muppetry.ca\n");
            fails++;
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, NULL, 0)))
            goto err;
    }

    for (size_t i = 0; multiname_emails[i] != NULL; i++) {
        /* Try one not in the certificate */
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, "bunsen@muppetry.ca", 0)))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_false(X509_verify_cert(ctx))) {
            TEST_info("Verify succeeded for non-present name bunsen@muppetry.ca\n");
            goto err;
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, NULL, 0)))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx)))
            goto err;
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, multiname_emails[i], strlen(multiname_emails[i]))))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx))) {
            TEST_info("Verify failed for initial name %s\n", multiname_emails[i]);
            fails++;
        }
        X509_STORE_CTX_cleanup(ctx);
        for (size_t j = 0; multiname_emails[j] != NULL; j++) {
            if (j != i) {
                if (!TEST_true(X509_VERIFY_PARAM_add1_rfc822(vpm, multiname_emails[j], 0)))
                    goto err;
                if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
                    goto err;
                if (!TEST_true(X509_verify_cert(ctx))) {
                    TEST_info("Verify failed with added name %s\n", multiname_emails[j]);
                    fails++;
                }
                X509_STORE_CTX_cleanup(ctx);
            }
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, NULL, 0)))
            goto err;
    }

    for (size_t i = 0; multiname_ips[i] != NULL; i++) {
        /* Try one not in the certificate */
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, "8.8.8.8")))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_false(X509_verify_cert(ctx))) {
            TEST_info("Verify succeeded for non-present name 8.8.8.8\n");
            goto err;
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, NULL)))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx)))
            goto err;
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, multiname_ips[i])))
            goto err;
        if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
            goto err;
        if (!TEST_true(X509_verify_cert(ctx))) {
            TEST_info("Verify failed for initial name %s\n", multiname_ips[i]);
            fails++;
        }
        X509_STORE_CTX_cleanup(ctx);
        for (size_t j = 0; multiname_ips[j] != NULL; j++) {
            if (j != i) {
                if (!TEST_true(X509_VERIFY_PARAM_add1_ip_asc(vpm, multiname_ips[j])))
                    goto err;
                if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
                    goto err;
                if (!TEST_true(X509_verify_cert(ctx))) {
                    TEST_info("Verify failed with added name %s\n", multiname_ips[j]);
                    fails++;
                }
                X509_STORE_CTX_cleanup(ctx);
            }
        }
        X509_STORE_CTX_cleanup(ctx);
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, NULL)))
            goto err;
    }

    /*
     * Test that individual categories work together, and a non-match will still fail validation
     */

    /* A dnsname, email and ip that are all valid in the cert should succeed */
    if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, "www.muppetry.ca", 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, "2001:503:ba3e::2:30")))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, "waldorf@mupptery.ca", 0)))
        goto err;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
        goto err;
    if (!TEST_true(X509_verify_cert(ctx)))
        fails++;
    X509_STORE_CTX_cleanup(ctx);

    /* Setting an non-matching email should fail validation even with valid dnsname and ip */
    if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, "bunsen@mupptery.ca", 0)))
        goto err;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
        goto err;
    if (!TEST_false(X509_verify_cert(ctx)))
        fails++;
    X509_STORE_CTX_cleanup(ctx);
    /* reset */
    if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, "waldorf@mupptery.ca", 0)))
        goto err;

    /* Setting an non-matching ip should fail validation even with valid dnsname and email */
    if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, "199.185.178.80")))
        goto err;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
        goto err;
    if (!TEST_false(X509_verify_cert(ctx)))
        fails++;
    X509_STORE_CTX_cleanup(ctx);
    /* reset */
    if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, "2001:503:ba3e::2:30")))
        goto err;

    /* Setting an non-matching dnsname should fail validation even with valid ip and email */
    if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, "www.libressl.org", 0)))
        goto err;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
        goto err;
    if (!TEST_false(X509_verify_cert(ctx)))
        fails++;
    X509_STORE_CTX_cleanup(ctx);
    /* reset */
    if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, "www.muppetry.ca", 0)))
        goto err;

    /* Adding non-matching values to each category with a match will still succeed */
    if (!TEST_true(X509_VERIFY_PARAM_add1_host(vpm, "www.libressl.org", 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_add1_ip_asc(vpm, "199.185.178.80")))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_add1_rfc822(vpm, "beck@openbsd.org", 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_add1_smtputf8(vpm, "学生@muppetry.ca", 0)))
        goto err;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, cert, NULL)))
        goto err;
    if (!TEST_true(X509_verify_cert(ctx)))
        fails++;
    X509_STORE_CTX_cleanup(ctx);

    ret = fails == 0;

err:
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return ret;
}

static int yolo_name_validation(const char *name, size_t len)
{
    return 1;
}

static int yolo_ip_validation(const uint8_t *name, size_t len)
{
    return 1;
}

static const char *valid_emails[] = {
    "@bb",
    "b@bb",
    "b@b-b",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bb",
    "b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    NULL,
};

static const char *invalid_emails[] = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bb",
    "b@b",
    "b@bb.",
    "b@bb..bb",
    "b@bb-.bb",
    "b@-bb.bb",
    "b@bb.-bb",
    "@",
    "@b",
    "b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    NULL,
};

static int test_vpm_input_validation(void)
{
    const char *utf8mail = "学生@muppetry.ca";
    const char *rfc822mail = "beaker@muppetry.ca";
    X509_VERIFY_PARAM *vpm = NULL;
    int ret = 0;

    if (!TEST_ptr(vpm = X509_VERIFY_PARAM_new()))
        goto err;

    if (!TEST_false(X509_VERIFY_PARAM_set1_rfc822(vpm, utf8mail, 0)))
        goto err;
    if (!TEST_false(X509_VERIFY_PARAM_set1_smtputf8(vpm, rfc822mail, 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_rfc822(vpm, rfc822mail, 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_smtputf8(vpm, utf8mail, 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, rfc822mail, 0)))
        goto err;
    if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, utf8mail, 0)))
        goto err;

    for (size_t i = 0; multiname_dnsnames[i] != NULL; i++) {
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, multiname_dnsnames[i], 0)))
            goto err;
        if (!TEST_false(X509_VERIFY_PARAM_set1_email(vpm, multiname_dnsnames[i], 0)))
            goto err;
    }
    for (size_t i = 0; multiname_emails[i] != NULL; i++) {
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, multiname_emails[i], 0)))
            goto err;
        if (!TEST_false(X509_VERIFY_PARAM_set1_host(vpm, multiname_emails[i], 0)))
            goto err;
    }
    for (size_t i = 0; valid_emails[i] != NULL; i++) {
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, valid_emails[i], 0)))
            goto err;
    }
    for (size_t i = 0; invalid_emails[i] != NULL; i++) {
        if (!TEST_false(X509_VERIFY_PARAM_set1_email(vpm, invalid_emails[i], 0)))
            goto err;
    }
    for (size_t i = 0; multiname_ips[i] != NULL; i++) {
        size_t l = strlen(multiname_ips[i]);
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, multiname_ips[i])))
            goto err;
        if (l == 4 || l == 16) {
            if (!TEST_true(X509_VERIFY_PARAM_set1_ip(vpm, (const uint8_t *)multiname_ips[i], l)))
                goto err;
        } else {
            if (!TEST_false(X509_VERIFY_PARAM_set1_ip(vpm, (const uint8_t *)multiname_ips[i], l)))
                goto err;
        }
    }

    X509_VERIFY_PARAM_set1_host_input_validation(vpm, yolo_name_validation);
    X509_VERIFY_PARAM_set1_rfc822_input_validation(vpm, yolo_name_validation);
    X509_VERIFY_PARAM_set1_smtputf8_input_validation(vpm, yolo_name_validation);
    X509_VERIFY_PARAM_set1_ip_input_validation(vpm, yolo_ip_validation);
    for (size_t i = 0; multiname_dnsnames[i] != NULL; i++) {
        /* should still work */
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, multiname_dnsnames[i], 0)))
            goto err;
        /* should be accepted now */
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, multiname_dnsnames[i], 0)))
            goto err;
    }
    for (size_t i = 0; multiname_emails[i] != NULL; i++) {
        /* should still work */
        if (!TEST_true(X509_VERIFY_PARAM_set1_email(vpm, multiname_emails[i], 0)))
            goto err;
        /* should be accepted now */
        if (!TEST_true(X509_VERIFY_PARAM_set1_host(vpm, multiname_emails[i], 0)))
            goto err;
    }
    for (size_t i = 0; multiname_ips[i] != NULL; i++) {
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip_asc(vpm, multiname_ips[i])))
            goto err;
        /* should be accepted now */
        if (!TEST_true(X509_VERIFY_PARAM_set1_ip(vpm, (const uint8_t *)multiname_ips[i], strlen(multiname_ips[i]))))
            goto err;
    }

    ret = 1;

err:
    X509_VERIFY_PARAM_free(vpm);
    return ret;
}

static int test_vpm_copy_string_nul_term(void)
{
    X509_VERIFY_PARAM *src = NULL, *dest = NULL;
    const char *test_host = "test.example.com";
    const char *test_email = "user@example.com";
    const char *ret_host, *ret_email;
    int ret = 0;

    if (!TEST_ptr(src = X509_VERIFY_PARAM_new())
        || !TEST_ptr(dest = X509_VERIFY_PARAM_new()))
        goto err;

    if (!TEST_true(X509_VERIFY_PARAM_set1_host(src, test_host, 0))
        || !TEST_true(X509_VERIFY_PARAM_set1_email(src, test_email, 0)))
        goto err;

    if (!TEST_true(X509_VERIFY_PARAM_set1(dest, src)))
        goto err;

    if (!TEST_ptr(ret_host = X509_VERIFY_PARAM_get0_host(dest, 0))
        || !TEST_str_eq(ret_host, test_host))
        goto err;

    if (!TEST_ptr(ret_email = X509_VERIFY_PARAM_get0_email(dest))
        || !TEST_str_eq(ret_email, test_email))
        goto err;

    ret = 1;

err:
    X509_VERIFY_PARAM_free(src);
    X509_VERIFY_PARAM_free(dest);
    return ret;
}

static int test_self_signed_good(void)
{
    return test_self_signed(root_f, 1, 1);
}

static int test_self_signed_bad(void)
{
    return test_self_signed(bad_f, 1, 0);
}

static int test_self_signed_error(void)
{
    return test_self_signed("nonexistent file name", 1, -1);
}

static int test_store_ctx(void)
{
    /* Verifying a cert where we have no trusted certs should fail */
    return test_self_signed(bad_f, 0, 0);
}

static int do_test_purpose(int purpose, int expected)
{
    X509 *eecert = load_cert_from_file(ee_cert); /* may result in NULL */
    X509 *untrcert = load_cert_from_file(ca_cert);
    X509 *trcert = load_cert_from_file(sroot_cert);
    STACK_OF(X509) *trusted = sk_X509_new_null();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int testresult = 0;

    if (!TEST_ptr(eecert)
        || !TEST_ptr(untrcert)
        || !TEST_ptr(trcert)
        || !TEST_ptr(trusted)
        || !TEST_ptr(untrusted)
        || !TEST_ptr(ctx))
        goto err;

    if (!TEST_true(sk_X509_push(trusted, trcert)))
        goto err;
    trcert = NULL;
    if (!TEST_true(sk_X509_push(untrusted, untrcert)))
        goto err;
    untrcert = NULL;

    if (!TEST_true(X509_STORE_CTX_init(ctx, NULL, eecert, untrusted)))
        goto err;

    if (!TEST_true(X509_STORE_CTX_set_purpose(ctx, purpose)))
        goto err;

    /*
     * X509_STORE_CTX_set0_trusted_stack() is bady named. Despite the set0 name
     * we are still responsible for freeing trusted after we have finished with
     * it.
     */
    X509_STORE_CTX_set0_trusted_stack(ctx, trusted);

    if (!TEST_int_eq(X509_verify_cert(ctx), expected))
        goto err;

    testresult = 1;
err:
    OSSL_STACK_OF_X509_free(trusted);
    OSSL_STACK_OF_X509_free(untrusted);
    X509_STORE_CTX_free(ctx);
    X509_free(eecert);
    X509_free(untrcert);
    X509_free(trcert);
    return testresult;
}

static int test_purpose_ssl_client(void)
{
    return do_test_purpose(X509_PURPOSE_SSL_CLIENT, 0);
}

static int test_purpose_ssl_server(void)
{
    return do_test_purpose(X509_PURPOSE_SSL_SERVER, 1);
}

static int test_purpose_any(void)
{
    return do_test_purpose(X509_PURPOSE_ANY, 1);
}

#ifndef OPENSSL_NO_ECX
/*
 * The CRL scope check compares the names of each distribution point of a
 * certificate with those of the IDP of each candidate CRL.  The number of
 * comparisons per certificate is bounded; a check that would exceed the bound
 * fails with X509_V_ERR_UNSPECIFIED.
 */
static const struct {
    int dp_names; /* names in the certificate's only distribution point */
    int idp_names; /* names in the CRL's IDP */
    int match; /* whether the last IDP name is the last DP name */
    int expected_err;
} crl_scope_tests[] = {
    { 10, 10, 0, X509_V_ERR_DIFFERENT_CRL_SCOPE },
    { 200, 200, 1, X509_V_OK },
    { 300, 300, 0, X509_V_ERR_UNSPECIFIED },
    { 300, 300, 1, X509_V_ERR_UNSPECIFIED },
};

/*
 * Return |n| names: dNSNames "n<i>.example", or URIs for them if |uri| is set.
 * If |last_dns| is set the last name is a dNSName even when |uri| is set.
 */
static GENERAL_NAMES *make_names(int n, int uri, int last_dns)
{
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *gen;
    char buf[64];
    int i;

    if (gens == NULL)
        return NULL;
    for (i = 0; i < n; i++) {
        int dns = !uri || (last_dns && i == n - 1);

        BIO_snprintf(buf, sizeof(buf), dns ? "n%d.example" : "http://n%d.example/", i);
        if ((gen = a2i_GENERAL_NAME(NULL, NULL, NULL, dns ? GEN_DNS : GEN_URI,
                 buf, 0))
                == NULL
            || !sk_GENERAL_NAME_push(gens, gen)) {
            GENERAL_NAME_free(gen);
            GENERAL_NAMES_free(gens);
            return NULL;
        }
    }
    return gens;
}

static DIST_POINT_NAME *make_dpname(GENERAL_NAMES *gens)
{
    DIST_POINT_NAME *dpn = DIST_POINT_NAME_new();

    if (dpn == NULL) {
        GENERAL_NAMES_free(gens);
        return NULL;
    }
    dpn->type = 0;
    dpn->name.fullname = gens;
    return dpn;
}

static X509 *make_crl_scope_cert(EVP_PKEY *key, const X509_NAME *issuer,
    const X509_NAME *subject, int ca, int dp_names)
{
    X509 *x = X509_new();
    X509V3_CTX v3ctx;
    X509_EXTENSION *ext = NULL;
    CRL_DIST_POINTS *crldp = NULL;
    DIST_POINT *dp = NULL;
    int ok = 0;

    if (x == NULL
        || !X509_set_version(x, X509_VERSION_3)
        || !ASN1_INTEGER_set(X509_get_serialNumber(x), ca ? 1 : 2)
        || !X509_set_issuer_name(x, issuer)
        || !X509_set_subject_name(x, subject)
        || X509_gmtime_adj(X509_getm_notBefore(x), -86400) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL
        || !X509_set_pubkey(x, key))
        goto end;
    X509V3_set_ctx(&v3ctx, NULL, x, NULL, NULL, 0);
    if (ca) {
        if ((ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                 "critical,CA:TRUE"))
                == NULL
            || !X509_add_ext(x, ext, -1))
            goto end;
        X509_EXTENSION_free(ext);
        if ((ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_key_usage,
                 "critical,keyCertSign,cRLSign"))
                == NULL
            || !X509_add_ext(x, ext, -1))
            goto end;
    }
    if (dp_names > 0) {
        if ((crldp = sk_DIST_POINT_new_null()) == NULL
            || (dp = DIST_POINT_new()) == NULL
            || (dp->distpoint = make_dpname(make_names(dp_names, 0, 0))) == NULL
            || !sk_DIST_POINT_push(crldp, dp))
            goto end;
        dp = NULL;
        if (X509_add1_ext_i2d(x, NID_crl_distribution_points, crldp, 0, 0) != 1)
            goto end;
    }
    if (X509_sign(x, key, NULL) <= 0)
        goto end;
    ok = 1;
end:
    X509_EXTENSION_free(ext);
    DIST_POINT_free(dp);
    CRL_DIST_POINTS_free(crldp);
    if (!ok) {
        X509_free(x);
        return NULL;
    }
    return x;
}

static X509_CRL *make_crl_scope_crl(EVP_PKEY *key, const X509_NAME *issuer,
    int idp_names, int match)
{
    X509_CRL *crl = X509_CRL_new(), *ret = NULL;
    ISSUING_DIST_POINT *idp = ISSUING_DIST_POINT_new();
    ASN1_TIME *tm = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    if (crl == NULL || idp == NULL
        || !X509_CRL_set_version(crl, X509_CRL_VERSION_2)
        || !X509_CRL_set_issuer_name(crl, issuer)
        || (tm = X509_gmtime_adj(NULL, -3600)) == NULL
        || !X509_CRL_set1_lastUpdate(crl, tm)
        || X509_gmtime_adj(tm, 86400) == NULL
        || !X509_CRL_set1_nextUpdate(crl, tm)
        || (idp->distpoint = make_dpname(make_names(idp_names, 1, match))) == NULL
        || X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, idp, 1, 0) != 1
        || X509_CRL_sign(crl, key, NULL) <= 0
        || (len = i2d_X509_CRL(crl, &der)) <= 0)
        goto end;
    /* The IDP is only cached on decoding */
    p = der;
    ret = d2i_X509_CRL(NULL, &p, len);
end:
    OPENSSL_free(der);
    ASN1_TIME_free(tm);
    ISSUING_DIST_POINT_free(idp);
    X509_CRL_free(crl);
    return ret;
}

static int test_crl_scope_names(int idx)
{
    EVP_PKEY *key = NULL;
    X509_NAME *root_name = NULL, *leaf_name = NULL;
    X509 *root = NULL, *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))
        || !TEST_ptr(root_name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(root_name, "CN", MBSTRING_ASC,
            (const unsigned char *)"Scope Root", -1, -1, 0))
        || !TEST_ptr(leaf_name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(leaf_name, "CN", MBSTRING_ASC,
            (const unsigned char *)"Scope Leaf", -1, -1, 0))
        || !TEST_ptr(root = make_crl_scope_cert(key, root_name, root_name, 1, 0))
        || !TEST_ptr(leaf = make_crl_scope_cert(key, root_name, leaf_name, 0,
                         crl_scope_tests[idx].dp_names))
        || !TEST_ptr(crl = make_crl_scope_crl(key, root_name,
                         crl_scope_tests[idx].idp_names,
                         crl_scope_tests[idx].match))
        || !TEST_ptr(crls = sk_X509_CRL_new_null())
        || !TEST_true(sk_X509_CRL_push(crls, crl)))
        goto err;
    crl = NULL;

    if (!TEST_ptr(store = X509_STORE_new())
        || !TEST_true(X509_STORE_add_cert(store, root))
        || !TEST_true(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK))
        || !TEST_ptr(ctx = X509_STORE_CTX_new())
        || !TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    X509_STORE_CTX_set0_crls(ctx, crls);

    if (!TEST_int_eq(X509_verify_cert(ctx),
            crl_scope_tests[idx].expected_err == X509_V_OK)
        || !TEST_int_eq(X509_STORE_CTX_get_error(ctx),
            crl_scope_tests[idx].expected_err))
        goto err;

    ret = 1;
err:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_CRL_free(crl);
    X509_free(leaf);
    X509_free(root);
    X509_NAME_free(leaf_name);
    X509_NAME_free(root_name);
    EVP_PKEY_free(key);
    return ret;
}
#endif

OPT_TEST_DECLARE_USAGE("certs-dir\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;

    if (!TEST_ptr(root_f = test_mk_file_path(certs_dir, "rootCA.pem"))
        || !TEST_ptr(roots_f = test_mk_file_path(certs_dir, "roots.pem"))
        || !TEST_ptr(untrusted_f = test_mk_file_path(certs_dir, "untrusted.pem"))
        || !TEST_ptr(bad_f = test_mk_file_path(certs_dir, "bad.pem"))
        || !TEST_ptr(req_f = test_mk_file_path(certs_dir, "sm2-csr.pem"))
        || !TEST_ptr(sroot_cert = test_mk_file_path(certs_dir, "sroot-cert.pem"))
        || !TEST_ptr(ca_cert = test_mk_file_path(certs_dir, "ca-cert.pem"))
        || !TEST_ptr(ee_cert = test_mk_file_path(certs_dir, "ee-cert.pem")))
        goto err;

    ADD_TEST(test_alt_chains_cert_forgery);
    ADD_TEST(test_store_ctx);
    ADD_TEST(test_distinguishing_id);
    ADD_TEST(test_req_distinguishing_id);
    ADD_TEST(test_self_signed_good);
    ADD_TEST(test_self_signed_bad);
    ADD_TEST(test_self_signed_error);
#ifndef OPENSSL_NO_ECX
    ADD_ALL_TESTS(test_crl_scope_names, OSSL_NELEM(crl_scope_tests));
#endif
    ADD_TEST(test_purpose_ssl_client);
    ADD_TEST(test_purpose_ssl_server);
    ADD_TEST(test_purpose_any);
    ADD_TEST(test_multiname_selfsigned);
    ADD_TEST(test_vpm_input_validation);
    ADD_TEST(test_vpm_copy_string_nul_term);
    return 1;
err:
    cleanup_tests();
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(root_f);
    OPENSSL_free(roots_f);
    OPENSSL_free(untrusted_f);
    OPENSSL_free(bad_f);
    OPENSSL_free(req_f);
    OPENSSL_free(sroot_cert);
    OPENSSL_free(ca_cert);
    OPENSSL_free(ee_cert);
}
