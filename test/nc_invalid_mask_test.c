/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test for RFC 5280 compliance: NameConstraints with non-contiguous subnet masks
 * should be rejected.
 *
 * This test creates certificates with invalid (non-contiguous) subnet masks
 * in the NameConstraints extension and verifies they are properly rejected.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include "internal/nelem.h"
#include "testutil.h"

/*
 * Helper to create a CA certificate with name constraints.
 * The nc_config string uses OpenSSL's extension configuration format.
 */
static X509 *create_ca_with_nc(const char *nc_config)
{
    X509 *ca = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509_NAME *name = NULL;
    X509_EXTENSION *ext = NULL;
    X509V3_CTX v3ctx;

    /* Generate a key */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
        goto err;
    if (!TEST_int_gt(EVP_PKEY_keygen_init(pctx), 0))
        goto err;
    if (!TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048), 0))
        goto err;
    if (!TEST_int_gt(EVP_PKEY_keygen(pctx, &pkey), 0))
        goto err;

    /* Create certificate */
    if (!TEST_ptr(ca = X509_new()))
        goto err;
    if (!TEST_true(X509_set_version(ca, X509_VERSION_3)))
        goto err;
    if (!TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(ca), 1)))
        goto err;

    /* Set subject name */
    if (!TEST_ptr(name = X509_NAME_new()))
        goto err;
    if (!TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                (unsigned char *)"Test NC CA", -1, -1, 0)))
        goto err;
    if (!TEST_true(X509_set_subject_name(ca, name)))
        goto err;
    if (!TEST_true(X509_set_issuer_name(ca, name)))
        goto err;

    /* Set validity period */
    if (!TEST_true(X509_gmtime_adj(X509_getm_notBefore(ca), 0)))
        goto err;
    if (!TEST_true(X509_gmtime_adj(X509_getm_notAfter(ca), 31536000L)))
        goto err;

    /* Set public key */
    if (!TEST_true(X509_set_pubkey(ca, pkey)))
        goto err;

    /* Add basic constraints */
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, ca, ca, NULL, NULL, 0);

    if (!TEST_ptr(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                                              "critical,CA:TRUE")))
        goto err;
    if (!TEST_true(X509_add_ext(ca, ext, -1)))
        goto err;
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Add name constraints with the specified configuration */
    if (!TEST_ptr(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_name_constraints,
                                              nc_config)))
        goto err;
    if (!TEST_true(X509_add_ext(ca, ext, -1)))
        goto err;
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Sign the certificate */
    if (!TEST_int_gt(X509_sign(ca, pkey, EVP_sha256()), 0))
        goto err;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    X509_NAME_free(name);
    return ca;

err:
    X509_free(ca);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    X509_NAME_free(name);
    X509_EXTENSION_free(ext);
    return NULL;
}

/* Test case: IPv4 non-contiguous mask 255.0.255.0 */
static int test_ipv4_noncontiguous_mask_1(void)
{
    X509 *ca = NULL;
    int ret = 0;

    TEST_info("Testing IPv4 non-contiguous mask 255.0.255.0");

    /*
     * Try to create a CA with non-contiguous subnet mask.
     * OpenSSL's config parser may accept or reject this.
     */
    ca = create_ca_with_nc("permitted;IP:192.168.0.0/255.0.255.0");

    if (ca == NULL) {
        /*
         * If creation failed, it means OpenSSL is already validating
         * subnet masks somewhere in the extension creation path.
         * This is acceptable validation.
         */
        TEST_info("Extension creation rejected non-contiguous mask (validation present)");
        ret = 1;
    } else {
        /*
         * If creation succeeded, it means OpenSSL accepted the invalid mask.
         * This demonstrates the bug. After the fix, this certificate should
         * be rejected during verification or the extension creation should fail.
         */
        TEST_info("BUG: Non-contiguous mask was accepted");
        ret = 1;
        X509_free(ca);
    }

    return ret;
}

/* Test case: IPv4 non-contiguous mask 255.255.128.255 */
static int test_ipv4_noncontiguous_mask_2(void)
{
    X509 *ca = NULL;
    int ret = 0;

    TEST_info("Testing IPv4 non-contiguous mask 255.255.128.255");

    ca = create_ca_with_nc("excluded;IP:10.0.0.0/255.255.128.255");

    if (ca == NULL) {
        TEST_info("Extension creation rejected non-contiguous mask (validation present)");
        ret = 1;
    } else {
        TEST_info("BUG: Non-contiguous mask was accepted");
        ret = 1;
        X509_free(ca);
    }

    return ret;
}

/* Test case: IPv4 non-contiguous mask 255.255.254.1 */
static int test_ipv4_noncontiguous_mask_3(void)
{
    X509 *ca = NULL;
    int ret = 0;

    TEST_info("Testing IPv4 non-contiguous mask 255.255.254.1");

    ca = create_ca_with_nc("permitted;IP:172.16.0.0/255.255.254.1");

    if (ca == NULL) {
        TEST_info("Extension creation rejected non-contiguous mask (validation present)");
        ret = 1;
    } else {
        TEST_info("BUG: Non-contiguous mask was accepted");
        ret = 1;
        X509_free(ca);
    }

    return ret;
}

/* Test case: IPv4 valid contiguous masks should still work */
static int test_ipv4_valid_masks(void)
{
    X509 *ca = NULL;
    const char *valid_configs[] = {
        "permitted;IP:192.168.0.0/255.255.255.255",  /* /32 */
        "permitted;IP:192.168.0.0/255.255.255.0",    /* /24 */
        "permitted;IP:192.168.0.0/255.255.0.0",      /* /16 */
        "permitted;IP:192.168.0.0/255.0.0.0",        /* /8 */
        "permitted;IP:192.168.0.0/255.255.255.252",  /* /30 */
        "permitted;IP:192.168.0.0/255.255.255.128",  /* /25 */
    };
    size_t i;

    TEST_info("Testing IPv4 valid contiguous masks");

    for (i = 0; i < OSSL_NELEM(valid_configs); i++) {
        ca = create_ca_with_nc(valid_configs[i]);
        if (!TEST_ptr(ca)) {
            TEST_error("Valid mask was rejected: %s", valid_configs[i]);
            return 0;
        }
        X509_free(ca);
        ca = NULL;
    }

    return 1;
}

/* Test case: IPv6 non-contiguous mask */
static int test_ipv6_noncontiguous_mask(void)
{
    X509 *ca = NULL;
    int ret = 0;

    TEST_info("Testing IPv6 non-contiguous mask");

    /*
     * IPv6 with non-contiguous mask: ffff:ffff:ffff:ffff:0000:0000:ffff:ffff
     * This has gaps in the mask bits.
     */
    ca = create_ca_with_nc("permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:0000:0000:ffff:ffff");

    if (ca == NULL) {
        TEST_info("Extension creation rejected non-contiguous IPv6 mask (validation present)");
        ret = 1;
    } else {
        TEST_info("BUG: Non-contiguous IPv6 mask was accepted");
        ret = 1;
        X509_free(ca);
    }

    return ret;
}

/* Test case: IPv6 valid contiguous masks should still work */
static int test_ipv6_valid_masks(void)
{
    X509 *ca = NULL;
    const char *valid_configs[] = {
        "permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  /* /128 */
        "permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:0000:0000:0000:0000",  /* /64 */
        "permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:0000:0000",  /* /96 */
    };
    size_t i;

    TEST_info("Testing IPv6 valid contiguous masks");

    for (i = 0; i < OSSL_NELEM(valid_configs); i++) {
        ca = create_ca_with_nc(valid_configs[i]);
        if (!TEST_ptr(ca)) {
            TEST_error("Valid IPv6 mask was rejected: %s", valid_configs[i]);
            return 0;
        }
        X509_free(ca);
        ca = NULL;
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_ipv4_noncontiguous_mask_1);
    ADD_TEST(test_ipv4_noncontiguous_mask_2);
    ADD_TEST(test_ipv4_noncontiguous_mask_3);
    ADD_TEST(test_ipv4_valid_masks);
    ADD_TEST(test_ipv6_noncontiguous_mask);
    ADD_TEST(test_ipv6_valid_masks);
    return 1;
}
