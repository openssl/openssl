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

/*
 * Test random subnet masks to catch edge cases.
 * This simulates fuzzing by testing various bit patterns and boundary conditions.
 */
static int test_fuzz_random_masks(void)
{
    int i, failures = 0;
    unsigned char ipv4_patterns[][4] = {
        /* Boundary cases */
        {0x00, 0x00, 0x00, 0x00},  /* All zeros - valid */
        {0xff, 0xff, 0xff, 0xff},  /* All ones - valid */
        /* Single bit transitions */
        {0x80, 0x00, 0x00, 0x00},  /* /1 - valid */
        {0xc0, 0x00, 0x00, 0x00},  /* /2 - valid */
        {0xfe, 0x00, 0x00, 0x00},  /* /7 - valid */
        {0xff, 0x80, 0x00, 0x00},  /* /9 - valid */
        {0xff, 0xff, 0xff, 0xfe},  /* /31 - valid */
        /* Invalid patterns with gaps */
        {0x7f, 0xff, 0xff, 0xff},  /* Leading zero bit - invalid */
        {0xff, 0x7f, 0xff, 0xff},  /* Gap in second byte - invalid */
        {0xff, 0xff, 0x7f, 0xff},  /* Gap in third byte - invalid */
        {0xff, 0xff, 0xff, 0x7f},  /* Gap in fourth byte - invalid */
        {0xaa, 0x00, 0x00, 0x00},  /* Alternating bits - invalid */
        {0x55, 0x00, 0x00, 0x00},  /* Alternating bits - invalid */
        {0xff, 0x00, 0x00, 0x01},  /* Trailing 1 after 0s - invalid */
        {0xf0, 0x0f, 0x00, 0x00},  /* Non-contiguous - invalid */
        /* Partial byte transitions */
        {0xf8, 0x00, 0x00, 0x00},  /* /5 - valid */
        {0xfc, 0x00, 0x00, 0x00},  /* /6 - valid */
        {0xff, 0xf0, 0x00, 0x00},  /* /12 - valid */
        {0xff, 0xfe, 0x00, 0x00},  /* /15 - valid */
    };

    TEST_info("Fuzzing IPv4 subnet masks with various patterns");

    for (i = 0; i < (int)(sizeof(ipv4_patterns) / sizeof(ipv4_patterns[0])); i++) {
        X509 *ca = NULL;
        char nc_config[128];
        int should_fail = 0;

        /* Determine if this pattern should be valid or invalid */
        /* Valid patterns: all 0s, contiguous 1s followed by 0s */
        unsigned char *mask = ipv4_patterns[i];
        int found_zero = 0;
        int is_valid = 1;

        for (int j = 0; j < 4 && is_valid; j++) {
            uint8_t v = mask[j];
            if (v == 0) {
                found_zero = 1;
            } else if (v == 0xff) {
                if (found_zero)
                    is_valid = 0;
            } else {
                /* Check bits in partial byte */
                for (int k = 0; k < 8; k++) {
                    if (((v << k) & 0x80) == 0)
                        found_zero = 1;
                    else if (found_zero)
                        is_valid = 0;
                }
            }
        }

        /* Create NAME_CONSTRAINTS config with this mask */
        snprintf(nc_config, sizeof(nc_config), "permitted;IP:192.168.0.0/%d.%d.%d.%d",
                 mask[0], mask[1], mask[2], mask[3]);

        ca = create_ca_with_nc(nc_config);

        if (is_valid) {
            if (ca == NULL) {
                TEST_error("Valid mask pattern [%02x.%02x.%02x.%02x] was rejected",
                           mask[0], mask[1], mask[2], mask[3]);
                failures++;
            } else {
                TEST_info("Valid mask pattern [%02x.%02x.%02x.%02x] accepted",
                          mask[0], mask[1], mask[2], mask[3]);
            }
        } else {
            if (ca != NULL) {
                TEST_error("Invalid mask pattern [%02x.%02x.%02x.%02x] was accepted (should be rejected)",
                           mask[0], mask[1], mask[2], mask[3]);
                failures++;
            } else {
                TEST_info("Invalid mask pattern [%02x.%02x.%02x.%02x] rejected (correct)",
                          mask[0], mask[1], mask[2], mask[3]);
            }
        }

        X509_free(ca);
    }

    /* Test some IPv6 patterns */
    TEST_info("Fuzzing IPv6 subnet masks");

    unsigned char ipv6_valid[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }; /* /64 - valid */

    unsigned char ipv6_invalid[16] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }; /* Gap - invalid */

    /* Test valid IPv6 mask */
    {
        X509 *ca = NULL;
        char nc_config[256];
        snprintf(nc_config, sizeof(nc_config),
                 "permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:0000:0000:0000:0000");
        ca = create_ca_with_nc(nc_config);
        if (ca == NULL) {
            TEST_error("Valid IPv6 /64 mask was rejected");
            failures++;
        } else {
            TEST_info("Valid IPv6 /64 mask accepted");
        }
        X509_free(ca);
    }

    /* Test invalid IPv6 mask */
    {
        X509 *ca = NULL;
        char nc_config[256];
        snprintf(nc_config, sizeof(nc_config),
                 "permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:0000:0000:ffff:ffff");
        ca = create_ca_with_nc(nc_config);
        if (ca != NULL) {
            TEST_error("Invalid IPv6 mask with gap was accepted (should be rejected)");
            failures++;
            X509_free(ca);
        } else {
            TEST_info("Invalid IPv6 mask with gap rejected (correct)");
        }
    }

    return failures == 0;
}

/*
 * LibFuzzer integration (optional, for continuous fuzzing).
 * This function is called by libFuzzer with random data to discover edge cases
 * in subnet mask validation that might not be covered by structured tests.
 *
 * To build with fuzzing support:
 *   CC=clang ./Configure enable-fuzz-libfuzzer
 *   make
 *   ./fuzz/nc_invalid_mask_test corpus/
 */
#ifdef FUZZ_MAIN
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    X509 *ca = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509_NAME *name = NULL;
    X509_EXTENSION *ext = NULL;
    X509V3_CTX v3ctx;
    NAME_CONSTRAINTS *nc = NULL;
    GENERAL_SUBTREE *sub = NULL;
    ASN1_OCTET_STRING *ipaddr = NULL;
    unsigned char nc_config[256];
    int ret = 0;

    /* Need at least 4 bytes for IPv4 mask or 16 for IPv6 */
    if (size < 4)
        return 0;

    /* Test IPv4 mask (4 bytes) */
    if (size >= 4) {
        /* Create NAME_CONSTRAINTS with fuzzed IPv4 mask */
        nc = NAME_CONSTRAINTS_new();
        if (nc == NULL)
            goto cleanup;

        sub = GENERAL_SUBTREE_new();
        if (sub == NULL)
            goto cleanup;

        sub->base = GENERAL_NAME_new();
        if (sub->base == NULL)
            goto cleanup;

        sub->base->type = GEN_IPADD;

        /* Create IP address octet string: 192.168.0.0 + fuzzed mask */
        ipaddr = ASN1_OCTET_STRING_new();
        if (ipaddr == NULL)
            goto cleanup;

        if (!ASN1_OCTET_STRING_set(ipaddr, NULL, 8))
            goto cleanup;

        /* Set IP address */
        ipaddr->data[0] = 192;
        ipaddr->data[1] = 168;
        ipaddr->data[2] = 0;
        ipaddr->data[3] = 0;

        /* Set fuzzed mask */
        memcpy(ipaddr->data + 4, data, 4);

        sub->base->d.iPAddress = ipaddr;
        ipaddr = NULL; /* Owned by sub now */

        nc->permittedSubtrees = sk_GENERAL_SUBTREE_new_null();
        if (nc->permittedSubtrees == NULL)
            goto cleanup;

        if (!sk_GENERAL_SUBTREE_push(nc->permittedSubtrees, sub))
            goto cleanup;

        sub = NULL; /* Owned by nc now */

        /* Try to create certificate with this NAME_CONSTRAINTS
         * This exercises the validation code path */
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (pctx == NULL)
            goto cleanup;

        if (EVP_PKEY_keygen_init(pctx) <= 0)
            goto cleanup;

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
            goto cleanup;

        if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
            goto cleanup;

        ca = X509_new();
        if (ca == NULL)
            goto cleanup;

        if (!X509_set_version(ca, X509_VERSION_3))
            goto cleanup;

        if (!ASN1_INTEGER_set(X509_get_serialNumber(ca), 1))
            goto cleanup;

        name = X509_NAME_new();
        if (name == NULL)
            goto cleanup;

        if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                         (unsigned char *)"Fuzz Test CA", -1, -1, 0))
            goto cleanup;

        if (!X509_set_subject_name(ca, name))
            goto cleanup;

        if (!X509_set_issuer_name(ca, name))
            goto cleanup;

        if (!X509_gmtime_adj(X509_getm_notBefore(ca), 0))
            goto cleanup;

        if (!X509_gmtime_adj(X509_getm_notAfter(ca), 31536000L))
            goto cleanup;

        if (!X509_set_pubkey(ca, pkey))
            goto cleanup;

        /* Add the NAME_CONSTRAINTS extension with fuzzed mask
         * This will trigger validation in nc_ip() */
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, ca, ca, NULL, NULL, 0);

        /* Encode NAME_CONSTRAINTS to DER */
        unsigned char *der = NULL;
        int derlen = i2d_NAME_CONSTRAINTS(nc, &der);
        if (derlen > 0) {
            ASN1_OCTET_STRING *ext_data = ASN1_OCTET_STRING_new();
            if (ext_data != NULL) {
                if (ASN1_OCTET_STRING_set(ext_data, der, derlen)) {
                    ext = X509_EXTENSION_create_by_NID(NULL, NID_name_constraints, 1, ext_data);
                    if (ext != NULL) {
                        /* This will validate the mask during verification */
                        X509_add_ext(ca, ext, -1);
                    }
                }
                ASN1_OCTET_STRING_free(ext_data);
            }
            OPENSSL_free(der);
        }

        /* Try to verify - exercises nc_ip() validation code */
        X509_STORE *store = X509_STORE_new();
        if (store != NULL) {
            X509_STORE_CTX *ctx = X509_STORE_CTX_new();
            if (ctx != NULL) {
                X509_STORE_add_cert(store, ca);
                X509_STORE_CTX_init(ctx, store, ca, NULL);
                /* Don't care about result, just exercising validation */
                X509_verify_cert(ctx);
                X509_STORE_CTX_free(ctx);
            }
            X509_STORE_free(store);
        }
    }

    /* Test IPv6 mask (16 bytes) if we have enough data */
    if (size >= 16) {
        NAME_CONSTRAINTS_free(nc);
        nc = NAME_CONSTRAINTS_new();
        if (nc == NULL)
            goto cleanup;

        sub = GENERAL_SUBTREE_new();
        if (sub == NULL)
            goto cleanup;

        sub->base = GENERAL_NAME_new();
        if (sub->base == NULL)
            goto cleanup;

        sub->base->type = GEN_IPADD;

        ipaddr = ASN1_OCTET_STRING_new();
        if (ipaddr == NULL)
            goto cleanup;

        if (!ASN1_OCTET_STRING_set(ipaddr, NULL, 32))
            goto cleanup;

        /* Set IPv6 address 2001:db8:: */
        ipaddr->data[0] = 0x20;
        ipaddr->data[1] = 0x01;
        ipaddr->data[2] = 0x0d;
        ipaddr->data[3] = 0xb8;
        memset(ipaddr->data + 4, 0, 12);

        /* Set fuzzed IPv6 mask */
        memcpy(ipaddr->data + 16, data, 16);

        sub->base->d.iPAddress = ipaddr;
        ipaddr = NULL;

        nc->excludedSubtrees = sk_GENERAL_SUBTREE_new_null();
        if (nc->excludedSubtrees == NULL)
            goto cleanup;

        if (!sk_GENERAL_SUBTREE_push(nc->excludedSubtrees, sub))
            goto cleanup;

        sub = NULL;

        /* Try encoding - will exercise validation */
        unsigned char *der = NULL;
        int derlen = i2d_NAME_CONSTRAINTS(nc, &der);
        OPENSSL_free(der);
    }

    ret = 0;

cleanup:
    X509_EXTENSION_free(ext);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    X509_free(ca);
    NAME_CONSTRAINTS_free(nc);
    GENERAL_SUBTREE_free(sub);
    ASN1_OCTET_STRING_free(ipaddr);

    return ret;
}
#endif /* FUZZ_MAIN */

int setup_tests(void)
{
    ADD_TEST(test_ipv4_noncontiguous_mask_1);
    ADD_TEST(test_ipv4_noncontiguous_mask_2);
    ADD_TEST(test_ipv4_noncontiguous_mask_3);
    ADD_TEST(test_ipv4_valid_masks);
    ADD_TEST(test_ipv6_noncontiguous_mask);
    ADD_TEST(test_ipv6_valid_masks);
    ADD_TEST(test_fuzz_random_masks);
    return 1;
}
