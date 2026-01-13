/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test for issue #26099 - Certificate policy extension validation
 * Ensures OpenSSL rejects certificate policies with missing OIDs
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "testutil.h"

/* Include internal header to access X509_POLICY_DATA and related functions */
#include "../crypto/x509/pcy_local.h"

/*
 * Test that ossl_policy_data_new() rejects a POLICYINFO with NULL policyid
 * This is the core fix for issue #26099 - ensuring the required OID is present
 */
static int test_null_policyid(void)
{
    POLICYINFO *pinfo = NULL;
    POLICYQUALINFO *qual = NULL;
    X509_POLICY_DATA *pdata = NULL;
    int ret = 0;

    /* Create a POLICYINFO with NULL policyid */
    if (!TEST_ptr(pinfo = POLICYINFO_new()))
        goto err;

    /* Deliberately set policyid to NULL - this is invalid per RFC 5280 */
    pinfo->policyid = NULL;

    /* Add a qualifier to make it more realistic */
    if (!TEST_ptr(qual = POLICYQUALINFO_new()))
        goto err;

    if (!TEST_ptr(qual->pqualid = OBJ_nid2obj(NID_id_qt_cps)))
        goto err;

    if (!TEST_ptr(qual->d.cpsuri = ASN1_IA5STRING_new()))
        goto err;

    if (!TEST_true(ASN1_STRING_set(qual->d.cpsuri, "http://example.com/cps", -1)))
        goto err;

    if (!TEST_ptr(pinfo->qualifiers = sk_POLICYQUALINFO_new_null()))
        goto err;

    if (!TEST_true(sk_POLICYQUALINFO_push(pinfo->qualifiers, qual)))
        goto err;

    qual = NULL; /* Now owned by pinfo */

    /*
     * Try to create policy data from this invalid POLICYINFO
     * This should return NULL due to the NULL policyid
     */
    pdata = ossl_policy_data_new(pinfo, NULL, 0);

    /* Verify that the function correctly rejected the NULL policyid */
    if (!TEST_ptr_null(pdata)) {
        TEST_error("ossl_policy_data_new() accepted NULL policyid (should have rejected)");
        goto err;
    }

    TEST_info("ossl_policy_data_new() correctly rejected NULL policyid");
    ret = 1;

err:
    ossl_policy_data_free(pdata);
    POLICYINFO_free(pinfo);
    POLICYQUALINFO_free(qual);
    return ret;
}

/*
 * Test that a valid certificate policy is still accepted
 * This ensures our fix doesn't break legitimate certificates
 */
static int test_valid_policyid(void)
{
    X509 *cert = NULL;
    BIO *bio = NULL;
    int ret = 0;
    uint32_t ex_flags;

    /* Load a certificate with valid policies */
    if (!TEST_ptr(bio = BIO_new_file(test_get_argument(0), "r")))
        return 0;

    if (!TEST_ptr(cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)))
        goto err;

    /* Process the certificate */
    X509_check_purpose(cert, -1, 0);

    /* Check that the certificate is NOT marked as having invalid policy */
    ex_flags = X509_get_extension_flags(cert);

    if (!TEST_false(ex_flags & EXFLAG_INVALID_POLICY)) {
        TEST_error("Valid certificate incorrectly rejected (flags=0x%x)", ex_flags);
        goto err;
    }

    TEST_info("Valid certificate with policies correctly accepted");
    ret = 1;

err:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    /* Test with programmatically created bad policy */
    ADD_TEST(test_null_policyid);

    /* Test with valid policy certificate if provided */
    if (test_get_argument_count() > 0)
        ADD_TEST(test_valid_policyid);

    return 1;
}
