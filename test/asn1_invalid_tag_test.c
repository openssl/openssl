/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Comprehensive tests for issue #28424: Invalid non-minimal tag encodings
 *
 * Tests verify that ASN1_get_object() correctly rejects tag values < 31
 * encoded in long form, which violates ITU-T X.690 (02/2021) Sec. 8.1.2
 */

#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "testutil.h"

/* Certificate from issue #28424 with invalid tag encoding at start */
static const char *issue_28424_cert_pem =
    "-----BEGIN CERTIFICATE-----\n"
    "P4AQggKaMIIBggIJAPgF9O2OuYHOMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMM\n"
    "BFRlc3QwHhcNMjUwOTAyMTU1MzMzWhcNMjUxMDAyMTU1MzMzWjAPMQ0wCwYDVQQD\n"
    "DARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFCUHUKqiQh3\n"
    "Nt8w+Z9vvdqsDz1bwsFaTJQmVKoRhMiFTxAJFLnVrKGc8QiYkBrmV+Hb7IpYxjrJ\n"
    "fiACoy1vJCfxkDXVQAIP6FxykGpbkP+gO7bms4zICyr3yww2bvdUaSEe1LmtMAur\n"
    "lj2xGjhZg4SF8WzaNUeOqp4JrXcpD6nIWIcfIb/kKSi8V4GB0OjyDtA/9VjxsQfw\n"
    "3N/Qj8FXDa01wwXQzRo+NqgEl4rGzzeljV+XRSlxDwZ3ME+EPC+Wq0YoqbkTpDwT\n"
    "Z19BUu62Lk2pFNHBiM65wW0NBPtTrOG+HehmKK9h3ZS6eYcqy7BIdMl+ILqnthiK\n"
    "pHK3fIKoswIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBKAh7nscFN+X0pGdgjm5tl\n"
    "0cDObIufUScm2mHo2/6D5e/rgRmv2N+m16nVb0ugaZqn9VITI4Ub07DmsentYm5H\n"
    "n7bvGMMgdgfvEaM0WieqUvRoz1B5SR9Ks7eRxYYaKGoHnJXItHx44bom9r5dNsy0\n"
    "Go/jNCEpe8JfGfGu786q1siCrK0NwV/m5ZKhWBXZg9air231TTXDT1W9UAp/H+7P\n"
    "pVpFSNqaRUYba+Pu7Vwe2172d4uKteoX20oPlMW5LbsAWpOiYi/yXs5qO8T2pvT3\n"
    "4TVt2UTxYe96kU7ehnMCtuA5bdtgGVy2RRHQrFhn1nHN1p0HB3nk3Vyfhxlyutnl\n"
    "-----END CERTIFICATE-----\n";

/*
 * Test structure for invalid tag encodings
 * Each entry contains a tag value that should be rejected when encoded in long form
 */
struct invalid_tag_test {
    const char *name;
    int tag_value;              /* Tag value < 31 */
    unsigned char encoding[4];  /* Long-form encoding bytes */
    size_t encoding_len;
};

/*
 * Test cases for invalid long-form encodings of tags < 31
 * Format: 0x1f (or 0x3f for constructed) followed by encoded tag value
 */
static struct invalid_tag_test invalid_tag_tests[] = {
    /* SEQUENCE (16) - the case from issue #28424 */
    {
        "SEQUENCE (tag 16) long-form",
        16,
        {0x3f, 0x80, 0x10, 0x00},  /* 0x3f = constructed+long, 0x80 0x10 = tag 16 */
        4
    },
    /* EOC (0) */
    {
        "EOC (tag 0) long-form",
        0,
        {0x1f, 0x80, 0x00, 0x00},  /* 0x1f = primitive+long, 0x80 0x00 = tag 0 */
        4
    },
    /* BOOLEAN (1) */
    {
        "BOOLEAN (tag 1) long-form",
        1,
        {0x1f, 0x80, 0x01, 0x00},
        4
    },
    /* INTEGER (2) */
    {
        "INTEGER (tag 2) long-form",
        2,
        {0x1f, 0x80, 0x02, 0x00},
        4
    },
    /* BIT STRING (3) */
    {
        "BIT STRING (tag 3) long-form",
        3,
        {0x1f, 0x80, 0x03, 0x00},
        4
    },
    /* OCTET STRING (4) */
    {
        "OCTET STRING (tag 4) long-form",
        4,
        {0x1f, 0x80, 0x04, 0x00},
        4
    },
    /* NULL (5) */
    {
        "NULL (tag 5) long-form",
        5,
        {0x1f, 0x80, 0x05, 0x00},
        4
    },
    /* OBJECT IDENTIFIER (6) */
    {
        "OBJECT IDENTIFIER (tag 6) long-form",
        6,
        {0x1f, 0x80, 0x06, 0x00},
        4
    },
    /* UTF8String (12) */
    {
        "UTF8String (tag 12) long-form",
        12,
        {0x1f, 0x80, 0x0c, 0x00},
        4
    },
    /* SET (17) */
    {
        "SET (tag 17) long-form",
        17,
        {0x3f, 0x80, 0x11, 0x00},  /* Constructed */
        4
    },
    /* PrintableString (19) */
    {
        "PrintableString (tag 19) long-form",
        19,
        {0x1f, 0x80, 0x13, 0x00},
        4
    },
    /* IA5String (22) */
    {
        "IA5String (tag 22) long-form",
        22,
        {0x1f, 0x80, 0x16, 0x00},
        4
    },
    /* UTCTime (23) */
    {
        "UTCTime (tag 23) long-form",
        23,
        {0x1f, 0x80, 0x17, 0x00},
        4
    },
    /* Edge case: tag 30 (highest tag before long-form required) */
    {
        "Tag 30 long-form (edge case)",
        30,
        {0x1f, 0x80, 0x1e, 0x00},
        4
    },
};

/*
 * Test structure for valid tag encodings
 */
struct valid_tag_test {
    const char *name;
    int tag_value;
    unsigned char encoding[4];
    size_t encoding_len;
    int expected_ret;  /* Expected return value from ASN1_get_object */
};

static struct valid_tag_test valid_tag_tests[] = {
    /* Short-form encodings (tags 0-30) - these should all work */
    {
        "BOOLEAN (tag 1) short-form",
        1,
        {0x01, 0x01, 0x00},  /* BOOLEAN, length 1, value 0 */
        3,
        0  /* Primitive */
    },
    {
        "INTEGER (tag 2) short-form",
        2,
        {0x02, 0x00},  /* INTEGER, length 0 */
        2,
        0
    },
    {
        "SEQUENCE (tag 16) short-form",
        16,
        {0x30, 0x00},  /* SEQUENCE, length 0 */
        2,
        V_ASN1_CONSTRUCTED
    },
    {
        "SET (tag 17) short-form",
        17,
        {0x31, 0x00},  /* SET, length 0 */
        2,
        V_ASN1_CONSTRUCTED
    },
    {
        "Tag 30 short-form (edge case)",
        30,
        {0x1e, 0x00},  /* Tag 30, length 0 */
        2,
        0
    },
    /* Long-form encodings (tags >= 31) - these are required to use long form */
    {
        "Tag 31 long-form (minimum valid)",
        31,
        {0x1f, 0x1f, 0x00},  /* 0x1f = long form indicator, 0x1f = tag 31 */
        3,
        0
    },
    {
        "Tag 32 long-form",
        32,
        {0x1f, 0x20, 0x00},  /* Tag 32 */
        3,
        0
    },
    {
        "Tag 100 long-form",
        100,
        {0x1f, 0x64, 0x00},  /* Tag 100 */
        3,
        0
    },
    {
        "Tag 127 long-form (single byte boundary)",
        127,
        {0x1f, 0x7f, 0x00},  /* Tag 127 */
        3,
        0
    },
    {
        "Tag 128 long-form (multi-byte)",
        128,
        {0x1f, 0x81, 0x00, 0x00},  /* 0x81 0x00 = tag 128 */
        4,
        0
    },
    {
        "Tag 255 long-form (multi-byte)",
        255,
        {0x1f, 0x81, 0x7f, 0x00},  /* 0x81 0x7f = tag 255 */
        4,
        0
    },
};

/*
 * Test that ASN1_get_object rejects invalid long-form encodings for tags < 31
 */
static int test_asn1_invalid_tag(int idx)
{
    struct invalid_tag_test *test = &invalid_tag_tests[idx];
    const unsigned char *p = test->encoding;
    long len = 0;
    int tag = 0, xclass = 0;
    int ret;
    unsigned long err;

    TEST_info("Testing: %s", test->name);
    ERR_clear_error();

    ret = ASN1_get_object(&p, &len, &tag, &xclass, test->encoding_len);

    if (!TEST_int_eq(ret, 0x80)) {
        TEST_error("Expected ASN1_get_object to return 0x80 (error)");
        return 0;
    }

    err = ERR_peek_error();
    if (!TEST_ulong_ne(err, 0)) {
        TEST_error("Expected an error to be raised");
        return 0;
    }

    if (!TEST_int_eq(ERR_GET_REASON(err), ASN1_R_INVALID_BER_TAG_ENCODING)) {
        TEST_error("Expected ASN1_R_INVALID_BER_TAG_ENCODING error");
        TEST_info("Got error: %s", ERR_error_string(err, NULL));
        return 0;
    }

    ERR_clear_error();
    TEST_info("✓ Correctly rejected invalid long-form encoding of tag %d", test->tag_value);
    return 1;
}

/*
 * Test that ASN1_get_object accepts valid tag encodings
 */
static int test_asn1_valid_tag(int idx)
{
    struct valid_tag_test *test = &valid_tag_tests[idx];
    const unsigned char *p = test->encoding;
    long len = 0;
    int tag = 0, xclass = 0;
    int ret;

    TEST_info("Testing: %s", test->name);
    ERR_clear_error();

    ret = ASN1_get_object(&p, &len, &tag, &xclass, test->encoding_len);

    if (!TEST_int_eq(ret, test->expected_ret)) {
        TEST_error("Unexpected return value from ASN1_get_object");
        TEST_info("Expected: 0x%x, Got: 0x%x", test->expected_ret, ret);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (!TEST_int_eq(tag, test->tag_value)) {
        TEST_error("Tag value mismatch");
        TEST_info("Expected: %d, Got: %d", test->tag_value, tag);
        return 0;
    }

    if (ERR_peek_error() != 0) {
        TEST_error("Unexpected error for valid encoding");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    TEST_info("✓ Correctly accepted valid encoding of tag %d", test->tag_value);
    return 1;
}

/*
 * Test that the certificate from issue #28424 is rejected
 */
static int test_issue_28424_certificate_pem(void)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    unsigned long err;
    int found_error = 0;
    int ret = 0;

    TEST_info("Testing certificate from issue #28424 (PEM format)");
    ERR_clear_error();

    bio = BIO_new_mem_buf(issue_28424_cert_pem, -1);
    if (!TEST_ptr(bio)) {
        TEST_error("Failed to create BIO");
        goto end;
    }

    /* This should fail due to invalid tag encoding */
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (!TEST_ptr_null(cert)) {
        TEST_error("Certificate should have been rejected but was accepted!");
        goto end;
    }

    /* Look for ASN1_R_INVALID_BER_TAG_ENCODING in error queue */
    while ((err = ERR_get_error()) != 0) {
        if (ERR_GET_LIB(err) == ERR_LIB_ASN1 &&
            ERR_GET_REASON(err) == ASN1_R_INVALID_BER_TAG_ENCODING) {
            found_error = 1;
            TEST_info("✓ Found expected error: ASN1_R_INVALID_BER_TAG_ENCODING");
            break;
        }
    }

    if (!TEST_true(found_error)) {
        TEST_error("Expected ASN1_R_INVALID_BER_TAG_ENCODING in error queue");
        goto end;
    }

    ret = 1;

end:
    BIO_free(bio);
    X509_free(cert);
    ERR_clear_error();
    return ret;
}

/*
 * Test that the raw DER bytes from issue #28424 are rejected
 */
static int test_issue_28424_certificate_der(void)
{
    /*
     * First few bytes of the certificate from issue #28424
     * 0x3f 0x80 0x10 = invalid long-form encoding for SEQUENCE (tag 16)
     */
    static const unsigned char invalid_cert_der[] = {
        0x3f, 0x80, 0x10, 0x82, 0x02, 0x9a, /* Invalid SEQUENCE tag */
        0x30, 0x82, 0x01, 0x82, 0x02, 0x09,  /* ... rest of cert */
    };
    const unsigned char *p = invalid_cert_der;
    X509 *cert = NULL;
    unsigned long err;
    int found_error = 0;
    int ret = 0;

    TEST_info("Testing certificate from issue #28424 (raw DER)");
    ERR_clear_error();

    cert = d2i_X509(NULL, &p, sizeof(invalid_cert_der));

    if (!TEST_ptr_null(cert)) {
        TEST_error("Certificate should have been rejected but was accepted!");
        goto end;
    }

    /* Look for our specific error */
    while ((err = ERR_get_error()) != 0) {
        if (ERR_GET_LIB(err) == ERR_LIB_ASN1 &&
            ERR_GET_REASON(err) == ASN1_R_INVALID_BER_TAG_ENCODING) {
            found_error = 1;
            TEST_info("✓ Found expected error: ASN1_R_INVALID_BER_TAG_ENCODING");
            break;
        }
    }

    if (!TEST_true(found_error)) {
        TEST_error("Expected ASN1_R_INVALID_BER_TAG_ENCODING");
        goto end;
    }

    ret = 1;

end:
    X509_free(cert);
    ERR_clear_error();
    return ret;
}

/*
 * Test edge cases around the tag 31 boundary
 */
static int test_tag_boundary_cases(void)
{
    int ret = 1;
    const unsigned char *p;
    long len;
    int tag, xclass, result;

    TEST_info("Testing tag boundary cases (tags 30, 31, 32)");

    /* Tag 30 with short form - VALID */
    {
        unsigned char tag30_short[] = {0x1e, 0x00};
        p = tag30_short;
        ERR_clear_error();
        result = ASN1_get_object(&p, &len, &tag, &xclass, sizeof(tag30_short));
        if (!TEST_int_ne(result, 0x80) || !TEST_int_eq(tag, 30)) {
            TEST_error("Tag 30 short-form should be valid");
            ret = 0;
        } else {
            TEST_info("✓ Tag 30 short-form accepted");
        }
    }

    /* Tag 30 with long form - INVALID */
    {
        unsigned char tag30_long[] = {0x1f, 0x80, 0x1e, 0x00};
        p = tag30_long;
        ERR_clear_error();
        result = ASN1_get_object(&p, &len, &tag, &xclass, sizeof(tag30_long));
        if (!TEST_int_eq(result, 0x80)) {
            TEST_error("Tag 30 long-form should be rejected");
            ret = 0;
        } else if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
                                ASN1_R_INVALID_BER_TAG_ENCODING)) {
            TEST_error("Wrong error for tag 30 long-form");
            ret = 0;
        } else {
            TEST_info("✓ Tag 30 long-form rejected");
        }
        ERR_clear_error();
    }

    /* Tag 31 with long form - VALID (required) */
    {
        unsigned char tag31_long[] = {0x1f, 0x1f, 0x00};
        p = tag31_long;
        ERR_clear_error();
        result = ASN1_get_object(&p, &len, &tag, &xclass, sizeof(tag31_long));
        if (!TEST_int_ne(result, 0x80) || !TEST_int_eq(tag, 31)) {
            TEST_error("Tag 31 long-form should be valid");
            ERR_print_errors_fp(stderr);
            ret = 0;
        } else {
            TEST_info("✓ Tag 31 long-form accepted");
        }
    }

    /* Tag 32 with long form - VALID */
    {
        unsigned char tag32_long[] = {0x1f, 0x20, 0x00};
        p = tag32_long;
        ERR_clear_error();
        result = ASN1_get_object(&p, &len, &tag, &xclass, sizeof(tag32_long));
        if (!TEST_int_ne(result, 0x80) || !TEST_int_eq(tag, 32)) {
            TEST_error("Tag 32 long-form should be valid");
            ret = 0;
        } else {
            TEST_info("✓ Tag 32 long-form accepted");
        }
    }

    return ret;
}

/*
 * Test that valid certificates still parse correctly
 * This ensures we didn't break normal certificate processing
 */
static int test_valid_certificate_still_works(void)
{
    /*
     * Valid self-signed certificate (correct encoding)
     * Generated with: openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
     *                 -out cert.pem -subj "/CN=Test" -days 1
     */
    static const char *valid_cert_pem =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIC/zCCAeegAwIBAgIUOo6s1qShz1pDHNAux5oSEC2RMcwwDQYJKoZIhvcNAQEL\n"
        "BQAwDzENMAsGA1UEAwwEVGVzdDAeFw0yNTEyMTgwMjI2MDBaFw0yNTEyMTkwMjI2\n"
        "MDBaMA8xDTALBgNVBAMMBFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
        "AoIBAQDq+p4GuB+i5fZefKbV0QhkT71uWA89nFgpcaz0A3gnqsQwJVtgZXLi7hW0\n"
        "x4b7cql7oKNuyheVRku4VXOv0GxtRu9/8dEToHY2LT2zHC7lVq2PiZbQkjdl4lG/\n"
        "wVffn/Lm60+wJQ2Zu9NMSJBp3AaEz79pzFrz1TnSEW++aDY7Z25EqLp6g2tu65qi\n"
        "rCwJjoyaYwSwXGEbned0MY+Faw5VXO6BGpFZ4OEcFY+Pw7dK93jzsPf226aae6oE\n"
        "bTFARf0RVZ7Vd4a82afr4gzMkQx61UzokMspzd7oFSuRzZr2i1WqxZlC8jHWWdUk\n"
        "FubRROAZDHq/CcJa4X3AfJ8D+mx7AgMBAAGjUzBRMB0GA1UdDgQWBBRz0dSTUJcS\n"
        "526yqAflndbVuOqUETAfBgNVHSMEGDAWgBRz0dSTUJcS526yqAflndbVuOqUETAP\n"
        "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDZJp6FjRBZXLiGi1+l\n"
        "vFdSlIRaoviGEYaMzueEQqVk7a/smuM96HBFhWqHYndpfWqptzGH6Tf6x+mECh/I\n"
        "5Z++Em6a4DHRza9iPPQsv8dMf3JPAKzxhliWCghPKap7lhjrZccBow//uqQ5ueLh\n"
        "//WNFUdybuK5bHRTdPNmKHceuPCCUZfqhchGIQRV1Ls3JZ/mqggh2BTazK5t1Dz3\n"
        "dSQBSrypvsEJV8GzyWJT1t/wrBnu7GvOdpKbjMpdGo32DZYZhuU5WHgNe74auRkE\n"
        "A6eEd0OjzMe/OKncQN0Y8gkIF/BIb1+/NynZMqXnlif1lOyaOdcFHa1fU7J8hvKr\n"
        "aLav\n"
        "-----END CERTIFICATE-----\n";

    BIO *bio = NULL;
    X509 *cert = NULL;
    int ret = 0;

    TEST_info("Testing that valid certificates still parse correctly");
    ERR_clear_error();

    bio = BIO_new_mem_buf(valid_cert_pem, -1);
    if (!TEST_ptr(bio)) {
        TEST_error("Failed to create BIO");
        goto end;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (!TEST_ptr(cert)) {
        TEST_error("Valid certificate should have been accepted!");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (ERR_peek_error() != 0) {
        TEST_error("Unexpected errors for valid certificate");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    TEST_info("✓ Valid certificate parsed successfully");
    ret = 1;

end:
    BIO_free(bio);
    X509_free(cert);
    ERR_clear_error();
    return ret;
}

/*
 * Test multi-byte long-form encodings for invalid tags
 * e.g., encoding tag 16 as: 0x1f 0x80 0x10 (multi-byte long form with leading zero)
 */
static int test_multibyte_invalid_encoding(void)
{
    /*
     * Tag 16 encoded as: 0x1f 0x80 0x10
     * 0x1f = long form indicator
     * 0x80 = continuation with value 0 (unnecessary leading zero)
     * 0x10 = final byte, value 16
     * Decodes to: (0 << 7) | 16 = 16
     * Invalid because tag 16 should use short form (0x30 for constructed SEQUENCE)
     */
    unsigned char multibyte_invalid[] = {0x1f, 0x80, 0x10, 0x00};
    const unsigned char *p = multibyte_invalid;
    long len = 0;
    int tag = 0, xclass = 0;
    int ret;
    unsigned long err;

    TEST_info("Testing multi-byte long-form encoding of tag < 31");
    ERR_clear_error();

    ret = ASN1_get_object(&p, &len, &tag, &xclass, sizeof(multibyte_invalid));

    if (!TEST_int_eq(ret, 0x80)) {
        TEST_error("Expected rejection of multi-byte encoding for tag 16");
        return 0;
    }

    err = ERR_peek_error();
    if (!TEST_int_eq(ERR_GET_REASON(err), ASN1_R_INVALID_BER_TAG_ENCODING)) {
        TEST_error("Expected ASN1_R_INVALID_BER_TAG_ENCODING");
        TEST_info("Got: %s", ERR_error_string(err, NULL));
        return 0;
    }

    ERR_clear_error();
    TEST_info("✓ Multi-byte invalid encoding correctly rejected");
    return 1;
}

int setup_tests(void)
{
    /* Test invalid encodings (should all be rejected) */
    ADD_ALL_TESTS(test_asn1_invalid_tag, OSSL_NELEM(invalid_tag_tests));

    /* Test valid encodings (should all be accepted) */
    ADD_ALL_TESTS(test_asn1_valid_tag, OSSL_NELEM(valid_tag_tests));

    /* Test the actual certificate from issue #28424 */
    ADD_TEST(test_issue_28424_certificate_pem);
    ADD_TEST(test_issue_28424_certificate_der);

    /* Test edge cases */
    ADD_TEST(test_tag_boundary_cases);
    ADD_TEST(test_multibyte_invalid_encoding);

    /* Regression test - ensure valid certs still work */
    ADD_TEST(test_valid_certificate_still_works);

    return 1;
}
