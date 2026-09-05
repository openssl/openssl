/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the x509 and x509v3 modules */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "testutil.h"
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "crypto/x509.h"

/**********************************************************************
 *
 * Test of x509v3
 *
 ***/

#include "../crypto/x509/ext_dat.h"
#include "../crypto/x509/standard_exts.h"

static int test_standard_exts(void)
{
    size_t i;
    int prev = -1, good = 1;
    const X509V3_EXT_METHOD *const *tmp;

    tmp = standard_exts;
    for (i = 0; i < OSSL_NELEM(standard_exts); i++, tmp++) {
        if ((*tmp)->ext_nid < prev)
            good = 0;
        prev = (*tmp)->ext_nid;
    }
    if (!good) {
        tmp = standard_exts;
        TEST_error("Extensions out of order!");
        for (i = 0; i < STANDARD_EXTENSION_COUNT; i++, tmp++)
            TEST_note("%d : %s", (*tmp)->ext_nid, OBJ_nid2sn((*tmp)->ext_nid));
    }
    return good;
}

typedef struct {
    const char *ipasc;
    const char *data;
    int length;
} IP_TESTDATA;

static IP_TESTDATA a2i_ipaddress_tests[] = {
    { "127.0.0.1", "\x7f\x00\x00\x01", 4 },
    { "1.2.3.4", "\x01\x02\x03\x04", 4 },
    { "1.2.3.255", "\x01\x02\x03\xff", 4 },
    { "255.255.255.255", "\xff\xff\xff\xff", 4 },

    { "::", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16 },
    { "::1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 },
    { "::01", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 },
    { "::0001", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 },
    { "ffff::", "\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16 },
    { "ffff::1", "\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16 },
    { "1::2", "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 16 },
    { "1:1:1:1:1:1:1:1", "\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01", 16 },
    { "2001:db8::ff00:42:8329", "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00\x42\x83\x29", 16 },
    { "::1.2.3.4", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04", 16 },
    { "ffff:ffff:ffff:ffff:ffff:ffff:1.2.3.4", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x02\x03\x04", 16 },

    { "1:1:1:1:1:1:1:1.test", NULL, 0 },
    { ":::1", NULL, 0 },
    { "2001::123g", NULL, 0 },

    /* Too few IPv4 components. */
    { "1", NULL, 0 },
    { "1.", NULL, 0 },
    { "1.2", NULL, 0 },
    { "1.2.", NULL, 0 },
    { "1.2.3", NULL, 0 },
    { "1.2.3.", NULL, 0 },

    /* Invalid embedded IPv4 address. */
    { "::1.2.3", NULL, 0 },

    /* IPv4 literals take the place of two IPv6 components. */
    { "1:2:3:4:5:6:7:1.2.3.4", NULL, 0 },

    /* '::' should have fewer than 16 components or it is redundant. */
    { "1:2:3:4:5:6:7::8", NULL, 0 },

    /* Embedded IPv4 addresses must be at the end. */
    { "::1.2.3.4:1", NULL, 0 },

    /* Too many components. */
    { "1.2.3.4.5", NULL, 0 },
    { "1:2:3:4:5:6:7:8:9", NULL, 0 },
    { "1:2:3:4:5::6:7:8:9", NULL, 0 },

    /* Stray whitespace or other invalid characters. */
    { "1.2.3.4 ", NULL, 0 },
    { "1.2.3 .4", NULL, 0 },
    { "1.2.3. 4", NULL, 0 },
    { " 1.2.3.4", NULL, 0 },
    { "1.2.3.4.", NULL, 0 },
    { "1.2.3.+4", NULL, 0 },
    { "1.2.3.-4", NULL, 0 },
    { "1.2.3.4.example.test", NULL, 0 },
    { "::1 ", NULL, 0 },
    { " ::1", NULL, 0 },
    { ":: 1", NULL, 0 },
    { ": :1", NULL, 0 },
    { "1.2.3.nope", NULL, 0 },
    { "::nope", NULL, 0 },

    /* Components too large. */
    { "1.2.3.256", NULL, 0 }, /* Overflows when adding */
    { "1.2.3.260", NULL, 0 }, /* Overflows when multiplying by 10 */
    { "1.2.3.999999999999999999999999999999999999999999", NULL, 0 },
    { "::fffff", NULL, 0 },

    /* Although not an overflow, more than four hex digits is an error. */
    { "::00000", NULL, 0 },

    /* Too many colons. */
    { ":::", NULL, 0 },
    { "1:::", NULL, 0 },
    { ":::2", NULL, 0 },
    { "1:::2", NULL, 0 },

    /* Only one group of zeros may be elided. */
    { "1::2::3", NULL, 0 },

    /* We only support decimal. */
    { "1.2.3.01", NULL, 0 },
    { "1.2.3.0x1", NULL, 0 },

    /* Random garbage. */
    { "example.test", NULL, 0 },
    { "", NULL, 0 },
    { " 1.2.3.4", NULL, 0 },
    { " 1.2.3.4 ", NULL, 0 },
    { "1.2.3.4.example.test", NULL, 0 },
};

static int test_a2i_ipaddress(int idx)
{
    int good = 1;
    ASN1_OCTET_STRING *ip;
    size_t len = a2i_ipaddress_tests[idx].length;

    ip = a2i_IPADDRESS(a2i_ipaddress_tests[idx].ipasc);
    if (len == 0) {
        if (!TEST_ptr_null(ip)) {
            good = 0;
            TEST_note("'%s' should not be parsed as IP address", a2i_ipaddress_tests[idx].ipasc);
        }
    } else {
        if (!TEST_ptr(ip)
            || !TEST_size_t_eq(ASN1_STRING_get_length(ip), len)
            || !TEST_mem_eq(ASN1_STRING_get0_data(ip), len,
                a2i_ipaddress_tests[idx].data, len)) {
            good = 0;
        }
    }
    ASN1_OCTET_STRING_free(ip);
    return good;
}

/**
 * @struct ip_asc_testdata_st
 * @brief One ossl_ipaddr_to_asc() case: input bytes and expected output.
 */
typedef struct ip_asc_testdata_st {
    const char *data; /**< The address bytes to convert */
    int length; /**< The number of bytes at data */
    const char *expected; /**< The string the conversion should produce */
} IP_ASC_TESTDATA;

/*-
 * ossl_ipaddr_to_asc() is not the inverse of a2i_IPADDRESS(): it neither
 * elides a run of zero groups as "::" nor emits lowercase hex, so the
 * expected strings below are not the RFC 5952 canonical presentation
 * forms of these addresses.
 */
static IP_ASC_TESTDATA ipaddr_to_asc_tests[] = {
    { "\x7f\x00\x00\x01", 4, "127.0.0.1" },
    { "\x01\x02\x03\x04", 4, "1.2.3.4" },
    { "\xff\xff\xff\xff", 4, "255.255.255.255" },

    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16,
        "0:0:0:0:0:0:0:0" },
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16,
        "0:0:0:0:0:0:0:1" },
    { "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00\x42\x83\x29", 16,
        "2001:DB8:0:0:0:FF00:42:8329" },

    /*
     * The longest output ossl_ipaddr_to_asc() can produce: 39 characters
     * and a nul exactly fill its 40-byte buffer, so the last group is
     * written with no room to spare.  A truncation guard that is off by
     * one drops that group.
     */
    { "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 16,
        "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF" },

    /* Only 4 and 16 are addresses; every other length is reported back. */
    { "", 0, "<invalid length=0>" },
    { "\x01\x02\x03", 3, "<invalid length=3>" },
    { "\x01\x02\x03\x04\x05", 5, "<invalid length=5>" },
};

/**
 * @brief Check ossl_ipaddr_to_asc() against one ipaddr_to_asc_tests entry.
 * @param idx index into ipaddr_to_asc_tests of the case to run
 * @returns 1 if the conversion produced the expected string, 0 otherwise
 */
static int test_ipaddr_to_asc(int idx)
{
    const IP_ASC_TESTDATA *t = &ipaddr_to_asc_tests[idx];
    char *asc = ossl_ipaddr_to_asc((const unsigned char *)t->data, t->length);
    int good = TEST_ptr(asc) && TEST_str_eq(asc, t->expected);

    OPENSSL_free(asc);
    return good;
}

/* Adding an extension to a CRL marks its cached encoding stale */
static int test_crl_add_ext_modifies(void)
{
    EVP_PKEY *pkey = NULL;
    X509_NAME *name = NULL;
    X509_CRL *crl = NULL, *copy = NULL;
    ASN1_TIME *tm = NULL;
    ASN1_INTEGER *num = NULL;
    X509_EXTENSION *ext = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"crl ext test", -1, -1, 0))
        || !TEST_ptr(tm = ASN1_TIME_set(NULL, 0))
        || !TEST_ptr(num = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(num, 1))
        || !TEST_ptr(crl = X509_CRL_new())
        || !TEST_true(X509_CRL_set_issuer_name(crl, name))
        || !TEST_true(X509_CRL_set1_lastUpdate(crl, tm))
        || !TEST_int_gt(X509_CRL_sign(crl, pkey, EVP_sha256()), 0))
        goto err;

    /* X509_CRL_add1_ext_i2d() on a decoded copy */
    if (!TEST_ptr(copy = X509_CRL_dup(crl))
        || !TEST_false(copy->crl.enc.modified)
        || !TEST_true(X509_CRL_add1_ext_i2d(copy, NID_crl_number, num, 0, 0))
        || !TEST_true(copy->crl.enc.modified))
        goto err;
    X509_CRL_free(copy);
    copy = NULL;

    /* X509_CRL_add_ext() on a decoded copy */
    if (!TEST_ptr(ext = X509V3_EXT_i2d(NID_crl_number, 0, num))
        || !TEST_ptr(copy = X509_CRL_dup(crl))
        || !TEST_false(copy->crl.enc.modified)
        || !TEST_true(X509_CRL_add_ext(copy, ext, -1))
        || !TEST_true(copy->crl.enc.modified))
        goto err;

    ret = 1;
err:
    X509_EXTENSION_free(ext);
    X509_CRL_free(copy);
    X509_CRL_free(crl);
    ASN1_INTEGER_free(num);
    ASN1_TIME_free(tm);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    return ret;
}

static int ck_purp(ossl_unused const X509_PURPOSE *purpose,
    ossl_unused const X509 *x, int ca)
{
    return 1;
}

static int tests_X509_PURPOSE(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    int id, idx, *p;
    X509_PURPOSE *xp;

#undef LN
#define LN "LN_test"
#undef SN
#define SN "SN_test"
#undef ARGS
#define ARGS(id, sn) id, X509_TRUST_MAX, 0, ck_purp, LN, sn, NULL
    return TEST_int_gt((id = X509_PURPOSE_get_unused_id(libctx)), X509_PURPOSE_MAX)
        && TEST_int_eq(X509_PURPOSE_get_count() + 1, id)
        && TEST_int_eq(X509_PURPOSE_get_by_id(id), -1)
        && TEST_int_eq(X509_PURPOSE_get_by_sname(SN), -1)

        /* add new entry with fresh id and fresh sname: */
        && TEST_int_eq(X509_PURPOSE_add(ARGS(id, SN)), 1)
        && TEST_int_ne((idx = X509_PURPOSE_get_by_sname(SN)), -1)
        && TEST_int_eq(X509_PURPOSE_get_by_id(id), idx)

        /* overwrite same entry, should be idempotent: */
        && TEST_int_eq(X509_PURPOSE_add(ARGS(id, SN)), 1)
        && TEST_int_eq(X509_PURPOSE_get_by_sname(SN), idx)
        && TEST_int_eq(X509_PURPOSE_get_by_id(id), idx)

        /* fail adding entry with same sname but existing conflicting id: */
        && TEST_int_eq(X509_PURPOSE_add(ARGS(X509_PURPOSE_MAX, SN)), 0)
        /* fail adding entry with same existing id but conflicting sname: */
        && TEST_int_eq(X509_PURPOSE_add(ARGS(id, SN "_different")), 0)

        && TEST_ptr((xp = X509_PURPOSE_get0(idx)))
        && TEST_int_eq(X509_PURPOSE_get_id(xp), id)
        && TEST_str_eq(X509_PURPOSE_get0_name(xp), LN)
        && TEST_str_eq(X509_PURPOSE_get0_sname(xp), SN)
        && TEST_int_eq(X509_PURPOSE_get_trust(xp), X509_TRUST_MAX)

        && TEST_int_eq(*(p = &xp->purpose), id)
        && TEST_int_eq(X509_PURPOSE_set(p, X509_PURPOSE_DEFAULT_ANY), 1)
        && TEST_int_eq(X509_PURPOSE_get_id(xp), X509_PURPOSE_DEFAULT_ANY);
}

/* 0000-01-01 00:00:00 UTC */
#define MIN_CERT_TIME INT64_C(-62167219200)
/* 9999-12-31 23:59:59 UTC */
#define MAX_CERT_TIME INT64_C(253402300799)
/* 1950-01-01 00:00:00 UTC */
#define MIN_UTC_TIME INT64_C(-631152000)
/* 2049-12-31 23:59:59 UTC */
#define MAX_UTC_TIME INT64_C(2524607999)

typedef struct {
    int64_t NotBefore;
    int64_t NotAfter;
} CERT_TEST_DATA;

/* clang-format off */
static CERT_TEST_DATA cert_test_data[] = {
    { 0, 0 },
    { 0, 1 },
    { 1, 1 },
    { -1, 0 },
    { -1, 1 },
    { 1442939232, 1443004020 },
    { 0, INT32_MAX },
    { INT32_MIN, 0 },
    { INT32_MIN, INT32_MAX },
    { 0, UINT32_MAX },
    { MIN_UTC_TIME, 0 },
    { MIN_UTC_TIME - 1, 0 },
    { 0, MAX_UTC_TIME },
    { 0, MAX_UTC_TIME + 1 },
    { MIN_UTC_TIME, MAX_UTC_TIME},
    { MIN_UTC_TIME - 1, MAX_UTC_TIME + 1 },
    { MIN_CERT_TIME,  MAX_CERT_TIME },
    { MIN_CERT_TIME,  MAX_CERT_TIME - 1 },
    { MIN_CERT_TIME + 1,  MAX_CERT_TIME },
    { MIN_CERT_TIME + 1,  MAX_CERT_TIME - 1 },
    { 0,  MAX_CERT_TIME },
    { 0,  MAX_CERT_TIME - 1 }
};
/* clang-format on */

/* Returns 0 for success, 1 if failed */
static int test_a_time(X509_STORE_CTX *ctx, X509 *x509,
    X509_CRL *crl,
    const int64_t test_time,
    int64_t notBefore, int64_t notAfter,
    const char *file, const int line)
{
    int expected_value, expected_crl_value, error, expected_error;
    X509_VERIFY_PARAM *vpm;

    expected_value = notBefore <= test_time;
    if (expected_value)
        expected_value = notAfter == MAX_CERT_TIME || notAfter >= test_time;

    expected_crl_value = notBefore <= test_time;
    if (expected_crl_value)
        expected_crl_value = notAfter >= test_time;

    if (notBefore > test_time)
        expected_error = X509_V_ERR_CERT_NOT_YET_VALID;
    else if (notAfter < test_time && notAfter != MAX_CERT_TIME)
        expected_error = X509_V_ERR_CERT_HAS_EXPIRED;
    else
        expected_error = 0;

    vpm = X509_STORE_CTX_get0_param(ctx);
    ossl_x509_verify_param_set_time_posix(vpm, test_time);
    if (ossl_x509_check_cert_time(ctx, x509, 0) != expected_value) {
        TEST_info("%s:%d - ossl_X509_check_cert_time %s unexpectedly when "
                  "verifying notBefore %lld, notAfter %lld at time %lld\n",
            file, line,
            expected_value ? "failed" : "succeeded",
            (long long)notBefore, (long long)notAfter,
            (long long)test_time);
        return 1;
    }
    if (ossl_x509_check_crl_time(ctx, crl, 0) != expected_crl_value) {
        TEST_info("%s:%d - ossl_X509_check_crl_time %s unexpectedly when "
                  "verifying lastUpdate %lld, nextUpdate %lld at time %lld\n",
            file, line,
            expected_value ? "failed" : "succeeded",
            (long long)notBefore, (long long)notAfter,
            (long long)test_time);
        return 1;
    }
    error = 0;
    if (X509_check_certificate_times(vpm, x509, &error) != expected_value) {
        TEST_info("%s:%d - X509_check_certificate_times %s unexpectedly "
                  "when verifying notBefore %lld, notAfter %lld at time %lld\n",
            file, line,
            expected_value ? "failed" : "succeeded",
            (long long)notBefore, (long long)notAfter,
            (long long)test_time);
        return 1;
    }
    if (error != expected_error) {
        TEST_info("%s:%d - ossl_X509_check_certificate_times error return was "
                  "%d, expected %d when verifying notBefore %lld, notAfter "
                  "%lld at time %lld\n",
            file, line,
            error, expected_error,
            (long long)notBefore, (long long)notAfter,
            (long long)test_time);
        return 1;
    }
    return 0;
}

static int do_x509_time_tests(CERT_TEST_DATA *tests, size_t ntests)
{
    int ret = 0;
    int failures = 0;
    X509 *x509 = NULL;
    X509_CRL *crl = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    ASN1_TIME *nb = NULL, *na = NULL;
    size_t i;

    if (!TEST_ptr(x509 = X509_new())) {
        TEST_info("Malloc failed");
        goto err;
    }
    if (!TEST_ptr(crl = X509_CRL_new())) {
        TEST_info("Malloc failed");
        goto err;
    }
    if (!TEST_ptr(ctx = X509_STORE_CTX_new())) {
        TEST_info("Malloc failed");
        goto err;
    }
    X509_STORE_CTX_init(ctx, NULL, NULL, NULL);
    if (!TEST_ptr(vpm = X509_VERIFY_PARAM_new())) {
        TEST_info("Malloc failed");
        goto err;
    }
    X509_STORE_CTX_set0_param(ctx, vpm);
    if (!TEST_ptr(nb = ASN1_TIME_new())) {
        TEST_info("Malloc failed");
        goto err;
    }
    if (!TEST_ptr(na = ASN1_TIME_new())) {
        TEST_info("Malloc failed");
        goto err;
    }

    for (i = 0; i < ntests; i++) {
        int64_t test_time;

        if (!TEST_true(ossl_posix_to_asn1_time(tests[i].NotBefore, &nb))) {
            TEST_info("Could not create NotBefore for time %lld\n", (long long)tests[i].NotBefore);
            goto err;
        }
        if (!TEST_true(ossl_posix_to_asn1_time(tests[i].NotAfter, &na))) {
            TEST_info("Could not create NotAfter for time %lld\n", (long long)tests[i].NotBefore);
            goto err;
        }

        /* Forcibly jam the times into the X509 */
        if (!TEST_true(X509_set1_notBefore(x509, nb)))
            goto err;

        if (!TEST_true(X509_set1_notAfter(x509, na)))
            TEST_info("X509_set1_notAftere failed");

        /* Forcibly jam the times into the CRL */
        if (!TEST_true(X509_CRL_set1_lastUpdate(crl, nb)))
            goto err;

        if (!TEST_true(X509_CRL_set1_nextUpdate(crl, na)))
            goto err;

        /* Test boundaries of NotBefore */
        test_time = tests[i].NotBefore - 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = tests[i].NotBefore;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = tests[i].NotBefore + 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        /* Test boundaries of NotAfter */
        test_time = tests[i].NotAfter - 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = tests[i].NotAfter;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = tests[i].NotAfter + 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = 1442939232;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = 1443004020;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = MIN_UTC_TIME;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = MIN_UTC_TIME - 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = MAX_UTC_TIME;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = MAX_UTC_TIME + 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        /* Test integer value boundaries */
        test_time = INT64_MIN;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = INT32_MIN;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = -1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = 0;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = 1;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = INT32_MAX;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = UINT32_MAX;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
        test_time = INT64_MAX;
        failures += test_a_time(ctx, x509, crl, test_time, tests[i].NotBefore,
            tests[i].NotAfter,
            __FILE__, __LINE__);
    }

    ret = (failures == 0);

err:
    X509_STORE_CTX_free(ctx);
    X509_free(x509);
    X509_CRL_free(crl);
    ASN1_STRING_free(nb);
    ASN1_STRING_free(na);
    return ret;
}

static int tests_X509_check_time(void)
{
    return do_x509_time_tests(cert_test_data, sizeof(cert_test_data) / sizeof(CERT_TEST_DATA));
}

static const char *kRSAModulusNeg[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIByjCCAXSgAwIBAgIQBjdsAKoAZIoRz7jUqlw19DANBgkqhkiG9w0BAQQFADAW\n",
    "MRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw05NjA1MjgyMjAyNTlaFw0zOTEyMzEy\n",
    "MzU5NTlaMBYxFDASBgNVBAMTC1Jvb3QgQWdlbmN5MFswDQYJKoZIhvcNAQEBBQAD\n",
    "SgAwRwJAgVUiuYqkb+3W59lmD1W8183VvE5AAiGisfeHMIVe0vJEudybdbb7Rl9C\n",
    "tp0jNgveVA/NvR+ZKhBYEctAy7WnQQIDAQABo4GeMIGbMFAGA1UEAwRJE0dGb3Ig\n",
    "VGVzdGluZyBQdXJwb3NlcyBPbmx5IFNhbXBsZSBTb2Z0d2FyZSBQdWJsaXNoaW5n\n",
    "IENyZWRlbnRpYWxzIEFnZW5jeTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRj\n",
    "oRgwFjEUMBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJ\n",
    "KoZIhvcNAQEEBQADQQAtLj57iUKJP6ghF/rw9cOV22JpW8ncwbP68MRvb2Savecb\n",
    "JWhyg2e9VrCNAb0q98xLvYeluocgTEIRQa0QFzuM\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static int tests_X509_check_crypto(void)
{
    X509 *rsa_n_neg = NULL;
    EVP_PKEY *pub = NULL;
    int test;

    test = TEST_ptr((rsa_n_neg = X509_from_strings(kRSAModulusNeg)))
        && TEST_ptr_null((pub = X509_get_pubkey(rsa_n_neg)))
        && TEST_err_r(ERR_LIB_EVP, EVP_R_DECODE_ERROR);

    EVP_PKEY_free(pub);
    X509_free(rsa_n_neg);
    return test;
}

/* https://github.com/openssl/openssl/issues/11722 */
static const char *kDistributionPointWrongTag[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDiTCCAnGgAwIBAgIFAO3UVNIwDQYJKoZIhvcNAQELBQAwfTEWMBQGA1UEBhMN\n",
    "VW5pdGVkTmF0aW9uczEQMA4GA1UECAwHTmV3WW9yazEQMA4GA1UEBwwHTmV3WW9y\n",
    "azEcMBoGA1UECgwTU29mdHdhcmVFbmdpbmVlcmluZzEQMA4GA1UECwwHVGVzdGlu\n",
    "ZzEPMA0GA1UEAwwGdW4ub3JnMCIYDzIwMTcwMTIzMDkzMDAwWhgPMjAxODEyMjMw\n",
    "OTMwMDBaMGwxCzAJBgNVBAYTAlVOMRAwDgYDVQQIEwdOZXdZb3JrMRAwDgYDVQQH\n",
    "EwdOZXdZb3JrMQ8wDQYDVQQKEwZzdWJPcmcxEzARBgNVBAsTCnN1Yk9yZ1VuaXQx\n",
    "EzARBgNVBAMTCnN1Yi51bi5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n",
    "AoIBAQDBpo9Viz3OQa6vmsyULUFLgznPkB3OX5Yf5XFBnZWoAu2d9qNypidARWUs\n",
    "DomjtevXKrQApnmuWlxqLV5Q4JGbggeq6UsAwnoXCnH7zhQqInczr0U7rzlUYsZq\n",
    "H+5haEfV9OewOIFHStAVXyTOqJuEfZOQKZbhhx7TDYg9IpoQisvKB4HbPfi6a6BV\n",
    "YPAqNFlSfnYsF7sHNztTJXxyRY/KjrBeKVWs3n2+QQaydI+seiDD1GKBhApHrrWo\n",
    "XtaP4VFbSyPszlRnW0ICAVrMItmt1rJBJlARVRq+gpU0gifmMheNBTWt8js6Ms/i\n",
    "XeSzBkrQtFsnbVE75qeTrybOxqTXAgMBAAGjHTAbMBkGA1UdHwEB/wQPMA2BCwBS\n",
    "ZWFzb24uLi4AMA0GCSqGSIb3DQEBCwUAA4IBAQCzwoxTrHgICZeYE7owZxV39BZh\n",
    "MAHYYzS16/EXdXPZvZFQkL+wMBGkPC82s/3D/4kjHUwDxmmu2jBR8k+vEiV5VMnw\n",
    "ZcoS22KFNVskk+CBfP0G5/d+ZfFMuW1tE3B1sO7RvYT1MtYt+DryRZ7vvLv7MlQb\n",
    "sE+le0VjCfZHAZ+D3GqhYNNy+qhKYaHQDg/tfA/J28yyYm1EMzUd//Bao9BbnRxi\n",
    "p4x2WfCFGB/ZP9BV0VA2KH3qF5M1RAETch/YbWqOIn+LxKomhvQSwQ4DEmRHRu69\n",
    "loi+aH8qoQ4hb91EeaNb3OCV3azSH8I8RGGZDM2I2fZmgFwZ+5w7rgFjKe6b\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static int tests_x509_check_dpn(void)
{
    X509 *cert = NULL;
    STACK_OF(DIST_POINT) *crls = NULL;
    int test, nid = NID_crl_distribution_points;

    test = TEST_ptr((cert = X509_from_strings(kDistributionPointWrongTag)))
        && TEST_ptr_null((crls = X509_get_ext_d2i(cert, nid, NULL, NULL)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG);

    sk_DIST_POINT_pop_free(crls, DIST_POINT_free);
    X509_free(cert);
    return test;
}

/* https://github.com/openssl/openssl/issues/20027 */
static const time_t mendel_verify_time = 1753284700; /* July 23th, 2025 */

static const char *kRootMendelsonAKIDKeyNULL[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIE5zCCA8+gAwIBAgIJAMgskwXwf1MLMA0GCSqGSIb3DQEBBQUAMIIBADELMAkG\n",
    "A1UEBhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJlcmxpbjEiMCAG\n",
    "A1UEChMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDFFMEMGA1UECxM8KGMpIDIw\n",
    "MTYgbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSCAtIGZvciBhdXRob3JpemVkIHVz\n",
    "ZSBvbmx5MT4wPAYDVQQDEzVtZW5kZWxzb24gUHVibGljIFByaW1hcnkgQ2VydGlm\n",
    "aWNhdGlvbiBBdXRob3JpdHkgLSBSNjEjMCEGCSqGSIb3DQEJARYUY2FAbWVuZGVs\n",
    "c29uLWUtYy5jb20wHhcNMTYwNjI5MTEwNDMxWhcNMjYwNjI3MTEwNDMxWjCCAQAx\n",
    "CzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdHZXJtYW55MQ8wDQYDVQQHEwZCZXJsaW4x\n",
    "IjAgBgNVBAoTGW1lbmRlbHNvbi1lLWNvbW1lcmNlIEdtYkgxRTBDBgNVBAsTPChj\n",
    "KSAyMDE2IG1lbmRlbHNvbi1lLWNvbW1lcmNlIEdtYkggLSBmb3IgYXV0aG9yaXpl\n",
    "ZCB1c2Ugb25seTE+MDwGA1UEAxM1bWVuZGVsc29uIFB1YmxpYyBQcmltYXJ5IENl\n",
    "cnRpZmljYXRpb24gQXV0aG9yaXR5IC0gUjYxIzAhBgkqhkiG9w0BCQEWFGNhQG1l\n",
    "bmRlbHNvbi1lLWMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n",
    "9wUk/mmMB1I3G3MdEyWdbhxM1hGNVOhEAvdyY+S2MxRP2W35kQ5HbztUofk/eACU\n",
    "6tz5PuCp0zIVEW2GJdwkNn9B6OUjKZpOLErXBP6o+KRzqq0NtVLOo5Zy/zQ4NPsN\n",
    "MNRwHdyoXVbBTZ1PSINb43mhlTTDO8B2oPArCaDFqMfdvvQRtKpD1RRM60Q+dDz8\n",
    "PV5AbvUTwvfOmCXqEq2IcEzh3bLzAJCRvGOxM5YAkTlfA+M6OED8zDnsgRVuG6E9\n",
    "Lqioh7zvUpmnA+ghKATtQ8Qwg5b+6TctJmxBbwVctZATuhiYXYSlhu2u06UyjPVj\n",
    "bnP/kNfd8spvPgI9L3SH/QIDAQABo2AwXjAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud\n",
    "DwEB/wQEAwIBBjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY2EubWVuZGVsc29u\n",
    "LWUtYy5jb20vbWVuZGVsc29uNi5jcmwwDQYJKoZIhvcNAQEFBQADggEBAN37IQQ5\n",
    "rb6TxWczML/cg9cPDa16Jpj/t0yxg97oKRFsqBm0C+rySlWGFzsbj3YKUQVfabKT\n",
    "DylOwjj2xIi6gsxWYcWz+kWzRDTs8IYLSLs8WQDtZIErI1eQTGfpfj/stH9fQ9D4\n",
    "0+xDDqPH+6dH8JzQ/OTx0D4apRxcdAaDQUlTI/5U5nRuQqZlI0B9rUgQZN/whl6z\n",
    "zaaCSj3gmP6AKqGznrvQGzu6W9zg9CezrxlZAeHsa0JDbZOqNvmNk3rsAA07H304\n",
    "+UXXZovSGVK73OGw5s+KHTKe6+1/dOFkCJfFnX5pLMrihc5UqSig4JdKPoyvpgNJ\n",
    "3mzVzjn/SyMJWo4=\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kLeafMendelsonAKIDKeyNULL[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIGBjCCBO6gAwIBAgIBKjANBgkqhkiG9w0BAQUFADCCAQAxCzAJBgNVBAYTAkRF\n",
    "MRAwDgYDVQQIEwdHZXJtYW55MQ8wDQYDVQQHEwZCZXJsaW4xIjAgBgNVBAoTGW1l\n",
    "bmRlbHNvbi1lLWNvbW1lcmNlIEdtYkgxRTBDBgNVBAsTPChjKSAyMDE2IG1lbmRl\n",
    "bHNvbi1lLWNvbW1lcmNlIEdtYkggLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTE+\n",
    "MDwGA1UEAxM1bWVuZGVsc29uIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24g\n",
    "QXV0aG9yaXR5IC0gUjYxIzAhBgkqhkiG9w0BCQEWFGNhQG1lbmRlbHNvbi1lLWMu\n",
    "Y29tMCAXDTE2MDYyOTExMDUwOVoYDzIwMjYwMTAxMDEwMTAxWjCB2zELMAkGA1UE\n",
    "BhMCREUxEDAOBgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJlcmxpbjEiMCAGA1UE\n",
    "ChMZbWVuZGVsc29uLWUtY29tbWVyY2UgR21iSDFFMEMGA1UECxM8KGMpIDIwMTYg\n",
    "bWVuZGVsc29uLWUtY29tbWVyY2UgR21iSCAtIGZvciBhdXRob3JpemVkIHVzZSBv\n",
    "bmx5MT4wPAYDVQQDEzVtZW5kZWxzb24gUHVibGljIFByaW1hcnkgQ2VydGlmaWNh\n",
    "dGlvbiBBdXRob3JpdHkgLSBJNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n",
    "ggEBAN/6W8TW8YYHgKxHxXg6Cy1pZRhXHr6WBqaUwTglNBf788y3XJdaG/e1kwaw\n",
    "MuYAdOYWt8sm2xYmpmJorcY7m4gTdcuMH8fCarDsRVdT2BMXxZ9JTIG4E9YflzOQ\n",
    "MvOn+tZ6UyPkgbfX2zfKydSH5FJiY31QNbBb3MI1zAFUYC3mqmMEgrHwm5qTFrYb\n",
    "p3v8ZBnBiWRR9H72IaV1ZjGP90Hyh6w/pQjo+TJnLIklLaTv6Cd70SWGhnhJwdPP\n",
    "/9YvzfSXt9sW8wj6PkXT2cqW08o4hkmcc95MoIdsH6re+Gv0d3qt1a3yMnEdHHF8\n",
    "g+t0P2VezEF+k0Mdib83HC8QAaMCAwEAAaOCAakwggGlMA8GA1UdEwEB/wQFMAMB\n",
    "Af8wggEkBgNVHSMEggEbMIIBF6GCAQikggEEMIIBADELMAkGA1UEBhMCREUxEDAO\n",
    "BgNVBAgTB0dlcm1hbnkxDzANBgNVBAcTBkJlcmxpbjEiMCAGA1UEChMZbWVuZGVs\n",
    "c29uLWUtY29tbWVyY2UgR21iSDFFMEMGA1UECxM8KGMpIDIwMTYgbWVuZGVsc29u\n",
    "LWUtY29tbWVyY2UgR21iSCAtIGZvciBhdXRob3JpemVkIHVzZSBvbmx5MT4wPAYD\n",
    "VQQDEzVtZW5kZWxzb24gUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRo\n",
    "b3JpdHkgLSBSNjEjMCEGCSqGSIb3DQEJARYUY2FAbWVuZGVsc29uLWUtYy5jb22C\n",
    "CQDILJMF8H9TCzAdBgNVHQ4EFgQUbPFwN+UTRvxdmehaSgrotrmrMv4wDgYDVR0P\n",
    "AQH/BAQDAgGGMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jYS5tZW5kZWxzb24t\n",
    "ZS1jLmNvbS9tZW5kZWxzb242LmNybDANBgkqhkiG9w0BAQUFAAOCAQEAV66ufDx8\n",
    "XusBk+G0z59P8+MYxdTJfnv6Q9ezZJ9zumVzp4CuuUp+8qtlC1+zN7HIgiR7C6eB\n",
    "fvAopruYUTa8m+7ZMN/vBi7XkmAX7oUM4hZYd/2yoUjL/AXF1p4fgKcCJmgvlctC\n",
    "tQrG+VdXOAmGGAhbfnOZPg+kRfO7MYKLn2BL266aPeEsBVg/xWw/NWOFYgCXeHb8\n",
    "2huxL0Ir8yK2Qv3Nqlbt/6irYMAvElCuQCrp7wqX8tXvE7/HmT/JKHTzTW+APp0A\n",
    "KHq3GiYk+/XgxHxfyVdo55iQOTqZSIigK8Yj2gFhocxCBifF6gbnbo6LTwH+I4Er\n",
    "TAjrRai7UZlqjw==\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static int tests_x509_check_akid(void)
{
    X509 *root = NULL, *leaf = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    STACK_OF(X509) *x509s = NULL;
    int test;

    test = TEST_ptr(ctx = X509_STORE_CTX_new())
        && TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(param = X509_VERIFY_PARAM_new())
        && TEST_ptr(x509s = sk_X509_new_null())
        && TEST_ptr((root = X509_from_strings(kRootMendelsonAKIDKeyNULL)))
        && TEST_ptr((leaf = X509_from_strings(kLeafMendelsonAKIDKeyNULL)))
        && TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL));

    if (test != 1)
        goto err;
    if (!TEST_true(sk_X509_push(x509s, root)))
        goto err;
    root = NULL;

    X509_STORE_CTX_set0_trusted_stack(ctx, x509s);
    X509_VERIFY_PARAM_set_depth(param, 16);
    X509_VERIFY_PARAM_set_time(param, mendel_verify_time);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;
    ERR_clear_error();

    test = TEST_int_eq(X509_verify_cert(ctx), 0)
        && TEST_int_eq(X509_STORE_CTX_get_error(ctx),
            X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER);

err:
    OSSL_STACK_OF_X509_free(x509s);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(root);

    return test;
}

static int test_X509_ALGOR_set_md_null(void)
{
    X509_ALGOR *alg = NULL;
    int ret = 0;

    if (!TEST_ptr(alg = X509_ALGOR_new()))
        goto err;

    if (!TEST_false(X509_ALGOR_set_md(alg, NULL)))
        goto err;

    ret = 1;

err:
    X509_ALGOR_free(alg);
    return ret;
}

/* https://github.com/openssl/openssl/issues/26325 */
static const char *kRootExtensionDuplicity[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDhDCCAmygAwIBAgIDCxQYMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAlVO\n",
    "MQ8wDQYDVQQIDAZNeSBTVDExFTATBgNVBAcMDE1ZIExvY2FsaXR5MTEUMBIGA1UE\n",
    "CgwLTVkgQ29tcGFueTExETAPBgNVBAsMCE15IFVuaXQxMRowGAYDVQQDDBF3d3cu\n",
    "bXljb21wYW55LmNvbTAeFw0xOTA2MTkwODU1NTlaFw0yOTA2MTkwODU1NTlaMHox\n",
    "CzAJBgNVBAYTAlVOMQ8wDQYDVQQIDAZNeSBTVDExFTATBgNVBAcMDE1ZIExvY2Fs\n",
    "aXR5MTEUMBIGA1UECgwLTXkgQ29tcGFueTExETAPBgNVBAsMCE15IFVuaXQxMRow\n",
    "GAYDVQQDDBF3d3cubXljb21wYW55LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n",
    "ADCCAQoCggEBALVNKQrEfNWp3s0FOW+9RAjXOMvhAprV/FsWo6M72Mq/EwaV4Ny+\n",
    "Q2CZ2Bs09KmRw43RG4dHHkB5/ewE7HhohQcHVH+tcWrM0IdgQIzKva2vICFZkp6O\n",
    "am71qSe8+qtLSkzlTYJv4oeTLmMA2SSwTTP74hB29MS6O8scaLcM+OqfaGzr6k/Z\n",
    "GnMMjI/zf4rbrLGPJcGGZ4jIMkrYm1PnwAwg6ijXrU0kb8DBgVvpmrluYfQdBvy6\n",
    "bSib3P9ckyCGqqszn50qQZqqa2n6Ol/CBwRsCuYuhazRsBcXiULQ1lv2JQG86ILb\n",
    "h/SXXfB4A6p0ti3tmcTMIPN5AI3y/EvUUwkCAwEAAaMTMBEwDwYDVR0TAQH/BAUw\n",
    "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAS6joG5vUo2kMLX0bcpjKzE3h40ZypVgJ\n",
    "bSCLu/alVcIDzdLTK/SOp2NMvtGmn+BMRvfzW+Lk58sMZ2QC3x+RZKHV+pDsT+Lj\n",
    "Zi1bhpvtzrN62PmYZXGTu0xPME3SlBLilUFIRgH5lrxzlBdRURMCbHJOblAfzVdw\n",
    "EBCtDVdGcox/mzu1Jo/sJQb59a49ZQpvwp7m7kZE0q6dBgElYX4JaRYhbwsv/tP2\n",
    "jEA+jQYNORgFvCOkITbaO4Avc7BXSCGkDHoH6GsANf0bdtaMQCbUMeaC2CYUzRoC\n",
    "fTEJ9LvFu7syeEDpUbgPXgRqpUQLyxoVYxWjXZ3CG5jeRmJzAEAoyg==\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kCertExtensionDuplicity[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIENDCCAxygAwIBAgIVASygDp5oUEVMj9bx6z7bj3ce5ypQMA0GCSqGSIb3DQEB\n",
    "CwUAMHoxCzAJBgNVBAYTAlVOMQ8wDQYDVQQIDAZNeSBTVDExFTATBgNVBAcMDE1Z\n",
    "IExvY2FsaXR5MTEUMBIGA1UECgwLTXkgQ29tcGFueTExETAPBgNVBAsMCE15IFVu\n",
    "aXQxMRowGAYDVQQDDBF3d3cubXljb21wYW55LmNvbTAiGA8yMDE5MDYxOTA4NTU1\n",
    "OVoYDzIwMjkwNjE5MDg1NTU5WjB7MQswCQYDVQQGEwJVTjEPMA0GA1UECAwGTXkg\n",
    "U1QxMRUwEwYDVQQHDAxNWSBMb2NhbGl0eTExFDASBgNVBAoMC015IENvbXBhbnkx\n",
    "MREwDwYDVQQLDAhNeSBVbml0MTEbMBkGA1UEAwwSd3d3Lm15Y29tcGFueTEuY29t\n",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtU0pCsR81anezQU5b71E\n",
    "CNc4y+ECmtX8WxajozvYyr8TBpXg3L5DYJnYGzT0qZHDjdEbh0ceQHn97ATseGiF\n",
    "BwdUf61xaszQh2BAjMq9ra8gIVmSno5qbvWpJ7z6q0tKTOVNgm/ih5MuYwDZJLBN\n",
    "M/viEHb0xLo7yxxotwz46p9obOvqT9kacwyMj/N/itussY8lwYZniMgyStibU+fA\n",
    "DCDqKNetTSRvwMGBW+mauW5h9B0G/LptKJvc/1yTIIaqqzOfnSpBmqprafo6X8IH\n",
    "BGwK5i6FrNGwFxeJQtDWW/YlAbzogtuH9Jdd8HgDqnS2Le2ZxMwg83kAjfL8S9RT\n",
    "CQIDAQABo4GrMIGoMFIGCCsGAQUFBwELBEYwRDBCBggrBgEFBQcwBYY2ZnRwOi8v\n",
    "NjYuMjMzLjIuMjM1L2Z8M2YvTUI5JT94dV89WEdlYXxIMFgmcTRpRm1YIXs9dS89\n",
    "MFIGCCsGAQUFBwELBEYwRDBCBggrBgEFBQcwBYY2ZnRwOi8vNjouMjMzLjIuMjM1\n",
    "L2Z8M2YvTUI5JT94dV89WEdlYXxIMFgmcTRpRm1YIXs9dS89MA0GCSqGSIb3DQEB\n",
    "CwUAA4IBAQCoLSlKFFlg2xSGf9PFrXayO9ODk4pUkzb/+u0fsf6Vekwo/0dFNxSM\n",
    "1sPtfoyprGMd7DK8R0rELq7k4+TaypV1JFBj9G9///dCTdX8Fg1SMRamIY0cs8Cu\n",
    "VJCPWpLD6RQzZm9WkUqcc1yhjW8eO7OABazKwFQBLRS97ocztbyNvPbsZ0xInSMV\n",
    "7E3xOj4XeibJ2y+EHUbMRDPtwZuy+E1m/kYScLAqIweVaxrWQnCC1HcARxL6eHx9\n",
    "8kzGS23XAT9jLvdxwNs23GXiAjzxifJmR7oujP+uALF+FfHdJb7vr6l8lVNzRnDH\n",
    "utv/6BamvgrYfDmA6GO3UItEgYozDtaN\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

/*
 * The following test checks for a duplicate extension with a known build-time
 * NID, which is detected in constant time.
 * */
static int tests_x509_check_ext_duplicity(void)
{
    X509 *root = NULL, *leaf = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    STACK_OF(X509) *x509s = NULL;
    const time_t verify_time = 1753284700; /* July 23th, 2025 */
    int test;

    test = TEST_ptr(ctx = X509_STORE_CTX_new())
        && TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(param = X509_VERIFY_PARAM_new())
        && TEST_ptr(x509s = sk_X509_new_null())
        && TEST_ptr((root = X509_from_strings(kRootExtensionDuplicity)))
        && TEST_ptr((leaf = X509_from_strings(kCertExtensionDuplicity)))
        && TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL));

    if (test != 1)
        goto err;
    if (!TEST_true(sk_X509_push(x509s, root)))
        goto err;
    root = NULL;

    X509_STORE_CTX_set0_trusted_stack(ctx, x509s);
    X509_VERIFY_PARAM_set_depth(param, 16);
    X509_VERIFY_PARAM_set_time(param, verify_time);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;
    ERR_clear_error();

    test = TEST_int_eq(X509_verify_cert(ctx), 0)
        && TEST_int_eq(X509_STORE_CTX_get_error(ctx),
            X509_V_ERR_DUPLICATE_EXTENSION);

err:
    OSSL_STACK_OF_X509_free(x509s);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(root);

    return test;
}

/* A minimal certificate with subject == issuer, for the caller to sign */
static X509 *make_unsigned_cert(EVP_PKEY *key, const char *cn)
{
    X509 *x = NULL;
    X509_NAME *name = NULL;

    if (!TEST_ptr(x = X509_new())
        || !TEST_true(X509_set_version(x, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(x), 1))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 3600))
        || !TEST_true(X509_set_pubkey(x, key))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0))
        || !TEST_true(X509_set_subject_name(x, name))
        || !TEST_true(X509_set_issuer_name(x, name))) {
        X509_free(x);
        x = NULL;
    }
    X509_NAME_free(name);
    return x;
}

static X509 *reparse_cert(X509 *x)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    X509 *ret = NULL;
    int len;

    if (TEST_int_gt(len = i2d_X509(x, &der), 0)) {
        p = der;
        ret = d2i_X509(NULL, &p, len);
    }
    OPENSSL_free(der);
    return ret;
}

/* Set a one byte SKID and a matching AKID keyid */
static int set_key_ids(X509 *x, unsigned char value)
{
    ASN1_OCTET_STRING *skid = NULL;
    AUTHORITY_KEYID *akid = NULL;
    int ret = 0;

    if (!TEST_ptr(skid = ASN1_OCTET_STRING_new())
        || !TEST_ptr(akid = AUTHORITY_KEYID_new())
        || !TEST_true(ASN1_OCTET_STRING_set(skid, &value, 1))
        || !TEST_ptr(akid->keyid = ASN1_OCTET_STRING_dup(skid))
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_subject_key_identifier, skid,
                            0, X509V3_ADD_REPLACE),
            1)
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_authority_key_identifier, akid,
                            0, X509V3_ADD_REPLACE),
            1))
        goto err;
    ret = 1;
err:
    ASN1_OCTET_STRING_free(skid);
    AUTHORITY_KEYID_free(akid);
    return ret;
}

static int add_proxy_cert_info(X509 *x, long pathlen)
{
    PROXY_CERT_INFO_EXTENSION *pci = NULL;
    int ret = 0;

    if (!TEST_ptr(pci = PROXY_CERT_INFO_EXTENSION_new())
        || !TEST_ptr(pci->pcPathLengthConstraint = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(pci->pcPathLengthConstraint, pathlen))
        || !TEST_ptr(pci->proxyPolicy->policyLanguage
            = OBJ_dup(OBJ_nid2obj(NID_id_ppl_anyLanguage)))
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_proxyCertInfo, pci, 1,
                            X509V3_ADD_REPLACE),
            1))
        goto err;
    ret = 1;
err:
    PROXY_CERT_INFO_EXTENSION_free(pci);
    return ret;
}

/*
 * This test checks for a duplicate extension with an undefined NID, where the
 * duplicate is detected via OID.
 */
static int tests_x509_check_ext_duplicity_nid_undef(void)
{
    X509 *root = NULL, *leaf = NULL, *reparsed = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    STACK_OF(X509) *x509s = NULL;
    ASN1_OBJECT *obj1 = NULL, *obj2 = NULL;
    ASN1_OCTET_STRING *oct1 = NULL, *oct2 = NULL;
    X509_EXTENSION *ext1 = NULL, *ext2 = NULL;
    const unsigned char data[] = { 0x04, 0x03, 0x41, 0x42, 0x43 };
    const time_t verify_time = 1753284700; /* July 23th, 2025 */
    const char *unknown_oid = "1.2.3.4.5.6.7.8.9";
    int test;

    test = TEST_ptr(ctx = X509_STORE_CTX_new())
        && TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(param = X509_VERIFY_PARAM_new())
        && TEST_ptr(x509s = sk_X509_new_null())
        && TEST_ptr((root = X509_from_strings(kRootMendelsonAKIDKeyNULL)))
        && TEST_ptr((leaf = X509_from_strings(kLeafMendelsonAKIDKeyNULL)))
        && TEST_ptr(obj1 = OBJ_txt2obj(unknown_oid, 1))
        && TEST_ptr(oct1 = ASN1_OCTET_STRING_new())
        && TEST_int_eq(ASN1_OCTET_STRING_set(oct1, data, sizeof(data)), 1)
        && TEST_ptr(ext1 = X509_EXTENSION_create_by_OBJ(NULL, obj1, 0, oct1))
        && TEST_int_eq(X509_add_ext(leaf, ext1, -1), 1)
        && TEST_ptr(obj2 = OBJ_txt2obj(unknown_oid, 1))
        && TEST_ptr(oct2 = ASN1_OCTET_STRING_new())
        && TEST_int_eq(ASN1_OCTET_STRING_set(oct2, data, sizeof(data)), 1)
        && TEST_ptr(ext2 = X509_EXTENSION_create_by_OBJ(NULL, obj2, 0, oct2))
        && TEST_int_eq(X509_add_ext(leaf, ext2, -1), 1);

    if (test != 1)
        goto err;
    /* Verify a parsed certificate carrying the duplicate extension */
    if (!TEST_ptr(reparsed = reparse_cert(leaf)))
        goto err;
    X509_free(leaf);
    leaf = reparsed;
    reparsed = NULL;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    if (!TEST_true(sk_X509_push(x509s, root)))
        goto err;
    root = NULL;

    X509_STORE_CTX_set0_trusted_stack(ctx, x509s);
    X509_VERIFY_PARAM_set_depth(param, 16);
    X509_VERIFY_PARAM_set_time(param, verify_time);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;
    ERR_clear_error();

    test = TEST_int_eq(X509_verify_cert(ctx), 0)
        && TEST_int_eq(X509_STORE_CTX_get_error(ctx),
            X509_V_ERR_DUPLICATE_EXTENSION);

err:
    ASN1_OBJECT_free(obj1);
    ASN1_OCTET_STRING_free(oct1);
    X509_EXTENSION_free(ext1);
    ASN1_OBJECT_free(obj2);
    ASN1_OCTET_STRING_free(oct2);
    X509_EXTENSION_free(ext2);
    OSSL_STACK_OF_X509_free(x509s);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(root);

    return test;
}

/*
 * This test checks for a duplicate extension with a dynamically registered NID,
 * where the duplicate is detected via OID.
 */
static int tests_x509_check_ext_duplicity_nid_dynamic(void)
{
    X509 *root = NULL, *leaf = NULL, *reparsed = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    STACK_OF(X509) *x509s = NULL;
    ASN1_OBJECT *obj1 = NULL, *obj2 = NULL;
    ASN1_OCTET_STRING *oct1 = NULL, *oct2 = NULL;
    X509_EXTENSION *ext1 = NULL, *ext2 = NULL;
    const unsigned char data[] = { 0x04, 0x03, 0x41, 0x42, 0x43 };
    const time_t verify_time = 1753284700; /* July 23th, 2025 */
    const char *oid = "1.2.3.4.5.6.7.8.9";
    const char *sn = "testOID";
    const char *ln = "testOID Long Name";
    int nid;
    int test;

    test = TEST_ptr(ctx = X509_STORE_CTX_new())
        && TEST_ptr(store = X509_STORE_new())
        && TEST_ptr(param = X509_VERIFY_PARAM_new())
        && TEST_ptr(x509s = sk_X509_new_null())
        && TEST_ptr((root = X509_from_strings(kRootMendelsonAKIDKeyNULL)))
        && TEST_ptr((leaf = X509_from_strings(kLeafMendelsonAKIDKeyNULL)))
        && TEST_true((nid = OBJ_create(oid, sn, ln)) != NID_undef)
        && TEST_ptr(obj1 = OBJ_nid2obj(nid))
        && TEST_ptr(oct1 = ASN1_OCTET_STRING_new())
        && TEST_int_eq(ASN1_OCTET_STRING_set(oct1, data, sizeof(data)), 1)
        && TEST_ptr(ext1 = X509_EXTENSION_create_by_OBJ(NULL, obj1, 0, oct1))
        && TEST_int_eq(X509_add_ext(leaf, ext1, -1), 1)
        && TEST_ptr(obj2 = OBJ_nid2obj(nid))
        && TEST_ptr(oct2 = ASN1_OCTET_STRING_new())
        && TEST_int_eq(ASN1_OCTET_STRING_set(oct2, data, sizeof(data)), 1)
        && TEST_ptr(ext2 = X509_EXTENSION_create_by_OBJ(NULL, obj2, 0, oct2))
        && TEST_int_eq(X509_add_ext(leaf, ext2, -1), 1);

    if (test != 1)
        goto err;
    /* Verify a parsed certificate carrying the duplicate extension */
    if (!TEST_ptr(reparsed = reparse_cert(leaf)))
        goto err;
    X509_free(leaf);
    leaf = reparsed;
    reparsed = NULL;
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    if (!TEST_true(sk_X509_push(x509s, root)))
        goto err;
    root = NULL;

    X509_STORE_CTX_set0_trusted_stack(ctx, x509s);
    X509_VERIFY_PARAM_set_depth(param, 16);
    X509_VERIFY_PARAM_set_time(param, verify_time);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;
    ERR_clear_error();

    test = TEST_int_eq(X509_verify_cert(ctx), 0)
        && TEST_int_eq(X509_STORE_CTX_get_error(ctx),
            X509_V_ERR_DUPLICATE_EXTENSION);

err:
    ASN1_OBJECT_free(obj1);
    ASN1_OCTET_STRING_free(oct1);
    X509_EXTENSION_free(ext1);
    ASN1_OBJECT_free(obj2);
    ASN1_OCTET_STRING_free(oct2);
    X509_EXTENSION_free(ext2);
    OSSL_STACK_OF_X509_free(x509s);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(root);

    return test;
}

/*
 * X509_ATTRIBUTE_create_by_NID() must accept a BIT STRING value supplied as
 * raw bytes plus an explicit length, as PKCS8_add_keyusage() does for
 * 'openssl pkcs12 -export -keyex' (0x10) and '-keysig' (0x80).
 * Regression test for https://github.com/openssl/openssl/issues/32234
 */
static int test_x509_attribute_bit_string(int idx)
{
    unsigned char usage = idx == 0 ? 0x10 : 0x80;
    X509_ATTRIBUTE *attr = NULL;
    const ASN1_BIT_STRING *bs;
    size_t length = 0;
    int unused_bits = -1, ret = 0;

    if (!TEST_ptr(attr = X509_ATTRIBUTE_create_by_NID(NULL, NID_key_usage,
                      V_ASN1_BIT_STRING, &usage, 1))
        || !TEST_ptr(bs = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_BIT_STRING,
                         NULL))
        || !TEST_true(ASN1_BIT_STRING_get_length(bs, &length, &unused_bits))
        || !TEST_size_t_eq(length, 1)
        || !TEST_int_eq(unused_bits, 0)
        || !TEST_mem_eq(ASN1_STRING_get0_data(bs), 1, &usage, 1))
        goto err;
    ret = 1;
err:
    X509_ATTRIBUTE_free(attr);
    return ret;
}

/*
 * Signing a parsed certificate again after changing its SKID and AKID must
 * rebuild the cached extension data of that same object: the SKID it reports
 * is the new one, and it is still classified as self-signed, which requires
 * the new AKID to be compared with the new SKID rather than the cached one.
 */
static int test_resign_rebuilds_cache(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL, *parsed = NULL;
    const ASN1_OCTET_STRING *skid;
    static const unsigned char old_id = 0x11, new_id = 0x22;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(cert = make_unsigned_cert(key, "resign test"))
        || !TEST_true(set_key_ids(cert, old_id))
        || !TEST_int_gt(X509_sign(cert, key, EVP_sha256()), 0)
        || !TEST_ptr(parsed = reparse_cert(cert)))
        goto err;

    if (!TEST_ptr(skid = X509_get0_subject_key_id(parsed))
        || !TEST_mem_eq(ASN1_STRING_get0_data(skid),
            ASN1_STRING_get_length(skid), &old_id, 1)
        || !TEST_int_ne(X509_get_extension_flags(parsed) & EXFLAG_SS, 0))
        goto err;

    if (!TEST_true(set_key_ids(parsed, new_id))
        || !TEST_int_gt(X509_sign(parsed, key, EVP_sha256()), 0))
        goto err;

    if (!TEST_ptr(skid = X509_get0_subject_key_id(parsed))
        || !TEST_mem_eq(ASN1_STRING_get0_data(skid),
            ASN1_STRING_get_length(skid), &new_id, 1)
        || !TEST_int_ne(X509_get_extension_flags(parsed) & EXFLAG_SS, 0))
        goto err;

    ret = 1;
err:
    X509_free(parsed);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Once the proxyCertInfo extension is removed and the certificate signed
 * again, it must no longer report being a proxy certificate or its old path
 * length.
 */
static int test_proxy_pathlen_not_stale(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL, *parsed = NULL;
    X509_EXTENSION *ext = NULL;
    int idx;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(cert = make_unsigned_cert(key, "proxy pathlen test"))
        || !TEST_true(add_proxy_cert_info(cert, 7))
        || !TEST_int_gt(X509_sign(cert, key, EVP_sha256()), 0)
        || !TEST_ptr(parsed = reparse_cert(cert)))
        goto err;

    if (!TEST_int_ne(X509_get_extension_flags(parsed) & EXFLAG_PROXY, 0)
        || !TEST_long_eq(X509_get_proxy_pathlen(parsed), 7))
        goto err;

    idx = X509_get_ext_by_NID(parsed, NID_proxyCertInfo, -1);
    if (!TEST_int_ge(idx, 0)
        || !TEST_ptr(ext = X509_delete_ext(parsed, idx)))
        goto err;
    X509_EXTENSION_free(ext);
    ext = NULL;

    if (!TEST_int_gt(X509_sign(parsed, key, EVP_sha256()), 0)
        || !TEST_int_eq(X509_get_extension_flags(parsed) & EXFLAG_PROXY, 0)
        || !TEST_long_eq(X509_get_proxy_pathlen(parsed), -1))
        goto err;

    ret = 1;
err:
    X509_EXTENSION_free(ext);
    X509_free(parsed);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A certificate with a malformed basicConstraints is flagged EXFLAG_INVALID;
 * X509_check_purpose() and X509_check_ca() then fail and raise
 * X509V3_R_INVALID_CERTIFICATE.
 */
static int test_invalid_ext_raises(void)
{
    static const unsigned char malformed[] = { 0x05, 0x00 };
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL, *parsed = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    X509_EXTENSION *ext = NULL;
    unsigned long errcode;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(cert = make_unsigned_cert(key, "invalid ext test"))
        || !TEST_ptr(oct = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(oct, malformed, sizeof(malformed)))
        || !TEST_ptr(ext = X509_EXTENSION_create_by_NID(NULL,
                         NID_basic_constraints, 1, oct))
        || !TEST_int_eq(X509_add_ext(cert, ext, -1), 1)
        || !TEST_int_gt(X509_sign(cert, key, EVP_sha256()), 0)
        || !TEST_ptr(parsed = reparse_cert(cert)))
        goto err;

    if (!TEST_int_ne(X509_get_extension_flags(parsed) & EXFLAG_INVALID, 0))
        goto err;

    ERR_clear_error();
    if (!TEST_int_eq(X509_check_purpose(parsed, -1, 0), -1))
        goto err;
    errcode = ERR_peek_error();
    if (!TEST_int_eq(ERR_GET_LIB(errcode), ERR_LIB_X509V3)
        || !TEST_int_eq(ERR_GET_REASON(errcode), X509V3_R_INVALID_CERTIFICATE))
        goto err;

    ERR_clear_error();
    if (!TEST_int_eq(X509_check_ca(parsed), 0))
        goto err;
    errcode = ERR_peek_error();
    if (!TEST_int_eq(ERR_GET_LIB(errcode), ERR_LIB_X509V3)
        || !TEST_int_eq(ERR_GET_REASON(errcode), X509V3_R_INVALID_CERTIFICATE))
        goto err;

    ret = 1;
err:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(oct);
    X509_free(parsed);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/* The top error is the one raised for an unfinalized certificate */
static int expect_unfinalized_error(void)
{
    unsigned long e = ERR_peek_error();

    return TEST_int_eq(ERR_GET_LIB(e), ERR_LIB_X509V3)
        && TEST_int_eq(ERR_GET_REASON(e), ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
}

/* Add an authorityKeyIdentifier carrying a key id, an issuer and a serial */
static int add_akid(X509 *x, unsigned char keyid_byte, long serial)
{
    AUTHORITY_KEYID *akid = NULL;
    GENERAL_NAME *gn = NULL;
    X509_NAME *iname = NULL;
    unsigned char id[20];
    int ret = 0;

    memset(id, keyid_byte, sizeof(id));
    if (!TEST_ptr(akid = AUTHORITY_KEYID_new())
        || !TEST_ptr(akid->keyid = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(akid->keyid, id, sizeof(id)))
        || !TEST_ptr(akid->serial = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(akid->serial, serial))
        || !TEST_ptr(iname = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(iname, "CN", MBSTRING_ASC,
            (const unsigned char *)"akid issuer", -1, -1, 0))
        || !TEST_ptr(gn = GENERAL_NAME_new())
        || !TEST_ptr(akid->issuer = GENERAL_NAMES_new()))
        goto err;
    GENERAL_NAME_set0_value(gn, GEN_DIRNAME, iname);
    iname = NULL;
    if (!TEST_true(sk_GENERAL_NAME_push(akid->issuer, gn)))
        goto err;
    gn = NULL;
    ret = TEST_int_eq(X509_add1_ext_i2d(x, NID_authority_key_identifier, akid,
                          0, X509V3_ADD_REPLACE),
        1);
err:
    X509_NAME_free(iname);
    GENERAL_NAME_free(gn);
    AUTHORITY_KEYID_free(akid);
    return ret;
}

/*
 * Add basicConstraints (CA, pathlen), keyUsage (ku_bit1, and ku_bit2 if not
 * negative), extendedKeyUsage (eku_nid), a subjectKeyIdentifier and an
 * authorityKeyIdentifier to x.
 */
static int add_cached_exts(X509 *x, unsigned char skid_byte,
    unsigned char akid_byte, long serial, long pathlen, int ku_bit1,
    int ku_bit2, int eku_nid)
{
    ASN1_OCTET_STRING *skid = NULL;
    ASN1_BIT_STRING *ku = NULL;
    EXTENDED_KEY_USAGE *eku = NULL;
    BASIC_CONSTRAINTS *bc = NULL;
    unsigned char id[20];
    int ret = 0;

    memset(id, skid_byte, sizeof(id));
    if (!TEST_ptr(bc = BASIC_CONSTRAINTS_new()))
        goto err;
    bc->ca = 1;
    if (!TEST_ptr(bc->pathlen = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(bc->pathlen, pathlen))
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_basic_constraints, bc, 1,
                            X509V3_ADD_REPLACE),
            1)
        || !TEST_ptr(ku = ASN1_BIT_STRING_new())
        || !TEST_true(ASN1_BIT_STRING_set_bit(ku, ku_bit1, 1)))
        goto err;
    if (ku_bit2 >= 0 && !TEST_true(ASN1_BIT_STRING_set_bit(ku, ku_bit2, 1)))
        goto err;
    if (!TEST_int_eq(X509_add1_ext_i2d(x, NID_key_usage, ku, 1,
                         X509V3_ADD_REPLACE),
            1)
        || !TEST_ptr(eku = sk_ASN1_OBJECT_new_null())
        || !TEST_true(sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(eku_nid)))
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_ext_key_usage, eku, 0,
                            X509V3_ADD_REPLACE),
            1)
        || !TEST_ptr(skid = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(skid, id, sizeof(id)))
        || !TEST_int_eq(X509_add1_ext_i2d(x, NID_subject_key_identifier, skid,
                            0, X509V3_ADD_REPLACE),
            1)
        || !add_akid(x, akid_byte, serial))
        goto err;
    ret = 1;
err:
    BASIC_CONSTRAINTS_free(bc);
    ASN1_BIT_STRING_free(ku);
    sk_ASN1_OBJECT_free(eku);
    ASN1_OCTET_STRING_free(skid);
    return ret;
}

/*
 * Every accessor of the extension cache returns its failure value and raises
 * ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED on an unfinalized certificate, and reports
 * the finalized values once a different certificate has been decoded into it.
 */
static int test_cache_accessors_finalization(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *a = NULL, *b = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    const ASN1_OCTET_STRING *oct;
    const ASN1_INTEGER *serial;
    const GENERAL_NAMES *gens;
    unsigned char idbuf[20];
    int len;

    /* Never signed, so unfinalized: pathlen 3, digitalSignature, clientAuth */
    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(a = make_unsigned_cert(key, "unfinalized"))
        || !add_cached_exts(a, 0xAA, 0xBB, 0x1111, 3, 0, -1, NID_client_auth))
        goto err;

    ERR_clear_error();
    if (!TEST_int_eq(X509_check_purpose(a, -1, 0), -1)
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_int_eq(X509_check_ca(a), 0) || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_uint_eq(X509_get_key_usage(a), 0) || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_uint_eq(X509_get_extended_key_usage(a), 0)
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_ptr_null(X509_get0_subject_key_id(a))
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_ptr_null(X509_get0_authority_key_id(a))
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_ptr_null(X509_get0_authority_issuer(a))
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_ptr_null(X509_get0_authority_serial(a))
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_long_eq(X509_get_pathlen(a), -1) || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_long_eq(X509_get_proxy_pathlen(a), -1)
        || !expect_unfinalized_error())
        goto err;
    ERR_clear_error();
    if (!TEST_int_eq(X509_get_extension_flags(a) & EXFLAG_SET, 0)
        || !TEST_ulong_eq(ERR_peek_error(), 0))
        goto err;

    /* A different, signed cert: pathlen 7, keyCertSign|cRLSign, serverAuth */
    if (!TEST_ptr(b = make_unsigned_cert(key, "finalized"))
        || !add_cached_exts(b, 0xCC, 0xDD, 0x4242, 7, 5, 6, NID_server_auth)
        || !TEST_int_gt(X509_sign(b, key, EVP_sha256()), 0)
        || !TEST_int_gt(len = i2d_X509(b, &der), 0))
        goto err;

    /* Decoding b into a finalizes a */
    p = der;
    if (!TEST_ptr(a = d2i_X509(&a, &p, len)))
        goto err;

    if (!TEST_int_eq(X509_check_purpose(a, -1, 0), 1)
        || !TEST_int_eq(X509_check_ca(a), 1)
        || !TEST_uint_eq(X509_get_key_usage(a), KU_KEY_CERT_SIGN | KU_CRL_SIGN)
        || !TEST_uint_eq(X509_get_extended_key_usage(a), XKU_SSL_SERVER)
        || !TEST_long_eq(X509_get_pathlen(a), 7)
        || !TEST_long_eq(X509_get_proxy_pathlen(a), -1)
        || !TEST_int_ne(X509_get_extension_flags(a) & EXFLAG_SET, 0)
        || !TEST_int_ne(X509_get_extension_flags(a) & EXFLAG_CA, 0))
        goto err;

    memset(idbuf, 0xCC, sizeof(idbuf));
    if (!TEST_ptr(oct = X509_get0_subject_key_id(a))
        || !TEST_mem_eq(ASN1_STRING_get0_data(oct), ASN1_STRING_get_length(oct),
            idbuf, sizeof(idbuf)))
        goto err;
    memset(idbuf, 0xDD, sizeof(idbuf));
    if (!TEST_ptr(oct = X509_get0_authority_key_id(a))
        || !TEST_mem_eq(ASN1_STRING_get0_data(oct), ASN1_STRING_get_length(oct),
            idbuf, sizeof(idbuf)))
        goto err;
    if (!TEST_ptr(gens = X509_get0_authority_issuer(a))
        || !TEST_int_eq(sk_GENERAL_NAME_num(gens), 1)
        || !TEST_ptr(serial = X509_get0_authority_serial(a))
        || !TEST_long_eq(ASN1_INTEGER_get(serial), 0x4242))
        goto err;

    ret = 1;
err:
    OPENSSL_free(der);
    X509_free(b);
    X509_free(a);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A failed X509_sign() leaves the certificate unfinalized rather than with the
 * cache from before the attempt. A 512-bit RSA key cannot sign a SHA-512
 * digest with PKCS#1 v1.5 padding, so signing fails after the signature
 * algorithm fields have been rewritten.
 */
static int test_failed_sign_unfinalizes(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *x = NULL;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)512))
        || !TEST_ptr(x = make_unsigned_cert(key, "failed sign"))
        || !TEST_int_gt(X509_sign(x, key, EVP_sha256()), 0)
        || !TEST_int_eq(X509_check_purpose(x, -1, 0), 1))
        goto err;

    if (!TEST_int_le(X509_sign(x, key, EVP_sha512()), 0))
        goto err;
    ERR_clear_error();
    if (!TEST_int_eq(X509_check_purpose(x, -1, 0), -1)
        || !expect_unfinalized_error())
        goto err;

    /* A successful sign finalizes it again */
    if (!TEST_int_gt(X509_sign(x, key, EVP_sha256()), 0)
        || !TEST_int_eq(X509_check_purpose(x, -1, 0), 1))
        goto err;

    ret = 1;
err:
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Modifying a finalized certificate with a setter or by adding or removing
 * an extension leaves it unfinalized until it is signed again.
 */
static int test_mutators_unfinalize(void)
{
    int ret = 0, i;
    EVP_PKEY *key = NULL;
    X509 *x = NULL;
    X509_EXTENSION *ext = NULL;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(x = make_unsigned_cert(key, "mutators"))
        || !TEST_true(set_key_ids(x, 0x11))
        || !TEST_int_gt(X509_sign(x, key, EVP_sha256()), 0)
        || !TEST_int_eq(X509_check_purpose(x, -1, 0), 1))
        goto err;

    for (i = 0; i < 4; i++) {
        switch (i) {
        case 0:
            if (!TEST_true(X509_set_version(x, X509_VERSION_2)))
                goto err;
            break;
        case 1:
            if (!TEST_true(X509_set_pubkey(x, key)))
                goto err;
            break;
        case 2:
            if (!TEST_true(set_key_ids(x, 0x22))) /* X509_add1_ext_i2d() */
                goto err;
            break;
        case 3:
            if (!TEST_int_ge(X509_get_ext_by_NID(x, NID_subject_key_identifier,
                                 -1),
                    0)
                || !TEST_ptr(ext = X509_delete_ext(x,
                                 X509_get_ext_by_NID(x,
                                     NID_subject_key_identifier, -1))))
                goto err;
            X509_EXTENSION_free(ext);
            ext = NULL;
            break;
        }
        ERR_clear_error();
        if (!TEST_int_eq(X509_check_purpose(x, -1, 0), -1)
            || !expect_unfinalized_error()
            || !TEST_int_gt(X509_sign(x, key, EVP_sha256()), 0)
            || !TEST_int_eq(X509_check_purpose(x, -1, 0), 1))
            goto err;
    }

    ret = 1;
err:
    X509_EXTENSION_free(ext);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A never-signed certificate encodes as an RFC 9925 unsigned certificate, and
 * parsing that finalizes it, so an application-synthesized trust anchor can
 * be used for verification without a signature.
 */
static int test_unsigned_cert_roundtrip(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    X509 *x = NULL, *parsed = NULL;
    BASIC_CONSTRAINTS *bc = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;
    int len;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(x = make_unsigned_cert(key, "unsigned"))
        || !TEST_ptr(bc = BASIC_CONSTRAINTS_new()))
        goto err;
    bc->ca = 0xff;
    if (!TEST_true(X509_add1_ext_i2d(x, NID_basic_constraints, bc, 1,
            X509V3_ADD_REPLACE))
        || !TEST_int_gt(len = i2d_X509(x, &der), 0))
        goto err;
    p = der;
    if (!TEST_ptr(parsed = d2i_X509(NULL, &p, len)))
        goto err;

    X509_get0_signature(&sig, &alg, parsed);
    if (!TEST_int_eq(OBJ_obj2nid(alg->algorithm), NID_id_alg_unsigned)
        || !TEST_ptr_null(alg->parameter)
        || !TEST_size_t_eq(ASN1_STRING_get_length(sig), 0)
        || !TEST_int_eq(X509_get_signature_nid(parsed), NID_id_alg_unsigned)
        || !TEST_int_eq(X509_check_purpose(parsed, -1, 0), 1)
        || !TEST_int_eq(X509_check_ca(parsed), 1))
        goto err;

    ret = 1;
err:
    OPENSSL_free(der);
    BASIC_CONSTRAINTS_free(bc);
    X509_free(parsed);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Signing leaves the cached encoding of the signed part current and equal
 * to the decoded one; modifying the object afterwards marks it stale.
 */
static int test_sign_caches_encoding(void)
{
    EVP_PKEY *pkey = NULL;
    X509_NAME *name = NULL;
    X509 *cert = NULL, *cert_copy = NULL;
    X509_CRL *crl = NULL, *crl_copy = NULL;
    X509_REQ *req = NULL, *req_copy = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"sign test", -1, -1, 0)))
        goto err;

    /* Certificate */
    if (!TEST_ptr(cert = X509_new())
        || !TEST_true(cert->cert_info.enc.modified)
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(X509_set_issuer_name(cert, name))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(cert), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(cert), 3600))
        || !TEST_true(X509_set_pubkey(cert, pkey))
        || !TEST_int_gt(X509_sign(cert, pkey, EVP_sha256()), 0)
        || !TEST_false(cert->cert_info.enc.modified)
        || !TEST_ptr(cert_copy = X509_dup(cert))
        || !TEST_false(cert_copy->cert_info.enc.modified)
        || !TEST_mem_eq(cert->cert_info.enc.enc,
            (size_t)cert->cert_info.enc.len,
            cert_copy->cert_info.enc.enc,
            (size_t)cert_copy->cert_info.enc.len)
        || !TEST_int_eq(X509_cmp(cert, cert_copy), 0)
        || !TEST_true(X509_set_version(cert, X509_VERSION_2))
        || !TEST_true(cert->cert_info.enc.modified)
        || !TEST_int_gt(X509_sign(cert, pkey, EVP_sha256()), 0)
        || !TEST_false(cert->cert_info.enc.modified)
        || !TEST_int_ne(X509_cmp(cert, cert_copy), 0))
        goto err;

    /* CRL */
    if (!TEST_ptr(crl = X509_CRL_new())
        || !TEST_true(crl->crl.enc.modified)
        || !TEST_true(X509_CRL_set_issuer_name(crl, name))
        || !TEST_true(X509_CRL_set1_lastUpdate(crl, X509_getm_notBefore(cert)))
        || !TEST_int_gt(X509_CRL_sign(crl, pkey, EVP_sha256()), 0)
        || !TEST_false(crl->crl.enc.modified)
        || !TEST_ptr(crl_copy = X509_CRL_dup(crl))
        || !TEST_false(crl_copy->crl.enc.modified)
        || !TEST_mem_eq(crl->crl.enc.enc, (size_t)crl->crl.enc.len,
            crl_copy->crl.enc.enc, (size_t)crl_copy->crl.enc.len))
        goto err;

    /* Request */
    if (!TEST_ptr(req = X509_REQ_new())
        || !TEST_true(req->req_info.enc.modified)
        || !TEST_true(X509_REQ_set_subject_name(req, name))
        || !TEST_true(X509_REQ_set_pubkey(req, pkey))
        || !TEST_int_gt(X509_REQ_sign(req, pkey, EVP_sha256()), 0)
        || !TEST_false(req->req_info.enc.modified)
        || !TEST_ptr(req_copy = X509_REQ_dup(req))
        || !TEST_false(req_copy->req_info.enc.modified)
        || !TEST_mem_eq(req->req_info.enc.enc, (size_t)req->req_info.enc.len,
            req_copy->req_info.enc.enc, (size_t)req_copy->req_info.enc.len))
        goto err;

    ret = 1;
err:
    X509_REQ_free(req_copy);
    X509_REQ_free(req);
    X509_CRL_free(crl_copy);
    X509_CRL_free(crl);
    X509_free(cert_copy);
    X509_free(cert);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    return ret;
}

/* A modified, unsigned certificate or CRL is equal only to itself */
static int test_cmp_modified(void)
{
    EVP_PKEY *pkey = NULL;
    X509_NAME *name = NULL;
    X509 *cert = NULL, *copy = NULL;
    X509_CRL *crl = NULL, *crl_copy = NULL;
    ASN1_INTEGER *serial = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"cmp test", -1, -1, 0))
        || !TEST_ptr(serial = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set(serial, 2)))
        goto err;

    if (!TEST_ptr(cert = X509_new())
        || !TEST_true(X509_set_subject_name(cert, name))
        || !TEST_true(X509_set_issuer_name(cert, name))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(cert), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(cert), 3600))
        || !TEST_true(X509_set_pubkey(cert, pkey))
        || !TEST_int_gt(X509_sign(cert, pkey, EVP_sha256()), 0)
        || !TEST_ptr(copy = X509_dup(cert))
        || !TEST_int_eq(X509_cmp(cert, copy), 0)
        || !TEST_int_eq(X509_cmp(cert, cert), 0)
        /* The copy is modified but still equal to itself */
        || !TEST_true(X509_set_serialNumber(copy, serial))
        || !TEST_int_eq(X509_cmp(copy, copy), 0)
        || !TEST_int_eq(X509_cmp(cert, copy), -1)
        || !TEST_int_eq(X509_cmp(copy, cert), 1)
        /* Both modified: unequal */
        || !TEST_true(X509_set_serialNumber(cert, serial))
        || !TEST_int_ne(X509_cmp(cert, copy), 0)
        /* Signing again makes them comparable and equal */
        || !TEST_int_gt(X509_sign(cert, pkey, EVP_sha256()), 0)
        || !TEST_int_gt(X509_sign(copy, pkey, EVP_sha256()), 0)
        || !TEST_int_eq(X509_cmp(cert, copy), 0))
        goto err;

    if (!TEST_ptr(crl = X509_CRL_new())
        || !TEST_true(X509_CRL_set_issuer_name(crl, name))
        || !TEST_true(X509_CRL_set1_lastUpdate(crl, X509_getm_notBefore(cert)))
        || !TEST_int_gt(X509_CRL_sign(crl, pkey, EVP_sha256()), 0)
        || !TEST_ptr(crl_copy = X509_CRL_dup(crl))
        || !TEST_int_eq(X509_CRL_match(crl, crl), 0)
        || !TEST_true(X509_CRL_set_version(crl_copy, X509_CRL_VERSION_2))
        || !TEST_int_eq(X509_CRL_match(crl_copy, crl_copy), 0)
        || !TEST_int_eq(X509_CRL_match(crl, crl_copy), -1)
        || !TEST_int_eq(X509_CRL_match(crl_copy, crl), 1))
        goto err;

    ret = 1;
err:
    X509_CRL_free(crl_copy);
    X509_CRL_free(crl);
    X509_free(copy);
    X509_free(cert);
    ASN1_INTEGER_free(serial);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_sign_caches_encoding);
    ADD_TEST(test_cmp_modified);
    ADD_TEST(test_standard_exts);
    ADD_ALL_TESTS(test_a2i_ipaddress, OSSL_NELEM(a2i_ipaddress_tests));
    ADD_ALL_TESTS(test_ipaddr_to_asc, OSSL_NELEM(ipaddr_to_asc_tests));
    ADD_TEST(test_crl_add_ext_modifies);
    ADD_TEST(tests_X509_PURPOSE);
    ADD_TEST(tests_X509_check_time);
    ADD_TEST(tests_X509_check_crypto);
    ADD_TEST(tests_x509_check_dpn);
    ADD_TEST(tests_x509_check_akid);
    ADD_TEST(test_X509_ALGOR_set_md_null);
    ADD_TEST(tests_x509_check_ext_duplicity);
    ADD_TEST(tests_x509_check_ext_duplicity_nid_undef);
    ADD_TEST(tests_x509_check_ext_duplicity_nid_dynamic);
    ADD_ALL_TESTS(test_x509_attribute_bit_string, 2);
    ADD_TEST(test_resign_rebuilds_cache);
    ADD_TEST(test_proxy_pathlen_not_stale);
    ADD_TEST(test_invalid_ext_raises);
    ADD_TEST(test_cache_accessors_finalization);
    ADD_TEST(test_failed_sign_unfinalizes);
    ADD_TEST(test_mutators_unfinalize);
    ADD_TEST(test_unsigned_cert_roundtrip);

    return 1;
}
