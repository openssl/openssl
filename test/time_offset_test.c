/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* time_t/offset (+/-XXXX) tests for ASN1 and X509 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "testutil.h"
#include "internal/nelem.h"

typedef struct {
    const char *data;
    int time_result;
    int type;
} TESTDATA;

/**********************************************************************
 *
 * Test driver
 *
 ***/

static TESTDATA tests[] = {
    { "20001201000000Z", 0, V_ASN1_GENERALIZEDTIME },
    { "20001201010000+0100", 0, V_ASN1_GENERALIZEDTIME },
    { "20001201050000+0500", 0, V_ASN1_GENERALIZEDTIME },
    { "20001130230000-0100", 0, V_ASN1_GENERALIZEDTIME },
    { "20001130190000-0500", 0, V_ASN1_GENERALIZEDTIME },
    { "20001130190001-0500", 1, V_ASN1_GENERALIZEDTIME }, /* +1 second */
    { "20001130185959-0500", -1, V_ASN1_GENERALIZEDTIME }, /* -1 second */
    { "001201000000Z", 0, V_ASN1_UTCTIME },
    { "001201010000+0100", 0, V_ASN1_UTCTIME },
    { "001201050000+0500", 0, V_ASN1_UTCTIME },
    { "001130230000-0100", 0, V_ASN1_UTCTIME },
    { "001130190000-0500", 0, V_ASN1_UTCTIME },
    { "001201000000-0000", 0, V_ASN1_UTCTIME },
    { "001201000001-0000", 1, V_ASN1_UTCTIME }, /* +1 second */
    { "001130235959-0000", -1, V_ASN1_UTCTIME }, /* -1 second */
    { "20001201000000+0000", 0, V_ASN1_GENERALIZEDTIME },
    { "20001201000000+0100", -1, V_ASN1_GENERALIZEDTIME },
    { "001201000000+0100", -1, V_ASN1_UTCTIME },
    { "20001201000000-0100", 1, V_ASN1_GENERALIZEDTIME },
    { "001201000000-0100", 1, V_ASN1_UTCTIME },
    { "20001201123400+1234", 0, V_ASN1_GENERALIZEDTIME },
    { "20001130112600-1234", 0, V_ASN1_GENERALIZEDTIME },
};

static time_t the_time = 975628800;
static ASN1_TIME *the_asn1_time;

static int test_offset(int idx)
{
    ASN1_TIME *at;
    const TESTDATA *testdata = &tests[idx];
    int ret = -2;
    int day, sec;

    at = ASN1_STRING_type_new(testdata->type);
    if (!TEST_ptr(at))
        return 0;
    if (!TEST_true(ASN1_STRING_set(at, (const unsigned char *)testdata->data,
            (int)strlen(testdata->data)))) {
        ASN1_TIME_free(at);
        return 0;
    }

    if (!TEST_true(ASN1_TIME_diff(&day, &sec, the_asn1_time, at))) {
        TEST_info("ASN1_TIME_diff() failed for %s\n",
            (const char *)ASN1_STRING_get0_data(at));
        ASN1_TIME_free(at);
        return 0;
    }
    if (day > 0)
        ret = 1;
    else if (day < 0)
        ret = -1;
    else if (sec > 0)
        ret = 1;
    else if (sec < 0)
        ret = -1;
    else
        ret = 0;

    if (!TEST_int_eq(testdata->time_result, ret)) {
        TEST_info("ASN1_TIME_diff() test failed for %s day=%d sec=%d\n",
            (const char *)ASN1_STRING_get0_data(at), day, sec);
        ASN1_TIME_free(at);
        return 0;
    }

    ret = ASN1_TIME_cmp_time_t(at, the_time);

    if (!TEST_int_eq(testdata->time_result, ret)) {
        TEST_info("ASN1_UTCTIME_cmp_time_t() test failed for %s\n",
            (const char *)ASN1_STRING_get0_data(at));
        ASN1_TIME_free(at);
        return 0;
    }

    ASN1_TIME_free(at);
    return 1;
}

int setup_tests(void)
{
    the_asn1_time = ASN1_STRING_type_new(V_ASN1_GENERALIZEDTIME);
    if (the_asn1_time == NULL)
        return 0;
    if (!ASN1_STRING_set(the_asn1_time,
            (const unsigned char *)"20001201000000Z", 15)) {
        ASN1_TIME_free(the_asn1_time);
        return 0;
    }
    ADD_ALL_TESTS(test_offset, OSSL_NELEM(tests));
    return 1;
}

void cleanup_tests(void)
{
    ASN1_TIME_free(the_asn1_time);
}
