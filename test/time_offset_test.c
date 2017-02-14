/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
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
#include "test_main.h"
#include "e_os.h"

typedef struct {
    const char *data;
    int time_result;
    int x509_result;
    int type;
} TESTDATA;


/**********************************************************************
 *
 * Test driver
 *
 ***/

static TESTDATA tests[] = {
    { "20001201000000Z",      0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001201010000+0100",  0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001201050000+0500",  0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001130230000-0100",  0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001130190000-0500",  0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001130190001-0500",  1,  1, V_ASN1_GENERALIZEDTIME }, /* +1 second */
    { "001201000000Z",        0, -1, V_ASN1_UTCTIME },
    { "001201010000+0100",    0, -1, V_ASN1_UTCTIME },
    { "001201050000+0500",    0, -1, V_ASN1_UTCTIME },
    { "001130230000-0100",    0, -1, V_ASN1_UTCTIME },
    { "001130190000-0500",    0, -1, V_ASN1_UTCTIME },
    { "001201000000-0000",    0, -1, V_ASN1_UTCTIME },
    { "001201000001-0000",    1,  1, V_ASN1_UTCTIME }, /* +1 second */
    { "20001201000000+0000",  0, -1, V_ASN1_GENERALIZEDTIME },
    { "20001201000000+0100", -1, -1, V_ASN1_GENERALIZEDTIME },
    { "001201000000+0100",   -1, -1, V_ASN1_UTCTIME },
    { "20001201000000-0100",  1,  1, V_ASN1_GENERALIZEDTIME },
    { "001201000000-0100",    1,  1, V_ASN1_UTCTIME },
};

static time_t the_time = 975628800;

static int test_offset(int idx)
{
    ASN1_TIME at;
    const TESTDATA *testdata = &tests[idx];
    int ret = -2;

    fprintf(stderr, "test (%s)\n", testdata->data);
    at.data = (unsigned char*)testdata->data;
    at.length = strlen(testdata->data);
    at.type = testdata->type;

    if (at.type == V_ASN1_UTCTIME)
        ret = ASN1_UTCTIME_cmp_time_t(&at, the_time);
    else
        ret = ASN1_GENERALIZEDTIME_cmp_time_t(&at, the_time);

    if (testdata->time_result != ret) {
        fprintf(stderr, "ERROR: ASN1_xxxTIME_cmp_t test failed for %s\n", at.data);
        return 0;
    }

    return 1;
}

void register_tests()
{
    ADD_ALL_TESTS(test_offset, OSSL_NELEM(tests));
}
