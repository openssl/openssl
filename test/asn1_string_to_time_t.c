/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests for converting ASN.1 string to time_t */

#include <crypto/asn1.h>
#include "testutil.h"
#include "internal/nelem.h"

typedef struct {
    char *input;
    time_t expected;
} TESTDATA;

static TESTDATA asn1_to_utc[] = {
    {
        /* 
         * last second of standard time in central Europe in 2021
         * specified in GMT
         */
        "210328005959Z",
        1616893199,
    },
    {
        /* 
         * first second of daylight saving time in central Europe in 2021
         * specified in GMT
         */
        "210328010000Z",
        1616893200,
    },
    {
        /* 
         * last second of standard time in central Europe in 2021
         * specified in offset to GMT
         */
        "20210328015959+0100",
        1616893199,
    },
    {
        /* 
         * first second of daylight saving time in central Europe in 2021
         * specified in offset to GMT
         */
        "20210328030000+0200",
        1616893200,
    },
    {
        /* 
         * Invalid strings should get -1 as a result
         */
        "INVALID",
        -1,
    },
};

static int convert_asn1_to_time_t(int idx)
{
    time_t testdateutc;
    
    testdateutc = asn1_string_to_time_t(asn1_to_utc[idx].input);

    if (!TEST_int_eq(testdateutc, asn1_to_utc[idx].expected)) {
        TEST_info("asn1_string_to_time_t (%s) failed: expected %li, got %li\n",
                asn1_to_utc[idx].input, asn1_to_utc[idx].expected, (signed long) testdateutc);
        return 0;
    }
    return 1;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(convert_asn1_to_time_t, OSSL_NELEM(asn1_to_utc));
    return 1;
}
