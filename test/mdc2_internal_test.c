/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the mdc2 module */

#include <stdio.h>
#include <string.h>

#include <openssl/mdc2.h>
#include "testutil.h"
#include "e_os.h"

typedef struct {
    const char *input;
    const unsigned char expected[MDC2_DIGEST_LENGTH];
} TESTDATA;

typedef struct {
    const char *case_name;
    int num;
    const TESTDATA *data;
} SIMPLE_FIXTURE;

/**********************************************************************
 *
 * Test of mdc2 internal functions
 *
 ***/

static SIMPLE_FIXTURE setup_mdc2(const char *const test_case_name)
{
    SIMPLE_FIXTURE fixture;
    fixture.case_name = test_case_name;
    return fixture;
}

static int execute_mdc2(SIMPLE_FIXTURE fixture)
{
    unsigned char md[MDC2_DIGEST_LENGTH];
    MDC2_CTX c;

    MDC2_Init(&c);
    MDC2_Update(&c, (const unsigned char *)fixture.data->input,
                strlen(fixture.data->input));
    MDC2_Final(&(md[0]), &c);

    if (memcmp(fixture.data->expected, md, MDC2_DIGEST_LENGTH)) {
        fprintf(stderr, "mdc2 test %d: unexpected output\n", fixture.num);
        return 0;
    }

    return 1;
}

static void teardown_mdc2(SIMPLE_FIXTURE fixture)
{
}

/**********************************************************************
 *
 * Test driver
 *
 ***/

static TESTDATA tests[] = {
    {
        "Now is the time for all ",
        {
            0x42, 0xE5, 0x0C, 0xD2, 0x24, 0xBA, 0xCE, 0xBA,
            0x76, 0x0B, 0xDD, 0x2B, 0xD4, 0x09, 0x28, 0x1A
        }
    }
};

static int drive_tests(int idx)
{
    SETUP_TEST_FIXTURE(SIMPLE_FIXTURE, setup_mdc2);
    fixture.num = idx;
    fixture.data = &tests[idx];
    EXECUTE_TEST(execute_mdc2, teardown_mdc2);
}

int main(int argc, char **argv)
{
    ADD_ALL_TESTS(drive_tests, OSSL_NELEM(tests));

    return run_tests(argv[0]);
}
