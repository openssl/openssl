/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the x509 and x509v3 modules */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "testutil.h"
#include "e_os.h"

typedef struct {
    const char *test_case_name;
    const char *test_section;
} SIMPLE_FIXTURE;

/**********************************************************************
 *
 * Test of x509v3
 *
 ***/

static SIMPLE_FIXTURE setup_standard_exts(const char *const test_case_name)
{
    SIMPLE_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    return fixture;
}

#include "../crypto/x509v3/ext_dat.h"
#include "../crypto/x509v3/standard_exts.h"

static int execute_standard_exts(SIMPLE_FIXTURE fixture)
{
    size_t i;
    int prev = -1, good = 1;
    const X509V3_EXT_METHOD **tmp;

    tmp = standard_exts;
    for (i = 0; i < OSSL_NELEM(standard_exts); i++, tmp++) {
        if ((*tmp)->ext_nid < prev)
            good = 0;
        prev = (*tmp)->ext_nid;

    }
    if (!good) {
        tmp = standard_exts;
        fprintf(stderr, "Extensions out of order!\n");
        for (i = 0; i < STANDARD_EXTENSION_COUNT; i++, tmp++)
            fprintf(stderr, "%d : %s\n", (*tmp)->ext_nid,
                    OBJ_nid2sn((*tmp)->ext_nid));
    } else {
        fprintf(stderr, "Order OK\n");
    }

    return good;
}

static void teardown_standard_exts(SIMPLE_FIXTURE fixture)
{
    ERR_print_errors_fp(stderr);
}

/**********************************************************************
 *
 * Test driver
 *
 ***/

static struct {
    const char *section;
    SIMPLE_FIXTURE (*setup)(const char *const test_case_name);
    int (*execute)(SIMPLE_FIXTURE);
    void (*teardown)(SIMPLE_FIXTURE);
} tests[] = {
    {"standard_exts", setup_standard_exts, execute_standard_exts,
     teardown_standard_exts},
};

static int drive_tests(int idx)
{
    SETUP_TEST_FIXTURE(SIMPLE_FIXTURE, tests[idx].setup);
    fixture.test_section = tests[idx].section;
    EXECUTE_TEST(tests[idx].execute, tests[idx].teardown);
}

int main(int argc, char **argv)
{
    ADD_ALL_TESTS(drive_tests, OSSL_NELEM(tests));

    return run_tests(argv[0]);
}
