/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the asn1 module */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "testutil.h"
#include "e_os.h"

typedef struct {
    const char *test_case_name;
    const char *test_section;
} SIMPLE_FIXTURE;

/**********************************************************************
 *
 * Test of a_strnid's tbl_standard
 *
 ***/

static SIMPLE_FIXTURE setup_tbl_standard(const char *const test_case_name)
{
    SIMPLE_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    return fixture;
}

#include "../crypto/asn1/tbl_standard.h"

static int execute_tbl_standard(SIMPLE_FIXTURE fixture)
{
    const ASN1_STRING_TABLE *tmp;
    int last_nid = -1;
    size_t i;

    for (tmp = tbl_standard, i = 0; i < OSSL_NELEM(tbl_standard); i++, tmp++) {
        if (tmp->nid < last_nid) {
            last_nid = 0;
            break;
        }
        last_nid = tmp->nid;
    }

    if (last_nid != 0) {
        fprintf(stderr, "%s: Table order OK\n", fixture.test_section);
        return 1;
    }

    for (tmp = tbl_standard, i = 0; i < OSSL_NELEM(tbl_standard); i++, tmp++)
        fprintf(stderr, "%s: Index %" OSSLzu ", NID %d, Name=%s\n",
               fixture.test_section, i, tmp->nid, OBJ_nid2ln(tmp->nid));

    return 0;
}

static void teardown_tbl_standard(SIMPLE_FIXTURE fixture)
{
}

/**********************************************************************
 *
 * Test of ameth_lib's standard_methods
 *
 ***/

static SIMPLE_FIXTURE setup_standard_methods(const char *const test_case_name)
{
    SIMPLE_FIXTURE fixture;
    fixture.test_case_name = test_case_name;
    return fixture;
}

#include "internal/asn1_int.h"
#include "../crypto/asn1/standard_methods.h"

static int execute_standard_methods(SIMPLE_FIXTURE fixture)
{
    const EVP_PKEY_ASN1_METHOD **tmp;
    int last_pkey_id = -1;
    size_t i;

    for (tmp = standard_methods, i = 0; i < OSSL_NELEM(standard_methods);
         i++, tmp++) {
        if ((*tmp)->pkey_id < last_pkey_id) {
            last_pkey_id = 0;
            break;
        }
        last_pkey_id = (*tmp)->pkey_id;
    }

    if (last_pkey_id != 0) {
        fprintf(stderr, "%s: Table order OK\n", fixture.test_section);
        return 1;
    }

    for (tmp = standard_methods, i = 0; i < OSSL_NELEM(standard_methods);
         i++, tmp++)
        fprintf(stderr, "%s: Index %" OSSLzu ", pkey ID %d, Name=%s\n",
               fixture.test_section, i, (*tmp)->pkey_id,
               OBJ_nid2sn((*tmp)->pkey_id));

    return 0;
}

static void teardown_standard_methods(SIMPLE_FIXTURE fixture)
{
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
    {"asn1 tlb_standard", setup_tbl_standard, execute_tbl_standard,
     teardown_tbl_standard},
    {"asn1 standard_methods", setup_standard_methods, execute_standard_methods,
     teardown_standard_methods}
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
