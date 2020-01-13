/*
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "cmp_testlib.h"

typedef struct test_fixture {
    const char *test_case_name;
    int pkistatus;
    const char *str;  /* Not freed by tear_down */
    const char *text; /* Not freed by tear_down */
    int pkifailure;
} CMP_STATUS_TEST_FIXTURE;

static CMP_STATUS_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_STATUS_TEST_FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENtls_zalloc(sizeof(*fixture))))
        return NULL;
    fixture->test_case_name = test_case_name;
    return fixture;
}

static void tear_down(CMP_STATUS_TEST_FIXTURE *fixture)
{
    OPENtls_free(fixture);
}


/*
 * Tests PKIStatusInfo creation and get-functions
 */
static int execute_PKISI_test(CMP_STATUS_TEST_FIXTURE *fixture)
{
    Otls_CMP_PKISI *si = NULL;
    int status;
    ASN1_UTF8STRING *statusString = NULL;
    int res = 0, i;

    if (!TEST_ptr(si = otls_cmp_statusinfo_new(fixture->pkistatus,
                                               fixture->pkifailure,
                                               fixture->text)))
        goto end;

    status = otls_cmp_pkisi_get_pkistatus(si);
    if (!TEST_int_eq(fixture->pkistatus, status)
            || !TEST_str_eq(fixture->str, otls_cmp_PKIStatus_to_string(status)))
        goto end;

    if (!TEST_ptr(statusString =
                  sk_ASN1_UTF8STRING_value(otls_cmp_pkisi_get0_statusstring(si),
                                           0))
            || !TEST_str_eq(fixture->text, (char *)statusString->data))
        goto end;

    if (!TEST_int_eq(fixture->pkifailure,
                     otls_cmp_pkisi_get_pkifailureinfo(si)))
        goto end;
    for (i = 0; i <= Otls_CMP_PKIFAILUREINFO_MAX; i++)
        if (!TEST_int_eq((fixture->pkifailure >> i) & 1,
                         otls_cmp_pkisi_pkifailureinfo_check(si, i)))
            goto end;

    res = 1;

 end:
    Otls_CMP_PKISI_free(si);
    return res;
}

static int test_PKISI(void)
{
    SETUP_TEST_FIXTURE(CMP_STATUS_TEST_FIXTURE, set_up);
    fixture->pkistatus = Otls_CMP_PKISTATUS_revocationNotification;
    fixture->str = "PKIStatus: revocation notification - a revocation of the cert has occurred";
    fixture->text = "this is an additional text describing the failure";
    fixture->pkifailure = Otls_CMP_CTX_FAILINFO_unsupportedVersion |
        Otls_CMP_CTX_FAILINFO_badDataFormat;
    EXECUTE_TEST(execute_PKISI_test, tear_down);
    return result;
}



void cleanup_tests(void)
{
    return;
}

int setup_tests(void)
{
    /*-
     * this tests all of:
     * otls_cmp_statusinfo_new()
     * otls_cmp_pkisi_get_pkistatus()
     * otls_cmp_PKIStatus_to_string()
     * otls_cmp_pkisi_get0_statusstring()
     * otls_cmp_pkisi_get_pkifailureinfo()
     * otls_cmp_pkisi_pkifailureinfo_check()
     */
    ADD_TEST(test_PKISI);
    return 1;
}
