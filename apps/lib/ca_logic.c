/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../apps/include/apps.h"
#include "ca_logic.h"

ASN1_TIME *asn1_string_to_ASN1_TIME(char *asn1_string)
{
    size_t len;
    ASN1_TIME *tmps = NULL;
    char *p;

    len = strlen(asn1_string) + 1;
    tmps = ASN1_STRING_new();
    if (tmps == NULL)
        return NULL;

    if (!ASN1_STRING_set(tmps, NULL, len)) {
        ASN1_STRING_free(tmps);
        return NULL;
    }

    if (strlen(asn1_string) == 13)
        tmps->type = V_ASN1_UTCTIME;
    else
        tmps->type = V_ASN1_GENERALIZEDTIME;
    p = (char*)tmps->data;

    tmps->length = BIO_snprintf(p, len, "%s", asn1_string);

    return tmps;
}

time_t *asn1_string_to_time_t(char *asn1_string)
{
    ASN1_TIME *testdate_asn1 = NULL;
    struct tm *testdate_tm = NULL;
    time_t *testdatelocal = NULL;
    time_t *testdateutc = NULL;

    testdate_asn1 = asn1_string_to_ASN1_TIME(asn1_string);
    if (testdate_asn1 == NULL)
        return NULL;

    testdate_tm = app_malloc(sizeof(*testdate_tm), "testdate_tm");

    if (!(ASN1_TIME_to_tm(testdate_asn1, testdate_tm))) {
        free(testdate_tm);
        ASN1_STRING_free(testdate_asn1);
        return NULL;
    }

    testdatelocal = app_malloc(sizeof(time_t), "testdatelocal");
    *testdatelocal = mktime(testdate_tm);
    free(testdate_tm);

    testdateutc = app_malloc(sizeof(time_t), "testdateutc");
    *testdateutc = *testdatelocal - timezone;

    free(testdatelocal);
    ASN1_STRING_free(testdate_asn1);
    return testdateutc;
}

