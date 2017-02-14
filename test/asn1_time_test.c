/*
 * Copyright 1999-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Time tests for the asn1 module */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "test_main.h"
#include "testutil.h"
#include "e_os.h"

struct testdata {
    char *data;             /* TIME string value */
    int type;               /* GENERALIZED OR UTC */
    int check_result;       /* check result */
    time_t t;               /* expected time_t*/
    int cmp_result;         /* compariston to baseline result */
    int convert_result;     /* convertion result */
    size_t time_t_size_req; /* minimum required sizeof(time_t) to handle this date/time */
};

/* ASSUMES SIGNED TIME_T */
static struct testdata tbl_testdata[] = {
    { "0",                 V_ASN1_GENERALIZEDTIME, 0,           0,  0, 0, 4 }, /* Bad time */
    { "19700101000000Z",   V_ASN1_UTCTIME,         0,           0,  0, 0, 4 },
    { "A00101000000Z",     V_ASN1_UTCTIME,         0,           0,  0, 0, 4 },
    { "19A00101000000Z",   V_ASN1_GENERALIZEDTIME, 0,           0,  0, 0, 4 },
    { "700101000000X",     V_ASN1_UTCTIME,         0,           0,  0, 0, 4 },
    { "19700101000000X",   V_ASN1_GENERALIZEDTIME, 0,           0,  0, 0, 4 },
    { "19700101000000Z",   V_ASN1_GENERALIZEDTIME, 1,           0, -1, 1, 4 }, /* Epoch begins */
    { "700101000000Z",     V_ASN1_UTCTIME,         1,           0, -1, 1, 4 }, /* ditto */
    { "20380119031407Z",   V_ASN1_GENERALIZEDTIME, 1,  0x7FFFFFFF,  1, 1, 4 }, /* Max 32bit time_t */
    { "20380119031408Z",   V_ASN1_GENERALIZEDTIME, 1,  0x80000000,  1, 1, 8 }, /* +1 to above */
    { "19011213204552Z",   V_ASN1_GENERALIZEDTIME, 1, -2147483648, -1, 0, 4 }, /* Min 32bit time_t */
    { "19011213204551Z",   V_ASN1_GENERALIZEDTIME, 1, -2147483649, -1, 0, 8 }, /* -1 to above */
    { "20371231235959Z",   V_ASN1_GENERALIZEDTIME, 1,  2145916799,  1, 1, 4 }, /* Just before 2038 */
    { "20371231235959Z",   V_ASN1_UTCTIME,         0,           0,  0, 1, 4 }, /* Bad UTC time */
    { "371231235959Z",     V_ASN1_UTCTIME,         1,  2145916799,  1, 1, 4 },
    { "19701006121456Z",   V_ASN1_GENERALIZEDTIME, 1,    24063296, -1, 1, 4 },
    { "701006121456Z",     V_ASN1_UTCTIME,         1,    24063296, -1, 1, 4 },
    { "19691006121456Z",   V_ASN1_GENERALIZEDTIME, 1,    -7472704, -1, 1, 4 },
    { "691006121456Z",     V_ASN1_UTCTIME,         1,    -7472704, -1, 1, 4 },
    { "19991231000000Z",   V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 }, /* Match baseline */
    { "199912310000Z",     V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 }, /* In various flavors */
    { "991231000000Z",     V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "9912310000Z",       V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "9912310000+0000",   V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "199912310000+0000", V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 },
    { "9912310000-0000",   V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "199912310000-0000", V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 },
    { "199912310100+0100", V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 },
    { "199912302300-0100", V_ASN1_GENERALIZEDTIME, 1,   946598400,  0, 1, 4 },
    { "9912310100+0100",   V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "9912302300-0100",   V_ASN1_UTCTIME,         1,   946598400,  0, 1, 4 },
    { "20500101120000Z",   V_ASN1_GENERALIZEDTIME, 1,  2524651200,  1, 0, 8 },
    { "19000101120000Z",   V_ASN1_GENERALIZEDTIME, 1, -2208945600, -1, 0, 8 },
};

/* A baseline time to compare to */
static ASN1_TIME gtime = {
    15,
    V_ASN1_GENERALIZEDTIME,
    (unsigned char*)"19991231000000Z",
    0
};
static time_t gtime_t = 946598400;

static int test_table(int idx)
{
    int error = 0;
    ASN1_TIME atime;
    ASN1_TIME *ptime;
    struct testdata *td = &tbl_testdata[idx];
    int day, sec;
    time_t t;
    struct tm tm;
    struct tm *ptm;
    char buf[256];
    int cmp_result = 0;

    fprintf(stderr, "INDEX: %d (%s)\n", idx, td->data);
    atime.data = (unsigned char*)td->data;
    atime.length = strlen((char*)atime.data);
    atime.type = td->type;

    if (sizeof(time_t) < td->time_t_size_req) {
        fprintf(stderr, "Skipping due to limited time_t bitspace\n");
        return 1;
    }

    if (ASN1_TIME_check(&atime) != td->check_result) {
        fprintf(stderr, "ERROR: ASN1_TIME_check(%s) unexpected result\n", atime.data);
        error = 1;
    }
    if (td->check_result == 0)
        return 1;

    /* Get the time */
    if (ASN1_TIME_get(&atime, &t, &tm) == 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_get(%s) failed\n", atime.data);
        error = 1;
    }
    if (t != td->t) {
        fprintf(stderr, "ERROR: ASN1_TIME_get(%s) time_t mismatch (expected: %ld, got: %ld)\n",
                atime.data, (long)td->t, (long)t);
        error = 1;
    }

    ptm = gmtime(&t);
    if (ptm == NULL) {
        fprintf(stderr, "ERROR: gmtime(%s->%ld) failed\n", atime.data, (long)t);
        error = 1;
    } else {
        cmp_result = 0;
        if (ptm->tm_sec != tm.tm_sec) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_sec mismatch: %d vs %d\n", ptm->tm_sec, tm.tm_sec);
        }
        if (ptm->tm_min != tm.tm_min) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_min mismatch: %d vs %d\n", ptm->tm_min, tm.tm_min);
        }
        if (ptm->tm_hour != tm.tm_hour) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_hour mismatch: %d vs %d\n", ptm->tm_hour, tm.tm_hour);
        }
        if (ptm->tm_mday != tm.tm_mday) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_mday mismatch: %d vs %d\n", ptm->tm_mday, tm.tm_mday);
        }
        if (ptm->tm_mon != tm.tm_mon) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_mon mismatch: %d vs %d\n", ptm->tm_mon, tm.tm_mon);
        }
        if (ptm->tm_year != tm.tm_year) {
            cmp_result = 1;
            fprintf(stderr, "ERROR: tm_year mismatch: %d vs %d\n", ptm->tm_year, tm.tm_year);
        }
        /* do not compare tm_wday, tm_yday nor tm_isdst */

        if (cmp_result == 1) {
            fprintf(stderr, "ERROR: mismatch: gmtime vs ASN1_TIME_get\n");
            fprintf(stderr, "ERROR: gmtime(%s->%ld) compare failed\n", atime.data, (long)t);
            strftime(buf, sizeof(buf), "%Y-%m-%d %T", ptm);
            fprintf(stderr, "gmtime:        %s\n", buf);
            strftime(buf, sizeof(buf), "%Y-%m-%d %T", &tm);
            fprintf(stderr, "ASN1_TIME_get: %s\n", buf);
            error = 1;
        }
    }

    if (ASN1_TIME_cmp_time_t(&atime, td->t) != 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_cmp_time_t((%s vs %ld) compare failed\n", atime.data, (long)td->t);
        error = 1;
    }

    if (ASN1_TIME_diff(&day, &sec, &atime, &atime) == 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_diff(%s) to self failed\n", atime.data);
        error = 1;
    }
    if (day != 0 || sec != 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_diff(%s) to self not equal\n", atime.data);
        error = 1;
    }

    if (ASN1_TIME_diff(&day, &sec, &gtime, &atime) == 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_diff(%s) to baseline failed\n", atime.data);
        error = 1;
    } else if (!((day == 0 && sec == 0 && td->cmp_result == 0) ||
                 ((day < 0 || sec < 0) && td->cmp_result == -1) ||
                 ((day > 0 || sec > 0) && td->cmp_result == 1))) {
        fprintf(stderr, "ERROR: ASN1_TIME_diff(%s) to baseline bad comparison\n", atime.data);
        error = 1;
    }

    if (ASN1_TIME_cmp_time_t(&atime, gtime_t) != td->cmp_result) {
        fprintf(stderr, "ERROR: ASN1_TIME_cmp_time_t(%s) to baseline bad comparison\n", atime.data);
        error = 1;
    }

    if ((ptime = ASN1_TIME_set(NULL, td->t)) == NULL) {
        fprintf(stderr, "ERROR: ASN1_TIME_set(%ld) failed\n", (long)td->t);
        error = 1;
    }
    if (ptime != NULL && ASN1_TIME_cmp_time_t(ptime, td->t) != 0) {
        fprintf(stderr, "ERROR: ASN1_TIME_set(%ld) compare failed (%s->%s)\n",
                (long)td->t, td->data, ptime->data);
        error = 1;
    }
    ASN1_TIME_free(ptime);

    if (td->type == V_ASN1_UTCTIME) {
        ptime = ASN1_TIME_to_generalizedtime(&atime, NULL);
        if (td->convert_result == 1 && ptime == NULL) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_generalizedtime(%s) failed\n", atime.data);
            error = 1;
        } else if (td->convert_result == 0 && ptime != NULL) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_generalizedtime(%s) should have failed\n", atime.data);
            error = 1;
        }
        if (ptime != NULL && ASN1_TIME_cmp_time_t(ptime, td->t) != 0) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_generalizedtime(%s->%s) bad result\n", atime.data, ptime->data);
            error = 1;
        }
        ASN1_TIME_free(ptime);
    } else if (td->type == V_ASN1_GENERALIZEDTIME) {
        ptime = ASN1_TIME_to_utctime(&atime, NULL);
        if (td->convert_result == 1 && ptime == NULL) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_utctime(%s) failed\n", atime.data);
            error = 1;
        } else if (td->convert_result == 0 && ptime != NULL) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_utctime(%s) should have failed\n", atime.data);
            error = 1;
        }
        if (ptime != NULL && ASN1_TIME_cmp_time_t(ptime, td->t) != 0) {
            fprintf(stderr, "ERROR: ASN1_TIME_to_utctime(%s->%s) bad result\n", atime.data, ptime->data);
            error = 1;
        }
        ASN1_TIME_free(ptime);
    }
    return !error;
}

void register_tests(void)
{
    ADD_ALL_TESTS(test_table, OSSL_NELEM(tbl_testdata));
}
