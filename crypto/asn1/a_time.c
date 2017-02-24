/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * This is an implementation of the ASN1 Time structure which is:
 *    Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include "asn1_locl.h"

IMPLEMENT_ASN1_MSTRING(ASN1_TIME, B_ASN1_TIME)

IMPLEMENT_ASN1_FUNCTIONS(ASN1_TIME)

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t)
{
    return ASN1_TIME_adj(s, t, 0, 0);
}

/* This may switch types */
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
                         int offset_day, long offset_sec)
{
    struct tm *ts;
    struct tm data;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL) {
        ASN1err(ASN1_F_ASN1_TIME_ADJ, ASN1_R_ERROR_GETTING_TIME);
        return NULL;
    }
    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }
    if ((ts->tm_year >= 50) && (ts->tm_year < 150))
        return asn1_utctime_from_tm(s, ts);
    return asn1_generalizedtime_from_tm(s, ts);
}

int ASN1_TIME_check(const ASN1_TIME *t)
{
    if (t->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_check(t);
    else if (t->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_check(t);
    return 0;
}

/* Convert an ASN1_TIME structure to GeneralizedTime */
/* Remove any fractions, and fixup for any offset information */
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
                                                   ASN1_GENERALIZEDTIME **out)
{
    ASN1_GENERALIZEDTIME *ret = NULL;
    struct tm tm;

    if (!asn1_time_to_tm(&tm, t))
            return NULL;

    if (out != NULL)
        ret = *out;

    ret = asn1_generalizedtime_from_tm(ret, &tm);

    if (out != NULL && ret != NULL)
        *out = ret;

    return ret;
}

/* Convert an ASN1_TIME structure to UTCTime */
/* Remove any fractions, and fixup for any offset information */
ASN1_UTCTIME *ASN1_TIME_to_utctime(const ASN1_TIME *t, ASN1_UTCTIME **out)
{
    ASN1_UTCTIME *ret = NULL;
    struct tm tm;

    if (!asn1_time_to_tm(&tm, t))
        return NULL;

    if (out != NULL)
        ret = *out;

    ret = asn1_utctime_from_tm(ret, &tm);

    if (out != NULL && ret != NULL)
        *out = ret;

    return ret;
}

/* Sets the string via simple copy without cleaning it up */
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str)
{
    /* Try UTC, if that fails, try GENERALIZED */
    if (ASN1_UTCTIME_set_string(s, str))
        return 1;
    return ASN1_GENERALIZEDTIME_set_string(s, str);
}

/* Sets the string as a clean UTCTIME or GENERALIZEDTIME */
int ASN1_TIME_set_string_gmt(ASN1_TIME *s, const char *str)
{
    ASN1_UTCTIME t;
    ASN1_UTCTIME *ret;
    struct tm tm;

    /* parse the current format */
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;
    t.type = V_ASN1_UTCTIME;

    if (!asn1_utctime_to_tm(&tm, &t)) {
        t.type = V_ASN1_GENERALIZEDTIME;
        if (!asn1_generalizedtime_to_tm(&tm, &t))
            return 0;
    }

    /* figure out what the format should be */
    if (tm.tm_year < 50 || tm.tm_year > 149) {
        if ((ret = asn1_generalizedtime_from_tm(s, &tm)) == NULL)
            return 0;
    } else {
        if ((ret = asn1_utctime_from_tm(s, &tm)) == NULL)
            return 0;
    }

    if (ret != s)
        ASN1_STRING_free(ret);

    return 1;
}

int asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t)
{
    if (t == NULL) {
        time_t now_t;
        time(&now_t);
        if (OPENSSL_gmtime(&now_t, tm))
            return 1;
        return 0;
    }

    if (t->type == V_ASN1_UTCTIME)
        return asn1_utctime_to_tm(tm, t);
    if (t->type == V_ASN1_GENERALIZEDTIME)
        return asn1_generalizedtime_to_tm(tm, t);
    return 0;
}

int ASN1_TIME_diff(int *pday, int *psec,
                   const ASN1_TIME *from, const ASN1_TIME *to)
{
    struct tm tm_from, tm_to;
    if (!asn1_time_to_tm(&tm_from, from))
        return 0;
    if (!asn1_time_to_tm(&tm_to, to))
        return 0;
    return OPENSSL_gmtime_diff(pday, psec, &tm_from, &tm_to);
}

int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t)
{
    if (s->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_cmp_time_t(s, t);
    if (s->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_cmp_time_t(s, t);
    return -2;
}

int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)
{
    if (tm->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_print(bp, tm);
    if (tm->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_print(bp, tm);
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int ASN1_TIME_print_gmt(BIO *bp, const ASN1_TIME *tm)
{
    if (tm->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_print_gmt(bp, tm);
    if (tm->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_print_gmt(bp, tm);
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int ASN1_TIME_get(const ASN1_TIME *s, time_t *t, struct tm *tm)
{
    struct tm atm;
    if (tm == NULL)
        tm = &atm;
    memset(tm, 0, sizeof(atm));
    if (asn1_time_to_tm(tm, s) == 0)
        return 0;
    return OPENSSL_timegm(tm, t);
}
