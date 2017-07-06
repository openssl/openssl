/*
 * Copyright 1999-2017 The OpenSSL Project Authors. All Rights Reserved.
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
        return ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
    return ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec);
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
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
                                                   ASN1_GENERALIZEDTIME **out)
{
    ASN1_GENERALIZEDTIME *ret = NULL;
    char *str;

    if (!ASN1_TIME_check(t))
        return NULL;

    if (out == NULL || *out == NULL) {
        if ((ret = ASN1_GENERALIZEDTIME_new()) == NULL)
            goto err;
    } else
        ret = *out;

    /* If already GeneralizedTime just copy across */
    if (t->type == V_ASN1_GENERALIZEDTIME) {
        if (!ASN1_STRING_set(ret, t->data, t->length))
            goto err;
        goto done;
    }

    /*
     * Grow the string by two bytes.
     * The actual allocation is t->length + 3 to include a terminator byte.
     */
    if (!ASN1_STRING_set(ret, NULL, t->length + 2))
        goto err;
    str = (char *)ret->data;
    /* Work out the century and prepend */
    memcpy(str, t->data[0] >= '5' ? "19" : "20", 2);
    /*
     * t->length + 1 is the size of the data and the allocated buffer has
     * this much space after the first two characters.
     */
    OPENSSL_strlcpy(str + 2, (const char *)t->data, t->length + 1);

 done:
   if (out != NULL && *out == NULL)
       *out = ret;
   return ret;

 err:
    if (out == NULL || *out != ret)
        ASN1_GENERALIZEDTIME_free(ret);
    return NULL;
}

int ASN1_TIME_set_string(ASN1_TIME *s, const char *str)
{
    ASN1_TIME t;

    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    t.type = V_ASN1_UTCTIME;

    if (!ASN1_TIME_check(&t)) {
        t.type = V_ASN1_GENERALIZEDTIME;
        if (!ASN1_TIME_check(&t))
            return 0;
    }

    if (s && !ASN1_STRING_copy((ASN1_STRING *)s, (ASN1_STRING *)&t))
        return 0;

    return 1;
}

int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str)
{
    ASN1_TIME t;
    struct tm tm;
    int rv = 0;

    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = ASN1_STRING_FLAG_X509_TIME;

    t.type = V_ASN1_UTCTIME;

    if (!ASN1_TIME_check(&t)) {
        t.type = V_ASN1_GENERALIZEDTIME;
        if (!ASN1_TIME_check(&t))
            goto out;
    }

    /*
     * Per RFC 5280 (section 4.1.2.5.), the valid input time
     * strings should be encoded with the following rules:
     *
     * 1. UTC: YYMMDDHHMMSSZ, if YY < 50 (20YY) --> UTC: YYMMDDHHMMSSZ
     * 2. UTC: YYMMDDHHMMSSZ, if YY >= 50 (19YY) --> UTC: YYMMDDHHMMSSZ
     * 3. G'd: YYYYMMDDHHMMSSZ, if YYYY >= 2050 --> G'd: YYYYMMDDHHMMSSZ
     * 4. G'd: YYYYMMDDHHMMSSZ, if YYYY < 2050 --> UTC: YYMMDDHHMMSSZ
     *
     * Only strings of the 4th rule should be reformatted, but since a
     * UTC can only present [1950, 2050), so if the given time string
     * is less than 1950 (e.g. 19230419000000Z), we do nothing...
     */

    if (s != NULL && t.type == V_ASN1_GENERALIZEDTIME) {
        if (!asn1_generalizedtime_to_tm(&tm, &t))
            goto out;
        if (tm.tm_year >= 50 && tm.tm_year < 150) {
            t.length -= 2;
            /*
             * it's OK to let original t.data go since that's assigned
             * to a piece of memory allocated outside of this function.
             * new t.data would be freed after ASN1_STRING_copy is done.
             */
            t.data = OPENSSL_zalloc(t.length + 1);
            if (t.data == NULL)
                goto out;
            memcpy(t.data, str + 2, t.length);
            t.type = V_ASN1_UTCTIME;
        }
    }

    if (s == NULL || ASN1_STRING_copy((ASN1_STRING *)s, (ASN1_STRING *)&t))
        rv = 1;

    if (t.data != (unsigned char *)str)
        OPENSSL_free(t.data);
out:
    return rv;
}

int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm)
{
    if (s == NULL) {
        time_t now_t;

        time(&now_t);
        memset(tm, 0, sizeof(*tm));
        if (OPENSSL_gmtime(&now_t, tm))
            return 1;
        return 0;
    }

    if (s->type == V_ASN1_UTCTIME) {
        memset(tm, 0, sizeof(*tm));
        return asn1_utctime_to_tm(tm, s);
    }
    if (s->type == V_ASN1_GENERALIZEDTIME) {
        memset(tm, 0, sizeof(*tm));
        return asn1_generalizedtime_to_tm(tm, s);
    }

    return 0;
}

int ASN1_TIME_diff(int *pday, int *psec,
                   const ASN1_TIME *from, const ASN1_TIME *to)
{
    struct tm tm_from, tm_to;

    if (!ASN1_TIME_to_tm(from, &tm_from))
        return 0;
    if (!ASN1_TIME_to_tm(to, &tm_to))
        return 0;
    return OPENSSL_gmtime_diff(pday, psec, &tm_from, &tm_to);
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
