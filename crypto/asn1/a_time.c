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

static int leap_year(const int year)
{
    if (year % 400 == 0 || (year % 100 != 0 && year % 4 == 0))
        return 1;
    return 0;
}

/*
 * Compute the day of the week and the day of the year from the year, month
 * and day.  The day of the year is straightforward, the day of the week uses
 * a form of Zeller's congruence.  For this months start with March and are
 * numbered 4 through 15.
 */
static void determine_days(struct tm *tm)
{
    static const int ydays[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int y = tm->tm_year + 1900;
    int m = tm->tm_mon;
    int d = tm->tm_mday;
    int c;

    tm->tm_yday = ydays[m] + d - 1;
    if (m >= 2) {
        /* March and onwards can be one day further into the year */
        tm->tm_yday += leap_year(y);
        m += 2;
    } else {
        /* Treat January and February as part of the previous year */
        m += 14;
        y--;
    }
    c = y / 100;
    y %= 100;
    /* Zeller's congruance */
    tm->tm_wday = (d + (13 * m) / 5 + y + y / 4 + c / 4 + 5 * c + 6) % 7;
}

int asn1_time_to_tm(struct tm *tm, const ASN1_TIME *d)
{
    static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
    static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    char *a;
    int n, i, i2, l, o, min_l = 11, strict = 0, end = 6, btz = 5, md;
    struct tm tmp;

    /*
     * ASN1_STRING_FLAG_X509_TIME is used to enforce RFC 5280
     * time string format, in which:
     *
     * 1. "seconds" is a 'MUST'
     * 2. "Zulu" timezone is a 'MUST'
     * 3. "+|-" is not allowed to indicate a time zone
     */
    if (d->type == V_ASN1_UTCTIME) {
        if (d->flags & ASN1_STRING_FLAG_X509_TIME) {
            min_l = 13;
            strict = 1;
        }
    } else if (d->type == V_ASN1_GENERALIZEDTIME) {
        end = 7;
        btz = 6;
        if (d->flags & ASN1_STRING_FLAG_X509_TIME) {
            min_l = 15;
            strict = 1;
        } else {
            min_l = 13;
        }
    } else {
        return 0;
    }

    l = d->length;
    a = (char *)d->data;
    o = 0;
    memset(&tmp, 0, sizeof(tmp));

    /*
     * GENERALIZEDTIME is similar to UTCTIME except the year is represented
     * as YYYY. This stuff treats everything as a two digit field so make
     * first two fields 00 to 99
     */

    if (l < min_l)
        goto err;
    for (i = 0; i < end; i++) {
        if (!strict && (i == btz) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        /* incomplete 2-digital number */
        if (++o == l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        /* no more bytes to read, but we haven't seen time-zone yet */
        if (++o == l)
            goto err;

        i2 = (d->type == V_ASN1_UTCTIME) ? i + 1 : i;

        if ((n < min[i2]) || (n > max[i2]))
            goto err;
        switch (i2) {
        case 0:
            /* UTC will never be here */
            tmp.tm_year = n * 100 - 1900;
            break;
        case 1:
            if (d->type == V_ASN1_UTCTIME)
                tmp.tm_year = n < 50 ? n + 100 : n;
            else
                tmp.tm_year += n;
            break;
        case 2:
            tmp.tm_mon = n - 1;
            break;
        case 3:
            /* check if tm_mday is valid in tm_mon */
            if (tmp.tm_mon == 1) {
                /* it's February */
                md = mdays[1] + leap_year(tmp.tm_year + 1900);
            } else {
                md = mdays[tmp.tm_mon];
            }
            if (n > md)
                goto err;
            tmp.tm_mday = n;
            determine_days(&tmp);
            break;
        case 4:
            tmp.tm_hour = n;
            break;
        case 5:
            tmp.tm_min = n;
            break;
        case 6:
            tmp.tm_sec = n;
            break;
        }
    }

    /*
     * Optional fractional seconds: decimal point followed by one or more
     * digits.
     */
    if (d->type == V_ASN1_GENERALIZEDTIME && a[o] == '.') {
        if (strict)
            /* RFC 5280 forbids fractional seconds */
            goto err;
        if (++o == l)
            goto err;
        i = o;
        while ((o < l) && (a[o] >= '0') && (a[o] <= '9'))
            o++;
        /* Must have at least one digit after decimal point */
        if (i == o)
            goto err;
        /* no more bytes to read, but we haven't seen time-zone yet */
        if (o == l)
            goto err;
    }

    /*
     * 'o' will never point to '\0' at this point, the only chance
     * 'o' can point to '\0' is either the subsequent if or the first
     * else if is true.
     */
    if (a[o] == 'Z') {
        o++;
    } else if (!strict && ((a[o] == '+') || (a[o] == '-'))) {
        int offsign = a[o] == '-' ? 1 : -1;
        int offset = 0;

        o++;
        /*
         * if not equal, no need to do subsequent checks
         * since the following for-loop will add 'o' by 4
         * and the final return statement will check if 'l'
         * and 'o' are equal.
         */
        if (o + 4 != l)
            goto err;
        for (i = end; i < end + 2; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            i2 = (d->type == V_ASN1_UTCTIME) ? i + 1 : i;
            if ((n < min[i2]) || (n > max[i2]))
                goto err;
            /* if tm is NULL, no need to adjust */
            if (tm != NULL) {
                if (i == end)
                    offset = n * 3600;
                else if (i == end + 1)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !OPENSSL_gmtime_adj(&tmp, 0, offset * offsign))
            goto err;
    } else {
        /* not Z, or not +/- in non-strict mode */
        goto err;
    }
    if (o == l) {
        /* success, check if tm should be filled */
        if (tm != NULL)
            *tm = tmp;
        return 1;
    }
 err:
    return 0;
}

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
    } else {
        ret = *out;
    }

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

    if (s != NULL && !ASN1_STRING_copy((ASN1_STRING *)s, (ASN1_STRING *)&t))
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
        if (!asn1_time_to_tm(&tm, &t))
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
        if (OPENSSL_gmtime(&now_t, tm) != NULL)
            return 1;
        return 0;
    }

    return asn1_time_to_tm(tm, s);
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
    return 0;
}
