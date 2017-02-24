/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_locl.h"

/* This is the primary function used to parse ASN1_UTCTIME */
int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)
{
    static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_UTCTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;

    if (l < 11)
        goto err;
    for (i = 0; i < 6; i++) {
        if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if (!isdigit(a[o]))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if (!isdigit(a[o]))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n < 50 ? n + 100 : n;
                break;
            case 1:
                tm->tm_mon = n - 1;
                break;
            case 2:
                tm->tm_mday = n;
                break;
            case 3:
                tm->tm_hour = n;
                break;
            case 4:
                tm->tm_min = n;
                break;
            case 5:
                tm->tm_sec = n;
                break;
            }
        }
    }
    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? 1 : -1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 6; i < 8; i++) {
            if (!isdigit(a[o]))
                goto err;
            n = a[o] - '0';
            o++;
            if (!isdigit(a[o]))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 6)
                    offset = n * 3600;
                else if (i == 7)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
            return 0;
    }
    return o == l;
 err:
    return 0;
}

/* Inverse of asn1_utctime_to_tm ()*/
ASN1_UTCTIME *asn1_utctime_from_tm(ASN1_UTCTIME *s, struct tm *ts)
{
    char *p;
    ASN1_UTCTIME *tmps = NULL;
    size_t len = 20;

    if ((ts->tm_year < 50) || (ts->tm_year >= 150))
        return NULL;

    if (s == NULL)
        tmps = ASN1_UTCTIME_new();
    else
        tmps = s;
    if (tmps == NULL)
        return NULL;

    if (!ASN1_STRING_set(tmps, NULL, len))
        goto err;

    p = (char*) tmps->data;
    BIO_snprintf(p, len, "%02d%02d%02d%02d%02d%02dZ", ts->tm_year % 100,
                 ts->tm_mon + 1, ts->tm_mday, ts->tm_hour, ts->tm_min,
                 ts->tm_sec);
    tmps->length = strlen(p);
    tmps->type = V_ASN1_UTCTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(tmps->data, tmps->data, tmps->length);
#endif
    return tmps;
 err:
    if (tmps != s)
        ASN1_STRING_free(tmps);
    return NULL;
}

int ASN1_UTCTIME_check(const ASN1_UTCTIME *d)
{
    return asn1_utctime_to_tm(NULL, d);
}

/* Sets the string via simple copy without cleaning it up */
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
    ASN1_UTCTIME t;

    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;
    t.type = V_ASN1_UTCTIME;

    if (!ASN1_UTCTIME_check(&t))
        return 0;

    if (s != NULL && !ASN1_STRING_copy(s, &t))
        return 0;

    return 1;
}

/* Sets the string as a clean UTCTIME */
int ASN1_UTCTIME_set_string_gmt(ASN1_UTCTIME *s, const char *str)
{
    ASN1_UTCTIME t;
    ASN1_UTCTIME *ret;
    struct tm tm;

    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;
    t.type = V_ASN1_UTCTIME;

    if (!asn1_utctime_to_tm(&tm, &t))
        return 0;

    if ((ret = asn1_utctime_from_tm(s, &tm)) == NULL)
        return 0;

    if (ret != s)
        ASN1_STRING_free(ret);

    return 1;
}

ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)
{
    return ASN1_UTCTIME_adj(s, t, 0, 0);
}

int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t)
{
    struct tm stm, ttm;
    int day, sec;

    if (!asn1_utctime_to_tm(&stm, s))
        return -2;

    if (!OPENSSL_gmtime(&t, &ttm))
        return -2;

    if (!OPENSSL_gmtime_diff(&day, &sec, &ttm, &stm))
        return -2;

    if (day > 0)
        return 1;
    if (day < 0)
        return -1;
    if (sec > 0)
        return 1;
    if (sec < 0)
        return -1;
    return 0;
}

/* Will not switch types */
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec)
{
    struct tm *ts;
    struct tm data;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        return NULL;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }

    return asn1_utctime_from_tm(s, ts);
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm)
{
    const char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

    i = tm->length;
    v = (const char *)tm->data;

    if (i < 10)
        goto err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 10; i++)
        if (!isdigit(v[i]))
            goto err;
    y = (v[0] - '0') * 10 + (v[1] - '0');
    if (y < 50)
        y += 100;
    M = (v[2] - '0') * 10 + (v[3] - '0');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[4] - '0') * 10 + (v[5] - '0');
    h = (v[6] - '0') * 10 + (v[7] - '0');
    m = (v[8] - '0') * 10 + (v[9] - '0');
    if (tm->length >= 12 && isdigit(v[10]) && isdigit(v[11]))
        s = (v[10] - '0') * 10 + (v[11] - '0');

    if (BIO_printf(bp, "%s %2d %02d:%02d:%02d %d%s",
                   _asn1_mon[M - 1], d, h, m, s, y + 1900,
                   (gmt) ? " GMT" : "") <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int ASN1_UTCTIME_print_gmt(BIO *bp, const ASN1_UTCTIME *t)
{
    struct tm tm;

    if (!asn1_utctime_to_tm(&tm, t))
        goto err;

    if (BIO_printf(bp, "%s %2d %02d:%02d:%02d %d GMT",
                   _asn1_mon[tm.tm_mon], tm.tm_mday, tm.tm_hour, tm.tm_min,
                   tm.tm_sec, tm.tm_year + 1900) <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int ASN1_UTCTIME_get(const ASN1_UTCTIME *s, time_t *t, struct tm *tm)
{
    if (s->type == V_ASN1_UTCTIME)
        return ASN1_TIME_get(s, t, tm);
    return 0;
}

int ASN1_UTCTIME_diff(int *pday, int *psec,
                      const ASN1_UTCTIME *from,
                      const ASN1_UTCTIME *to)
{
    if (from->type == V_ASN1_UTCTIME &&
        to->type == V_ASN1_UTCTIME)
        return ASN1_TIME_diff(pday, psec, from, to);
    return 0;
}
