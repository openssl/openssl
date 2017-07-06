/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_locl.h"

int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)
{
    static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o, min_l = 11, strict = 0;

    if (d->type != V_ASN1_UTCTIME)
        return 0;
    l = d->length;
    a = (char *)d->data;
    o = 0;

    /*
     * ASN1_STRING_FLAG_X509_TIME is used to enforce RFC 5280
     * time string format, in which:
     *
     * 1. "seconds" is a 'MUST'
     * 2. "Zulu" timezone is a 'MUST'
     * 3. "+|-" is not allowed to indicate a time zone
     */

    if (d->flags & ASN1_STRING_FLAG_X509_TIME) {
        min_l = 13;
        strict = 1;
    }

    if (l < min_l)
        goto err;
    for (i = 0; i < 6; i++) {
        if (!strict && (i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
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

    /*
     * 'o' will never point to '\0' at this point, the only chance
     * 'o' can point th '\0' is either the subsequent if or the first
     * else if is true.
     */
    if (a[o] == 'Z') {
        o++;
    } else if (!strict && ((a[o] == '+') || (a[o] == '-'))) {
        int offsign = a[o] == '-' ? 1 : -1, offset = 0;
        o++;
        if (o + 4 != l)
            goto err;
        for (i = 6; i < 8; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
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
    } else {
        /* not Z, or not +/- in non-strict mode */
        return 0;
    }
    return o == l;
 err:
    return 0;
}

int ASN1_UTCTIME_check(const ASN1_UTCTIME *d)
{
    return asn1_utctime_to_tm(NULL, d);
}

int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
    ASN1_UTCTIME t;

    t.type = V_ASN1_UTCTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    if (ASN1_UTCTIME_check(&t)) {
        if (s != NULL) {
            if (!ASN1_STRING_set((ASN1_STRING *)s, str, t.length))
                return 0;
            s->type = V_ASN1_UTCTIME;
        }
        return 1;
    }
    return 0;
}

ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)
{
    return ASN1_UTCTIME_adj(s, t, 0, 0);
}

ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec)
{
    char *p;
    struct tm *ts;
    struct tm data;
    const size_t len = 20;
    int free_s = 0;

    if (s == NULL) {
        s = ASN1_UTCTIME_new();
        if (s == NULL)
            goto err;
        free_s = 1;
    }

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        goto err;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            goto err;
    }

    if ((ts->tm_year < 50) || (ts->tm_year >= 150))
        goto err;

    p = (char *)s->data;
    if ((p == NULL) || ((size_t)s->length < len)) {
        p = OPENSSL_malloc(len);
        if (p == NULL) {
            ASN1err(ASN1_F_ASN1_UTCTIME_ADJ, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        OPENSSL_free(s->data);
        s->data = (unsigned char *)p;
    }

    s->length = BIO_snprintf(p, len, "%02d%02d%02d%02d%02d%02dZ",
                             ts->tm_year % 100, ts->tm_mon + 1, ts->tm_mday,
                             ts->tm_hour, ts->tm_min, ts->tm_sec);
    s->type = V_ASN1_UTCTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(s->data, s->data, s->length);
#endif
    return s;
 err:
    if (free_s)
        ASN1_UTCTIME_free(s);
    return NULL;
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
        if ((v[i] > '9') || (v[i] < '0'))
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
    if (tm->length >= 12 &&
        (v[10] >= '0') && (v[10] <= '9') && (v[11] >= '0') && (v[11] <= '9'))
        s = (v[10] - '0') * 10 + (v[11] - '0');

    if (BIO_printf(bp, "%s %2d %02d:%02d:%02d %d%s",
                   _asn1_mon[M - 1], d, h, m, s, y + 1900,
                   (gmt) ? " GMT" : "") <= 0)
        return 0;
    return 1;
 err:
    BIO_write(bp, "Bad time value", 14);
    return 0;
}
