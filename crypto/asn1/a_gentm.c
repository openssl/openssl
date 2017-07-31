/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * GENERALIZEDTIME implementation. Based on UTCTIME
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_locl.h"

int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
{
    /* wrapper around asn1_time_to_tm */
    if (d->type != V_ASN1_GENERALIZEDTIME)
        return 0;
    return asn1_time_to_tm(tm, d);
}

int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *d)
{
    return asn1_generalizedtime_to_tm(NULL, d);
}

int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str)
{
    ASN1_GENERALIZEDTIME t;

    t.type = V_ASN1_GENERALIZEDTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    if (ASN1_GENERALIZEDTIME_check(&t)) {
        if (s != NULL) {
            if (!ASN1_STRING_set((ASN1_STRING *)s, str, t.length))
                return 0;
            s->type = V_ASN1_GENERALIZEDTIME;
        }
        return 1;
    }
    return 0;
}

ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
                                               time_t t)
{
    return ASN1_GENERALIZEDTIME_adj(s, t, 0, 0);
}

ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec)
{
    char *p;
    struct tm *ts;
    struct tm data;
    const size_t len = 20;
    ASN1_GENERALIZEDTIME *tmps = NULL;

    if (s == NULL)
        tmps = ASN1_GENERALIZEDTIME_new();
    else
        tmps = s;
    if (tmps == NULL)
        return NULL;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        goto err;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            goto err;
    }

    p = (char *)tmps->data;
    if ((p == NULL) || ((size_t)tmps->length < len)) {
        p = OPENSSL_malloc(len);
        if (p == NULL) {
            ASN1err(ASN1_F_ASN1_GENERALIZEDTIME_ADJ, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        OPENSSL_free(tmps->data);
        tmps->data = (unsigned char *)p;
    }

    tmps->length = BIO_snprintf(p, len, "%04d%02d%02d%02d%02d%02dZ",
                                ts->tm_year + 1900, ts->tm_mon + 1,
                                ts->tm_mday, ts->tm_hour, ts->tm_min,
                                ts->tm_sec);
    tmps->type = V_ASN1_GENERALIZEDTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(tmps->data, tmps->data, tmps->length);
#endif
    return tmps;
 err:
    if (s == NULL)
        ASN1_GENERALIZEDTIME_free(tmps);
    return NULL;
}

int ASN1_GENERALIZEDTIME_print(BIO *bp, const ASN1_GENERALIZEDTIME *tm)
{
    if (tm->type != V_ASN1_GENERALIZEDTIME)
        return 0;
    return ASN1_TIME_print(bp, tm);
}
