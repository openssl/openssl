/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/asn1t.h"
#include "internal/numbers.h"
#include <openssl/bn.h>
#include "asn1_locl.h"

/*
 * Custom primitive types for handling int32_t, int64_t, uint32_t, uint64_t.
 * This converts between an ASN1_INTEGER and those types directly.
 * This is preferred to using the LONG / ZLONG primitives.
 */

/*
 * We abuse the ASN1_ITEM fields |size| as a flags field
 */
#define INTxx_FLAG_ZERO_DEFAULT (1<<0)
#define INTxx_FLAG_SIGNED       (1<<1)

static int uint64_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(uint64_t *)pval = 0;
    return 1;
}

static void uint64_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(uint64_t *)pval = 0;
}

static int uint64_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                    const ASN1_ITEM *it)
{
    uint64_t utmp;
    int neg = 0;
    /* this exists to bypass broken gcc optimization */
    char *cp = (char *)pval;

    /* use memcpy, because we may not be uint64_t aligned */
    memcpy(&utmp, cp, sizeof(utmp));

    if ((it->size & INTxx_FLAG_ZERO_DEFAULT) == INTxx_FLAG_ZERO_DEFAULT
        && utmp == 0)
        return -1;
    if ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED
        && (int64_t)utmp < 0)
        neg = 1;

    return i2c_uint64_int(cont, utmp, neg);
}

static int uint64_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                    int utype, char *free_cont, const ASN1_ITEM *it)
{
    uint64_t utmp = 0;
    char *cp = (char *)pval;
    int neg = 0;

    if (!c2i_uint64_int(&utmp, &neg, &cont, len))
        return 0;
    if ((it->size & INTxx_FLAG_SIGNED) == 0 && neg) {
        ASN1err(ASN1_F_UINT64_C2I, ASN1_R_ILLEGAL_NEGATIVE_VALUE);
        return 0;
    }
    memcpy(cp, &utmp, sizeof(utmp));
    return 1;
}

static int uint64_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                        int indent, const ASN1_PCTX *pctx)
{
    if ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED)
        return BIO_printf(out, "%"BIO_PRI64"d\n", *(int64_t *)pval);
    return BIO_printf(out, "%"BIO_PRI64"u\n", *(uint64_t *)pval);
}

/* 32-bit variants */

static int uint32_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(uint32_t *)pval = 0;
    return 1;
}

static void uint32_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(uint32_t *)pval = 0;
}

static int uint32_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                    const ASN1_ITEM *it)
{
    uint32_t utmp;
    int neg = 0;
    /* this exists to bypass broken gcc optimization */
    char *cp = (char *)pval;

    /* use memcpy, because we may not be uint32_t aligned */
    memcpy(&utmp, cp, sizeof(utmp));

    if ((it->size & INTxx_FLAG_ZERO_DEFAULT) == INTxx_FLAG_ZERO_DEFAULT
        && utmp == 0)
        return -1;
    if ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED
        && (int32_t)utmp < 0)
        neg = 1;

    return i2c_uint64_int(cont, (uint64_t)utmp, neg);
}

static int uint32_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                    int utype, char *free_cont, const ASN1_ITEM *it)
{
    uint64_t utmp = 0;
    uint32_t utmp2 = 0;
    char *cp = (char *)pval;
    int neg = 0;

    if (!c2i_uint64_int(&utmp, &neg, &cont, len))
        return 0;
    if ((it->size & INTxx_FLAG_SIGNED) == 0 && neg) {
        ASN1err(ASN1_F_UINT32_C2I, ASN1_R_ILLEGAL_NEGATIVE_VALUE);
        return 0;
    }
    utmp2 = (uint32_t)utmp;
    if (utmp != utmp2
        || ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED
            && !neg && utmp2 > INT32_MAX)) {
        ASN1err(ASN1_F_UINT32_C2I, ASN1_R_TOO_LARGE);
        return 0;
    }
    memcpy(cp, &utmp2, sizeof(utmp2));
    return 1;
}

static int uint32_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                        int indent, const ASN1_PCTX *pctx)
{
    if ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED)
        return BIO_printf(out, "%d\n", *(int32_t *)pval);
    return BIO_printf(out, "%u\n", *(uint32_t *)pval);
}


/* Define the primitives themselves */

static ASN1_PRIMITIVE_FUNCS uint32_pf = {
    NULL, 0,
    uint32_new,
    uint32_free,
    uint32_free,                  /* Clear should set to initial value */
    uint32_c2i,
    uint32_i2c,
    uint32_print
};

static ASN1_PRIMITIVE_FUNCS uint64_pf = {
    NULL, 0,
    uint64_new,
    uint64_free,
    uint64_free,                  /* Clear should set to initial value */
    uint64_c2i,
    uint64_i2c,
    uint64_print
};

ASN1_ITEM_start(INT32)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint32_pf,
    INTxx_FLAG_SIGNED, "INT32"
ASN1_ITEM_end(INT32)

ASN1_ITEM_start(UINT32)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint32_pf, 0, "UINT32"
ASN1_ITEM_end(UINT32)

ASN1_ITEM_start(INT64)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint64_pf,
    INTxx_FLAG_SIGNED, "INT64"
ASN1_ITEM_end(INT64)

ASN1_ITEM_start(UINT64)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint64_pf, 0, "UINT64"
ASN1_ITEM_end(UINT64)

ASN1_ITEM_start(ZINT32)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint32_pf,
    INTxx_FLAG_ZERO_DEFAULT|INTxx_FLAG_SIGNED, "ZINT32"
ASN1_ITEM_end(ZINT32)

ASN1_ITEM_start(ZUINT32)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint32_pf,
    INTxx_FLAG_ZERO_DEFAULT, "ZUINT32"
ASN1_ITEM_end(ZUINT32)

ASN1_ITEM_start(ZINT64)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint64_pf,
    INTxx_FLAG_ZERO_DEFAULT|INTxx_FLAG_SIGNED, "ZINT64"
ASN1_ITEM_end(ZINT64)

ASN1_ITEM_start(ZUINT64)
    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint64_pf,
    INTxx_FLAG_ZERO_DEFAULT, "ZUINT64"
ASN1_ITEM_end(ZUINT64)

