/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>

/* Cheap and nasty Unicode stuff */

unsigned char *OPENSSL_asc2uni(const char *asc, int asclen,
                               unsigned char **uni, int *unilen)
{
    int ulen, i;
    unsigned char *unitmp;

    if (asclen == -1)
        asclen = strlen(asc);
    ulen = asclen * 2 + 2;
    if ((unitmp = OPENSSL_malloc(ulen)) == NULL)
        return NULL;
    for (i = 0; i < ulen - 2; i += 2) {
        unitmp[i] = 0;
        unitmp[i + 1] = asc[i >> 1];
    }
    /* Make result double null terminated */
    unitmp[ulen - 2] = 0;
    unitmp[ulen - 1] = 0;
    if (unilen)
        *unilen = ulen;
    if (uni)
        *uni = unitmp;
    return unitmp;
}

char *OPENSSL_uni2asc(unsigned char *uni, int unilen)
{
    int asclen, i;
    char *asctmp;
    /* string must contain an even number of bytes */
    if (unilen & 1)
        return NULL;
    asclen = unilen / 2;
    /* If no terminating zero allow for one */
    if (!unilen || uni[unilen - 1])
        asclen++;
    uni++;
    if ((asctmp = OPENSSL_malloc(asclen)) == NULL)
        return NULL;
    for (i = 0; i < unilen; i += 2)
        asctmp[i >> 1] = uni[i];
    asctmp[asclen - 1] = 0;
    return asctmp;
}

int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

#ifndef OPENSSL_NO_STDIO
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

#ifndef OPENSSL_NO_STDIO
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif
