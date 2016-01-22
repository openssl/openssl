/* asn_pack.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>

/* ASN1 packing and unpacking functions */

ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_STRING **oct)
{
    ASN1_STRING *octmp;

     if (oct == NULL|| *oct== NULL) {
        if ((octmp = ASN1_STRING_new()) == NULL) {
            ASN1err(ASN1_F_ASN1_ITEM_PACK, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        if (oct)
            *oct = octmp;
    } else
        octmp = *oct;

    OPENSSL_free(octmp->data);
    octmp->data = NULL;

    if ((octmp->length = ASN1_item_i2d(obj, &octmp->data, it)) == 0) {
        ASN1err(ASN1_F_ASN1_ITEM_PACK, ASN1_R_ENCODE_ERROR);
        return NULL;
    }
    if (!octmp->data) {
        ASN1err(ASN1_F_ASN1_ITEM_PACK, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return octmp;
}

/* Extract an ASN1 object from an ASN1_STRING */

void *ASN1_item_unpack(ASN1_STRING *oct, const ASN1_ITEM *it)
{
    const unsigned char *p;
    void *ret;

    p = oct->data;
    if ((ret = ASN1_item_d2i(NULL, &p, oct->length, it)) == NULL)
        ASN1err(ASN1_F_ASN1_ITEM_UNPACK, ASN1_R_DECODE_ERROR);
    return ret;
}
