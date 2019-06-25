/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509v3.h>
#include "ext_dat.h"

const X509V3_EXT_METHOD v3_crl_num = {
    NID_crl_number, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    0,
    0, 0, 0, 0, NULL
};

const X509V3_EXT_METHOD v3_delta_crl = {
    NID_delta_crl, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    0,
    0, 0, 0, 0, NULL
};

static void *s2i_asn1_int(X509V3_EXT_METHOD *meth, X509V3_CTX *ctx,
                          const char *value)
{
    return s2i_ASN1_INTEGER(meth, value);
}

const X509V3_EXT_METHOD v3_inhibit_anyp = {
    NID_inhibit_any_policy, 0, ASN1_ITEM_ref(ASN1_INTEGER),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_INTEGER,
    (X509V3_EXT_S2I)s2i_asn1_int,
    0, 0, 0, 0, NULL
};

char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5)
{
    char *tmp;

    if (ia5 == NULL || ia5->length == 0)
        return NULL;
    if ((tmp = OPENSSL_malloc(ia5->length + 1)) == NULL) {
        X509V3err(X509V3_F_I2S_ASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memcpy(tmp, ia5->data, ia5->length);
    tmp[ia5->length] = 0;
    return tmp;
}

ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                   X509V3_CTX *ctx, const char *str)
{
    ASN1_IA5STRING *ia5;

    if (str == NULL) {
        X509V3err(X509V3_F_S2I_ASN1_IA5STRING,
                  X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if ((ia5 = ASN1_IA5STRING_new()) == NULL) {
        X509V3err(X509V3_F_S2I_ASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!ASN1_STRING_set((ASN1_STRING *)ia5, str, strlen(str))) {
        ASN1_IA5STRING_free(ia5);
        return NULL;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(ia5->data, ia5->data, ia5->length);
#endif                          /* CHARSET_EBCDIC */
    return ia5;
}
