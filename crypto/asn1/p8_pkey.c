/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

/* Minor tweak to operation: zero private key data */
static int pkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    /* Since the structure must still be valid use ASN1_OP_FREE_PRE */
    if (operation == ASN1_OP_FREE_PRE) {
        PKCS8_PRIV_KEY_INFO *key = (PKCS8_PRIV_KEY_INFO *)*pval;
        if (key->pkey)
            OPENSSL_cleanse(key->pkey->data, key->pkey->length);
    }

    if (operation == ASN1_OP_D2I_POST) {
        PKCS8_PRIV_KEY_INFO *key = (PKCS8_PRIV_KEY_INFO *)*pval;

        if (key->version == 0 && key->pubkey != NULL) {
            ERR_raise_data(ERR_LIB_ASN1, ERR_R_UNSUPPORTED,
                           "Version 1 PKCS#8 doesn't support public key");
            return 0;
        }
    }
    return 1;
}

ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb) = {
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkeyalg, X509_ALGOR),
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkey, ASN1_OCTET_STRING),
        ASN1_IMP_SET_OF_OPT(PKCS8_PRIV_KEY_INFO, attributes, X509_ATTRIBUTE, 0),
        ASN1_IMP_OPT(PKCS8_PRIV_KEY_INFO, pubkey, ASN1_BIT_STRING, 1)
} ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

int PKCS8_pkey_set0_ex(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
                       int version, int ptype, void *pval,
                       unsigned char *privenc, int privenclen,
                       unsigned char *pubenc, int pubenclen)
{
    /* Pubkey was addded in RFC 5958, so version should be at least 1 */
    if (pubenc != NULL && version <= 0)
        return 0;
    if (version >= 0) {
        if (!ASN1_INTEGER_set(priv->version, version))
            return 0;
    }
    if (!X509_ALGOR_set0(priv->pkeyalg, aobj, ptype, pval))
        return 0;
    if (privenc)
        ASN1_STRING_set0(priv->pkey, privenc, privenclen);
    if (pubenc)
        ASN1_STRING_set0(priv->pubkey, pubenc, pubenclen);
    return 1;
}

int PKCS8_pkey_get0_ex(const ASN1_OBJECT **ppkalg,
                       const unsigned char **pprivk, int *pprivklen,
                       const unsigned char **ppubk, int *ppubklen,
                       const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8)
{
    if (ppkalg)
        *ppkalg = p8->pkeyalg->algorithm;
    if (pprivk) {
        *pprivk = ASN1_STRING_get0_data(p8->pkey);
        *pprivklen = ASN1_STRING_length(p8->pkey);
    }
    if (ppubk) {
        /* ASN1_INTEGER_get() returns the value of a but it returns 0 if a is NULL and -1 on error */
        long version = ASN1_INTEGER_get(p8->version);

        if (version > 0) {
            *ppubk = ASN1_STRING_get0_data(p8->pubkey);
            *ppubklen = ASN1_STRING_length(p8->pubkey);
        } else {
            *ppubk = NULL;
            *ppubklen = 0;
        }
    }
    if (pa)
        *pa = p8->pkeyalg;
    return 1;
}

int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
                    int version,
                    int ptype, void *pval, unsigned char *penc, int penclen)
{
    return PKCS8_pkey_set0_ex(priv, aobj, version, ptype, pval,
                              penc, penclen, NULL, 0);
}

int PKCS8_pkey_get0(const ASN1_OBJECT **ppkalg,
                    const unsigned char **pk, int *ppklen,
                    const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8)
{
    return PKCS8_pkey_get0_ex(ppkalg, pk, ppklen, NULL, NULL, pa, p8);
}

const STACK_OF(X509_ATTRIBUTE) *
PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8)
{
    return p8->attributes;
}

int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO *p8, int nid, int type,
                                const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&p8->attributes, nid, type, bytes, len) != NULL)
        return 1;
    return 0;
}

int PKCS8_pkey_add1_attr_by_OBJ(PKCS8_PRIV_KEY_INFO *p8, const ASN1_OBJECT *obj, int type,
                                const unsigned char *bytes, int len)
{
    return (X509at_add1_attr_by_OBJ(&p8->attributes, obj, type, bytes, len) != NULL);
}

int PKCS8_pkey_add1_attr(PKCS8_PRIV_KEY_INFO *p8, X509_ATTRIBUTE *attr)
{
    return (X509at_add1_attr(&p8->attributes, attr) != NULL);
}
