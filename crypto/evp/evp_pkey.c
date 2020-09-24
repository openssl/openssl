/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/rand.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/x509.h"

/* Extract a private key from a PKCS8 structure */

EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8, OPENSSL_CTX *libctx,
                            const char *propq)
{
    EVP_PKEY *pkey = NULL;
    const ASN1_OBJECT *algoid;
    char obj_tmp[80];

    if (!PKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
        return NULL;

    if ((pkey = EVP_PKEY_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
        EVPerr(0, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
        ERR_add_error_data(2, "TYPE=", obj_tmp);
        goto error;
    }

    if (pkey->ameth->priv_decode_ex != NULL) {
        if (!pkey->ameth->priv_decode_ex(pkey, p8, libctx, propq))
            goto error;
    } else if (pkey->ameth->priv_decode != NULL) {
        if (!pkey->ameth->priv_decode(pkey, p8)) {
            EVPerr(0, EVP_R_PRIVATE_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        EVPerr(0, EVP_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    return pkey;

 error:
    EVP_PKEY_free(pkey);
    return NULL;
}

EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8)
{
    return EVP_PKCS82PKEY_ex(p8, NULL, NULL);
}

/* Turn a private key into a PKCS8 structure */

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(const EVP_PKEY *pkey)
{
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
    if (p8  == NULL) {
        EVPerr(EVP_F_EVP_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Force a key downgrade if that's possible */
    /* TODO(3.0) Is there a better way for provider-native keys? */
    if (EVP_PKEY_get0(pkey) == NULL)
        return NULL;

    if (pkey->ameth) {
        if (pkey->ameth->priv_encode) {
            if (!pkey->ameth->priv_encode(p8, pkey)) {
                EVPerr(EVP_F_EVP_PKEY2PKCS8, EVP_R_PRIVATE_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            EVPerr(EVP_F_EVP_PKEY2PKCS8, EVP_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        EVPerr(EVP_F_EVP_PKEY2PKCS8, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        goto error;
    }
    return p8;
 error:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
}

/* EVP_PKEY attribute functions */

int EVP_PKEY_get_attr_count(const EVP_PKEY *key)
{
    return X509at_get_attr_count(key->attributes);
}

int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(key->attributes, nid, lastpos);
}

int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, const ASN1_OBJECT *obj,
                             int lastpos)
{
    return X509at_get_attr_by_OBJ(key->attributes, obj, lastpos);
}

X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc)
{
    return X509at_get_attr(key->attributes, loc);
}

X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc)
{
    return X509at_delete_attr(key->attributes, loc);
}

int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&key->attributes, attr))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
                              const ASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_OBJ(&key->attributes, obj, type, bytes, len))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&key->attributes, nid, type, bytes, len))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_txt(&key->attributes, attrname, type, bytes, len))
        return 1;
    return 0;
}

const char *EVP_PKEY_get0_first_alg_name(const EVP_PKEY *key)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    const char *name = NULL;

    if (key->keymgmt != NULL)
        return EVP_KEYMGMT_get0_first_name(key->keymgmt);

    /* Otherwise fallback to legacy */
    ameth = EVP_PKEY_get0_asn1(key);
    if (ameth != NULL)
        EVP_PKEY_asn1_get0_info(NULL, NULL,
                                NULL, NULL, &name, ameth);

    return name;
}
