/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/decoder.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/asn1.h"

EVP_PKEY *d2i_PrivateKey_ex(int keytype, EVP_PKEY **a, const unsigned char **pp,
                            long length, OSSL_LIB_CTX *libctx,
                            const char *propq)
{
    OSSL_DECODER_CTX *dctx = NULL;
    size_t len = length;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY **ppkey = &pkey;
    const char *key_name = NULL;
    const char *input_structures[] = { "type-specific", "pkcs8", NULL };
    int i, ret;

    if (keytype != EVP_PKEY_NONE) {
        key_name = evp_pkey_type2name(keytype);
        if (key_name == NULL)
            return NULL;
    }
    if (a != NULL && *a != NULL)
        ppkey = a;

    for (i = 0;  i < (int)OSSL_NELEM(input_structures); ++i) {
        dctx = OSSL_DECODER_CTX_new_for_pkey(ppkey, "DER",
                                             input_structures[i], key_name,
                                             EVP_PKEY_KEYPAIR, libctx, propq);
        if (dctx == NULL)
            return NULL;

        ret = OSSL_DECODER_from_data(dctx, pp, &len);
        OSSL_DECODER_CTX_free(dctx);
        if (ret) {
            if (*ppkey != NULL
                && evp_keymgmt_util_has(*ppkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
                return *ppkey;
            goto err;
        }
    }
    /* Fall through to error if all decodes failed */
err:
    if (ppkey != a)
        EVP_PKEY_free(*ppkey);
    return NULL;
}

EVP_PKEY *evp_privatekey_from_binary(int keytype, EVP_PKEY **a,
                                     const unsigned char **pp, long length,
                                     OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY *ret;
    const unsigned char *p = *pp;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ERR_raise(ERR_LIB_ASN1, ERR_R_EVP_LIB);
            return NULL;
        }
    } else {
        ret = *a;
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(ret->engine);
        ret->engine = NULL;
#endif
    }

    if (!EVP_PKEY_set_type(ret, keytype)) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
    }

    ERR_set_mark();
    if (!ret->ameth->old_priv_decode ||
        !ret->ameth->old_priv_decode(ret, &p, length)) {
        if (ret->ameth->priv_decode != NULL
                || ret->ameth->priv_decode_ex != NULL) {
            EVP_PKEY *tmp;
            PKCS8_PRIV_KEY_INFO *p8 = NULL;
            p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, length);
            if (p8 == NULL) {
                ERR_clear_last_mark();
                goto err;
            }
            tmp = EVP_PKCS82PKEY_ex(p8, libctx, propq);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (tmp == NULL) {
                ERR_clear_last_mark();
                goto err;
            }
            EVP_PKEY_free(ret);
            ret = tmp;
            ERR_pop_to_mark();
            if (EVP_PKEY_type(keytype) != EVP_PKEY_base_id(ret))
                goto err;
        } else {
            ERR_clear_last_mark();
            ERR_raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB);
            goto err;
        }
    } else {
      ERR_clear_last_mark();
    }
    *pp = p;
    if (a != NULL)
        (*a) = ret;
    return ret;
 err:
    if (a == NULL || *a != ret)
        EVP_PKEY_free(ret);
    return NULL;
}

EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
                         long length)
{
    return d2i_PrivateKey_ex(type, a, pp, length, NULL, NULL);
}

/*
 * This works like d2i_PrivateKey() except it passes the keytype as
 * EVP_PKEY_NONE, which then figures out the type during decoding.
 */
EVP_PKEY *d2i_AutoPrivateKey_ex(EVP_PKEY **a, const unsigned char **pp,
                                long length, OSSL_LIB_CTX *libctx,
                                const char *propq)
{
    return d2i_PrivateKey_ex(EVP_PKEY_NONE, a, pp, length, libctx, propq);
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
                             long length)
{
    return d2i_AutoPrivateKey_ex(a, pp, length, NULL, NULL);
}
