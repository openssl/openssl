/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h" /* EVP_PKEY_assign() */

#include "internal/cryptlib.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/x509.h"
#include "crypto/slh_dsa.h"

/* Minimal ASN1 method table to support PUB_KEY decoding */
#define IMPLEMENT_PKEY_ASN1_METHOD(alg, name, PKEY_NAME)                       \
    const EVP_PKEY_ASN1_METHOD ossl_slh_dsa_##name##_asn1_meth =               \
    {                                                                          \
        EVP_PKEY_SLH_DSA_##PKEY_NAME, EVP_PKEY_SLH_DSA_##PKEY_NAME,            \
        0,                                                                     \
        alg,                                                                   \
        "OpenSSL " alg " algorithm",                                           \
        slh_dsa_pub_decode, NULL, NULL, NULL,                                  \
        NULL, NULL, NULL,                                                      \
        NULL, NULL, NULL,                                                      \
        NULL, NULL, NULL, NULL, NULL, NULL,                                    \
        NULL,                                                                  \
        slh_dsa_free,                                                          \
    }

static SLH_DSA_KEY *ossl_slh_dsa_key_create(const X509_ALGOR *palg,
                                            const unsigned char *p, int p_len,
                                            int id, int public,
                                            OSSL_LIB_CTX *libctx,
                                            const char *propq)
{
    int ret = 0;
    SLH_DSA_KEY *key = NULL;

    if (p == NULL)
        return 0;
    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF)
            return 0;
        if (id == EVP_PKEY_NONE)
            id = OBJ_obj2nid(palg->algorithm);
        else if (id != OBJ_obj2nid(palg->algorithm))
            return 0;
    }
    if (id == EVP_PKEY_NONE)
        return 0;

    key = ossl_slh_dsa_key_new(libctx, OBJ_nid2ln(id));
    if (key == NULL)
        return 0;
    if (public)
        ret = ossl_slh_dsa_set_pub(key, p, p_len);
    else
        ret = ossl_slh_dsa_set_priv(key, p, p_len);

    if (ret == 0) {
        ossl_slh_dsa_key_free(key);
        key = NULL;
    }
    return key;
}

static int slh_dsa_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;
    SLH_DSA_KEY *key;
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int ret = 0;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    ossl_x509_PUBKEY_get0_libctx(&libctx, &propq, pubkey);
    key = ossl_slh_dsa_key_create(palg, p, pklen, pkey->ameth->pkey_id, 1,
                                  libctx, propq);
    if (key != NULL) {
        ret = 1;
        EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, key);
    }
    return ret;
}

static void slh_dsa_free(EVP_PKEY *pkey)
{
    ossl_slh_dsa_key_free(pkey->pkey.slh_dsa);
}

IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-128s", sha2_128s, SHA2_128S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-128f", sha2_128f, SHA2_128F);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-192s", sha2_192s, SHA2_192S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-192f", sha2_192f, SHA2_192F);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-256s", sha2_256s, SHA2_256S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-256f", sha2_256f, SHA2_256F);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-128s", shake_128s, SHAKE_128S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-128f", shake_128f, SHAKE_128F);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-192s", shake_192s, SHAKE_192S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-192f", shake_192f, SHAKE_192F);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-256s", shake_256s, SHAKE_256S);
IMPLEMENT_PKEY_ASN1_METHOD("SLH-DSA-SHA2-256f", shake_256f, SHAKE_256F);
