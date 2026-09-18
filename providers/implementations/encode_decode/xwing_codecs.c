/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "crypto/x509.h"
#include "prov/provider_ctx.h"
#include "prov/xwing_codecs.h"

static int xwing_algor_ok(const X509_ALGOR *alg)
{
    const ASN1_OBJECT *obj = NULL;
    const void *pval = NULL;
    int ptype = V_ASN1_UNDEF;

    if (alg == NULL)
        return 0;
    X509_ALGOR_get0(&obj, &ptype, &pval, alg);
    return OBJ_obj2nid(obj) == NID_X_Wing && ptype == V_ASN1_UNDEF;
}

MLX_KEY *ossl_xwing_d2i_PUBKEY(const unsigned char *der, long derlen,
    PROV_CTX *provctx, const char *propq)
{
    const unsigned char *p = der, *pub = NULL;
    X509_PUBKEY *spki = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *obj = NULL;
    MLX_KEY *key = NULL;
    int publen = 0;

    if (der == NULL || derlen <= 0
        || (spki = ossl_d2i_X509_PUBKEY_INTERNAL(&p, derlen,
                PROV_LIBCTX_OF(provctx), propq)) == NULL
        || p != der + derlen
        || !X509_PUBKEY_get0_param(&obj, &pub, &publen, &alg, spki)
        || !xwing_algor_ok(alg)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid X-Wing SubjectPublicKeyInfo");
        goto end;
    }
    key = ossl_mlx_key_new(provctx, MLX_VARIANT_XWING, propq);
    if (key == NULL
        || publen != (long)(key->minfo->pubkey_bytes
                            + key->xinfo->pubkey_bytes)
        || !ossl_mlx_set_public_key(key, pub, (size_t)publen)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid X-Wing public key length or key material");
        ossl_mlx_key_free(key);
        key = NULL;
    }
end:
    ossl_X509_PUBKEY_INTERNAL_free(spki);
    return key;
}

MLX_KEY *ossl_xwing_d2i_PKCS8(const unsigned char *der, long derlen,
    PROV_CTX *provctx, const char *propq)
{
    const unsigned char *p = der, *seed = NULL;
    const X509_ALGOR *alg = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    MLX_KEY *key = NULL;
    int seedlen = 0;

    if (der == NULL || derlen <= 0
        || (p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derlen)) == NULL
        || p != der + derlen
        || !PKCS8_pkey_get0(NULL, &seed, &seedlen, &alg, p8)
        || !xwing_algor_ok(alg)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid X-Wing PrivateKeyInfo");
        goto end;
    }
    key = ossl_mlx_key_new(provctx, MLX_VARIANT_XWING, propq);
    if (key == NULL || seedlen != (long)key->xinfo->seed_bytes
        || !ossl_mlx_set_seed(key, seed, (size_t)seedlen)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid X-Wing seed length or key material");
        ossl_mlx_key_free(key);
        key = NULL;
    }
end:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return key;
}

int ossl_xwing_i2d_pubkey(const MLX_KEY *key, unsigned char **out)
{
    unsigned char *buf;
    size_t len;

    if (key == NULL || out == NULL)
        return 0;
    len = key->minfo->pubkey_bytes + key->xinfo->pubkey_bytes;
    if (len > INT_MAX || (buf = OPENSSL_malloc(len)) == NULL)
        return 0;
    if (!ossl_mlx_encode_public_key(key, buf, len)) {
        OPENSSL_free(buf);
        return 0;
    }
    *out = buf;
    return (int)len;
}

int ossl_xwing_i2d_prvkey(const MLX_KEY *key, unsigned char **out)
{
    unsigned char *buf;
    size_t len;

    if (key == NULL || out == NULL)
        return 0;
    len = key->xinfo->seed_bytes;
    if (len > INT_MAX || (buf = OPENSSL_malloc(len)) == NULL)
        return 0;
    if (!ossl_mlx_encode_seed(key, buf, len)) {
        OPENSSL_clear_free(buf, len);
        return 0;
    }
    *out = buf;
    return (int)len;
}
