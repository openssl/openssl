/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "internal/nelem.h"
#include "prov/mlx_codecs.h"

typedef struct mlx_codec_st {
    unsigned int variant;
    int evp_type;
    const char *algorithm_name;
    const unsigned char *spki_prefix;
    size_t spki_prefix_len;
} MLX_CODEC;

/*-
 * X-Wing:
 * Public key bytes: 1216 (0x04c0)
 *
 * This is the fixed DER prefix for an X-Wing SubjectPublicKeyInfo.  It is
 * two bytes longer than an ML-KEM SPKI prefix because the X-Wing OID is two
 * bytes longer than the NIST ML-KEM OIDs.
 */
/* clang-format off */
static const unsigned char xwing_spki_prefix[] = {
    0x30, 0x82, 0x04, 0xd4, 0x30, 0x0d, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x83, 0xe6, 0x2d, 0x81, 0xc8, 0x7a, 0x03, 0x82, 0x04, 0xc1, 0x00
};
/* clang-format on */

/* Add future MLX hybrid encodings here. */
static const MLX_CODEC mlx_codecs[] = {
    { MLX_VARIANT_XWING, NID_X_Wing, "X-Wing",
      xwing_spki_prefix, sizeof(xwing_spki_prefix) }
};

static const MLX_CODEC *mlx_get_codec(unsigned int variant)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(mlx_codecs); ++i) {
        if (mlx_codecs[i].variant == variant)
            return &mlx_codecs[i];
    }
    return NULL;
}

static int mlx_algor_ok(const X509_ALGOR *alg, int evp_type)
{
    const ASN1_OBJECT *obj = NULL;
    const void *pval = NULL;
    int ptype = V_ASN1_UNDEF;

    if (alg == NULL)
        return 0;
    X509_ALGOR_get0(&obj, &ptype, &pval, alg);
    return OBJ_obj2nid(obj) == evp_type && ptype == V_ASN1_UNDEF;
}

MLX_KEY *ossl_mlx_d2i_PUBKEY(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq)
{
    const MLX_CODEC *codec = mlx_get_codec(variant);
    MLX_KEY *key = NULL;
    size_t publen;

    if (der == NULL || derlen <= 0 || codec == NULL)
        return NULL;
    key = ossl_mlx_key_new(provctx, variant, propq);
    if (key == NULL)
        return NULL;
    publen = key->minfo->pubkey_bytes + key->xinfo->pubkey_bytes;
    if ((size_t)derlen != codec->spki_prefix_len + publen
        || memcmp(der, codec->spki_prefix, codec->spki_prefix_len) != 0) {
        ossl_mlx_key_free(key);
        return NULL;
    }
    if (!ossl_mlx_set_public_key(key, der + codec->spki_prefix_len, publen)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid %s public key material", codec->algorithm_name);
        ossl_mlx_key_free(key);
        return NULL;
    }
    return key;
}

MLX_KEY *ossl_mlx_d2i_PKCS8(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq)
{
    const MLX_CODEC *codec = mlx_get_codec(variant);
    const unsigned char *p = der, *seed = NULL;
    const X509_ALGOR *alg = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    MLX_KEY *key = NULL;
    int seedlen = 0;

    if (der == NULL || derlen <= 0 || codec == NULL
        || (p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derlen)) == NULL
        || p != der + derlen
        || !PKCS8_pkey_get0(NULL, &seed, &seedlen, &alg, p8)
        || !mlx_algor_ok(alg, codec->evp_type)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid %s PrivateKeyInfo",
            codec == NULL ? "MLX" : codec->algorithm_name);
        goto end;
    }
    key = ossl_mlx_key_new(provctx, variant, propq);
    if (key == NULL || seedlen != (long)key->xinfo->seed_bytes
        || !ossl_mlx_set_seed(key, seed, (size_t)seedlen)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid %s seed length or key material", codec->algorithm_name);
        ossl_mlx_key_free(key);
        key = NULL;
    }
end:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return key;
}

int ossl_mlx_i2d_pubkey(const MLX_KEY *key, unsigned char **out)
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

int ossl_mlx_i2d_prvkey(const MLX_KEY *key, unsigned char **out)
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
