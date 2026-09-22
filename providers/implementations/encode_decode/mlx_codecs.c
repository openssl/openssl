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
#include "internal/encoder.h"
#include "internal/nelem.h"
#include "prov/mlx_codecs.h"

typedef int (*mlx_d2i_private_fn)(MLX_KEY *key,
    const unsigned char *in, size_t inlen);
typedef int (*mlx_i2d_private_fn)(const MLX_KEY *key, unsigned char **out);

typedef struct mlx_codec_st {
    unsigned int variant;
    int evp_type;
    const char *algorithm_name;
    const unsigned char *spki_prefix;
    size_t spki_prefix_len;
    mlx_d2i_private_fn d2i_private;
    mlx_i2d_private_fn i2d_private;
    const char *text_private_label;
} MLX_CODEC;

static int mlx_seed_d2i_private(MLX_KEY *key,
    const unsigned char *in, size_t inlen)
{
    return key != NULL && in != NULL
        && inlen == key->xinfo->seed_bytes
        && ossl_mlx_set_seed(key, in, inlen);
}

static int mlx_seed_i2d_private(const MLX_KEY *key, unsigned char **out)
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
        xwing_spki_prefix, sizeof(xwing_spki_prefix),
        mlx_seed_d2i_private, mlx_seed_i2d_private, "seed:" }
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
    const unsigned char *p = der, *private_data = NULL;
    const X509_ALGOR *alg = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    MLX_KEY *key = NULL;
    int private_len = 0;

    if (der == NULL || derlen <= 0 || codec == NULL
        || (p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derlen)) == NULL
        || p != der + derlen
        || !PKCS8_pkey_get0(NULL, &private_data, &private_len, &alg, p8)
        || !mlx_algor_ok(alg, codec->evp_type)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid %s PrivateKeyInfo",
            codec == NULL ? "MLX" : codec->algorithm_name);
        goto end;
    }
    key = ossl_mlx_key_new(provctx, variant, propq);
    if (key == NULL || private_len < 0 || codec->d2i_private == NULL
        || !codec->d2i_private(key, private_data, (size_t)private_len)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "invalid %s private key material", codec->algorithm_name);
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
    const MLX_CODEC *codec;

    if (key == NULL || out == NULL)
        return 0;
    codec = mlx_get_codec(key->variant);
    if (codec == NULL || codec->i2d_private == NULL)
        return 0;
    return codec->i2d_private(key, out);
}

int ossl_mlx_key_to_text(BIO *out, const MLX_KEY *key, int selection)
{
    const MLX_CODEC *codec;
    unsigned char *prvenc = NULL, *pubenc = NULL;
    size_t publen = 0;
    int prvlen = 0;
    int ret = 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    codec = mlx_get_codec(key->variant);
    if (codec == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && mlx_kem_have_prvkey(key)) {
        if (BIO_printf(out, "%s Private-Key:\n", codec->algorithm_name) <= 0
            || codec->text_private_label == NULL
            || (prvlen = ossl_mlx_i2d_prvkey(key, &prvenc)) <= 0
            || !ossl_bio_print_labeled_buf(out, codec->text_private_label,
                prvenc, (size_t)prvlen))
            goto end;
        ret = 1;
    }

    /* The public key is output regardless of the selection. */
    if (mlx_kem_have_pubkey(key)) {
        if (ret == 0
            && BIO_printf(out, "%s Public-Key:\n", codec->algorithm_name) <= 0)
            goto end;
        publen = key->minfo->pubkey_bytes + key->xinfo->pubkey_bytes;
        if ((pubenc = OPENSSL_malloc(publen)) == NULL
            || !ossl_mlx_encode_public_key(key, pubenc, publen)
            || !ossl_bio_print_labeled_buf(out, "ek:", pubenc, publen))
            goto end;
        ret = 1;
    }

    if (ret == 0)
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
            "no %s key material available", codec->algorithm_name);

end:
    OPENSSL_clear_free(prvenc, prvlen > 0 ? (size_t)prvlen : 0);
    OPENSSL_free(pubenc);
    return ret;
}
