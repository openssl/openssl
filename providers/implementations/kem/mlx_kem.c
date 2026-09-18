/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "prov/implementations.h"
#include "prov/mlx_kem.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

static OSSL_FUNC_kem_newctx_fn mlx_kem_newctx;
static OSSL_FUNC_kem_freectx_fn mlx_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn mlx_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn mlx_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn mlx_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn mlx_kem_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn mlx_kem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn mlx_kem_settable_ctx_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    MLX_KEY *key;
    int op;
    unsigned char entropy[MLX_MAX_ENCAP_SEED_BYTES];
    size_t entropy_len;
} PROV_MLX_KEM_CTX;

static void *mlx_kem_newctx(void *provctx)
{
    PROV_MLX_KEM_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->key = NULL;
    ctx->op = 0;
    ctx->entropy_len = 0;
    return ctx;
}

static void mlx_kem_freectx(void *vctx)
{
    PROV_MLX_KEM_CTX *ctx = vctx;

    if (ctx != NULL)
        OPENSSL_cleanse(ctx->entropy, sizeof(ctx->entropy));
    OPENSSL_free(vctx);
}

static int mlx_kem_init(void *vctx, int op, void *key,
    ossl_unused const OSSL_PARAM params[])
{
    PROV_MLX_KEM_CTX *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;
    ctx->key = key;
    ctx->op = op;
    ctx->entropy_len = 0;
    return mlx_kem_set_ctx_params(vctx, params);
}

static int
mlx_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    MLX_KEY *key = vkey;

    if (!mlx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return mlx_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int
mlx_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    MLX_KEY *key = vkey;

    if (!mlx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return mlx_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static const OSSL_PARAM *mlx_kem_settable_ctx_params(ossl_unused void *vctx,
    ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static int
mlx_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_MLX_KEM_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    void *dst;
    size_t len = 0;

    if (ctx == NULL || params == NULL)
        return ctx != NULL;
    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p == NULL)
        return 1;
    if (ctx->op != EVP_PKEY_OP_ENCAPSULATE || ctx->key == NULL
        || ctx->key->xinfo->combiner != MLX_COMBINER_C2PRI
        || ctx->key->xinfo->encap_seed_bytes == 0)
        return 0;
    dst = ctx->entropy;
    if (!OSSL_PARAM_get_octet_string(p, &dst, sizeof(ctx->entropy), &len)
        || len != ctx->key->xinfo->encap_seed_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return 0;
    }
    ctx->entropy_len = len;
    return 1;
}

static int mlx_c2pri_combine(unsigned char *out, const MLX_KEY *key,
    const unsigned char *ss, size_t sslen,
    const unsigned char *ct_t, size_t ct_t_len)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    unsigned char *pk_t = NULL;
    size_t pk_t_len;
    unsigned int outlen = 0;
    int ret = 0;

    if (out == NULL || key == NULL || ss == NULL || ct_t == NULL
        || key->xinfo->combiner != MLX_COMBINER_C2PRI)
        return 0;
    pk_t_len = key->xinfo->pubkey_bytes;
    pk_t = OPENSSL_malloc(pk_t_len);
    if (pk_t == NULL
        || EVP_PKEY_get_octet_string_param(key->xkey,
               OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pk_t, pk_t_len, &pk_t_len)
            <= 0
        || pk_t_len != key->xinfo->pubkey_bytes)
        goto end;
    md = EVP_MD_fetch(key->libctx, key->xinfo->kdf_name, key->propq);
    mctx = EVP_MD_CTX_new();
    if (md == NULL || mctx == NULL)
        goto end;
    ret = EVP_DigestInit_ex2(mctx, md, NULL)
        && EVP_DigestUpdate(mctx, ss, sslen)
        && EVP_DigestUpdate(mctx, ct_t, ct_t_len)
        && EVP_DigestUpdate(mctx, pk_t, pk_t_len)
        && EVP_DigestUpdate(mctx, key->xinfo->label, key->xinfo->label_len)
        && EVP_DigestFinal_ex(mctx, out, &outlen)
        && outlen == key->xinfo->hybrid_shsec_bytes;
end:
    OPENSSL_clear_free(pk_t, pk_t_len);
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    return ret;
}

static int mlx_kem_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,
    unsigned char *shsec, size_t *slen)
{
    PROV_MLX_KEM_CTX *mlxctx = vctx;
    MLX_KEY *key = mlxctx->key;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *xkey = NULL;
    OSSL_PARAM params[3], *prms = NULL;
    size_t encap_clen;
    size_t encap_slen;
    uint8_t *cbuf;
    uint8_t *sbuf;
    uint8_t ss_tmp[MLX_MAX_COMBINED_SHARED_SECRET_BYTES];
    uint8_t *ss = shsec;
    size_t combined_slen = ML_KEM_SHARED_SECRET_BYTES + key->xinfo->shsec_bytes;
    int c2pri = key->xinfo->combiner == MLX_COMBINER_C2PRI;
    int ml_kem_slot = key->xinfo->ml_kem_slot;
    int ret = 0;

    if (!mlx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    encap_clen = key->minfo->ctext_bytes + key->xinfo->pubkey_bytes;
    encap_slen = c2pri ? key->xinfo->hybrid_shsec_bytes
                       : ML_KEM_SHARED_SECRET_BYTES + key->xinfo->shsec_bytes;
    if (c2pri && combined_slen > sizeof(ss_tmp))
        return 0;
    if (c2pri)
        ss = ss_tmp;

    if (ctext == NULL) {
        if (clen == NULL && slen == NULL)
            return 0;
        if (clen != NULL)
            *clen = encap_clen;
        if (slen != NULL)
            *slen = encap_slen;
        return 1;
    }
    if (shsec == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_OUTPUT_BUFFER,
            "null shared-secret output buffer");
        return 0;
    }

    if (clen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
            "null ciphertext input/output length pointer");
        return 0;
    } else if (*clen < encap_clen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "ciphertext buffer too small");
        return 0;
    } else {
        *clen = encap_clen;
    }

    if (slen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
            "null shared secret input/output length pointer");
        return 0;
    } else if (*slen < encap_slen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "shared-secret buffer too small");
        return 0;
    } else {
        *slen = encap_slen;
    }

    /* ML-KEM encapsulation */
    if (mlxctx->entropy_len != 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
            mlxctx->entropy, ML_KEM_RANDOM_BYTES);
        params[1] = OSSL_PARAM_construct_end();
        prms = params;
    }
    encap_clen = key->minfo->ctext_bytes;
    encap_slen = ML_KEM_SHARED_SECRET_BYTES;
    cbuf = ctext + ml_kem_slot * key->xinfo->pubkey_bytes;
    sbuf = ss + ml_kem_slot * key->xinfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->mkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_encapsulate_init(ctx, prms) <= 0
        || EVP_PKEY_encapsulate(ctx, cbuf, &encap_clen, sbuf, &encap_slen) <= 0)
        goto end;
    if (encap_clen != key->minfo->ctext_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s ciphertext output size: %lu",
            key->minfo->algorithm_name, (unsigned long)encap_clen);
        goto end;
    }
    if (encap_slen != ML_KEM_SHARED_SECRET_BYTES) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->minfo->algorithm_name, (unsigned long)encap_slen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /*-
     * ECDHE encapsulation
     *
     * Generate own ephemeral private key and add its public key to ctext.
     *
     * Note, we could support a settable parameter that sets an extant ECDH
     * keypair as the keys to use in encap, making it possible to reuse the
     * same (TLS client) ECDHE keypair for both the classical EC keyshare and a
     * corresponding ECDHE + ML-KEM keypair.  But the TLS layer would then need
     * know that this is a hybrid, and that it can partly reuse the same keys
     * as another group for which a keyshare will be sent.  Deferred until we
     * support generating multiple keyshares, there's a workable keyshare
     * prediction specification, and the optimisation is justified.
     */
    cbuf = ctext + (1 - ml_kem_slot) * key->minfo->ctext_bytes;
    encap_clen = key->xinfo->pubkey_bytes;
    if (mlxctx->entropy_len != 0) {
#ifndef FIPS_MODULE
        if (key->xinfo->group_name == NULL) {
            xkey = EVP_PKEY_new_raw_private_key_ex(key->libctx,
                key->xinfo->algorithm_name, key->propq,
                mlxctx->entropy + ML_KEM_RANDOM_BYTES,
                mlxctx->entropy_len - ML_KEM_RANDOM_BYTES);
        } else {
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME,
                (char *)key->xinfo->group_name, 0);
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_DHKEM_IKM,
                mlxctx->entropy + ML_KEM_RANDOM_BYTES,
                mlxctx->entropy_len - ML_KEM_RANDOM_BYTES);
            params[2] = OSSL_PARAM_construct_end();
            ctx = EVP_PKEY_CTX_new_from_name(key->libctx,
                key->xinfo->algorithm_name, key->propq);
            if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
                || EVP_PKEY_CTX_set_params(ctx, params) <= 0
                || EVP_PKEY_generate(ctx, &xkey) <= 0)
                goto end;
        }
#else
        goto end;
#endif
    } else {
        ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &xkey) <= 0)
            goto end;
    }
    if (xkey == NULL
        || EVP_PKEY_get_octet_string_param(xkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
               cbuf, encap_clen, &encap_clen)
            <= 0)
        goto end;
    if (encap_clen != key->xinfo->pubkey_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s public key output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)encap_clen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Derive the ECDH shared secret */
    encap_slen = key->xinfo->shsec_bytes;
    sbuf = ss + (1 - ml_kem_slot) * ML_KEM_SHARED_SECRET_BYTES;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, xkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, key->xkey) <= 0
        || EVP_PKEY_derive(ctx, sbuf, &encap_slen) <= 0)
        goto end;
    if (encap_slen != key->xinfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)encap_slen);
        goto end;
    }

    if (c2pri
        && !mlx_c2pri_combine(shsec, key, ss, combined_slen,
            ctext + (1 - ml_kem_slot) * key->minfo->ctext_bytes,
            key->xinfo->pubkey_bytes))
        goto end;
    ret = 1;
end:
    OPENSSL_cleanse(ss_tmp, sizeof(ss_tmp));
    OPENSSL_cleanse(mlxctx->entropy, sizeof(mlxctx->entropy));
    mlxctx->entropy_len = 0;
    /* Erase any partial shared secret on failure */
    if (ret == 0)
        OPENSSL_cleanse(shsec, c2pri ? key->xinfo->hybrid_shsec_bytes : combined_slen);
    EVP_PKEY_free(xkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int mlx_kem_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,
    const uint8_t *ctext, size_t clen)
{
    MLX_KEY *key = ((PROV_MLX_KEM_CTX *)vctx)->key;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *xkey = NULL;
    const uint8_t *cbuf;
    uint8_t *sbuf;
    uint8_t ss_tmp[MLX_MAX_COMBINED_SHARED_SECRET_BYTES];
    uint8_t *ss = shsec;
    size_t combined_slen = ML_KEM_SHARED_SECRET_BYTES + key->xinfo->shsec_bytes;
    int c2pri = key->xinfo->combiner == MLX_COMBINER_C2PRI;
    size_t decap_slen = c2pri ? key->xinfo->hybrid_shsec_bytes : combined_slen;
    size_t decap_clen = key->minfo->ctext_bytes + key->xinfo->pubkey_bytes;
    int ml_kem_slot = key->xinfo->ml_kem_slot;
    int ret = 0;

    if (!mlx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (c2pri && combined_slen > sizeof(ss_tmp))
        return 0;
    if (c2pri)
        ss = ss_tmp;

    if (shsec == NULL) {
        if (slen == NULL)
            return 0;
        *slen = decap_slen;
        return 1;
    }

    /* For now tolerate newly-deprecated NULL length pointers. */
    if (slen == NULL) {
        slen = &decap_slen;
    } else if (*slen < decap_slen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "shared-secret buffer too small");
        return 0;
    } else {
        *slen = decap_slen;
    }
    if (clen != decap_clen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_WRONG_CIPHERTEXT_SIZE,
            "wrong decapsulation input ciphertext size: %lu",
            (unsigned long)clen);
        return 0;
    }

    /* ML-KEM decapsulation */
    decap_clen = key->minfo->ctext_bytes;
    decap_slen = ML_KEM_SHARED_SECRET_BYTES;
    cbuf = ctext + ml_kem_slot * key->xinfo->pubkey_bytes;
    sbuf = ss + ml_kem_slot * key->xinfo->shsec_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->mkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, sbuf, &decap_slen, cbuf, decap_clen) <= 0)
        goto end;
    if (decap_slen != ML_KEM_SHARED_SECRET_BYTES) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->minfo->algorithm_name, (unsigned long)decap_slen);
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* ECDH decapsulation */
    decap_clen = key->xinfo->pubkey_bytes;
    decap_slen = key->xinfo->shsec_bytes;
    cbuf = ctext + (1 - ml_kem_slot) * key->minfo->ctext_bytes;
    sbuf = ss + (1 - ml_kem_slot) * ML_KEM_SHARED_SECRET_BYTES;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
    if (ctx == NULL
        || (xkey = EVP_PKEY_new()) == NULL
        || EVP_PKEY_copy_parameters(xkey, key->xkey) <= 0
        || EVP_PKEY_set1_encoded_public_key(xkey, cbuf, decap_clen) <= 0
        || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, xkey) <= 0
        || EVP_PKEY_derive(ctx, sbuf, &decap_slen) <= 0)
        goto end;
    if (decap_slen != key->xinfo->shsec_bytes) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
            "unexpected %s shared secret output size: %lu",
            key->xinfo->algorithm_name, (unsigned long)decap_slen);
        goto end;
    }

    if (c2pri
        && !mlx_c2pri_combine(shsec, key, ss, combined_slen,
            ctext + (1 - ml_kem_slot) * key->minfo->ctext_bytes,
            key->xinfo->pubkey_bytes))
        goto end;
    ret = 1;
end:
    OPENSSL_cleanse(ss_tmp, sizeof(ss_tmp));
    /* Erase any partial shared secret on failure */
    if (ret == 0)
        OPENSSL_cleanse(shsec, c2pri ? key->xinfo->hybrid_shsec_bytes : combined_slen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(xkey);
    return ret;
}

const OSSL_DISPATCH ossl_mlx_kem_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (OSSL_FUNC)mlx_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (OSSL_FUNC)mlx_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (OSSL_FUNC)mlx_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (OSSL_FUNC)mlx_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (OSSL_FUNC)mlx_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (OSSL_FUNC)mlx_kem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (OSSL_FUNC)mlx_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (OSSL_FUNC)mlx_kem_settable_ctx_params },
    OSSL_DISPATCH_END
};
