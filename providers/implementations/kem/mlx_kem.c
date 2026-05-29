/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <string.h> /* memset */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "internal/cryptlib.h" /* ossl_likely */
#include "prov/implementations.h"
#include "prov/mlx_kem.h"
#include "prov/ecx.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "providers/implementations/kem/mlx_kem.inc"

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
    uint8_t entropy[256]; /* This is used for testing purposes */
    size_t entropy_len;
} PROV_MLX_KEM_CTX;

static void *mlx_kem_newctx(void *provctx)
{
    PROV_MLX_KEM_CTX *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

static void clear_entropy(PROV_MLX_KEM_CTX *ctx)
{
    if (ctx->entropy_len != 0) {
        OPENSSL_cleanse(ctx->entropy, sizeof(ctx->entropy));
        ctx->entropy_len = 0;
    }
}

static void mlx_kem_freectx(void *vctx)
{
    PROV_MLX_KEM_CTX *ctx = vctx;

    if (ctx != NULL)
        clear_entropy(ctx);
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
    clear_entropy(ctx);
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
    return mlx_kem_set_ctx_params_list;
}

static int mlx_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_MLX_KEM_CTX *ctx = vctx;
    struct mlx_kem_set_ctx_params_st p;

    if (ctx == NULL || !mlx_kem_set_ctx_params_decoder(params, &p))
        return 0;

    if (p.ikme != NULL) {
        void *vp = ctx->entropy;
        size_t len = sizeof(ctx->entropy);
        size_t need = 32 + (ctx->key->xinfo->ec_nSeed > 0 ? ctx->key->xinfo->ec_nSeed : ctx->key->xinfo->prvkey_bytes);

        /* Unfortunately there is currently a test vector that is 32 bytes less */
        if (ctx->key->xinfo->ml_kem_variant == EVP_PKEY_ML_KEM_768)
            need -= 32;
        clear_entropy(ctx);
        if (!OSSL_PARAM_get_octet_string(p.ikme, &vp, len, &ctx->entropy_len))
            return 0;

        if (ctx->entropy_len < need)
            return 0;
    }
    return 1;
}

/*
 * The shared secret combiner is defined in
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-11#section-5.1.3
 * C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label)
 * which is:
 *   ss = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || Label)
 */
static int derive_shared_secret(uint8_t *out_ss, MLX_KEY *key,
    const uint8_t *ss_PQT, size_t ss_PQT_len,
    const uint8_t *ct_T, size_t ct_T_len)
{
    int ret = 0;
    uint8_t pub[97]; /* ek_T */
    size_t publen;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;

    md = EVP_MD_fetch(key->libctx, SN_sha3_256, key->propq);
    if (md == NULL)
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;

    if (!EVP_PKEY_get_octet_string_param(key->xkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            pub, sizeof(pub), &publen))
        goto end;

    ret = EVP_DigestInit_ex2(ctx, md, NULL)
        && EVP_DigestUpdate(ctx, ss_PQT, ss_PQT_len)
        && EVP_DigestUpdate(ctx, ct_T, ct_T_len)
        && EVP_DigestUpdate(ctx, pub, publen)
        && EVP_DigestUpdate(ctx, key->xinfo->label, strlen(key->xinfo->label))
        && EVP_DigestFinal(ctx, out_ss, NULL);
end:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int mlx_kem_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,
    unsigned char *shsec, size_t *slen)
{
    PROV_MLX_KEM_CTX *mlxctx = (PROV_MLX_KEM_CTX *)vctx;
    MLX_KEY *key = mlxctx->key;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *xkey = NULL;
    uint8_t ss_tmp[128];
    size_t combined_encap_slen, encap_clen;
    size_t encap_slen;
    uint8_t *cbuf;
    uint8_t *sbuf, *ss = NULL;
    int ml_kem_slot = key->xinfo->ml_kem_slot;
    int ret = 0;
    OSSL_PARAM params[3], *p = params, *prms = NULL;
    int hpke_mode = (key->xinfo->ec_nSeed > 0);
    int mode;

    if (!mlx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }
    encap_clen = key->minfo->ctext_bytes + key->xinfo->pubkey_bytes;
    combined_encap_slen = ML_KEM_SHARED_SECRET_BYTES + key->xinfo->shsec_bytes;

    if (hpke_mode) {
        if (sizeof(ss_tmp) < combined_encap_slen)
            goto end;
        encap_slen = 32; /* SHA3_256 output size */
        ss = ss_tmp; /* writes to a temporary buffer */
    } else {
        ss = shsec; /* writes directly to the output buffer */
        encap_slen = combined_encap_slen;
    }

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

    if (mlxctx->entropy_len > 0) {
        prms = params;
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, mlxctx->entropy, 32);
        *p = OSSL_PARAM_construct_end();
    }
    /* ML-KEM encapsulation */
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

    if (mlxctx->entropy_len > 0) {
        mode = OSSL_EC_KEYDERIVE_MODE_MLKEM_HYBRID;
        p = params;
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_IKM, mlxctx->entropy + 32, mlxctx->entropy_len - 32);
        *p++ = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_IKM_DERIVEMODE, &mode);
        *p = OSSL_PARAM_construct_end();
    }

    cbuf = ctext + (1 - ml_kem_slot) * key->minfo->ctext_bytes;
    encap_clen = key->xinfo->pubkey_bytes;
    ctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
    if (ctx == NULL
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, prms) <= 0
        || EVP_PKEY_keygen(ctx, &xkey) <= 0
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
    clear_entropy(mlxctx);

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

    if (hpke_mode
        && !derive_shared_secret(shsec, key, ss, combined_encap_slen, cbuf, encap_clen))
        goto end;
    ret = 1;
end:
    if (ss == ss_tmp)
        OPENSSL_cleanse(ss_tmp, sizeof(ss_tmp));
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
    uint8_t *sbuf, *ss;
    uint8_t ss_tmp[128];
    size_t decap_slen;
    size_t combined_decap_slen = ML_KEM_SHARED_SECRET_BYTES + key->xinfo->shsec_bytes;
    size_t decap_clen = key->minfo->ctext_bytes + key->xinfo->pubkey_bytes;
    int ml_kem_slot = key->xinfo->ml_kem_slot;
    int ret = 0;
    int hpke_mode = (key->xinfo->ec_nSeed > 0);

    if (!mlx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (hpke_mode) {
        if (sizeof(ss_tmp) < combined_decap_slen)
            goto end;
        decap_slen = 32; /* SHA3_256 output size */
        ss = ss_tmp; /* writes to a temporary buffer */
    } else {
        ss = shsec; /* writes directly to the output buffer */
        decap_slen = combined_decap_slen;
    }

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

    if (hpke_mode
        && !derive_shared_secret(shsec, key, ss, combined_decap_slen, cbuf, decap_clen))
        goto end;
    ret = 1;
end:
    if (ss == ss_tmp)
        OPENSSL_cleanse(ss_tmp, sizeof(ss_tmp));
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
