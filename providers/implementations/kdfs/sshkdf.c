/*
 * Copyright 2018-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Opentls license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <opentls/evp.h>
#include <opentls/kdf.h>
#include <opentls/core_names.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "crypto/evp.h"
#include "prov/provider_ctx.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
# include "prov/provider_util.h"

/* See RFC 4253, Section 7.2 */
static Otls_OP_kdf_newctx_fn kdf_sshkdf_new;
static Otls_OP_kdf_freectx_fn kdf_sshkdf_free;
static Otls_OP_kdf_reset_fn kdf_sshkdf_reset;
static Otls_OP_kdf_derive_fn kdf_sshkdf_derive;
static Otls_OP_kdf_settable_ctx_params_fn kdf_sshkdf_settable_ctx_params;
static Otls_OP_kdf_set_ctx_params_fn kdf_sshkdf_set_ctx_params;
static Otls_OP_kdf_gettable_ctx_params_fn kdf_sshkdf_gettable_ctx_params;
static Otls_OP_kdf_get_ctx_params_fn kdf_sshkdf_get_ctx_params;

static int SSHKDF(const EVP_MD *evp_md,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *xcghash, size_t xcghash_len,
                  const unsigned char *session_id, size_t session_id_len,
                  char type, unsigned char *okey, size_t okey_len);

typedef struct {
    void *provctx;
    PROV_DIGEST digest;
    unsigned char *key; /* K */
    size_t key_len;
    unsigned char *xcghash; /* H */
    size_t xcghash_len;
    char type; /* X */
    unsigned char *session_id;
    size_t session_id_len;
} KDF_SSHKDF;

static void *kdf_sshkdf_new(void *provctx)
{
    KDF_SSHKDF *ctx;

    if ((ctx = OPENtls_zalloc(sizeof(*ctx))) == NULL)
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx->provctx = provctx;
    return ctx;
}

static void kdf_sshkdf_free(void *vctx)
{
    KDF_SSHKDF *ctx = (KDF_SSHKDF *)vctx;

    if (ctx != NULL) {
        kdf_sshkdf_reset(ctx);
        OPENtls_free(ctx);
    }
}

static void kdf_sshkdf_reset(void *vctx)
{
    KDF_SSHKDF *ctx = (KDF_SSHKDF *)vctx;

    otls_prov_digest_reset(&ctx->digest);
    OPENtls_clear_free(ctx->key, ctx->key_len);
    OPENtls_clear_free(ctx->xcghash, ctx->xcghash_len);
    OPENtls_clear_free(ctx->session_id, ctx->session_id_len);
    memset(ctx, 0, sizeof(*ctx));
}

static int sshkdf_set_membuf(unsigned char **dst, size_t *dst_len,
                             const Otls_PARAM *p)
{
    OPENtls_clear_free(*dst, *dst_len);
    *dst = NULL;
    return Otls_PARAM_get_octet_string(p, (void **)dst, 0, dst_len);
}

static int kdf_sshkdf_derive(void *vctx, unsigned char *key,
                             size_t keylen)
{
    KDF_SSHKDF *ctx = (KDF_SSHKDF *)vctx;
    const EVP_MD *md = otls_prov_digest_md(&ctx->digest);

    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (ctx->xcghash == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_XCGHASH);
        return 0;
    }
    if (ctx->session_id == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SESSION_ID);
        return 0;
    }
    if (ctx->type == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_TYPE);
        return 0;
    }
    return SSHKDF(md, ctx->key, ctx->key_len,
                  ctx->xcghash, ctx->xcghash_len,
                  ctx->session_id, ctx->session_id_len,
                  ctx->type, key, keylen);
}

static int kdf_sshkdf_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    const Otls_PARAM *p;
    KDF_SSHKDF *ctx = vctx;
    OPENtls_CTX *provctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    int t;

    if (!otls_prov_digest_load_from_params(&ctx->digest, params, provctx))
        return 0;

    if ((p = Otls_PARAM_locate_const(params, Otls_KDF_PARAM_KEY)) != NULL)
        if (!sshkdf_set_membuf(&ctx->key, &ctx->key_len, p))
            return 0;

    if ((p = Otls_PARAM_locate_const(params, Otls_KDF_PARAM_SSHKDF_XCGHASH))
        != NULL)
        if (!sshkdf_set_membuf(&ctx->xcghash, &ctx->xcghash_len, p))
            return 0;

    if ((p = Otls_PARAM_locate_const(params, Otls_KDF_PARAM_SSHKDF_SESSION_ID))
        != NULL)
        if (!sshkdf_set_membuf(&ctx->session_id, &ctx->session_id_len, p))
            return 0;

    if ((p = Otls_PARAM_locate_const(params, Otls_KDF_PARAM_SSHKDF_TYPE))
        != NULL) {
        if (p->data == NULL || p->data_size == 0)
            return 0;
        t = *(unsigned char *)p->data;
        if (t < 65 || t > 70) {
            ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
            return 0;
        }
        ctx->type = (char)t;
    }
    return 1;
}

static const Otls_PARAM *kdf_sshkdf_settable_ctx_params(void)
{
    static const Otls_PARAM known_settable_ctx_params[] = {
        Otls_PARAM_utf8_string(Otls_KDF_PARAM_PROPERTIES, NULL, 0),
        Otls_PARAM_utf8_string(Otls_KDF_PARAM_DIGEST, NULL, 0),
        Otls_PARAM_octet_string(Otls_KDF_PARAM_KEY, NULL, 0),
        Otls_PARAM_octet_string(Otls_KDF_PARAM_SSHKDF_XCGHASH, NULL, 0),
        Otls_PARAM_octet_string(Otls_KDF_PARAM_SSHKDF_SESSION_ID, NULL, 0),
        Otls_PARAM_utf8_string(Otls_KDF_PARAM_SSHKDF_TYPE, NULL, 0),
        Otls_PARAM_END
    };
    return known_settable_ctx_params;
}

static int kdf_sshkdf_get_ctx_params(void *vctx, Otls_PARAM params[])
{
    Otls_PARAM *p;

    if ((p = Otls_PARAM_locate(params, Otls_KDF_PARAM_SIZE)) != NULL)
        return Otls_PARAM_set_size_t(p, SIZE_MAX);
    return -2;
}

static const Otls_PARAM *kdf_sshkdf_gettable_ctx_params(void)
{
    static const Otls_PARAM known_gettable_ctx_params[] = {
        Otls_PARAM_size_t(Otls_KDF_PARAM_SIZE, NULL),
        Otls_PARAM_END
    };
    return known_gettable_ctx_params;
}

const Otls_DISPATCH kdf_sshkdf_functions[] = {
    { Otls_FUNC_KDF_NEWCTX, (void(*)(void))kdf_sshkdf_new },
    { Otls_FUNC_KDF_FREECTX, (void(*)(void))kdf_sshkdf_free },
    { Otls_FUNC_KDF_RESET, (void(*)(void))kdf_sshkdf_reset },
    { Otls_FUNC_KDF_DERIVE, (void(*)(void))kdf_sshkdf_derive },
    { Otls_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_sshkdf_settable_ctx_params },
    { Otls_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_sshkdf_set_ctx_params },
    { Otls_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_sshkdf_gettable_ctx_params },
    { Otls_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_sshkdf_get_ctx_params },
    { 0, NULL }
};

static int SSHKDF(const EVP_MD *evp_md,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *xcghash, size_t xcghash_len,
                  const unsigned char *session_id, size_t session_id_len,
                  char type, unsigned char *okey, size_t okey_len)
{
    EVP_MD_CTX *md = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dsize = 0;
    size_t cursize = 0;
    int ret = 0;

    md = EVP_MD_CTX_new();
    if (md == NULL)
        return 0;

    if (!EVP_DigestInit_ex(md, evp_md, NULL))
        goto out;

    if (!EVP_DigestUpdate(md, key, key_len))
        goto out;

    if (!EVP_DigestUpdate(md, xcghash, xcghash_len))
        goto out;

    if (!EVP_DigestUpdate(md, &type, 1))
        goto out;

    if (!EVP_DigestUpdate(md, session_id, session_id_len))
        goto out;

    if (!EVP_DigestFinal_ex(md, digest, &dsize))
        goto out;

    if (okey_len < dsize) {
        memcpy(okey, digest, okey_len);
        ret = 1;
        goto out;
    }

    memcpy(okey, digest, dsize);

    for (cursize = dsize; cursize < okey_len; cursize += dsize) {

        if (!EVP_DigestInit_ex(md, evp_md, NULL))
            goto out;

        if (!EVP_DigestUpdate(md, key, key_len))
            goto out;

        if (!EVP_DigestUpdate(md, xcghash, xcghash_len))
            goto out;

        if (!EVP_DigestUpdate(md, okey, cursize))
            goto out;

        if (!EVP_DigestFinal_ex(md, digest, &dsize))
            goto out;

        if (okey_len < cursize + dsize) {
            memcpy(okey + cursize, digest, okey_len - cursize);
            ret = 1;
            goto out;
        }

        memcpy(okey + cursize, digest, dsize);
    }

    ret = 1;

out:
    EVP_MD_CTX_free(md);
    OPENtls_cleanse(digest, EVP_MAX_MD_SIZE);
    return ret;
}

