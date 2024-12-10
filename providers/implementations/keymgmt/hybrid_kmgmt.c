/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/hybrid_pkey.h"
#include "hybrid_kmgmt_local.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/common.h"
#include "internal/e_os.h"
#include "internal/params.h"
#include "internal/param_names.h"
#include "internal/refcount.h"

HYBRID_PKEY *ossl_hybrid_kmgmt_new(void *provctx,
                                   const HYBRID_ALG_INFO *info)
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)OPENSSL_zalloc(sizeof(*key));
    unsigned int i;

    if (key == NULL)
        return NULL;
    key->libctx = PROV_LIBCTX_OF(provctx);
    key->info = info;
    INIT_ACCUMULATE_HYBRID_NUMBERS(key);
    for (i = 0; i < key->info->num_algs; i++) {
        if ((key->keys[i] = EVP_PKEY_new()) == NULL)
            goto err;
        ACCUMULATE_HYBRID_NUMBERS(key, i);
    }
    return key;

 err:
    ossl_hybrid_kmgmt_free(key);
    return NULL;
}

void ossl_hybrid_pkey_free(HYBRID_PKEY *key)
{
    unsigned int i;

    if (key != NULL) {
        for (i = 0; i < key->info->num_algs; i++)
            EVP_PKEY_free(key->keys[i]);
        OPENSSL_free(key->propq);
        OPENSSL_free(key);
    }
}

void ossl_hybrid_kmgmt_free(void *vkey)
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;

    ossl_hybrid_pkey_free(key);
}

void *ossl_hybrid_kmgmt_dup(const void *vold, ossl_unused int selection)
{
    const HYBRID_PKEY *old = (HYBRID_PKEY *)vold;
    HYBRID_PKEY *key;
    unsigned int i;

    if (old == NULL
            || (key = (HYBRID_PKEY *)OPENSSL_zalloc(sizeof(*key))) == NULL)
        return NULL;
    if (old->propq != NULL && (key->propq = strdup(old->propq)) == NULL)
        goto err;
    for (i = 0; i < key->info->num_algs; i++)
        if ((key->keys[i] = EVP_PKEY_dup(old->keys[i])) == NULL)
            goto err;
    key->info = old->info;
    key->pubkey_length = old->pubkey_length;
    key->bits = old->bits;
    key->security_bits = old->security_bits;
    return key;

 err:
    ossl_hybrid_kmgmt_free(key);
    return NULL;
}

int ossl_hybrid_kmgmt_has(const void *vkey, int selection)
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;
    unsigned int i;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    for (i = 0; i < key->info->num_algs; i++)
        if (!evp_keymgmt_util_has(key->keys[i], selection))
            return 0;
    return 1;
}

int ossl_hybrid_kmgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    HYBRID_PKEY *key1 = (HYBRID_PKEY *)vkey1;
    HYBRID_PKEY *key2 = (HYBRID_PKEY *)vkey2;
    unsigned int i;
    int t, res = 1;

    if (!ossl_prov_is_running())
        return 0;

    if (key1 == NULL || key2 == NULL)
        return key1 == key2;

    for (i = 0; i < key1->info->num_algs; i++) {
        /* Return the worst of the result values */
        t = evp_keymgmt_util_match(key1->keys[i], key2->keys[i], selection);
        if (t < res)
            res = t;
    }
    return res;
}

/* Get a sub-param */
#define GET_SUBALG_PARAM(lname, type)                                       \
    static int lname ## _subalg_get_param                                   \
        (unsigned int n, type **s, OSSL_PARAM *param)                       \
    {                                                                       \
        OSSL_PARAM prms[2] = { OSSL_PARAM_END, OSSL_PARAM_END };            \
        unsigned int i;                                                     \
        int got = 0;                                                        \
                                                                            \
        for (i = 0; i < n; i++) {                                           \
            *prms = *param;                                                 \
            OSSL_PARAM_set_all_unmodified(prms);                            \
            if (!type ## _get_params(s[i], prms))                           \
                return 0;                                                   \
            if (OSSL_PARAM_modified(prms)) {                                \
                if (got) {                                                  \
                    ERR_raise(ERR_LIB_PROV,                                 \
                              PROV_R_DUPLICATE_VALUES_FOR_GETTER);          \
                    return 0;                                               \
                }                                                           \
                got = 1;                                                    \
                *param = *prms;                                             \
            }                                                               \
        }                                                                   \
        return 1;                                                           \
    }

GET_SUBALG_PARAM(key, EVP_PKEY)
GET_SUBALG_PARAM(ctx, EVP_PKEY_CTX)

#define SET_SUBALG_PARAM(lname, type)                                       \
    static int lname ## _subalg_set_param                                   \
        (unsigned int n, type **s, const OSSL_PARAM *param)                 \
    {                                                                       \
        OSSL_PARAM prms[2] = { OSSL_PARAM_END, OSSL_PARAM_END };            \
        unsigned int i;                                                     \
                                                                            \
        *prms = *param;                                                     \
        for (i = 0; i < n; i++) {                                           \
            if (!type ## _set_params(s[i], prms))                           \
                return 0;                                                   \
        }                                                                   \
        return 1;                                                           \
    }

SET_SUBALG_PARAM(key, EVP_PKEY)
SET_SUBALG_PARAM(ctx, EVP_PKEY_CTX)

int ossl_hybrid_kmgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;
    OSSL_PARAM prms[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p;
    unsigned char *q;
    unsigned int i;
    int type;

    if (ossl_param_is_empty(params))
        return 1;

    for (p = params; params->key != NULL; params++) {
        type = ossl_param_find_pidx(p->key);
        switch (type) {
        case PIDX_PKEY_PARAM_SECURITY_BITS:
            if (!OSSL_PARAM_set_size_t(p, key->security_bits))
                return 0;
            break;

        case PIDX_PKEY_PARAM_BITS:
            if (!OSSL_PARAM_set_size_t(p, key->bits))
                return 0;
            break;

        case PIDX_PKEY_PARAM_MAX_SIZE:
            if (!OSSL_PARAM_set_size_t(p, key->pubkey_length))
                return 0;
            break;

#ifdef FIPS_MODULE
        case PIDX_PKEY_PARAM_FIPS_APPROVED_INDICATOR:
            {
                int fips = 1;

                *prms = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FIPS_APPROVED_INDICATOR,
                                                 &fips);
                for (i = 0; i < key->info->num_algs && fips; i++)
                    if (!EVP_PKEY_get_params(key->keys[i], prms))
                        return 0;
                if (!OSSL_PARAM_set_int(p, fips))
                    return 0;
            };
            break;
#endif

        case PIDX_PKEY_PARAM_PUB_KEY:
        case PIDX_PKEY_PARAM_PRIV_KEY:
        case PIDX_PKEY_PARAM_ENCODED_PUBLIC_KEY:
            if (key->pubkey_length > p->data_size) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH,
                               "length is %u bytes, have %u bytes",
                               key->pubkey_length, p->data_size);
                return 0;
            }
            q = p->data;
            *prms = *p;
            OSSL_PARAM_set_all_unmodified(prms);
            for (i = 0; i < key->info->num_algs; i++) {
                prms->data = q;
                prms->data_size = key->info->alg[i].pubkey_length_bytes;
                q += key->info->alg[i].pubkey_length_bytes;
                if (!EVP_PKEY_get_params(key->keys[i], prms)
                        || !OSSL_PARAM_modified(prms))
                    return 0;
            }
            break;

        case PIDX_KEM_PARAM_IKME:
            /*
             * If NIST decides to validate hybrid algorithms using ACVP
             * testing, we would need to support whatever format they use for
             * input key material and some special processing would likely be
             * required for this parameter.  Until NIST does this, we'll just
             * pass the key material through unmolested.
             */
        default:
            if (!key_subalg_get_param(key->info->num_algs, key->keys, p))
                return 0;
            break;
        }
    }
    return 1;
}

int ossl_hybrid_kmgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;
    OSSL_PARAM prms[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned char *q;
    char *str;
    const OSSL_PARAM *p;
    unsigned int i;
    int type;

    if (ossl_param_is_empty(params))
        return 1;

    for (p = params; params->key != NULL; params++) {
        type = ossl_param_find_pidx(p->key);
        switch (type) {
        case PIDX_PKEY_PARAM_ENCODED_PUBLIC_KEY:
            if (key->pubkey_length != p->data_size) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH,
                               "length must be %u bytes, have %u bytes",
                               key->pubkey_length, p->data_size);
                return 0;
            }
            q = p->data;
            *prms = *p;
            for (i = 0; i < key->info->num_algs; i++) {
                prms->data = q;
                prms->data_size = key->info->alg[i].pubkey_length_bytes;
                q += key->info->alg[i].pubkey_length_bytes;
                if (!EVP_PKEY_set_params(key->keys[i], prms))
                    return 0;
            }
            break;

        case PIDX_PKEY_PARAM_PROPERTIES:
            str = NULL;     /* Force allocation of value */
            if (!OSSL_PARAM_get_utf8_string(p, &str, SIZE_MAX))
                return 0;
            OPENSSL_free(key->propq);
            key->propq = str;
            /* Fall through */

        default:
            if (!key_subalg_set_param(key->info->num_algs, key->keys, prms))
                return 0;
            break;
        }
    }
    return 1;
}

int ossl_hybrid_kmgmt_validate(const void *vctx, int selection, int checktype)
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    size_t key_length;
    unsigned int i;
    const int pub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    const int priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (!ossl_prov_is_running())
        return 0;
    if ((key_length = ctx->pubkey_length) == 0)
        return 0;

    if (pub || priv)
        for (i = 0; i < ctx->info->num_algs; i++)
            if ((priv && !EVP_PKEY_private_check(ctx->ctxs[i]))
                    || (pub && !EVP_PKEY_public_check(ctx->ctxs[i]))
                    || (pub && priv && !EVP_PKEY_pairwise_check(ctx->ctxs[i])))
                return 0;
    return 1;
}

void ossl_hybrid_pkey_ctx_free(HYBRID_PKEY_CTX *ctx)
{
    unsigned int i;

    if (ctx != NULL) {
        for (i = 0; i < ctx->info->num_algs; i++)
            EVP_PKEY_CTX_free(ctx->ctxs[i]);
        OPENSSL_free(ctx->propq);
        OPENSSL_free(ctx);
    }
}

HYBRID_PKEY_CTX *ossl_hybrid_pkey_ctx_alloc(OSSL_LIB_CTX *libctx,
                                            const HYBRID_ALG_INFO *info)
{
    HYBRID_PKEY_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    unsigned int i;

    if (ctx != NULL) {
        ctx->libctx = libctx;
        ctx->info = info;
        INIT_ACCUMULATE_HYBRID_NUMBERS(ctx);
        for (i = 0; i < ctx->info->num_algs; i++)
            ACCUMULATE_HYBRID_NUMBERS(ctx, i);
    }
    return ctx;
}

HYBRID_PKEY_CTX *ossl_hybrid_kmgmt_gen_init(void *provctx,
                                            int selection,
                                            const OSSL_PARAM params[],
                                            const HYBRID_ALG_INFO *info)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    HYBRID_PKEY_CTX *ctx;
    unsigned int i;

    ctx = ossl_hybrid_pkey_ctx_alloc(libctx, info);
    if (ctx == NULL)
        return NULL;

    for (i = 0; i < info->num_algs; i++) {
        EVP_PKEY_CTX_free(ctx->ctxs[i]);
        ctx->ctxs[i] = EVP_PKEY_CTX_new_from_name(libctx, info->alg[i].name,
                                                  ctx->propq);
        if (ctx->ctxs[i] == NULL || !EVP_PKEY_keygen_init(ctx->ctxs[i]))
            goto err;
    }

    if (!ossl_hybrid_kmgmt_gen_set_params(ctx, params))
        goto err;

    return ctx;
 err:
    ossl_hybrid_pkey_ctx_free(ctx);
    return NULL;
}

int ossl_hybrid_get_ctx_params(HYBRID_PKEY_CTX *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM prms[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned char *q;
    OSSL_PARAM *p;
    size_t t, ds, bytes_written = 0;
    unsigned int i;
    int type;

    if (ossl_param_is_empty(params))
        return 1;

    for (p = params; params->key != NULL; params++) {
        type = ossl_param_find_pidx(p->key);
        switch (type) {
        case PIDX_PKEY_PARAM_SECURITY_BITS:
            if (!OSSL_PARAM_set_size_t(p, ctx->security_bits))
                return 0;
            break;

        case PIDX_PKEY_PARAM_BITS:
            if (!OSSL_PARAM_set_size_t(p, ctx->bits))
                return 0;
            break;

        case PIDX_PKEY_PARAM_MAX_SIZE:
            if (!OSSL_PARAM_set_size_t(p, ctx->pubkey_length))
                return 0;
            break;

        case PIDX_PKEY_PARAM_ENCODED_PUBLIC_KEY:
            t = ctx->pubkey_length;
            if (t > p->data_size) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH,
                               "length must be %u bytes, have %u bytes",
                               t, p->data_size);
                p->data_size = t;
                return 0;
            }
            ds = p->data_size;
            p->data_size = t;
            q = p->data;
            *prms = *p;
            for (i = 0; i < ctx->info->num_algs; i++) {
                prms->data = q;
                prms->data_size = ctx->info->alg[i].pubkey_length_bytes;
                /* Confirm there is space in the param's data buffer */
                if (!ossl_assert(bytes_written 
                                 < ds - ctx->info->alg[i].pubkey_length_bytes))
                    return 0;
                q += ctx->info->alg[i].pubkey_length_bytes;
                bytes_written += ctx->info->alg[i].pubkey_length_bytes;
                OSSL_PARAM_set_all_unmodified(prms);
                if (!EVP_PKEY_CTX_get_params(ctx->ctxs[i], prms)
                        || !OSSL_PARAM_modified(prms))
                    return 0;
            }
            break;

        default:
            if (!ctx_subalg_get_param(ctx->info->num_algs, ctx->ctxs, p))
                return 0;
            break;
        }
    }
    return 1;
}

int ossl_hybrid_set_ctx_params(HYBRID_PKEY_CTX *ctx, const OSSL_PARAM params[])
{
    char *str = NULL;
    const OSSL_PARAM *p;

    if (ossl_param_is_empty(params))
        return 1;

    if (!ctx_subalg_set_param(ctx->info->num_algs, ctx->ctxs, params))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL)
        if (strcmp(p->key, OSSL_PKEY_PARAM_PROPERTIES) == 0) {
            if (!OSSL_PARAM_get_utf8_string(p, &str, SIZE_MAX))
                return 0;
            OPENSSL_free(ctx->propq);
            ctx->propq = str;
        }
    return 1;
}

int ossl_hybrid_kmgmt_gen_get_params(void *vctx, OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;

    return ossl_hybrid_get_ctx_params(ctx, params);
}

int ossl_hybrid_kmgmt_gen_set_params(void *vctx, const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;

    return ossl_hybrid_set_ctx_params(ctx, params);
}

void *ossl_hybrid_kmgmt_gen(void *vctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY *key = OPENSSL_zalloc(sizeof(*key));
    unsigned int i;

    if (key == NULL)
        return NULL;

    key->libctx = ctx->libctx;
    key->info = ctx->info;
    if (ctx->propq != NULL) {
        key->propq = OPENSSL_strdup(ctx->propq);
        if (key->propq == NULL)
            goto err;
    }
    INIT_ACCUMULATE_HYBRID_NUMBERS(key);
    for (i = 0; i < ctx->info->num_algs; i++) {
        if (EVP_PKEY_keygen(ctx->ctxs[i], key->keys + i) <= 0)
            goto err;
        ACCUMULATE_HYBRID_NUMBERS(key, i);
    }
    return key;
 err:
    ossl_hybrid_kmgmt_free(key);
    return NULL;
}

void ossl_hybrid_kmgmt_gen_cleanup(void *vctx)
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    unsigned int i;

    if (ctx != NULL) {
        for (i = 0; i < ctx->info->num_algs; i++)
            EVP_PKEY_CTX_free(ctx->ctxs[i]);
        OPENSSL_free(ctx->propq);
        OPENSSL_free(ctx);
    }
}

int ossl_hybrid_kmgmt_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)keydata;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char **pptr = NULL;
    size_t *plen = NULL;
    OSSL_PARAM *lprm = NULL;
    unsigned int i, j, k, nparams;
    size_t data_size;
    int res = 0;

    nparams = ossl_param_nelem(params);
    if (nparams == 0)
        return 0;

    /* Allocate storage for a copy of the OSSL_PARAMS and working pointers */
    lprm = OPENSSL_memdup(params, (1 + nparams) * sizeof(*params));
    pptr = OPENSSL_malloc(nparams * sizeof(*pptr));
    plen = OPENSSL_malloc(nparams * sizeof(*plen));
    if (lprm == NULL || pptr == NULL || plen == NULL)
        goto err;

    for (j = 0; j < nparams; j++) {
        pptr[j] = params[j].data;
        plen[j] = params[j].data_size;
    }

    /* For each key, build a set of OSSL_PARAMs */
    for (i = 0; i < key->info->num_algs; i++) {
        for (k = j = 0; j < nparams; j++) {
            /* Each is length prefixed in big endian format */
            if (plen[j] < 4)
                goto err;
            plen[j] -= 4;
            data_size = *pptr[j]++ << 24;
            data_size += *pptr[j]++ << 16;
            data_size += *pptr[j]++ << 8;
            data_size += *pptr[j]++;

            /* Only include this param if it's got an associated value */
            if (data_size > 0) {
                if (plen[j] < data_size)
                    goto err;
                lprm[k] = params[j];
                lprm[k].data = pptr[j];
                lprm[k++].data_size = data_size;
                pptr[j] += data_size;
                plen[j] -= data_size;
            }
        }
        /* Don't bother if there are no params */
        if (k > 0) {
            lprm[k] = OSSL_PARAM_construct_end();
            ctx = EVP_PKEY_CTX_new_from_name(key->libctx,
                                             key->info->alg[i].name,
                                             key->propq);
            if (ctx == NULL
                    || EVP_PKEY_fromdata_init(ctx) <= 0
                    || EVP_PKEY_fromdata(ctx, key->keys + i, selection,
                                         lprm) <= 0)
                goto err;
        }
    }
    res = 1;
 err:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(lprm);
    OPENSSL_free(pptr);
    OPENSSL_free(plen);
    return res;
}

typedef struct {
    unsigned int alg_n;
    unsigned int param_n;
    OSSL_PARAM params[MAX_HYBRID_PARAMS + 1];
    struct {
        unsigned char *data;
        size_t data_size;
    } *d[MAX_HYBRID_PARAMS][MAX_HYBRID_ALGS];
} HYBRID_EXPORT_CB_ARG;

static int hybrid_export_cb(const OSSL_PARAM params[], void *varg)
{
    HYBRID_EXPORT_CB_ARG *arg = (HYBRID_EXPORT_CB_ARG *)varg;
    unsigned char *data;
    unsigned int i;
    int pos;
    OSSL_PARAM *p;

    /* Record information about each OSSL_PARAM this algorithm exports */
    for (i = 0; params[i].key != NULL; i++) {
        if ((p = OSSL_PARAM_locate(arg->params, params[i].key)) == NULL) {
            if (arg->param_n == MAX_HYBRID_PARAMS)
                return 0;
            p = arg->params + arg->param_n++;
            memcpy(p, params + i, sizeof(*p));
            p->data = NULL;
            p->data_size = 0;
        }
        data = OPENSSL_memdup(params->data, params->data_size);
        if (data == NULL)
            return 0;
        pos = p - arg->params;
        arg->d[pos][arg->alg_n]->data = data;
        arg->d[pos][arg->alg_n]->data_size = params->data_size;
    }
    arg->alg_n++;
    return 1;
}

int ossl_hybrid_kmgmt_export(void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    HYBRID_PKEY *key = (HYBRID_PKEY *)keydata;
    HYBRID_EXPORT_CB_ARG arg;
    unsigned int i, j;
    int ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    /* Gather all the key data */
    memset(&arg, 0, sizeof(arg));
    for (i = 0; i < key->info->num_algs; i++)
        if (!EVP_PKEY_export(key->keys[i], selection,
                             &hybrid_export_cb, &arg))
            goto err;

    /* Package each OSSL_PARAM */
    for (i = 0; i < arg.param_n; i++) {
        size_t total = sizeof(size_t) * key->info->num_algs;
        unsigned char *p;

        /* Allocate sufficient space */
        for (j = 0; j < key->info->num_algs; j++)
            if (arg.d[i][j]->data != NULL)
                total += arg.d[i][j]->data_size;
        p = OPENSSL_malloc(total);
        if (p == NULL)
            goto err;

        /*
         * Concatenate each individual OSSL_PARAM together.
         * Each value is prefixed with its length in big endian order.
         */
        arg.params[i].data = p;
        for (j = 0; j < key->info->num_algs; j++) {
            *p++ = 0xff & (arg.d[i][j]->data_size >> 24);
            *p++ = 0xff & (arg.d[i][j]->data_size >> 16);
            *p++ = 0xff & (arg.d[i][j]->data_size >> 8);
            *p++ = 0xff & (arg.d[i][j]->data_size);

            if (arg.d[i][j]->data != NULL) {
                memcpy(p, arg.d[i][j]->data, arg.d[i][j]->data_size);
                p += arg.d[i][j]->data_size;
            }
        }
        arg.params[i].data_size = p - (unsigned char *)arg.params[i].data;
    }

    /* Finished, pass to caller's call back */
    arg.params[arg.param_n] = OSSL_PARAM_construct_end();
    ret = param_cb(arg.params, cbarg);
err:
    /* Be conservative and clear everything in case it's private */
    for (i = 0; i < arg.param_n; i++) {
        OPENSSL_clear_free(arg.params[i].data, arg.params[i].data_size);
        for (j = 0; j < arg.alg_n; j++)
            OPENSSL_clear_free(arg.d[i][j]->data, arg.d[i][j]->data_size);
    }
    return ret;
}

const OSSL_PARAM *ossl_hybrid_gettable_common(const OSSL_PARAM *r)
{
    return r->key == NULL ? NULL : r;
}

const OSSL_PARAM *ossl_hybrid_settable_common(const OSSL_PARAM *r)
{
    return r->key == NULL ? NULL : r;
}
