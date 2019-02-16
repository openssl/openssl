/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/evp_int.h"
#include "kdf_local.h"

static void kdf_tls1_prf_reset(EVP_KDF_IMPL *impl);
static int tls1_prf_alg(const EVP_MD *md,
                        const unsigned char *sec, size_t slen,
                        const unsigned char *seed, size_t seed_len,
                        unsigned char *out, size_t olen);

#define TLS1_PRF_MAXBUF 1024

/* TLS KDF kdf context structure */

struct evp_kdf_impl_st {
    /* Digest to use for PRF */
    const EVP_MD *md;
    /* Secret value to use for PRF */
    unsigned char *sec;
    size_t seclen;
    /* Buffer of concatenated seed data */
    unsigned char seed[TLS1_PRF_MAXBUF];
    size_t seedlen;
};

static EVP_KDF_IMPL *kdf_tls1_prf_new(void)
{
    EVP_KDF_IMPL *impl;

    if ((impl = OPENSSL_zalloc(sizeof(*impl))) == NULL)
        KDFerr(KDF_F_KDF_TLS1_PRF_NEW, ERR_R_MALLOC_FAILURE);
    return impl;
}

static void kdf_tls1_prf_free(EVP_KDF_IMPL *impl)
{
    kdf_tls1_prf_reset(impl);
    OPENSSL_free(impl);
}

static void kdf_tls1_prf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_clear_free(impl->sec, impl->seclen);
    OPENSSL_cleanse(impl->seed, impl->seedlen);
    memset(impl, 0, sizeof(*impl));
}

static int kdf_tls1_prf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    const unsigned char *p;
    size_t len;
    const EVP_MD *md;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_MD:
        md = va_arg(args, const EVP_MD *);
        if (md == NULL)
            return 0;

        impl->md = md;
        return 1;

    case EVP_KDF_CTRL_SET_TLS_SECRET:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        OPENSSL_clear_free(impl->sec, impl->seclen);
        impl->sec = OPENSSL_memdup(p, len);
        if (impl->sec == NULL)
            return 0;

        impl->seclen  = len;
        return 1;

    case EVP_KDF_CTRL_RESET_TLS_SEED:
        OPENSSL_cleanse(impl->seed, impl->seedlen);
        impl->seedlen = 0;
        return 1;

    case EVP_KDF_CTRL_ADD_TLS_SEED:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (len == 0 || p == NULL)
            return 1;

        if (len > (TLS1_PRF_MAXBUF - impl->seedlen))
            return 0;

        memcpy(impl->seed + impl->seedlen, p, len);
        impl->seedlen += len;
        return 1;

    default:
        return -2;
    }
}

static int kdf_tls1_prf_ctrl_str(EVP_KDF_IMPL *impl,
                                 const char *type, const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KDF_TLS1_PRF_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }
    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(impl, kdf_tls1_prf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "secret") == 0)
        return kdf_str2ctrl(impl, kdf_tls1_prf_ctrl,
                            EVP_KDF_CTRL_SET_TLS_SECRET, value);

    if (strcmp(type, "hexsecret") == 0)
        return kdf_hex2ctrl(impl, kdf_tls1_prf_ctrl,
                            EVP_KDF_CTRL_SET_TLS_SECRET, value);

    if (strcmp(type, "seed") == 0)
        return kdf_str2ctrl(impl, kdf_tls1_prf_ctrl, EVP_KDF_CTRL_ADD_TLS_SEED,
                            value);

    if (strcmp(type, "hexseed") == 0)
        return kdf_hex2ctrl(impl, kdf_tls1_prf_ctrl, EVP_KDF_CTRL_ADD_TLS_SEED,
                            value);

    return -2;
}

static int kdf_tls1_prf_derive(EVP_KDF_IMPL *impl, unsigned char *key,
                               size_t keylen)
{
    if (impl->md == NULL) {
        KDFerr(KDF_F_KDF_TLS1_PRF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (impl->sec == NULL) {
        KDFerr(KDF_F_KDF_TLS1_PRF_DERIVE, KDF_R_MISSING_SECRET);
        return 0;
    }
    if (impl->seedlen == 0) {
        KDFerr(KDF_F_KDF_TLS1_PRF_DERIVE, KDF_R_MISSING_SEED);
        return 0;
    }
    return tls1_prf_alg(impl->md, impl->sec, impl->seclen,
                        impl->seed, impl->seedlen,
                        key, keylen);
}

const EVP_KDF_METHOD tls1_prf_kdf_meth = {
    EVP_KDF_TLS1_PRF,
    kdf_tls1_prf_new,
    kdf_tls1_prf_free,
    kdf_tls1_prf_reset,
    kdf_tls1_prf_ctrl,
    kdf_tls1_prf_ctrl_str,
    NULL,
    kdf_tls1_prf_derive
};

static int tls1_prf_P_hash(const EVP_MD *md,
                           const unsigned char *sec, size_t sec_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char *out, size_t olen)
{
    int chunk;
    EVP_MAC_CTX *ctx = NULL, *ctx_tmp = NULL, *ctx_init = NULL;
    unsigned char A1[EVP_MAX_MD_SIZE];
    size_t A1_len;
    int ret = 0;

    chunk = EVP_MD_size(md);
    if (!ossl_assert(chunk > 0))
        goto err;

    ctx = EVP_MAC_CTX_new_id(EVP_MAC_HMAC);
    ctx_tmp = EVP_MAC_CTX_new_id(EVP_MAC_HMAC);
    ctx_init = EVP_MAC_CTX_new_id(EVP_MAC_HMAC);
    if (ctx == NULL || ctx_tmp == NULL || ctx_init == NULL)
        goto err;
    if (EVP_MAC_ctrl(ctx_init, EVP_MAC_CTRL_SET_FLAGS, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW) != 1)
        goto err;
    if (EVP_MAC_ctrl(ctx_init, EVP_MAC_CTRL_SET_MD, md) != 1)
        goto err;
    if (EVP_MAC_ctrl(ctx_init, EVP_MAC_CTRL_SET_KEY, sec, sec_len) != 1)
        goto err;
    if (!EVP_MAC_init(ctx_init))
        goto err;
    if (!EVP_MAC_CTX_copy(ctx, ctx_init))
        goto err;
    if (seed != NULL && !EVP_MAC_update(ctx, seed, seed_len))
        goto err;
    if (!EVP_MAC_final(ctx, A1, &A1_len))
        goto err;

    for (;;) {
        /* Reinit mac contexts */
        if (!EVP_MAC_CTX_copy(ctx, ctx_init))
            goto err;
        if (!EVP_MAC_update(ctx, A1, A1_len))
            goto err;
        if (olen > (size_t)chunk && !EVP_MAC_CTX_copy(ctx_tmp, ctx))
            goto err;
        if (seed != NULL && !EVP_MAC_update(ctx, seed, seed_len))
            goto err;

        if (olen > (size_t)chunk) {
            size_t mac_len;
            if (!EVP_MAC_final(ctx, out, &mac_len))
                goto err;
            out += mac_len;
            olen -= mac_len;
            /* calc the next A1 value */
            if (!EVP_MAC_final(ctx_tmp, A1, &A1_len))
                goto err;
        } else {                /* last one */

            if (!EVP_MAC_final(ctx, A1, &A1_len))
                goto err;
            memcpy(out, A1, olen);
            break;
        }
    }
    ret = 1;
 err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_tmp);
    EVP_MAC_CTX_free(ctx_init);
    OPENSSL_cleanse(A1, sizeof(A1));
    return ret;
}

static int tls1_prf_alg(const EVP_MD *md,
                        const unsigned char *sec, size_t slen,
                        const unsigned char *seed, size_t seed_len,
                        unsigned char *out, size_t olen)
{
    if (EVP_MD_type(md) == NID_md5_sha1) {
        size_t i;
        unsigned char *tmp;
        if (!tls1_prf_P_hash(EVP_md5(), sec, slen/2 + (slen & 1),
                             seed, seed_len, out, olen))
            return 0;

        if ((tmp = OPENSSL_malloc(olen)) == NULL) {
            KDFerr(KDF_F_TLS1_PRF_ALG, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!tls1_prf_P_hash(EVP_sha1(), sec + slen/2, slen/2 + (slen & 1),
                             seed, seed_len, tmp, olen)) {
            OPENSSL_clear_free(tmp, olen);
            return 0;
        }
        for (i = 0; i < olen; i++)
            out[i] ^= tmp[i];
        OPENSSL_clear_free(tmp, olen);
        return 1;
    }
    if (!tls1_prf_P_hash(md, sec, slen, seed, seed_len, out, olen))
        return 0;

    return 1;
}
