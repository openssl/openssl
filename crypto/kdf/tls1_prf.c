/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Refer to "The TLS Protocol Version 1.0" Section 5
 * (https://tools.ietf.org/html/rfc2246#section-5) and
 * "The Transport Layer Security (TLS) Protocol Version 1.2" Section 5
 * (https://tools.ietf.org/html/rfc5246#section-5).
 *
 * For TLS v1.0 and TLS v1.1 the TLS PRF algorithm is given by:
 *
 *   PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
 *                              P_SHA-1(S2, label + seed)
 *
 * where P_MD5 and P_SHA-1 are defined by P_<hash>, below, and S1 and S2 are
 * two halves of the secret (with the possibility of one shared byte, in the
 * case where the length of the original secret is odd).  S1 is taken from the
 * first half of the secret, S2 from the second half.
 *
 * For TLS v1.2 the TLS PRF algorithm is given by:
 *
 *   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 * where hash is SHA-256 for all cipher suites defined in RFC 5246 as well as
 * those published prior to TLS v1.2 while the TLS v1.2 protocol is in effect,
 * unless defined otherwise by the cipher suite.
 *
 * P_<hash> is an expansion function that uses a single hash function to expand
 * a secret and seed into an arbitrary quantity of output:
 *
 *   P_<hash>(secret, seed) = HMAC_<hash>(secret, A(1) + seed) +
 *                            HMAC_<hash>(secret, A(2) + seed) +
 *                            HMAC_<hash>(secret, A(3) + seed) + ...
 *
 * where + indicates concatenation.  P_<hash> can be iterated as many times as
 * is necessary to produce the required quantity of data.
 *
 * A(i) is defined as:
 *     A(0) = seed
 *     A(i) = HMAC_<hash>(secret, A(i-1))
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
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

        impl->seclen = len;
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

const EVP_KDF tls1_prf_kdf_meth = {
    EVP_KDF_TLS1_PRF,
    kdf_tls1_prf_new,
    kdf_tls1_prf_free,
    kdf_tls1_prf_reset,
    kdf_tls1_prf_ctrl,
    kdf_tls1_prf_ctrl_str,
    NULL,
    kdf_tls1_prf_derive
};

/*
 * Refer to "The TLS Protocol Version 1.0" Section 5
 * (https://tools.ietf.org/html/rfc2246#section-5) and
 * "The Transport Layer Security (TLS) Protocol Version 1.2" Section 5
 * (https://tools.ietf.org/html/rfc5246#section-5).
 *
 * P_<hash> is an expansion function that uses a single hash function to expand
 * a secret and seed into an arbitrary quantity of output:
 *
 *   P_<hash>(secret, seed) = HMAC_<hash>(secret, A(1) + seed) +
 *                            HMAC_<hash>(secret, A(2) + seed) +
 *                            HMAC_<hash>(secret, A(3) + seed) + ...
 *
 * where + indicates concatenation.  P_<hash> can be iterated as many times as
 * is necessary to produce the required quantity of data.
 *
 * A(i) is defined as:
 *     A(0) = seed
 *     A(i) = HMAC_<hash>(secret, A(i-1))
 */
static int tls1_prf_P_hash(const EVP_MD *md,
                           const unsigned char *sec, size_t sec_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char *out, size_t olen)
{
    size_t chunk;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL, *ctx_Ai = NULL, *ctx_init = NULL;
    unsigned char Ai[EVP_MAX_MD_SIZE];
    size_t Ai_len;
    int ret = 0;
    OSSL_PARAM params[4];
    int mac_flags;
    const char *mdname = EVP_MD_name(md);

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL); /* Implicit fetch */
    ctx_init = EVP_MAC_CTX_new(mac);
    if (ctx_init == NULL)
        goto err;

    /* TODO(3.0) rethink "flags", also see hmac.c in providers */
    mac_flags = EVP_MD_CTX_FLAG_NON_FIPS_ALLOW;
    params[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_FLAGS, &mac_flags);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_ALGORITHM,
                                                 (char *)mdname,
                                                 strlen(mdname) + 1);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                  (void *)sec, sec_len);
    params[3] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_CTX_set_params(ctx_init, params))
        goto err;
    if (!EVP_MAC_init(ctx_init))
        goto err;
    chunk = EVP_MAC_size(ctx_init);
    if (chunk == 0)
        goto err;
    /* A(0) = seed */
    ctx_Ai = EVP_MAC_CTX_dup(ctx_init);
    if (ctx_Ai == NULL)
        goto err;
    if (seed != NULL && !EVP_MAC_update(ctx_Ai, seed, seed_len))
        goto err;

    for (;;) {
        /* calc: A(i) = HMAC_<hash>(secret, A(i-1)) */
        if (!EVP_MAC_final(ctx_Ai, Ai, &Ai_len, sizeof(Ai)))
            goto err;
        EVP_MAC_CTX_free(ctx_Ai);
        ctx_Ai = NULL;

        /* calc next chunk: HMAC_<hash>(secret, A(i) + seed) */
        ctx = EVP_MAC_CTX_dup(ctx_init);
        if (ctx == NULL)
            goto err;
        if (!EVP_MAC_update(ctx, Ai, Ai_len))
            goto err;
        /* save state for calculating next A(i) value */
        if (olen > chunk) {
            ctx_Ai = EVP_MAC_CTX_dup(ctx);
            if (ctx_Ai == NULL)
                goto err;
        }
        if (seed != NULL && !EVP_MAC_update(ctx, seed, seed_len))
            goto err;
        if (olen <= chunk) {
            /* last chunk - use Ai as temp bounce buffer */
            if (!EVP_MAC_final(ctx, Ai, &Ai_len, sizeof(Ai)))
                goto err;
            memcpy(out, Ai, olen);
            break;
        }
        if (!EVP_MAC_final(ctx, out, NULL, olen))
            goto err;
        EVP_MAC_CTX_free(ctx);
        ctx = NULL;
        out += chunk;
        olen -= chunk;
    }
    ret = 1;
 err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_Ai);
    EVP_MAC_CTX_free(ctx_init);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(Ai, sizeof(Ai));
    return ret;
}

/*
 * Refer to "The TLS Protocol Version 1.0" Section 5
 * (https://tools.ietf.org/html/rfc2246#section-5) and
 * "The Transport Layer Security (TLS) Protocol Version 1.2" Section 5
 * (https://tools.ietf.org/html/rfc5246#section-5).
 *
 * For TLS v1.0 and TLS v1.1:
 *
 *   PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
 *                              P_SHA-1(S2, label + seed)
 *
 * S1 is taken from the first half of the secret, S2 from the second half.
 *
 *   L_S = length in bytes of secret;
 *   L_S1 = L_S2 = ceil(L_S / 2);
 *
 * For TLS v1.2:
 *
 *   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 */
static int tls1_prf_alg(const EVP_MD *md,
                        const unsigned char *sec, size_t slen,
                        const unsigned char *seed, size_t seed_len,
                        unsigned char *out, size_t olen)
{
    if (EVP_MD_type(md) == NID_md5_sha1) {
        /* TLS v1.0 and TLS v1.1 */
        size_t i;
        unsigned char *tmp;
        /* calc: L_S1 = L_S2 = ceil(L_S / 2) */
        size_t L_S1 = (slen + 1) / 2;
        size_t L_S2 = L_S1;

        if (!tls1_prf_P_hash(EVP_md5(), sec, L_S1,
                             seed, seed_len, out, olen))
            return 0;

        if ((tmp = OPENSSL_malloc(olen)) == NULL) {
            KDFerr(KDF_F_TLS1_PRF_ALG, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!tls1_prf_P_hash(EVP_sha1(), sec + slen - L_S2, L_S2,
                             seed, seed_len, tmp, olen)) {
            OPENSSL_clear_free(tmp, olen);
            return 0;
        }
        for (i = 0; i < olen; i++)
            out[i] ^= tmp[i];
        OPENSSL_clear_free(tmp, olen);
        return 1;
    }

    /* TLS v1.2 */
    if (!tls1_prf_P_hash(md, sec, slen, seed, seed_len, out, olen))
        return 0;

    return 1;
}
