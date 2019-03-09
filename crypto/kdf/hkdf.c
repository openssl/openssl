/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "internal/evp_int.h"
#include "kdf_local.h"

#define HKDF_MAXBUF 1024

static void kdf_hkdf_reset(EVP_KDF_IMPL *impl);
static int HKDF(const EVP_MD *evp_md,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *key, size_t key_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t okm_len);
static int HKDF_Extract(const EVP_MD *evp_md,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *prk, size_t prk_len);
static int HKDF_Expand(const EVP_MD *evp_md,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len);

struct evp_kdf_impl_st {
    int mode;
    const EVP_MD *md;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char info[HKDF_MAXBUF];
    size_t info_len;
};

static EVP_KDF_IMPL *kdf_hkdf_new(void)
{
    EVP_KDF_IMPL *impl;

    if ((impl = OPENSSL_zalloc(sizeof(*impl))) == NULL)
        KDFerr(KDF_F_KDF_HKDF_NEW, ERR_R_MALLOC_FAILURE);
    return impl;
}

static void kdf_hkdf_free(EVP_KDF_IMPL *impl)
{
    kdf_hkdf_reset(impl);
    OPENSSL_free(impl);
}

static void kdf_hkdf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_free(impl->salt);
    OPENSSL_clear_free(impl->key, impl->key_len);
    OPENSSL_cleanse(impl->info, impl->info_len);
    memset(impl, 0, sizeof(*impl));
}

static int kdf_hkdf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
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

    case EVP_KDF_CTRL_SET_HKDF_MODE:
        impl->mode = va_arg(args, int);
        return 1;

    case EVP_KDF_CTRL_SET_SALT:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (len == 0 || p == NULL)
            return 1;

        OPENSSL_free(impl->salt);
        impl->salt = OPENSSL_memdup(p, len);
        if (impl->salt == NULL)
            return 0;

        impl->salt_len = len;
        return 1;

    case EVP_KDF_CTRL_SET_KEY:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        OPENSSL_clear_free(impl->key, impl->key_len);
        impl->key = OPENSSL_memdup(p, len);
        if (impl->key == NULL)
            return 0;

        impl->key_len  = len;
        return 1;

    case EVP_KDF_CTRL_RESET_HKDF_INFO:
        OPENSSL_cleanse(impl->info, impl->info_len);
        impl->info_len = 0;
        return 1;

    case EVP_KDF_CTRL_ADD_HKDF_INFO:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (len == 0 || p == NULL)
            return 1;

        if (len > (HKDF_MAXBUF - impl->info_len))
            return 0;

        memcpy(impl->info + impl->info_len, p, len);
        impl->info_len += len;
        return 1;

    default:
        return -2;
    }
}

static int kdf_hkdf_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                             const char *value)
{
    if (strcmp(type, "mode") == 0) {
        int mode;

        if (strcmp(value, "EXTRACT_AND_EXPAND") == 0)
            mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        else if (strcmp(value, "EXTRACT_ONLY") == 0)
            mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        else if (strcmp(value, "EXPAND_ONLY") == 0)
            mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        else
            return 0;

        return call_ctrl(kdf_hkdf_ctrl, impl, EVP_KDF_CTRL_SET_HKDF_MODE, mode);
    }

    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "salt") == 0)
        return kdf_str2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_SET_SALT, value);

    if (strcmp(type, "hexsalt") == 0)
        return kdf_hex2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_SET_SALT, value);

    if (strcmp(type, "key") == 0)
        return kdf_str2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "info") == 0)
        return kdf_str2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_ADD_HKDF_INFO,
                            value);

    if (strcmp(type, "hexinfo") == 0)
        return kdf_hex2ctrl(impl, kdf_hkdf_ctrl, EVP_KDF_CTRL_ADD_HKDF_INFO,
                            value);

    return -2;
}

static size_t kdf_hkdf_size(EVP_KDF_IMPL *impl)
{
    if (impl->mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
        return SIZE_MAX;

    if (impl->md == NULL) {
        KDFerr(KDF_F_KDF_HKDF_SIZE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    return EVP_MD_size(impl->md);
}

static int kdf_hkdf_derive(EVP_KDF_IMPL *impl, unsigned char *key,
                           size_t keylen)
{
    if (impl->md == NULL) {
        KDFerr(KDF_F_KDF_HKDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (impl->key == NULL) {
        KDFerr(KDF_F_KDF_HKDF_DERIVE, KDF_R_MISSING_KEY);
        return 0;
    }

    switch (impl->mode) {
    case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
        return HKDF(impl->md, impl->salt, impl->salt_len, impl->key,
                    impl->key_len, impl->info, impl->info_len, key,
                    keylen);

    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        return HKDF_Extract(impl->md, impl->salt, impl->salt_len, impl->key,
                            impl->key_len, key, keylen);

    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        return HKDF_Expand(impl->md, impl->key, impl->key_len, impl->info,
                           impl->info_len, key, keylen);

    default:
        return 0;
    }
}

const EVP_KDF_METHOD hkdf_kdf_meth = {
    EVP_KDF_HKDF,
    kdf_hkdf_new,
    kdf_hkdf_free,
    kdf_hkdf_reset,
    kdf_hkdf_ctrl,
    kdf_hkdf_ctrl_str,
    kdf_hkdf_size,
    kdf_hkdf_derive
};

static int HKDF(const EVP_MD *evp_md,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *key, size_t key_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    int ret;
    size_t prk_len = EVP_MD_size(evp_md);

    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, prk_len))
        return 0;

    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));

    return ret;
}

static int HKDF_Extract(const EVP_MD *evp_md,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *key, size_t key_len,
                        unsigned char *prk, size_t prk_len)
{
    if (prk_len != (size_t)EVP_MD_size(evp_md)) {
        KDFerr(KDF_F_HKDF_EXTRACT, KDF_R_WRONG_OUTPUT_BUFFER_SIZE);
        return 0;
    }
    return HMAC(evp_md, salt, salt_len, key, key_len, prk, NULL) != NULL;
}

static int HKDF_Expand(const EVP_MD *evp_md,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    int ret = 0;
    unsigned int i;
    unsigned char prev[EVP_MAX_MD_SIZE];
    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);
    size_t n = okm_len / dig_len;

    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return 0;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return 0;

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;

        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmac, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmac, info, info_len))
            goto err;

        if (!HMAC_Update(hmac, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmac, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = 1;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}
