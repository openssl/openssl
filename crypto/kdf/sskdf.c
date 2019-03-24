/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Refer to https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final
 * Section 4.1.
 *
 * The Single Step KDF algorithm is given by:
 *
 * Result(0) = empty bit string (i.e., the null string).
 * For i = 1 to reps, do the following:
 *   Increment counter by 1.
 *   Result(i) = Result(i – 1) || H(counter || Z || FixedInfo).
 * DKM = LeftmostBits(Result(reps), L))
 *
 * NOTES:
 *   Z is a shared secret required to produce the derived key material.
 *   counter is a 4 byte buffer.
 *   FixedInfo is a bit string containing context specific data.
 *   DKM is the output derived key material.
 *   L is the required size of the DKM.
 *   reps = [L / H_outputBits]
 *   H(x) is the auxiliary function that can be either a hash, HMAC or KMAC.
 *   H_outputBits is the length of the output of the auxiliary function H(x).
 *
 * Currently there is not a comprehensive list of test vectors for this
 * algorithm, especially for H(x) = HMAC and H(x) = KMAC.
 * Test vectors for H(x) = Hash are indirectly used by CAVS KAS tests.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include "kdf_local.h"

struct evp_kdf_impl_st {
    const EVP_MAC *mac; /* H(x) = HMAC_hash OR H(x) = KMAC */
    const EVP_MD *md;   /* H(x) = hash OR when H(x) = HMAC_hash */
    unsigned char *secret;
    size_t secret_len;
    unsigned char *info;
    size_t info_len;
    unsigned char *salt;
    size_t salt_len;
    size_t out_len; /* optional KMAC parameter */
};

#define SSKDF_MAX_INLEN (1<<30)
#define SSKDF_KMAC128_DEFAULT_SALT_SIZE (168 - 4)
#define SSKDF_KMAC256_DEFAULT_SALT_SIZE (136 - 4)

/* KMAC uses a Customisation string of 'KDF' */
static const unsigned char kmac_custom_str[] = { 0x4B, 0x44, 0x46 };

/*
 * Refer to https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final
 * Section 4. One-Step Key Derivation using H(x) = hash(x)
 */
static int SSKDF_hash_kdm(const EVP_MD *kdf_md,
                          const unsigned char *z, size_t z_len,
                          const unsigned char *info, size_t info_len,
                          unsigned char *derived_key, size_t derived_key_len)
{
    int ret = 0, hlen;
    size_t counter, out_len, len = derived_key_len;
    unsigned char c[4];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char *out = derived_key;
    EVP_MD_CTX *ctx = NULL, *ctx_init = NULL;

    if (z_len > SSKDF_MAX_INLEN || info_len > SSKDF_MAX_INLEN
            || derived_key_len > SSKDF_MAX_INLEN
            || derived_key_len == 0)
        return 0;

    hlen = EVP_MD_size(kdf_md);
    if (hlen <= 0)
        return 0;
    out_len = (size_t)hlen;

    ctx = EVP_MD_CTX_create();
    ctx_init = EVP_MD_CTX_create();
    if (ctx == NULL || ctx_init == NULL)
        goto end;

    if (!EVP_DigestInit(ctx_init, kdf_md))
        goto end;

    for (counter = 1;; counter++) {
        c[0] = (unsigned char)((counter >> 24) & 0xff);
        c[1] = (unsigned char)((counter >> 16) & 0xff);
        c[2] = (unsigned char)((counter >> 8) & 0xff);
        c[3] = (unsigned char)(counter & 0xff);

        if (!(EVP_MD_CTX_copy_ex(ctx, ctx_init)
                && EVP_DigestUpdate(ctx, c, sizeof(c))
                && EVP_DigestUpdate(ctx, z, z_len)
                && EVP_DigestUpdate(ctx, info, info_len)))
            goto end;
        if (len >= out_len) {
            if (!EVP_DigestFinal_ex(ctx, out, NULL))
                goto end;
            out += out_len;
            len -= out_len;
            if (len == 0)
                break;
        } else {
            if (!EVP_DigestFinal_ex(ctx, mac, NULL))
                goto end;
            memcpy(out, mac, len);
            break;
        }
    }
    ret = 1;
end:
    EVP_MD_CTX_destroy(ctx);
    EVP_MD_CTX_destroy(ctx_init);
    OPENSSL_cleanse(mac, sizeof(mac));
    return ret;
}

static int kmac_init(EVP_MAC_CTX *ctx, const unsigned char *custom,
                     size_t custom_len, size_t kmac_out_len,
                     size_t derived_key_len, unsigned char **out)
{
    /* Only KMAC has custom data - so return if not KMAC */
    if (custom == NULL)
        return 1;

    if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_CUSTOM, custom, custom_len) <= 0)
        return 0;

    /* By default only do one iteration if kmac_out_len is not specified */
    if (kmac_out_len == 0)
        kmac_out_len = derived_key_len;
    /* otherwise check the size is valid */
    else if (!(kmac_out_len == derived_key_len
            || kmac_out_len == 20
            || kmac_out_len == 28
            || kmac_out_len == 32
            || kmac_out_len == 48
            || kmac_out_len == 64))
        return 0;

    if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_SIZE, kmac_out_len) <= 0)
        return 0;

    /*
     * For kmac the output buffer can be larger than EVP_MAX_MD_SIZE: so
     * alloc a buffer for this case.
     */
    if (kmac_out_len > EVP_MAX_MD_SIZE) {
        *out = OPENSSL_zalloc(kmac_out_len);
        if (*out == NULL)
            return 0;
    }
    return 1;
}

/*
 * Refer to https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final
 * Section 4. One-Step Key Derivation using MAC: i.e either
 *     H(x) = HMAC-hash(salt, x) OR
 *     H(x) = KMAC#(salt, x, outbits, CustomString='KDF')
 */
static int SSKDF_mac_kdm(const EVP_MAC *kdf_mac, const EVP_MD *hmac_md,
                         const unsigned char *kmac_custom,
                         size_t kmac_custom_len, size_t kmac_out_len,
                         const unsigned char *salt, size_t salt_len,
                         const unsigned char *z, size_t z_len,
                         const unsigned char *info, size_t info_len,
                         unsigned char *derived_key, size_t derived_key_len)
{
    int ret = 0;
    size_t counter, out_len, len;
    unsigned char c[4];
    unsigned char mac_buf[EVP_MAX_MD_SIZE];
    unsigned char *out = derived_key;
    EVP_MAC_CTX *ctx = NULL, *ctx_init = NULL;
    unsigned char *mac = mac_buf, *kmac_buffer = NULL;

    if (z_len > SSKDF_MAX_INLEN || info_len > SSKDF_MAX_INLEN
            || derived_key_len > SSKDF_MAX_INLEN
            || derived_key_len == 0)
        return 0;

    ctx = EVP_MAC_CTX_new(kdf_mac);
    ctx_init = EVP_MAC_CTX_new(kdf_mac);
    if (ctx == NULL || ctx_init == NULL)
        goto end;
    if (hmac_md != NULL &&
            EVP_MAC_ctrl(ctx_init, EVP_MAC_CTRL_SET_MD, hmac_md) <= 0)
        goto end;

    if (EVP_MAC_ctrl(ctx_init, EVP_MAC_CTRL_SET_KEY, salt, salt_len) <= 0)
        goto end;

    if (!kmac_init(ctx_init, kmac_custom, kmac_custom_len, kmac_out_len,
                   derived_key_len, &kmac_buffer))
        goto end;
    if (kmac_buffer != NULL)
        mac = kmac_buffer;

    if (!EVP_MAC_init(ctx_init))
        goto end;

    out_len = EVP_MAC_size(ctx_init); /* output size */
    if (out_len <= 0)
        goto end;
    len = derived_key_len;

    for (counter = 1;; counter++) {
        c[0] = (unsigned char)((counter >> 24) & 0xff);
        c[1] = (unsigned char)((counter >> 16) & 0xff);
        c[2] = (unsigned char)((counter >> 8) & 0xff);
        c[3] = (unsigned char)(counter & 0xff);

        if (!(EVP_MAC_CTX_copy(ctx, ctx_init)
                && EVP_MAC_update(ctx, c, sizeof(c))
                && EVP_MAC_update(ctx, z, z_len)
                && EVP_MAC_update(ctx, info, info_len)))
            goto end;
        if (len >= out_len) {
            if (!EVP_MAC_final(ctx, out, NULL))
                goto end;
            out += out_len;
            len -= out_len;
            if (len == 0)
                break;
        } else {
            if (!EVP_MAC_final(ctx, mac, NULL))
                goto end;
            memcpy(out, mac, len);
            break;
        }
    }
    ret = 1;
end:
    if (kmac_buffer != NULL)
        OPENSSL_clear_free(kmac_buffer, kmac_out_len);
    else
        OPENSSL_cleanse(mac_buf, sizeof(mac_buf));

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_init);
    return ret;
}

static EVP_KDF_IMPL *sskdf_new(void)
{
    EVP_KDF_IMPL *impl;

    if ((impl = OPENSSL_zalloc(sizeof(*impl))) == NULL)
        KDFerr(KDF_F_SSKDF_NEW, ERR_R_MALLOC_FAILURE);
    return impl;
}

static void sskdf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_clear_free(impl->secret, impl->secret_len);
    OPENSSL_clear_free(impl->info, impl->info_len);
    OPENSSL_clear_free(impl->salt, impl->salt_len);
    memset(impl, 0, sizeof(*impl));
}

static void sskdf_free(EVP_KDF_IMPL *impl)
{
    sskdf_reset(impl);
    OPENSSL_free(impl);
}

static int sskdf_set_buffer(va_list args, unsigned char **out, size_t *out_len)
{
    const unsigned char *p;
    size_t len;

    p = va_arg(args, const unsigned char *);
    len = va_arg(args, size_t);
    if (len == 0 || p == NULL)
        return 1;

    OPENSSL_free(*out);
    *out = OPENSSL_memdup(p, len);
    if (*out == NULL)
        return 0;

    *out_len = len;
    return 1;
}

static int sskdf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    const EVP_MD *md;
    const EVP_MAC *mac;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_KEY:
        return sskdf_set_buffer(args, &impl->secret, &impl->secret_len);

    case EVP_KDF_CTRL_SET_SSKDF_INFO:
        return sskdf_set_buffer(args, &impl->info, &impl->info_len);

    case EVP_KDF_CTRL_SET_MD:
        md = va_arg(args, const EVP_MD *);
        if (md == NULL)
            return 0;

        impl->md = md;
        return 1;

    case EVP_KDF_CTRL_SET_MAC:
        mac = va_arg(args, const EVP_MAC *);
        if (mac == NULL)
            return 0;

        impl->mac = mac;
        return 1;

    case EVP_KDF_CTRL_SET_SALT:
        return sskdf_set_buffer(args, &impl->salt, &impl->salt_len);

    case EVP_KDF_CTRL_SET_MAC_SIZE:
        impl->out_len = va_arg(args, size_t);
        return 1;

    default:
        return -2;
    }
}

/* Pass a mac to a ctrl */
static int sskdf_mac2ctrl(EVP_KDF_IMPL *impl,
                          int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                          int cmd, const char *mac_name)
{
    const EVP_MAC *mac;

    if (mac_name == NULL || (mac = EVP_get_macbyname(mac_name)) == NULL) {
        KDFerr(KDF_F_SSKDF_MAC2CTRL, KDF_R_INVALID_MAC_TYPE);
        return 0;
    }
    return call_ctrl(ctrl, impl, cmd, mac);
}

static int sskdf_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                          const char *value)
{
    if (strcmp(type, "secret") == 0 || strcmp(type, "key") == 0)
         return kdf_str2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_KEY,
                             value);

    if (strcmp(type, "hexsecret") == 0 || strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_KEY,
                            value);

    if (strcmp(type, "info") == 0)
        return kdf_str2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_SSKDF_INFO,
                            value);

    if (strcmp(type, "hexinfo") == 0)
        return kdf_hex2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_SSKDF_INFO,
                            value);

    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "mac") == 0)
        return sskdf_mac2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_MAC, value);

    if (strcmp(type, "salt") == 0)
        return kdf_str2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_SALT, value);

    if (strcmp(type, "hexsalt") == 0)
        return kdf_hex2ctrl(impl, sskdf_ctrl, EVP_KDF_CTRL_SET_SALT, value);


    if (strcmp(type, "maclen") == 0) {
        int val = atoi(value);
        if (val < 0) {
            KDFerr(KDF_F_SSKDF_CTRL_STR, KDF_R_VALUE_ERROR);
            return 0;
        }
        return call_ctrl(sskdf_ctrl, impl, EVP_KDF_CTRL_SET_MAC_SIZE,
                         (size_t)val);
    }
    return -2;
}

static size_t sskdf_size(EVP_KDF_IMPL *impl)
{
    int len;

    if (impl->md == NULL) {
        KDFerr(KDF_F_SSKDF_SIZE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    len = EVP_MD_size(impl->md);
    return (len <= 0) ? 0 : (size_t)len;
}

static int sskdf_derive(EVP_KDF_IMPL *impl, unsigned char *key, size_t keylen)
{
    if (impl->secret == NULL) {
        KDFerr(KDF_F_SSKDF_DERIVE, KDF_R_MISSING_SECRET);
        return 0;
    }

    if (impl->mac != NULL) {
        /* H(x) = KMAC or H(x) = HMAC */
        int ret;
        const unsigned char *custom = NULL;
        size_t custom_len = 0;
        int nid;
        int default_salt_len;

        nid = EVP_MAC_nid(impl->mac);
        if (nid == EVP_MAC_HMAC) {
            /* H(x) = HMAC(x, salt, hash) */
            if (impl->md == NULL) {
                KDFerr(KDF_F_SSKDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
                return 0;
            }
            default_salt_len = EVP_MD_block_size(impl->md);
            if (default_salt_len <= 0)
                return 0;
        } else if (nid == EVP_MAC_KMAC128 || nid == EVP_MAC_KMAC256) {
            /* H(x) = KMACzzz(x, salt, custom) */
            custom = kmac_custom_str;
            custom_len = sizeof(kmac_custom_str);
            if (nid == EVP_MAC_KMAC128)
                default_salt_len = SSKDF_KMAC128_DEFAULT_SALT_SIZE;
            else
                default_salt_len = SSKDF_KMAC256_DEFAULT_SALT_SIZE;
        } else {
            KDFerr(KDF_F_SSKDF_DERIVE, KDF_R_UNSUPPORTED_MAC_TYPE);
            return 0;
        }
        /* If no salt is set then use a default_salt of zeros */
        if (impl->salt == NULL || impl->salt_len <= 0) {
            impl->salt = OPENSSL_zalloc(default_salt_len);
            if (impl->salt == NULL) {
                KDFerr(KDF_F_SSKDF_DERIVE, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            impl->salt_len = default_salt_len;
        }
        ret = SSKDF_mac_kdm(impl->mac, impl->md,
                            custom, custom_len, impl->out_len,
                            impl->salt, impl->salt_len,
                            impl->secret, impl->secret_len,
                            impl->info, impl->info_len, key, keylen);
        return ret;
    } else {
        /* H(x) = hash */
        if (impl->md == NULL) {
            KDFerr(KDF_F_SSKDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
            return 0;
        }
        return SSKDF_hash_kdm(impl->md, impl->secret, impl->secret_len,
                              impl->info, impl->info_len, key, keylen);
    }
}

const EVP_KDF_METHOD ss_kdf_meth = {
    EVP_KDF_SS,
    sskdf_new,
    sskdf_free,
    sskdf_reset,
    sskdf_ctrl,
    sskdf_ctrl_str,
    sskdf_size,
    sskdf_derive
};
