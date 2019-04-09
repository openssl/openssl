/*
 * Copyright 2018-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "internal/evp_int.h"
#include "kdf_local.h"

/* See RFC 4253, Section 7.2 */

static void kdf_sshkdf_reset(EVP_KDF_IMPL *impl);
static int SSHKDF(const EVP_MD *evp_md,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *xcghash, size_t xcghash_len,
                  const unsigned char *session_id, size_t session_id_len,
                  char type, unsigned char *okey, size_t okey_len);

struct evp_kdf_impl_st {
    const EVP_MD *md;
    unsigned char *key; /* K */
    size_t key_len;
    unsigned char *xcghash; /* H */
    size_t xcghash_len;
    char type; /* X */
    unsigned char *session_id;
    size_t session_id_len;
};

static EVP_KDF_IMPL *kdf_sshkdf_new(void)
{
    EVP_KDF_IMPL *impl;

    if ((impl = OPENSSL_zalloc(sizeof(*impl))) == NULL)
        KDFerr(KDF_F_KDF_SSHKDF_NEW, ERR_R_MALLOC_FAILURE);
    return impl;
}

static void kdf_sshkdf_free(EVP_KDF_IMPL *impl)
{
    kdf_sshkdf_reset(impl);
    OPENSSL_free(impl);
}

static void kdf_sshkdf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_clear_free(impl->key, impl->key_len);
    OPENSSL_clear_free(impl->xcghash, impl->xcghash_len);
    OPENSSL_clear_free(impl->session_id, impl->session_id_len);
    memset(impl, 0, sizeof(*impl));
}

static int kdf_sshkdf_parse_buffer_arg(unsigned char **dst, size_t *dst_len,
                                       va_list args)
{
    const unsigned char *p;
    size_t len;

    p = va_arg(args, const unsigned char *);
    len = va_arg(args, size_t);
    OPENSSL_clear_free(*dst, *dst_len);
    *dst = OPENSSL_memdup(p, len);
    if (*dst == NULL)
        return 0;

    *dst_len = len;
    return 1;
}

static int kdf_sshkdf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    int t;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_MD:
        impl->md = va_arg(args, const EVP_MD *);
        if (impl->md == NULL)
            return 0;

        return 1;

    case EVP_KDF_CTRL_SET_KEY:
        return kdf_sshkdf_parse_buffer_arg(&impl->key,
                                           &impl->key_len, args);

    case EVP_KDF_CTRL_SET_SSHKDF_XCGHASH:
        return kdf_sshkdf_parse_buffer_arg(&impl->xcghash,
                                           &impl->xcghash_len, args);

    case EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID:
        return kdf_sshkdf_parse_buffer_arg(&impl->session_id,
                                           &impl->session_id_len, args);

    case EVP_KDF_CTRL_SET_SSHKDF_TYPE:
        t = va_arg(args, int);
        if (t < 65 || t > 70) {
            KDFerr(KDF_F_KDF_SSHKDF_CTRL, KDF_R_VALUE_ERROR);
            return 0;
        }

        impl->type = (char)t;
        return 1;

    default:
        return -2;

    }
}

static int kdf_sshkdf_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                               const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KDF_SSHKDF_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "md") == 0)
        return kdf_md2ctrl(impl, kdf_sshkdf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "key") == 0)
        return kdf_str2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "xcghash") == 0)
        return kdf_str2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, value);

    if (strcmp(type, "hexxcghash") == 0)
        return kdf_hex2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, value);

    if (strcmp(type, "session_id") == 0)
        return kdf_str2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, value);

    if (strcmp(type, "hexsession_id") == 0)
        return kdf_hex2ctrl(impl, kdf_sshkdf_ctrl,
                            EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, value);

    if (strcmp(type, "type") == 0) {
        if (strlen(value) != 1) {
            KDFerr(KDF_F_KDF_SSHKDF_CTRL_STR, KDF_R_VALUE_ERROR);
            return 0;
        }

        return call_ctrl(kdf_sshkdf_ctrl, impl, EVP_KDF_CTRL_SET_SSHKDF_TYPE,
                         (int)value[0]);
    }

    KDFerr(KDF_F_KDF_SSHKDF_CTRL_STR, KDF_R_UNKNOWN_PARAMETER_TYPE);
    return -2;
}

static size_t kdf_sshkdf_size(EVP_KDF_IMPL *impl)
{
    return SIZE_MAX;
}

static int kdf_sshkdf_derive(EVP_KDF_IMPL *impl, unsigned char *key,
                             size_t keylen)
{
    if (impl->md == NULL) {
        KDFerr(KDF_F_KDF_SSHKDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (impl->key == NULL) {
        KDFerr(KDF_F_KDF_SSHKDF_DERIVE, KDF_R_MISSING_KEY);
        return 0;
    }
    if (impl->xcghash == NULL) {
        KDFerr(KDF_F_KDF_SSHKDF_DERIVE, KDF_R_MISSING_XCGHASH);
        return 0;
    }
    if (impl->session_id == NULL) {
        KDFerr(KDF_F_KDF_SSHKDF_DERIVE, KDF_R_MISSING_SESSION_ID);
        return 0;
    }
    if (impl->type == 0) {
        KDFerr(KDF_F_KDF_SSHKDF_DERIVE, KDF_R_MISSING_TYPE);
        return 0;
    }
    return SSHKDF(impl->md, impl->key, impl->key_len,
                  impl->xcghash, impl->xcghash_len,
                  impl->session_id, impl->session_id_len,
                  impl->type, key, keylen);
}

const EVP_KDF_METHOD sshkdf_kdf_meth = {
    EVP_KDF_SSHKDF,
    kdf_sshkdf_new,
    kdf_sshkdf_free,
    kdf_sshkdf_reset,
    kdf_sshkdf_ctrl,
    kdf_sshkdf_ctrl_str,
    kdf_sshkdf_size,
    kdf_sshkdf_derive,
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
    OPENSSL_cleanse(digest, EVP_MAX_MD_SIZE);
    return ret;
}

