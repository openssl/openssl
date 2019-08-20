/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/evp_int.h"
#include "kdf_local.h"

/* Constants specified in SP800-132 */
#define KDF_PBKDF2_MIN_KEY_LEN_BITS  112
#define KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO 0xFFFFFFFF
#define KDF_PBKDF2_MIN_ITERATIONS 1000
#define KDF_PBKDF2_MIN_SALT_LEN   (128 / 8)
/*
 * For backwards compatibility reasons,
 * Extra checks are done by default in fips mode only.
 */
#ifdef FIPS_MODE
# define KDF_PBKDF2_DEFAULT_CHECKS 1
#else
# define KDF_PBKDF2_DEFAULT_CHECKS 0
#endif /* FIPS_MODE */

static void kdf_pbkdf2_reset(EVP_KDF_IMPL *impl);
static void kdf_pbkdf2_init(EVP_KDF_IMPL *impl);
static int  pbkdf2_derive(const char *pass, size_t passlen,
                          const unsigned char *salt, int saltlen, int iter,
                          const EVP_MD *digest, unsigned char *key,
                          size_t keylen, int extra_checks);

struct evp_kdf_impl_st {
    unsigned char *pass;
    size_t pass_len;
    unsigned char *salt;
    size_t salt_len;
    int iter;
    const EVP_MD *md;
    int lower_bound_checks;
};

static EVP_KDF_IMPL *kdf_pbkdf2_new(void)
{
    EVP_KDF_IMPL *impl;

    impl = OPENSSL_zalloc(sizeof(*impl));
    if (impl == NULL) {
        KDFerr(KDF_F_KDF_PBKDF2_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    kdf_pbkdf2_init(impl);
    return impl;
}

static void kdf_pbkdf2_free(EVP_KDF_IMPL *impl)
{
    kdf_pbkdf2_reset(impl);
    OPENSSL_free(impl);
}

static void kdf_pbkdf2_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_free(impl->salt);
    OPENSSL_clear_free(impl->pass, impl->pass_len);
    memset(impl, 0, sizeof(*impl));
    kdf_pbkdf2_init(impl);
}

static void kdf_pbkdf2_init(EVP_KDF_IMPL *impl)
{
    impl->iter = PKCS5_DEFAULT_ITER;
    impl->md = EVP_sha1();
    impl->lower_bound_checks = KDF_PBKDF2_DEFAULT_CHECKS;
}

static int pbkdf2_set_membuf(unsigned char **buffer, size_t *buflen,
                             const unsigned char *new_buffer,
                             size_t new_buflen)
{
    if (new_buffer == NULL)
        return 1;

    OPENSSL_clear_free(*buffer, *buflen);

    if (new_buflen > 0) {
        *buffer = OPENSSL_memdup(new_buffer, new_buflen);
    } else {
        *buffer = OPENSSL_malloc(1);
    }
    if (*buffer == NULL) {
        KDFerr(KDF_F_PBKDF2_SET_MEMBUF, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *buflen = new_buflen;
    return 1;
}

static int kdf_pbkdf2_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    int iter, pkcs5, min_iter;
    const unsigned char *p;
    size_t len;
    const EVP_MD *md;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_PBKDF2_PKCS5_MODE:
        pkcs5 = va_arg(args, int);
        impl->lower_bound_checks = (pkcs5 == 0) ? 1 : 0;
        return 1;
    case EVP_KDF_CTRL_SET_PASS:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        return pbkdf2_set_membuf(&impl->pass, &impl->pass_len, p, len);

    case EVP_KDF_CTRL_SET_SALT:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (impl->lower_bound_checks != 0 && len < KDF_PBKDF2_MIN_SALT_LEN) {
            KDFerr(KDF_F_KDF_PBKDF2_CTRL, KDF_R_INVALID_SALT_LEN);
            return 0;
        }
        return pbkdf2_set_membuf(&impl->salt, &impl->salt_len, p, len);

    case EVP_KDF_CTRL_SET_ITER:
        iter = va_arg(args, int);
        min_iter = impl->lower_bound_checks != 0 ? KDF_PBKDF2_MIN_ITERATIONS : 1;
        if (iter < min_iter) {
            KDFerr(KDF_F_KDF_PBKDF2_CTRL, KDF_R_INVALID_ITERATION_COUNT);
            return 0;
        }
        impl->iter = iter;
        return 1;

    case EVP_KDF_CTRL_SET_MD:
        md = va_arg(args, const EVP_MD *);
        if (md == NULL) {
            KDFerr(KDF_F_KDF_PBKDF2_CTRL, KDF_R_VALUE_MISSING);
            return 0;
        }

        impl->md = md;
        return 1;

    default:
        return -2;
    }
}

static int kdf_pbkdf2_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                               const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KDF_PBKDF2_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "pass") == 0)
        return kdf_str2ctrl(impl, kdf_pbkdf2_ctrl, EVP_KDF_CTRL_SET_PASS,
                            value);

    if (strcmp(type, "hexpass") == 0)
        return kdf_hex2ctrl(impl, kdf_pbkdf2_ctrl, EVP_KDF_CTRL_SET_PASS,
                            value);

    if (strcmp(type, "salt") == 0)
        return kdf_str2ctrl(impl, kdf_pbkdf2_ctrl, EVP_KDF_CTRL_SET_SALT,
                            value);

    if (strcmp(type, "hexsalt") == 0)
        return kdf_hex2ctrl(impl, kdf_pbkdf2_ctrl, EVP_KDF_CTRL_SET_SALT,
                            value);

    if (strcmp(type, "iter") == 0)
        return call_ctrl(kdf_pbkdf2_ctrl, impl, EVP_KDF_CTRL_SET_ITER,
                         atoi(value));

    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(impl, kdf_pbkdf2_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "pkcs5") == 0)
        return kdf_str2ctrl(impl, kdf_pbkdf2_ctrl,
                            EVP_KDF_CTRL_SET_PBKDF2_PKCS5_MODE, value);
    return -2;
}

static int kdf_pbkdf2_derive(EVP_KDF_IMPL *impl, unsigned char *key,
                             size_t keylen)
{
    if (impl->pass == NULL) {
        KDFerr(KDF_F_KDF_PBKDF2_DERIVE, KDF_R_MISSING_PASS);
        return 0;
    }

    if (impl->salt == NULL) {
        KDFerr(KDF_F_KDF_PBKDF2_DERIVE, KDF_R_MISSING_SALT);
        return 0;
    }

    return pbkdf2_derive((char *)impl->pass, impl->pass_len,
                         impl->salt, impl->salt_len, impl->iter,
                         impl->md, key, keylen, impl->lower_bound_checks);
}

const EVP_KDF pbkdf2_kdf_meth = {
    EVP_KDF_PBKDF2,
    kdf_pbkdf2_new,
    kdf_pbkdf2_free,
    kdf_pbkdf2_reset,
    kdf_pbkdf2_ctrl,
    kdf_pbkdf2_ctrl_str,
    NULL,
    kdf_pbkdf2_derive
};

/*
 * This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2. SHA1 version verified against test vectors
 * posted by Peter Gutmann to the PKCS-TNG mailing list.
 *
 * The constraints specified by SP800-132 have been added i.e.
 *  - Check the range of the key length.
 *  - Minimum iteration count of 1000.
 *  - Randomly-generated portion of the salt shall be at least 128 bits.
 */
static int pbkdf2_derive(const char *pass, size_t passlen,
                         const unsigned char *salt, int saltlen, int iter,
                         const EVP_MD *digest, unsigned char *key,
                         size_t keylen, int lower_bound_checks)
{
    int ret = 0;
    unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
    int cplen, j, k, tkeylen, mdlen;
    unsigned long i = 1;
    HMAC_CTX *hctx_tpl = NULL, *hctx = NULL;

    mdlen = EVP_MD_size(digest);
    if (mdlen <= 0)
        return 0;

    /*
     * This check should always be done because keylen / mdlen >= (2^32 - 1)
     * results in an overflow of the loop counter 'i'.
     */
    if ((keylen / mdlen) >= KDF_PBKDF2_MAX_KEY_LEN_DIGEST_RATIO) {
        KDFerr(KDF_F_PBKDF2_DERIVE, KDF_R_INVALID_KEY_LEN);
        return 0;
    }

    if (lower_bound_checks) {
         if ((keylen * 8) < KDF_PBKDF2_MIN_KEY_LEN_BITS) {
             KDFerr(KDF_F_PBKDF2_DERIVE, KDF_R_INVALID_KEY_LEN);
             return 0;
         }
         if (saltlen < KDF_PBKDF2_MIN_SALT_LEN) {
             KDFerr(KDF_F_PBKDF2_DERIVE, KDF_R_INVALID_SALT_LEN);
            return 0;
         }
         if (iter < KDF_PBKDF2_MIN_ITERATIONS) {
             KDFerr(KDF_F_PBKDF2_DERIVE, KDF_R_INVALID_ITERATION_COUNT);
             return 0;
         }
    }

    hctx_tpl = HMAC_CTX_new();
    if (hctx_tpl == NULL)
        return 0;
    p = key;
    tkeylen = keylen;
    if (!HMAC_Init_ex(hctx_tpl, pass, passlen, digest, NULL))
        goto err;
    hctx = HMAC_CTX_new();
    if (hctx == NULL)
        goto err;
    while (tkeylen) {
        if (tkeylen > mdlen)
            cplen = mdlen;
        else
            cplen = tkeylen;
        /*
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        if (!HMAC_CTX_copy(hctx, hctx_tpl))
            goto err;
        if (!HMAC_Update(hctx, salt, saltlen)
                || !HMAC_Update(hctx, itmp, 4)
                || !HMAC_Final(hctx, digtmp, NULL))
            goto err;
        memcpy(p, digtmp, cplen);
        for (j = 1; j < iter; j++) {
            if (!HMAC_CTX_copy(hctx, hctx_tpl))
                goto err;
            if (!HMAC_Update(hctx, digtmp, mdlen)
                    || !HMAC_Final(hctx, digtmp, NULL))
                goto err;
            for (k = 0; k < cplen; k++)
                p[k] ^= digtmp[k];
        }
        tkeylen -= cplen;
        i++;
        p += cplen;
    }
    ret = 1;

err:
    HMAC_CTX_free(hctx);
    HMAC_CTX_free(hctx_tpl);
    return ret;
}
