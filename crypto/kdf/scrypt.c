/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include "internal/evp_int.h"
#include "internal/numbers.h"
#include "kdf_local.h"

#ifndef OPENSSL_NO_SCRYPT

static void kdf_scrypt_reset(EVP_KDF_IMPL *impl);
static void kdf_scrypt_init(EVP_KDF_IMPL *impl);
static int atou64(const char *nptr, uint64_t *result);
static int scrypt_alg(const char *pass, size_t passlen,
                      const unsigned char *salt, size_t saltlen,
                      uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                      unsigned char *key, size_t keylen);

struct evp_kdf_impl_st {
    unsigned char *pass;
    size_t pass_len;
    unsigned char *salt;
    size_t salt_len;
    uint64_t N;
    uint32_t r, p;
    uint64_t maxmem_bytes;
};

/* Custom uint64_t parser since we do not have strtoull */
static int atou64(const char *nptr, uint64_t *result)
{
    uint64_t value = 0;

    while (*nptr) {
        unsigned int digit;
        uint64_t new_value;

        if ((*nptr < '0') || (*nptr > '9')) {
            return 0;
        }
        digit = (unsigned int)(*nptr - '0');
        new_value = (value * 10) + digit;
        if ((new_value < digit) || ((new_value - digit) / 10 != value)) {
            /* Overflow */
            return 0;
        }
        value = new_value;
        nptr++;
    }
    *result = value;
    return 1;
}

static EVP_KDF_IMPL *kdf_scrypt_new(void)
{
    EVP_KDF_IMPL *impl;

    impl = OPENSSL_zalloc(sizeof(*impl));
    if (impl == NULL) {
        KDFerr(KDF_F_KDF_SCRYPT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    kdf_scrypt_init(impl);
    return impl;
}

static void kdf_scrypt_free(EVP_KDF_IMPL *impl)
{
    kdf_scrypt_reset(impl);
    OPENSSL_free(impl);
}

static void kdf_scrypt_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_free(impl->salt);
    OPENSSL_clear_free(impl->pass, impl->pass_len);
    memset(impl, 0, sizeof(*impl));
    kdf_scrypt_init(impl);
}

static void kdf_scrypt_init(EVP_KDF_IMPL *impl)
{
    /* Default values are the most conservative recommendation given in the
     * original paper of C. Percival. Derivation uses roughly 1 GiB of memory
     * for this parameter choice (approx. 128 * r * N * p bytes).
     */
    impl->N = 1 << 20;
    impl->r = 8;
    impl->p = 1;
    impl->maxmem_bytes = 1025 * 1024 * 1024;
}

static int scrypt_set_membuf(unsigned char **buffer, size_t *buflen,
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
        KDFerr(KDF_F_SCRYPT_SET_MEMBUF, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *buflen = new_buflen;
    return 1;
}

static int is_power_of_two(uint64_t value)
{
    return (value != 0) && ((value & (value - 1)) == 0);
}

static int kdf_scrypt_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    uint64_t u64_value;
    uint32_t value;
    const unsigned char *p;
    size_t len;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_PASS:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        return scrypt_set_membuf(&impl->pass, &impl->pass_len, p, len);

    case EVP_KDF_CTRL_SET_SALT:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        return scrypt_set_membuf(&impl->salt, &impl->salt_len, p, len);

    case EVP_KDF_CTRL_SET_SCRYPT_N:
        u64_value = va_arg(args, uint64_t);
        if ((u64_value <= 1) || !is_power_of_two(u64_value))
            return 0;

        impl->N = u64_value;
        return 1;

    case EVP_KDF_CTRL_SET_SCRYPT_R:
        value = va_arg(args, uint32_t);
        if (value < 1)
            return 0;

        impl->r = value;
        return 1;

    case EVP_KDF_CTRL_SET_SCRYPT_P:
        value = va_arg(args, uint32_t);
        if (value < 1)
            return 0;

        impl->p = value;
        return 1;

    case EVP_KDF_CTRL_SET_MAXMEM_BYTES:
        u64_value = va_arg(args, uint64_t);
        if (u64_value < 1)
            return 0;

        impl->maxmem_bytes = u64_value;
        return 1;

    default:
        return -2;
    }
}

static int kdf_scrypt_ctrl_uint32(EVP_KDF_IMPL *impl, int cmd,
                                  const char *value)
{
    int int_value = atoi(value);

    if (int_value < 0 || (uint64_t)int_value > UINT32_MAX) {
        KDFerr(KDF_F_KDF_SCRYPT_CTRL_UINT32, KDF_R_VALUE_ERROR);
        return 0;
    }
    return call_ctrl(kdf_scrypt_ctrl, impl, cmd, (uint32_t)int_value);
}

static int kdf_scrypt_ctrl_uint64(EVP_KDF_IMPL *impl, int cmd,
                                  const char *value)
{
    uint64_t u64_value;

    if (!atou64(value, &u64_value)) {
        KDFerr(KDF_F_KDF_SCRYPT_CTRL_UINT64, KDF_R_VALUE_ERROR);
        return 0;
    }
    return call_ctrl(kdf_scrypt_ctrl, impl, cmd, u64_value);
}

static int kdf_scrypt_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                               const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KDF_SCRYPT_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "pass") == 0)
        return kdf_str2ctrl(impl, kdf_scrypt_ctrl, EVP_KDF_CTRL_SET_PASS,
                            value);

    if (strcmp(type, "hexpass") == 0)
        return kdf_hex2ctrl(impl, kdf_scrypt_ctrl, EVP_KDF_CTRL_SET_PASS,
                            value);

    if (strcmp(type, "salt") == 0)
        return kdf_str2ctrl(impl, kdf_scrypt_ctrl, EVP_KDF_CTRL_SET_SALT,
                            value);

    if (strcmp(type, "hexsalt") == 0)
        return kdf_hex2ctrl(impl, kdf_scrypt_ctrl, EVP_KDF_CTRL_SET_SALT,
                            value);

    if (strcmp(type, "N") == 0)
        return kdf_scrypt_ctrl_uint64(impl, EVP_KDF_CTRL_SET_SCRYPT_N, value);

    if (strcmp(type, "r") == 0)
        return kdf_scrypt_ctrl_uint32(impl, EVP_KDF_CTRL_SET_SCRYPT_R, value);

    if (strcmp(type, "p") == 0)
        return kdf_scrypt_ctrl_uint32(impl, EVP_KDF_CTRL_SET_SCRYPT_P, value);

    if (strcmp(type, "maxmem_bytes") == 0)
        return kdf_scrypt_ctrl_uint64(impl, EVP_KDF_CTRL_SET_MAXMEM_BYTES,
                                      value);

    return -2;
}

static int kdf_scrypt_derive(EVP_KDF_IMPL *impl, unsigned char *key,
                             size_t keylen)
{
    if (impl->pass == NULL) {
        KDFerr(KDF_F_KDF_SCRYPT_DERIVE, KDF_R_MISSING_PASS);
        return 0;
    }

    if (impl->salt == NULL) {
        KDFerr(KDF_F_KDF_SCRYPT_DERIVE, KDF_R_MISSING_SALT);
        return 0;
    }

    return scrypt_alg((char *)impl->pass, impl->pass_len, impl->salt,
                      impl->salt_len, impl->N, impl->r, impl->p,
                      impl->maxmem_bytes, key, keylen);
}

const EVP_KDF_METHOD scrypt_kdf_meth = {
    EVP_KDF_SCRYPT,
    kdf_scrypt_new,
    kdf_scrypt_free,
    kdf_scrypt_reset,
    kdf_scrypt_ctrl,
    kdf_scrypt_ctrl_str,
    NULL,
    kdf_scrypt_derive
};

#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa208_word_specification(uint32_t inout[16])
{
    int i;
    uint32_t x[16];

    memcpy(x, inout, sizeof(x));
    for (i = 8; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; ++i)
        inout[i] += x[i];
    OPENSSL_cleanse(x, sizeof(x));
}

static void scryptBlockMix(uint32_t *B_, uint32_t *B, uint64_t r)
{
    uint64_t i, j;
    uint32_t X[16], *pB;

    memcpy(X, B + (r * 2 - 1) * 16, sizeof(X));
    pB = B;
    for (i = 0; i < r * 2; i++) {
        for (j = 0; j < 16; j++)
            X[j] ^= *pB++;
        salsa208_word_specification(X);
        memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
    }
    OPENSSL_cleanse(X, sizeof(X));
}

static void scryptROMix(unsigned char *B, uint64_t r, uint64_t N,
                        uint32_t *X, uint32_t *T, uint32_t *V)
{
    unsigned char *pB;
    uint32_t *pV;
    uint64_t i, k;

    /* Convert from little endian input */
    for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++) {
        *pV = *pB++;
        *pV |= *pB++ << 8;
        *pV |= *pB++ << 16;
        *pV |= (uint32_t)*pB++ << 24;
    }

    for (i = 1; i < N; i++, pV += 32 * r)
        scryptBlockMix(pV, pV - 32 * r, r);

    scryptBlockMix(X, V + (N - 1) * 32 * r, r);

    for (i = 0; i < N; i++) {
        uint32_t j;
        j = X[16 * (2 * r - 1)] % N;
        pV = V + 32 * r * j;
        for (k = 0; k < 32 * r; k++)
            T[k] = X[k] ^ *pV++;
        scryptBlockMix(X, T, r);
    }
    /* Convert output to little endian */
    for (i = 0, pB = B; i < 32 * r; i++) {
        uint32_t xtmp = X[i];
        *pB++ = xtmp & 0xff;
        *pB++ = (xtmp >> 8) & 0xff;
        *pB++ = (xtmp >> 16) & 0xff;
        *pB++ = (xtmp >> 24) & 0xff;
    }
}

#ifndef SIZE_MAX
# define SIZE_MAX    ((size_t)-1)
#endif

/*
 * Maximum power of two that will fit in uint64_t: this should work on
 * most (all?) platforms.
 */

#define LOG2_UINT64_MAX         (sizeof(uint64_t) * 8 - 1)

/*
 * Maximum value of p * r:
 * p <= ((2^32-1) * hLen) / MFLen =>
 * p <= ((2^32-1) * 32) / (128 * r) =>
 * p * r <= (2^30-1)
 */

#define SCRYPT_PR_MAX   ((1 << 30) - 1)

static int scrypt_alg(const char *pass, size_t passlen,
                      const unsigned char *salt, size_t saltlen,
                      uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                      unsigned char *key, size_t keylen)
{
    int rv = 0;
    unsigned char *B;
    uint32_t *X, *V, *T;
    uint64_t i, Blen, Vlen;

    /* Sanity check parameters */
    /* initial check, r,p must be non zero, N >= 2 and a power of 2 */
    if (r == 0 || p == 0 || N < 2 || (N & (N - 1)))
        return 0;
    /* Check p * r < SCRYPT_PR_MAX avoiding overflow */
    if (p > SCRYPT_PR_MAX / r) {
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }

    /*
     * Need to check N: if 2^(128 * r / 8) overflows limit this is
     * automatically satisfied since N <= UINT64_MAX.
     */

    if (16 * r <= LOG2_UINT64_MAX) {
        if (N >= (((uint64_t)1) << (16 * r))) {
            EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
            return 0;
        }
    }

    /* Memory checks: check total allocated buffer size fits in uint64_t */

    /*
     * B size in section 5 step 1.S
     * Note: we know p * 128 * r < UINT64_MAX because we already checked
     * p * r < SCRYPT_PR_MAX
     */
    Blen = p * 128 * r;
    /*
     * Yet we pass it as integer to PKCS5_PBKDF2_HMAC... [This would
     * have to be revised when/if PKCS5_PBKDF2_HMAC accepts size_t.]
     */
    if (Blen > INT_MAX) {
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }

    /*
     * Check 32 * r * (N + 2) * sizeof(uint32_t) fits in uint64_t
     * This is combined size V, X and T (section 4)
     */
    i = UINT64_MAX / (32 * sizeof(uint32_t));
    if (N + 2 > i / r) {
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }
    Vlen = 32 * r * (N + 2) * sizeof(uint32_t);

    /* check total allocated size fits in uint64_t */
    if (Blen > UINT64_MAX - Vlen) {
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }

    /* Check that the maximum memory doesn't exceed a size_t limits */
    if (maxmem > SIZE_MAX)
        maxmem = SIZE_MAX;

    if (Blen + Vlen > maxmem) {
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_MEMORY_LIMIT_EXCEEDED);
        return 0;
    }

    /* If no key return to indicate parameters are OK */
    if (key == NULL)
        return 1;

    B = OPENSSL_malloc((size_t)(Blen + Vlen));
    if (B == NULL) {
        EVPerr(EVP_F_SCRYPT_ALG, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    X = (uint32_t *)(B + Blen);
    T = X + 32 * r;
    V = T + 32 * r;
    if (PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, 1, EVP_sha256(),
                          (int)Blen, B) == 0)
        goto err;

    for (i = 0; i < p; i++)
        scryptROMix(B + 128 * r * i, r, N, X, T, V);

    if (PKCS5_PBKDF2_HMAC(pass, passlen, B, (int)Blen, 1, EVP_sha256(),
                          keylen, key) == 0)
        goto err;
    rv = 1;
 err:
    if (rv == 0)
        EVPerr(EVP_F_SCRYPT_ALG, EVP_R_PBKDF2_ERROR);

    OPENSSL_clear_free(B, (size_t)(Blen + Vlen));
    return rv;
}

#endif
