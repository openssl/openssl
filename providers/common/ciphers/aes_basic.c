/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "internal/modes_int.h"
#include "internal/evp_int.h"
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include "ciphers_locl.h"
#include "internal/providercommonerr.h"
#include "internal/aes_platform.h"

#define MAXBITCHUNK     ((size_t)1 << (sizeof(size_t) * 8 - 4))

#if defined(AESNI_CAPABLE)

/* AES-NI section. */

static int aesni_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                          size_t keylen)
{
    int ret;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = aesni_set_decrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f) aesni_decrypt;
        dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) aesni_cbc_encrypt : NULL;
    } else {
        ret = aesni_set_encrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f) aesni_encrypt;
        if (dat->mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) aesni_cbc_encrypt;
        else if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
        else
            dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        PROVerr(PROV_F_AESNI_INIT_KEY, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aesni_cbc_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    aesni_cbc_encrypt(in, out, len, &ctx->ks.ks, ctx->iv, ctx->enc);

    return 1;
}

static int aesni_ecb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    if (len < AES_BLOCK_SIZE)
        return 1;

    aesni_ecb_encrypt(in, out, len, &ctx->ks.ks, ctx->enc);

    return 1;
}

# define aesni_ofb_cipher aes_ofb_cipher
static int aesni_ofb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define aesni_cfb_cipher aes_cfb_cipher
static int aesni_cfb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define aesni_cfb8_cipher aes_cfb8_cipher
static int aesni_cfb8_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_cfb1_cipher aes_cfb1_cipher
static int aesni_cfb1_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_ctr_cipher aes_ctr_cipher
static int aesni_ctr_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define BLOCK_CIPHER_generic_prov(mode) \
static const PROV_AES_CIPHER aesni_##mode = { \
        aesni_init_key,                 \
        aesni_##mode##_cipher};         \
static const PROV_AES_CIPHER aes_##mode = { \
        aes_init_key,                   \
        aes_##mode##_cipher}; \
const PROV_AES_CIPHER *PROV_AES_CIPHER_##mode(size_t keylen) \
{ return AESNI_CAPABLE?&aesni_##mode:&aes_##mode; }


#elif defined(SPARC_AES_CAPABLE)

static int aes_t4_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                           size_t keylen)
{
    int ret, bits;

    bits = keylen * 8;
    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = 0;
        aes_t4_set_decrypt_key(key, bits, &dat->ks.ks);
        dat->block = (block128_f) aes_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes128_t4_cbc_decrypt : NULL;
            break;
        case 192:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes192_t4_cbc_decrypt : NULL;
            break;
        case 256:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
        }
    } else {
        ret = 0;
        aes_t4_set_encrypt_key(key, bits, &dat->ks.ks);
        dat->block = (block128_f)aes_t4_encrypt;
        switch (bits) {
        case 128:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes128_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes192_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes192_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 256:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes256_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
        }
    }

    if (ret < 0) {
        PROVerr(PROV_F_AES_T4_INIT_KEY, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

# define aes_t4_cbc_cipher aes_cbc_cipher
static int aes_t4_cbc_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ecb_cipher aes_ecb_cipher
static int aes_t4_ecb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ofb_cipher aes_ofb_cipher
static int aes_t4_ofb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb_cipher aes_cfb_cipher
static int aes_t4_cfb_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb8_cipher aes_cfb8_cipher
static int aes_t4_cfb8_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_cfb1_cipher aes_cfb1_cipher
static int aes_t4_cfb1_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_ctr_cipher aes_ctr_cipher
static int aes_t4_ctr_cipher(PROV_AES_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define BLOCK_CIPHER_generic_prov(mode) \
static const PROV_AES_CIPHER aes_t4_##mode = { \
        aes_t4_init_key,                 \
        aes_t4_##mode##_cipher};         \
static const PROV_AES_CIPHER aes_##mode = { \
        aes_init_key,                   \
        aes_##mode##_cipher}; \
const PROV_AES_CIPHER *PROV_AES_CIPHER_##mode(size_t keylen) \
{ return SPARC_AES_CAPABLE?&aes_t4_##mode:&aes_##mode; }


#elif defined(S390X_aes_128_CAPABLE)
/*
 * IBM S390X support
 */
# include "s390x_arch.h"

# define s390x_aes_init_key aes_init_key
static int s390x_aes_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                              size_t keylen);
# define S390X_AES_CBC_CTX          PROV_AES_KEY

# define s390x_aes_cbc_init_key aes_init_key

# define s390x_aes_cbc_cipher aes_cbc_cipher
static int s390x_aes_cbc_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len);

static int s390x_aes_ecb_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                                  size_t keylen)
{
    dat->plat.s390x.fc = S390X_AES_FC(keylen);
    if (!dat->enc)
        dat->plat.s390x.fc |= S390X_DECRYPT;

    memcpy(dat->plat.s390x.param.km.k, key, keylen);
    return 1;
}

static int s390x_aes_ecb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    s390x_km(in, len, out, dat->plat.s390x.fc,
             &dat->plat.s390x.param.km);
    return 1;
}

static int s390x_aes_ofb_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                                  size_t keylen)
{
    memcpy(dat->plat.s390x.param.kmo_kmf.cv, dat->iv, AES_BLOCK_SIZE);
    memcpy(dat->plat.s390x.param.kmo_kmf.k, key, keylen);
    dat->plat.s390x.fc = S390X_AES_FC(keylen);
    dat->plat.s390x.res = 0;
    return 1;
}

static int s390x_aes_ofb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    int n = dat->plat.s390x.res;
    int rem;

    while (n && len) {
        *out = *in ^ dat->plat.s390x.param.kmo_kmf.cv[n];
        n = (n + 1) & 0xf;
        --len;
        ++in;
        ++out;
    }

    rem = len & 0xf;

    len &= ~(size_t)0xf;
    if (len) {
        s390x_kmo(in, len, out, dat->plat.s390x.fc,
                  &dat->plat.s390x.param.kmo_kmf);

        out += len;
        in += len;
    }

    if (rem) {
        s390x_km(dat->plat.s390x.param.kmo_kmf.cv, 16,
                 dat->plat.s390x.param.kmo_kmf.cv, dat->plat.s390x.fc,
                 dat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            out[n] = in[n] ^ dat->plat.s390x.param.kmo_kmf.cv[n];
            ++n;
        }
    }

    dat->plat.s390x.res = n;
    return 1;
}

static int s390x_aes_cfb_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                                  size_t keylen)
{
    dat->plat.s390x.fc = S390X_AES_FC(keylen);
    dat->plat.s390x.fc |= 16 << 24;   /* 16 bytes cipher feedback */
    if (!dat->enc)
        dat->plat.s390x.fc |= S390X_DECRYPT;

    dat->plat.s390x.res = 0;
    memcpy(dat->plat.s390x.param.kmo_kmf.cv, dat->iv, AES_BLOCK_SIZE);
    memcpy(dat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    int n = dat->plat.s390x.res;
    int rem;
    unsigned char tmp;

    while (n && len) {
        tmp = *in;
        *out = dat->plat.s390x.param.kmo_kmf.cv[n] ^ tmp;
        dat->plat.s390x.param.kmo_kmf.cv[n] = dat->enc ? *out : tmp;
        n = (n + 1) & 0xf;
        --len;
        ++in;
        ++out;
    }

    rem = len & 0xf;

    len &= ~(size_t)0xf;
    if (len) {
        s390x_kmf(in, len, out, dat->plat.s390x.fc,
                  &dat->plat.s390x.param.kmo_kmf);

        out += len;
        in += len;
    }

    if (rem) {
        s390x_km(dat->plat.s390x.param.kmo_kmf.cv, 16,
                 dat->plat.s390x.param.kmo_kmf.cv,
                 S390X_AES_FC(dat->keylen), dat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            tmp = in[n];
            out[n] = dat->plat.s390x.param.kmo_kmf.cv[n] ^ tmp;
            dat->plat.s390x.param.kmo_kmf.cv[n] = dat->enc ? out[n] : tmp;
            ++n;
        }
    }

    dat->plat.s390x.res = n;
    return 1;
}

static int s390x_aes_cfb8_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                                  size_t keylen)
{
    dat->plat.s390x.fc = S390X_AES_FC(keylen);
    dat->plat.s390x.fc |= 1 << 24;   /* 1 byte cipher feedback */
    if (!dat->enc)
        dat->plat.s390x.fc |= S390X_DECRYPT;

    memcpy(dat->plat.s390x.param.kmo_kmf.cv, dat->iv, AES_BLOCK_SIZE);
    memcpy(dat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb8_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    s390x_kmf(in, len, out, dat->plat.s390x.fc,
              &dat->plat.s390x.param.kmo_kmf);
    return 1;
}

# define s390x_aes_cfb1_init_key aes_init_key

# define s390x_aes_cfb1_cipher aes_cfb1_cipher
static int s390x_aes_cfb1_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len);
# define S390X_AES_CTR_CTX          PROV_AES_KEY

# define s390x_aes_ctr_init_key aes_init_key

# define s390x_aes_ctr_cipher aes_ctr_cipher
static int s390x_aes_ctr_cipher(PROV_AES_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len);

# define BLOCK_CIPHER_generic_prov(mode) \
static const PROV_AES_CIPHER s390x_aes_##mode = { \
        s390x_aes_##mode##_init_key,    \
        s390x_aes_##mode##_cipher       \
};  \
static const PROV_AES_CIPHER aes_##mode = { \
        aes_init_key,           \
        aes_##mode##_cipher     \
}; \
const PROV_AES_CIPHER *PROV_AES_CIPHER_##mode(size_t keylen) \
{   \
    if ((keylen == 16 && S390X_aes_128_##mode##_CAPABLE)           \
            || (keylen == 24 && S390X_aes_192_##mode##_CAPABLE)    \
            || (keylen == 32 && S390X_aes_256_##mode##_CAPABLE))   \
        return &s390x_aes_##mode;   \
    \
    return &aes_##mode; \
}

#else
/* The generic case */
# define BLOCK_CIPHER_generic_prov(mode) \
static const PROV_AES_CIPHER aes_##mode = { \
        aes_init_key,                   \
        aes_##mode##_cipher}; \
const PROV_AES_CIPHER *PROV_AES_CIPHER_##mode(size_t keylen) \
{ return &aes_##mode; }

#endif

static int aes_init_key(PROV_AES_KEY *dat, const unsigned char *key,
                        size_t keylen)
{
    int ret;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
#ifdef HWAES_CAPABLE
        if (HWAES_CAPABLE) {
            ret = HWAES_set_decrypt_key(key, keylen * 8, &dat->ks.ks);
            dat->block = (block128_f)HWAES_decrypt;
            dat->stream.cbc = NULL;
# ifdef HWAES_cbc_encrypt
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)HWAES_cbc_encrypt;
# endif
        } else
#endif
#ifdef BSAES_CAPABLE
        if (BSAES_CAPABLE && dat->mode == EVP_CIPH_CBC_MODE) {
            ret = AES_set_decrypt_key(key, keylen * 8, &dat->ks.ks);
            dat->block = (block128_f)AES_decrypt;
            dat->stream.cbc = (cbc128_f)bsaes_cbc_encrypt;
        } else
#endif
#ifdef VPAES_CAPABLE
        if (VPAES_CAPABLE) {
            ret = vpaes_set_decrypt_key(key, keylen * 8, &dat->ks.ks);
            dat->block = (block128_f)vpaes_decrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ?(cbc128_f)vpaes_cbc_encrypt : NULL;
        } else
#endif
        {
            ret = AES_set_decrypt_key(key, keylen * 8, &dat->ks.ks);
            dat->block = (block128_f)AES_decrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ? (cbc128_f)AES_cbc_encrypt : NULL;
        }
    } else
#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        ret = HWAES_set_encrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f)HWAES_encrypt;
        dat->stream.cbc = NULL;
# ifdef HWAES_cbc_encrypt
        if (dat->mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f)HWAES_cbc_encrypt;
        else
# endif
# ifdef HWAES_ctr32_encrypt_blocks
        if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f)HWAES_ctr32_encrypt_blocks;
        else
# endif
            (void)0;            /* terminate potentially open 'else' */
    } else
#endif
#ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE && dat->mode == EVP_CIPH_CTR_MODE) {
        ret = AES_set_encrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f)AES_encrypt;
        dat->stream.ctr = (ctr128_f)bsaes_ctr32_encrypt_blocks;
    } else
#endif
#ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        ret = vpaes_set_encrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f)vpaes_encrypt;
        dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                          ? (cbc128_f)vpaes_cbc_encrypt : NULL;
    } else
#endif
    {
        ret = AES_set_encrypt_key(key, keylen * 8, &dat->ks.ks);
        dat->block = (block128_f)AES_encrypt;
        dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                          ? (cbc128_f)AES_cbc_encrypt : NULL;
#ifdef AES_CTR_ASM
        if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f)AES_ctr32_encrypt;
#endif
    }

    if (ret < 0) {
        PROVerr(PROV_F_AES_INIT_KEY, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aes_cbc_cipher(PROV_AES_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks, dat->iv, dat->enc);
    else if (dat->enc)
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, dat->iv, dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, dat->iv, dat->block);

    return 1;
}

static int aes_ecb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t i;

    if (len < AES_BLOCK_SIZE)
        return 1;

    for (i = 0, len -= AES_BLOCK_SIZE; i <= len; i += AES_BLOCK_SIZE)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

static int aes_ofb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int num = dat->num;
    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks, dat->iv, &num, dat->block);
    dat->num = num;

    return 1;
}

static int aes_cfb_cipher(PROV_AES_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int num = dat->num;
    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks, dat->iv, &num, dat->enc,
                          dat->block);
    dat->num = num;

    return 1;
}

static int aes_cfb8_cipher(PROV_AES_KEY *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    int num = dat->num;
    CRYPTO_cfb128_8_encrypt(in, out, len, &dat->ks, dat->iv, &num, dat->enc,
                            dat->block);
    dat->num = num;

    return 1;
}

static int aes_cfb1_cipher(PROV_AES_KEY *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    int num = dat->num;

    if ((dat->flags & EVP_CIPH_FLAG_LENGTH_BITS) != 0) {
        CRYPTO_cfb128_1_encrypt(in, out, len, &dat->ks, dat->iv, &num,
                                dat->enc, dat->block);
        dat->num = num;
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, &dat->ks,
                                dat->iv, &num, dat->enc, dat->block);
        len -= MAXBITCHUNK;
        out += MAXBITCHUNK;
        in  += MAXBITCHUNK;
    }
    if (len)
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, &dat->ks, dat->iv, &num,
                                dat->enc, dat->block);

    dat->num = num;

    return 1;
}

static int aes_ctr_cipher(PROV_AES_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    unsigned int num = dat->num;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks, dat->iv, dat->buf,
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks, dat->iv, dat->buf,
                              &num, dat->block);
    dat->num = num;

    return 1;
}

BLOCK_CIPHER_generic_prov(cbc)
BLOCK_CIPHER_generic_prov(ecb)
BLOCK_CIPHER_generic_prov(ofb)
BLOCK_CIPHER_generic_prov(cfb)
BLOCK_CIPHER_generic_prov(cfb1)
BLOCK_CIPHER_generic_prov(cfb8)
BLOCK_CIPHER_generic_prov(ctr)

