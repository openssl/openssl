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
#include "internal/evp_int.h"
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include "ciphers_locl.h"
#include "internal/providercommonerr.h"
#include "internal/ciphermode_platform.h"

#define MAXBITCHUNK     ((size_t)1 << (sizeof(size_t) * 8 - 4))
#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

#if defined(AESNI_CAPABLE)

/* AES-NI section. */

static int aesni_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                          size_t keylen)
{
    int ret;
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = aesni_set_decrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) aesni_decrypt;
        dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) aesni_cbc_encrypt : NULL;
    } else {
        ret = aesni_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) aesni_encrypt;
        if (dat->mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) aesni_cbc_encrypt;
        else if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
        else
            dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aesni_cbc_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    const AES_KEY *ks = ctx->ks;

    aesni_cbc_encrypt(in, out, len, ks, ctx->iv, ctx->enc);

    return 1;
}

static int aesni_ecb_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    if (len < ctx->blocksize)
        return 1;

    aesni_ecb_encrypt(in, out, len, ctx->ks, ctx->enc);

    return 1;
}

# define aesni_ofb128_cipher generic_ofb128_cipher
static int aesni_ofb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                               const unsigned char *in, size_t len);

# define aesni_cfb128_cipher generic_cfb128_cipher
static int aesni_cfb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define aesni_cfb8_cipher generic_cfb8_cipher
static int aesni_cfb8_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_cfb1_cipher generic_cfb1_cipher
static int aesni_cfb1_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_ctr_cipher generic_ctr_cipher
static int aesni_ctr_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER aesni_##mode = {                              \
        aesni_init_key,                                                        \
        aesni_##mode##_cipher};                                                \
static const PROV_GENERIC_CIPHER aes_##mode = {                                \
        aes_init_key,                                                          \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{ return AESNI_CAPABLE?&aesni_##mode:&aes_##mode; }


#elif defined(SPARC_AES_CAPABLE)

static int aes_t4_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                           size_t keylen)
{
    int ret, bits;
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    dat->ks = &adat->ks.ks;

    bits = keylen * 8;
    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = 0;
        aes_t4_set_decrypt_key(key, bits, dat->ks);
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
        aes_t4_set_encrypt_key(key, bits, dat->ks);
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
        ERR_raise(ERR_LIB_PROV, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

# define aes_t4_cbc_cipher aes_cbc_cipher
static int aes_t4_cbc_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ecb_cipher aes_ecb_cipher
static int aes_t4_ecb_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ofb_cipher aes_ofb_cipher
static int aes_t4_ofb_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb_cipher aes_cfb_cipher
static int aes_t4_cfb_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb8_cipher aes_cfb8_cipher
static int aes_t4_cfb8_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_cfb1_cipher aes_cfb1_cipher
static int aes_t4_cfb1_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_ctr_cipher aes_ctr_cipher
static int aes_t4_ctr_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER aes_t4_##mode = {                             \
        aes_t4_init_key,                                                       \
        aes_t4_##mode##_cipher};                                               \
static const PROV_GENERIC_CIPHER aes_##mode = {                                \
        aes_init_key,                                                          \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{ return SPARC_AES_CAPABLE?&aes_t4_##mode:&aes_##mode; }


#elif defined(S390X_aes_128_CAPABLE)
/*
 * IBM S390X support
 */
# include "s390x_arch.h"

# define s390x_aes_init_key aes_init_key
static int s390x_aes_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                              size_t keylen);
# define S390X_AES_CBC_CTX          PROV_GENERIC_KEY

# define s390x_aes_cbc_init_key aes_init_key

# define s390x_aes_cbc_cipher aes_cbc_cipher
static int s390x_aes_cbc_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len);

static int s390x_aes_ecb_init_key(PROV_GENERIC_KEY *dat,
                                  const unsigned char *key, size_t keylen)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    if (!dat->enc)
        adat->plat.s390x.fc |= S390X_DECRYPT;

    memcpy(adat->plat.s390x.param.km.k, key, keylen);
    return 1;
}

static int s390x_aes_ecb_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    s390x_km(in, len, out, adat->plat.s390x.fc, &adat->plat.s390x.param.km);
    return 1;
}

static int s390x_aes_ofb_init_key(PROV_GENERIC_KEY *dat,
                                  const unsigned char *key, size_t keylen)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->blocksize);
    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    adat->plat.s390x.res = 0;
    return 1;
}

static int s390x_aes_ofb_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;
    int n = adat->plat.s390x.res;
    int rem;

    while (n && len) {
        *out = *in ^ adat->plat.s390x.param.kmo_kmf.cv[n];
        n = (n + 1) & 0xf;
        --len;
        ++in;
        ++out;
    }

    rem = len & 0xf;

    len &= ~(size_t)0xf;
    if (len) {
        s390x_kmo(in, len, out, adat->plat.s390x.fc,
                  &adat->plat.s390x.param.kmo_kmf);

        out += len;
        in += len;
    }

    if (rem) {
        s390x_km(adat->plat.s390x.param.kmo_kmf.cv, 16,
                 adat->plat.s390x.param.kmo_kmf.cv, adat->plat.s390x.fc,
                 adat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            out[n] = in[n] ^ adat->plat.s390x.param.kmo_kmf.cv[n];
            ++n;
        }
    }

    adat->plat.s390x.res = n;
    return 1;
}

static int s390x_aes_cfb_init_key(PROV_GENERIC_KEY *dat,
                                  const unsigned char *key, size_t keylen)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    adat->plat.s390x.fc |= 16 << 24;   /* 16 bytes cipher feedback */
    if (!dat->enc)
        adat->plat.s390x.fc |= S390X_DECRYPT;

    adat->plat.s390x.res = 0;
    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->blocksize);
    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;
    int n = adat->plat.s390x.res;
    int rem;
    unsigned char tmp;

    while (n && len) {
        tmp = *in;
        *out = adat->plat.s390x.param.kmo_kmf.cv[n] ^ tmp;
        adat->plat.s390x.param.kmo_kmf.cv[n] = dat->enc ? *out : tmp;
        n = (n + 1) & 0xf;
        --len;
        ++in;
        ++out;
    }

    rem = len & 0xf;

    len &= ~(size_t)0xf;
    if (len) {
        s390x_kmf(in, len, out, adat->plat.s390x.fc,
                  &adat->plat.s390x.param.kmo_kmf);

        out += len;
        in += len;
    }

    if (rem) {
        s390x_km(adat->plat.s390x.param.kmo_kmf.cv, 16,
                 adat->plat.s390x.param.kmo_kmf.cv,
                 S390X_AES_FC(dat->keylen), adat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            tmp = in[n];
            out[n] = adat->plat.s390x.param.kmo_kmf.cv[n] ^ tmp;
            adat->plat.s390x.param.kmo_kmf.cv[n] = dat->enc ? out[n] : tmp;
            ++n;
        }
    }

    adat->plat.s390x.res = n;
    return 1;
}

static int s390x_aes_cfb8_init_key(PROV_GENERIC_KEY *dat,
                                   const unsigned char *key, size_t keylen)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    adat->plat.s390x.fc |= 1 << 24;   /* 1 byte cipher feedback */
    if (!dat->enc)
        adat->plat.s390x.fc |= S390X_DECRYPT;

    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->blocksize);
    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb8_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    s390x_kmf(in, len, out, adat->plat.s390x.fc,
              &adat->plat.s390x.param.kmo_kmf);
    return 1;
}

# define s390x_aes_cfb1_init_key aes_init_key

# define s390x_aes_cfb1_cipher aes_cfb1_cipher
static int s390x_aes_cfb1_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len);
# define S390X_AES_CTR_CTX          PROV_GENERIC_KEY

# define s390x_aes_ctr_init_key aes_init_key

# define s390x_aes_ctr_cipher aes_ctr_cipher
static int s390x_aes_ctr_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                const unsigned char *in, size_t len);

# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER s390x_aes_##mode = {                          \
        s390x_aes_##mode##_init_key,                                           \
        s390x_aes_##mode##_cipher                                              \
};                                                                             \
static const PROV_GENERIC_CIPHER aes_##mode = {                                \
        aes_init_key,                                                          \
        generic_##mode##_cipher                                                \
};                                                                             \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{                                                                              \
    if ((keybits == 128 && S390X_aes_128_##mode##_CAPABLE)                     \
            || (keybits == 192 && S390X_aes_192_##mode##_CAPABLE)              \
            || (keybits == 256 && S390X_aes_256_##mode##_CAPABLE))             \
        return &s390x_aes_##mode;                                              \
                                                                               \
    return &aes_##mode;                                                        \
}

#else
/* The generic case */
# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER aes_##mode = {                                \
        aes_init_key,                                                          \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{ return &aes_##mode; }

#endif

static int aes_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                        size_t keylen)
{
    int ret;
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
#ifdef HWAES_CAPABLE
        if (HWAES_CAPABLE) {
            ret = HWAES_set_decrypt_key(key, keylen * 8, ks);
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
            ret = AES_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f)AES_decrypt;
            dat->stream.cbc = (cbc128_f)bsaes_cbc_encrypt;
        } else
#endif
#ifdef VPAES_CAPABLE
        if (VPAES_CAPABLE) {
            ret = vpaes_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f)vpaes_decrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ?(cbc128_f)vpaes_cbc_encrypt : NULL;
        } else
#endif
        {
            ret = AES_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f)AES_decrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ? (cbc128_f)AES_cbc_encrypt : NULL;
        }
    } else
#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        ret = HWAES_set_encrypt_key(key, keylen * 8, ks);
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
        ret = AES_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f)AES_encrypt;
        dat->stream.ctr = (ctr128_f)bsaes_ctr32_encrypt_blocks;
    } else
#endif
#ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        ret = vpaes_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f)vpaes_encrypt;
        dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                          ? (cbc128_f)vpaes_cbc_encrypt : NULL;
    } else
#endif
    {
        ret = AES_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f)AES_encrypt;
        dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                          ? (cbc128_f)AES_cbc_encrypt : NULL;
#ifdef AES_CTR_ASM
        if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f)AES_ctr32_encrypt;
#endif
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int generic_cbc_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, dat->ks, dat->iv, dat->enc);
    else if (dat->enc)
        CRYPTO_cbc128_encrypt(in, out, len, dat->ks, dat->iv, dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, dat->ks, dat->iv, dat->block);

    return 1;
}

static int generic_ecb_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    size_t i, bl = dat->blocksize;

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, dat->ks);

    return 1;
}

static int generic_ofb128_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_ofb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->block);
    dat->num = num;

    return 1;
}

static int generic_cfb128_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                                 const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_cfb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
                          dat->block);
    dat->num = num;

    return 1;
}

static int generic_cfb8_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_cfb128_8_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
                            dat->block);
    dat->num = num;

    return 1;
}

static int generic_cfb1_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    int num = dat->num;

    if ((dat->flags & EVP_CIPH_FLAG_LENGTH_BITS) != 0) {
        CRYPTO_cfb128_1_encrypt(in, out, len, dat->ks, dat->iv, &num,
                                dat->enc, dat->block);
        dat->num = num;
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, dat->ks,
                                dat->iv, &num, dat->enc, dat->block);
        len -= MAXBITCHUNK;
        out += MAXBITCHUNK;
        in  += MAXBITCHUNK;
    }
    if (len)
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, dat->ks, dat->iv, &num,
                                dat->enc, dat->block);

    dat->num = num;

    return 1;
}

static int generic_ctr_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    unsigned int num = dat->num;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, dat->ks, dat->iv, dat->buf,
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, dat->ks, dat->iv, dat->buf,
                              &num, dat->block);
    dat->num = num;

    return 1;
}

BLOCK_CIPHER_aes_generic_prov(cbc)
BLOCK_CIPHER_aes_generic_prov(ecb)
BLOCK_CIPHER_aes_generic_prov(ofb128)
BLOCK_CIPHER_aes_generic_prov(cfb128)
BLOCK_CIPHER_aes_generic_prov(cfb1)
BLOCK_CIPHER_aes_generic_prov(cfb8)
BLOCK_CIPHER_aes_generic_prov(ctr)

#ifndef FIPS_MODE

# ifndef OPENSSL_NO_ARIA

/*
 * TODO (3.0) The chunked code needs to move when other ciphers start using
 * these methods. It is only here currently to avoid 'not used' errors.
 */
#define chunked_ctr_cipher generic_ctr_cipher
#define chunked_cfb1_cipher generic_cfb1_cipher
#define chunked_ecb_cipher generic_ecb_cipher

static int chunked_cbc_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        generic_cbc_cipher(ctx, out, in, EVP_MAXCHUNK);
        inl -= EVP_MAXCHUNK;
        in  += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl > 0)
        generic_cbc_cipher(ctx, out, in, inl);
    return 1;
}

static int chunked_cfb8_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    size_t chunk = EVP_MAXCHUNK;

    if (inl < chunk)
        chunk = inl;
    while (inl > 0 && inl >= chunk) {
        generic_cfb8_cipher(ctx, out, in, inl);
        inl -= chunk;
        in += chunk;
        out += chunk;
        if (inl < chunk)
            chunk = inl;
    }
    return 1;
}

static int chunked_cfb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl)
{
    size_t chunk = EVP_MAXCHUNK;

    if (inl < chunk)
        chunk = inl;
    while (inl > 0 && inl >= chunk) {
        generic_cfb128_cipher(ctx, out, in, inl);
        inl -= chunk;
        in += chunk;
        out += chunk;
        if (inl < chunk)
            chunk = inl;
    }
    return 1;
}

static int chunked_ofb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        generic_ofb128_cipher(ctx, out, in, EVP_MAXCHUNK);
        inl -= EVP_MAXCHUNK;
        in  += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl > 0)
        generic_ofb128_cipher(ctx, out, in, inl);
    return 1;
}

static int aria_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                         size_t keylen)
{
    int ret, mode = dat->mode;
    PROV_ARIA_KEY *adat = (PROV_ARIA_KEY *)dat;
    ARIA_KEY *ks = &adat->ks.ks;

    if (dat->enc || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE))
        ret = aria_set_encrypt_key(key, keylen * 8, ks);
    else
        ret = aria_set_decrypt_key(key, keylen * 8, ks);
    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, EVP_R_ARIA_KEY_SETUP_FAILED);
        return 0;
    }
    dat->ks = ks;
    dat->block = (block128_f)aria_encrypt;
    return 1;
}

# define BLOCK_CIPHER_aria_chunked_prov(mode)                                  \
static const PROV_GENERIC_CIPHER aria_##mode = {                               \
        aria_init_key,                                                         \
        chunked_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_ARIA_CIPHER_##mode(size_t keybits)             \
{ return &aria_##mode; }

BLOCK_CIPHER_aria_chunked_prov(cbc)
BLOCK_CIPHER_aria_chunked_prov(ecb)
BLOCK_CIPHER_aria_chunked_prov(ofb128)
BLOCK_CIPHER_aria_chunked_prov(cfb128)
BLOCK_CIPHER_aria_chunked_prov(cfb1)
BLOCK_CIPHER_aria_chunked_prov(cfb8)
BLOCK_CIPHER_aria_chunked_prov(ctr)

# endif /* OPENSSL_NO_ARIA */

# ifndef OPENSSL_NO_CAMELLIA
#  if defined(SPARC_CMLL_CAPABLE)
static int t4_camellia_init_key(PROV_GENERIC_KEY *dat,
                                const unsigned char *key, size_t keylen)
{
    int ret = 0, bits, mode = dat->mode;
    PROV_CAMELLIA_KEY *adat = (PROV_CAMELLIA_KEY *)dat;
    CAMELLIA_KEY *ks = &adat->ks.ks;

    dat->ks = ks;
    bits = keylen * 8;

    cmll_t4_set_key(key, bits, ks);

    if (dat->enc || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE)) {
        dat->block = (block128_f) cmll_t4_encrypt;
        switch (bits) {
        case 128:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll128_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
        case 256:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll256_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
            break;
        }
    } else {
        dat->block = (block128_f) cmll_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll128_t4_cbc_decrypt : NULL;
            break;
        case 192:
        case 256:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
            break;
        }
    }
    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, EVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }
    return 1;
}

#   define BLOCK_CIPHER_camellia_generic_prov(mode)                            \
static const PROV_GENERIC_CIPHER t4_camellia_##mode = {                        \
    t4_camellia_##mode##_init_key,                                             \
    generic_##mode##_cipher                                                    \
};                                                                             \
static const PROV_GENERIC_CIPHER camellia_##mode = {                           \
    camellia_init_key,                                                         \
    generic_##mode##_cipher                                                    \
};                                                                             \
const PROV_GENERIC_CIPHER *PROV_CAMELLIA_CIPHER_##mode(size_t keybits)         \
{                                                                              \
    if (SPARC_CMLL_CAPABLE)                                                    \
        return &t4_camellia_##mode;                                            \
                                                                               \
    return &camellia_##mode;                                                   \
}

#  else
/* The generic case for camellia */
#   define BLOCK_CIPHER_camellia_generic_prov(mode)                            \
static const PROV_GENERIC_CIPHER camellia_##mode = {                           \
        camellia_init_key,                                                     \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_CAMELLIA_CIPHER_##mode(size_t keybits)         \
{ return &camellia_##mode; }
#  endif /* SPARC_CMLL_CAPABLE */

static int camellia_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                             size_t keylen)
{
    int ret, mode = dat->mode;
    PROV_CAMELLIA_KEY *adat = (PROV_CAMELLIA_KEY *)dat;
    CAMELLIA_KEY *ks = &adat->ks.ks;

    dat->ks = ks;
    ret = Camellia_set_key(key, keylen * 8, ks);
    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, EVP_R_ARIA_KEY_SETUP_FAILED);
        return 0;
    }
    if (dat->enc || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE)) {
        dat->block = (block128_f) Camellia_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) Camellia_cbc_encrypt : NULL;
    } else {
        dat->block = (block128_f) Camellia_decrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) Camellia_cbc_encrypt : NULL;
    }
    return 1;
}

BLOCK_CIPHER_camellia_generic_prov(cbc)
BLOCK_CIPHER_camellia_generic_prov(ecb)
BLOCK_CIPHER_camellia_generic_prov(ofb128)
BLOCK_CIPHER_camellia_generic_prov(cfb128)
BLOCK_CIPHER_camellia_generic_prov(cfb1)
BLOCK_CIPHER_camellia_generic_prov(cfb8)
BLOCK_CIPHER_camellia_generic_prov(ctr)
# endif /* OPENSSL_NO_CAMELLIA */
#endif /* FIPS_MODE */
