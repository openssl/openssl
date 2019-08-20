/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * IBM S390X AES basic modes support
 * Note this file is included by aes_gcm_hw.c
 */

# include "s390x_arch.h"

# define s390x_aes_init_key aes_init_key
static int s390x_aes_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                              size_t keylen);
# define s390x_aes_cbc_init_key aes_init_key
# define s390x_aes_cbc_cipher generic_cbc_cipher

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
# define s390x_aes_cfb1_cipher generic_cfb1_cipher
# define s390x_aes_ctr_init_key aes_init_key
# define s390x_aes_ctr_cipher aes_ctr_cipher

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
