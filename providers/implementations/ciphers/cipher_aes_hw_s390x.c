/*
 * Copyright 2001-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * IBM S390X support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes.h"
#include "arch/s390x_arch.h"
#include <stdio.h>

#if defined(S390X_aes_128_CAPABLE)

static int s390x_aes_ecb_initkey(PROV_CIPHER_CTX *dat,
    const unsigned char *key, size_t keylen)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    memcpy(adat->plat.s390x.param.km.k, key, keylen);
    return 1;
}

static int s390x_aes_ecb_cipher_hw(PROV_CIPHER_CTX *dat, unsigned char *out,
    const unsigned char *in, size_t len)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    unsigned int modifier = adat->base.enc ? 0 : S390X_DECRYPT;

    s390x_km(in, len, out, adat->plat.s390x.fc | modifier,
        &adat->plat.s390x.param.km);
    return 1;
}

static const PROV_CIPHER_HW s390x_aes_ecb = {
    s390x_aes_ecb_initkey,
    s390x_aes_ecb_cipher_hw,
    ossl_cipher_aes_copyctx
};

static int s390x_aes_ofb128_initkey(PROV_CIPHER_CTX *dat,
    const unsigned char *key, size_t keylen)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;

    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    return 1;
}

static int s390x_aes_ofb128_cipher_hw(PROV_CIPHER_CTX *dat, unsigned char *out,
    const unsigned char *in, size_t len)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    int n = dat->num;
    int rem;

    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->ivlen);
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
            adat->plat.s390x.param.kmo_kmf.cv,
            adat->plat.s390x.fc,
            adat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            out[n] = in[n] ^ adat->plat.s390x.param.kmo_kmf.cv[n];
            ++n;
        }
    }

    memcpy(dat->iv, adat->plat.s390x.param.kmo_kmf.cv, dat->ivlen);
    dat->num = n;
    return 1;
}

static const PROV_CIPHER_HW s390x_aes_ofb128 = {
    s390x_aes_ofb128_initkey,
    s390x_aes_ofb128_cipher_hw,
    ossl_cipher_aes_copyctx
};

static int s390x_aes_cfb128_initkey(PROV_CIPHER_CTX *dat,
    const unsigned char *key, size_t keylen)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    adat->plat.s390x.fc |= 16 << 24; /* 16 bytes cipher feedback */
    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb128_cipher_hw(PROV_CIPHER_CTX *dat, unsigned char *out,
    const unsigned char *in, size_t len)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    unsigned int modifier = adat->base.enc ? 0 : S390X_DECRYPT;
    int n = dat->num;
    int rem;
    unsigned char tmp;

    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->ivlen);
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
        s390x_kmf(in, len, out, adat->plat.s390x.fc | modifier,
            &adat->plat.s390x.param.kmo_kmf);

        out += len;
        in += len;
    }

    if (rem) {
        s390x_km(adat->plat.s390x.param.kmo_kmf.cv, 16,
            adat->plat.s390x.param.kmo_kmf.cv,
            S390X_AES_FC(dat->keylen),
            adat->plat.s390x.param.kmo_kmf.k);

        while (rem--) {
            tmp = in[n];
            out[n] = adat->plat.s390x.param.kmo_kmf.cv[n] ^ tmp;
            adat->plat.s390x.param.kmo_kmf.cv[n] = dat->enc ? out[n] : tmp;
            ++n;
        }
    }

    memcpy(dat->iv, adat->plat.s390x.param.kmo_kmf.cv, dat->ivlen);
    dat->num = n;
    return 1;
}

static const PROV_CIPHER_HW s390x_aes_cfb128 = {
    s390x_aes_cfb128_initkey,
    s390x_aes_cfb128_cipher_hw,
    ossl_cipher_aes_copyctx
};

static int s390x_aes_cfb8_initkey(PROV_CIPHER_CTX *dat,
    const unsigned char *key, size_t keylen)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;

    adat->plat.s390x.fc = S390X_AES_FC(keylen);
    adat->plat.s390x.fc |= 1 << 24; /* 1 byte cipher feedback */
    memcpy(adat->plat.s390x.param.kmo_kmf.k, key, keylen);
    return 1;
}

static int s390x_aes_cfb8_cipher_hw(PROV_CIPHER_CTX *dat, unsigned char *out,
    const unsigned char *in, size_t len)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    unsigned int modifier = adat->base.enc ? 0 : S390X_DECRYPT;

    memcpy(adat->plat.s390x.param.kmo_kmf.cv, dat->iv, dat->ivlen);
    s390x_kmf(in, len, out, adat->plat.s390x.fc | modifier,
        &adat->plat.s390x.param.kmo_kmf);
    memcpy(dat->iv, adat->plat.s390x.param.kmo_kmf.cv, dat->ivlen);
    return 1;
}

static const PROV_CIPHER_HW s390x_aes_cfb8 = {
    s390x_aes_cfb8_initkey,
    s390x_aes_cfb8_cipher_hw,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_s390x(enum aes_modes mode,
    size_t keybits)
{
    switch (mode) {
    case AES_MODE_ECB:
        if ((keybits == 128 && S390X_aes_128_ecb_CAPABLE)
            || (keybits == 192 && S390X_aes_192_ecb_CAPABLE)
            || (keybits == 256 && S390X_aes_256_ecb_CAPABLE))
            return &s390x_aes_ecb;
        break;
    case AES_MODE_CFB128:
        if ((keybits == 128 && S390X_aes_128_cfb_CAPABLE)
            || (keybits == 192 && S390X_aes_192_cfb_CAPABLE)
            || (keybits == 256 && S390X_aes_256_cfb_CAPABLE))
            return &s390x_aes_cfb128;
        break;
    case AES_MODE_CFB8:
        if ((keybits == 128 && S390X_aes_128_cfb8_CAPABLE)
            || (keybits == 192 && S390X_aes_192_cfb8_CAPABLE)
            || (keybits == 256 && S390X_aes_256_cfb8_CAPABLE))
            return &s390x_aes_cfb8;
        break;
    case AES_MODE_OFB128:
        if ((keybits == 128 && S390X_aes_128_ofb_CAPABLE)
            || (keybits == 192 && S390X_aes_192_ofb_CAPABLE)
            || (keybits == 256 && S390X_aes_256_ofb_CAPABLE))
            return &s390x_aes_ofb128;
        break;
    default:
        break;
    }
    return NULL;
}

#endif
