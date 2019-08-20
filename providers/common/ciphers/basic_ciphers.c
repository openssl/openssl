/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
//#include <openssl/crypto.h>
#include <openssl/err.h>
//#include <string.h>
//#include <assert.h>
//#include <openssl/aes.h>
#include "internal/evp_int.h"
//#include <openssl/rand.h>
//#include <openssl/cmac.h>
#include "ciphers_locl.h"
#include "internal/providercommonerr.h"
#include "internal/ciphermode_platform.h"

#if defined(AESNI_CAPABLE)
# include "basic_aesni.c"
#elif defined(SPARC_AES_CAPABLE)
# include "basic_aes_t4.c"
#elif defined(S390X_aes_128_CAPABLE)
# include "basic_aes_s390x.c"
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

BLOCK_CIPHER_aes_generic_prov(cbc)
BLOCK_CIPHER_aes_generic_prov(ecb)
BLOCK_CIPHER_aes_generic_prov(ofb128)
BLOCK_CIPHER_aes_generic_prov(cfb128)
BLOCK_CIPHER_aes_generic_prov(cfb1)
BLOCK_CIPHER_aes_generic_prov(cfb8)
BLOCK_CIPHER_aes_generic_prov(ctr)

#if !defined(OPENSSL_NO_ARIA) && !defined(FIPS_MODE)

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

#endif /* OPENSSL_NO_ARIA */

#if !defined(OPENSSL_NO_CAMELLIA) && !defined(FIPS_MODE)
# if defined(SPARC_CMLL_CAPABLE)
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

#  define BLOCK_CIPHER_camellia_generic_prov(mode)                             \
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

# else
/* The generic case for camellia */
#  define BLOCK_CIPHER_camellia_generic_prov(mode)                             \
static const PROV_GENERIC_CIPHER camellia_##mode = {                           \
        camellia_init_key,                                                     \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_CAMELLIA_CIPHER_##mode(size_t keybits)         \
{ return &camellia_##mode; }
# endif /* SPARC_CMLL_CAPABLE */

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
#endif /* OPENSSL_NO_CAMELLIA */
