/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_BYTEORDER_H
# define OPENSSL_BYTEORDER_H
# pragma once

# include <openssl/e_os2.h>

/*
 * "Modern" compilers do a decent job of optimising these functions to just a
 * couple of instruction ([swap +] store, or load [+ swap]) when either no
 * swapping is required, or a suitable swap instruction is available.
 */

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u16_le(uint8_t *out, uint16_t val)
{
    *out++ = (val & 0xff);
    *out++ = (val >> 8) & 0xff;
    return out;
}

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u16_be(uint8_t *out, uint16_t val)
{
    *out++ = (val >> 8) & 0xff;
    *out++ = (val & 0xff);
    return out;
}

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u32_le(uint8_t *out, uint32_t val)
{
    *out++ = (val & 0xff);
    *out++ = (val >> 8) & 0xff;
    *out++ = (val >> 16) & 0xff;
    *out++ = (val >> 24) & 0xff;
    return out;
}

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u32_be(uint8_t *out, uint32_t val)
{
    *out++ = (val >> 24) & 0xff;
    *out++ = (val >> 16) & 0xff;
    *out++ = (val >> 8) & 0xff;
    *out++ = (val & 0xff);
    return out;
}

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u64_le(uint8_t *out, uint64_t val)
{
    *out++ = (val & 0xff);
    *out++ = (val >> 8) & 0xff;
    *out++ = (val >> 16) & 0xff;
    *out++ = (val >> 24) & 0xff;
    *out++ = (val >> 32) & 0xff;
    *out++ = (val >> 40) & 0xff;
    *out++ = (val >> 48) & 0xff;
    *out++ = (val >> 56) & 0xff;
    return out;
}

static ossl_inline ossl_unused uint8_t *
OSSL_CRYPTO_store_u64_be(uint8_t *out, uint64_t val)
{
    *out++ = (val >> 56) & 0xff;
    *out++ = (val >> 48) & 0xff;
    *out++ = (val >> 40) & 0xff;
    *out++ = (val >> 32) & 0xff;
    *out++ = (val >> 24) & 0xff;
    *out++ = (val >> 16) & 0xff;
    *out++ = (val >> 8) & 0xff;
    *out++ = (val & 0xff);
    return out;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u16_le(uint16_t *val, const uint8_t *in)
{
    uint16_t b0 = *in++;
    uint16_t b1 = *in++;

    *val = b0 | (b1 << 8);
    return in;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u16_be(uint16_t *val, const uint8_t *in)
{
    uint16_t b1 = *in++;
    uint16_t b0 = *in++;

    *val = b0 | (b1 << 8);
    return in;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u32_le(uint32_t *val, const uint8_t *in)
{
    uint32_t b0 = *in++;
    uint32_t b1 = *in++;
    uint32_t b2 = *in++;
    uint32_t b3 = *in++;

    *val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return in;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u32_be(uint32_t *val, const uint8_t *in)
{
    uint32_t b3 = *in++;
    uint32_t b2 = *in++;
    uint32_t b1 = *in++;
    uint32_t b0 = *in++;

    *val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return in;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u64_le(uint64_t *val, const uint8_t *in)
{
    uint64_t b0 = *in++;
    uint64_t b1 = *in++;
    uint64_t b2 = *in++;
    uint64_t b3 = *in++;
    uint64_t b4 = *in++;
    uint64_t b5 = *in++;
    uint64_t b6 = *in++;
    uint64_t b7 = *in++;

    *val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
    return in;
}

static ossl_inline ossl_unused const uint8_t *
OSSL_CRYPTO_load_u64_be(uint64_t *val, const uint8_t *in)
{
    uint64_t b7 = *in++;
    uint64_t b6 = *in++;
    uint64_t b5 = *in++;
    uint64_t b4 = *in++;
    uint64_t b3 = *in++;
    uint64_t b2 = *in++;
    uint64_t b1 = *in++;
    uint64_t b0 = *in++;

    *val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
    return in;
}

#endif
