/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

# include <openssl/obj_mac.h>
# include "crypto/evp.h"

static const EVP_MD sha1_md = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
};

const EVP_MD *EVP_sha1(void)
{
    return &sha1_md;
}

static const EVP_MD sha224_md = {
    NID_sha224,
    NID_sha224WithRSAEncryption,
};

const EVP_MD *EVP_sha224(void)
{
    return &sha224_md;
}

static const EVP_MD sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
};

const EVP_MD *EVP_sha256(void)
{
    return &sha256_md;
}

static const EVP_MD sha512_224_md = {
    NID_sha512_224,
    NID_sha512_224WithRSAEncryption,
};

const EVP_MD *EVP_sha512_224(void)
{
    return &sha512_224_md;
}

static const EVP_MD sha512_256_md = {
    NID_sha512_256,
    NID_sha512_256WithRSAEncryption,
};

const EVP_MD *EVP_sha512_256(void)
{
    return &sha512_256_md;
}

static const EVP_MD sha384_md = {
    NID_sha384,
    NID_sha384WithRSAEncryption,
};

const EVP_MD *EVP_sha384(void)
{
    return &sha384_md;
}

static const EVP_MD sha512_md = {
    NID_sha512,
    NID_sha512WithRSAEncryption,
};

const EVP_MD *EVP_sha512(void)
{
    return &sha512_md;
}

# define EVP_MD_SHA3(bitlen)                            \
    const EVP_MD *EVP_sha3_##bitlen(void)               \
    {                                                   \
        static const EVP_MD sha3_##bitlen##_md = {      \
            NID_sha3_##bitlen,                          \
            NID_RSA_SHA3_##bitlen,                      \
        };                                              \
        return &sha3_##bitlen##_md;                     \
    }
# define EVP_MD_SHAKE(bitlen)                           \
    const EVP_MD *EVP_shake##bitlen(void)               \
    {                                                   \
        static const EVP_MD shake##bitlen##_md = {      \
            NID_shake##bitlen,                          \
            0,                                          \
        };                                              \
        return &shake##bitlen##_md;                     \
    }

EVP_MD_SHA3(224)
EVP_MD_SHA3(256)
EVP_MD_SHA3(384)
EVP_MD_SHA3(512)

EVP_MD_SHAKE(128)
EVP_MD_SHAKE(256)
