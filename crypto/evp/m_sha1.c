/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include "crypto/evp.h"
#include "crypto/sha.h"

static int init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA1_Final(md, EVP_MD_CTX_md_data(ctx));
}

static int ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return sha1_ctrl(ctx != NULL ? EVP_MD_CTX_md_data(ctx) : NULL, cmd, p1, p2);
}

static const EVP_MD sha1_md = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init,
    update,
    final,
    NULL,
    NULL,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
    ctrl
};

const EVP_MD *EVP_sha1(void)
{
    return &sha1_md;
}

static int init224(EVP_MD_CTX *ctx)
{
    return SHA224_Init(EVP_MD_CTX_md_data(ctx));
}

static int update224(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA224_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final224(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA224_Final(md, EVP_MD_CTX_md_data(ctx));
}

static int init256(EVP_MD_CTX *ctx)
{
    return SHA256_Init(EVP_MD_CTX_md_data(ctx));
}

static int update256(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final256(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA256_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD sha224_md = {
    NID_sha224,
    NID_sha224WithRSAEncryption,
    SHA224_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init224,
    update224,
    final224,
    NULL,
    NULL,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

const EVP_MD *EVP_sha224(void)
{
    return &sha224_md;
}

static const EVP_MD sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init256,
    update256,
    final256,
    NULL,
    NULL,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

const EVP_MD *EVP_sha256(void)
{
    return &sha256_md;
}

static int init512_224(EVP_MD_CTX *ctx)
{
    return sha512_224_init(EVP_MD_CTX_md_data(ctx));
}

static int init512_256(EVP_MD_CTX *ctx)
{
    return sha512_256_init(EVP_MD_CTX_md_data(ctx));
}

static int init384(EVP_MD_CTX *ctx)
{
    return SHA384_Init(EVP_MD_CTX_md_data(ctx));
}

static int update384(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA384_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final384(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA384_Final(md, EVP_MD_CTX_md_data(ctx));
}

static int init512(EVP_MD_CTX *ctx)
{
    return SHA512_Init(EVP_MD_CTX_md_data(ctx));
}

/* See comment in SHA224/256 section */
static int update512(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA512_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final512(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA512_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD sha512_224_md = {
    NID_sha512_224,
    NID_sha512_224WithRSAEncryption,
    SHA224_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512_224,
    update512,
    final512,
    NULL,
    NULL,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha512_224(void)
{
    return &sha512_224_md;
}

static const EVP_MD sha512_256_md = {
    NID_sha512_256,
    NID_sha512_256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512_256,
    update512,
    final512,
    NULL,
    NULL,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha512_256(void)
{
    return &sha512_256_md;
}

static const EVP_MD sha384_md = {
    NID_sha384,
    NID_sha384WithRSAEncryption,
    SHA384_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init384,
    update384,
    final384,
    NULL,
    NULL,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha384(void)
{
    return &sha384_md;
}

static const EVP_MD sha512_md = {
    NID_sha512,
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512,
    update512,
    final512,
    NULL,
    NULL,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha512(void)
{
    return &sha512_md;
}
