/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_BLAKE2

# include <stddef.h>
# include <openssl/obj_mac.h>
# include "crypto/evp.h"
# include "internal/blake2.h"

static int init(EVP_MD_CTX *ctx)
{
    return blake2b512_init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return blake2b_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return blake2b_final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD blake2b_md = {
    NID_blake2b512,
    0,
    BLAKE2B_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    BLAKE2B_BLOCKBYTES,
    sizeof(BLAKE2B_CTX),
};

const EVP_MD *EVP_blake2b512(void)
{
    return &blake2b_md;
}
#endif /* OPENSSL_NO_BLAKE2 */
