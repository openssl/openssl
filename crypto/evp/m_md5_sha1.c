/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_MD5

# include <string.h>
# include <openssl/evp.h>
# include <openssl/obj_mac.h>
# include "internal/evp_int.h"
# include "internal/md5_sha1.h"

static int init(EVP_MD_CTX *ctx)
{
    return md5_sha1_init(EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return md5_sha1_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return md5_sha1_final(md, EVP_MD_CTX_md_data(ctx));
}

static int ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)
{
    return md5_sha1_ctrl(EVP_MD_CTX_md_data(ctx), cmd, mslen, ms);
}

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_SHA1_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    MD5_SHA1_CBLOCK,
    sizeof(EVP_MD *) + sizeof(MD5_SHA1_CTX),
    ctrl
};

const EVP_MD *EVP_md5_sha1(void)
{
    return &md5_sha1_md;
}

#endif /* OPENSSL_NO_MD5 */
