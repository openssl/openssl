/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"
#include "prov/md5_sha1.h"   /* diverse MD5_SHA1 macros */
#include "legacy_meth.h"

IMPLEMENT_LEGACY_EVP_MD_METH_LC(md5_sha1_int, md5_sha1)
static int md5_sha1_int_ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)
{
    return md5_sha1_ctrl(EVP_MD_CTX_md_data(ctx), cmd, mslen, ms);
}

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_SHA1_DIGEST_LENGTH,
    0,
    LEGACY_EVP_MD_METH_TABLE(md5_sha1_int_init, md5_sha1_int_update,
                             md5_sha1_int_final, md5_sha1_int_ctrl,
                             MD5_SHA1_CBLOCK),
};

const EVP_MD *EVP_md5_sha1(void)
{
    return &md5_sha1_md;
}
