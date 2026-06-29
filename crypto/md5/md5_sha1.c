/*
 * Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * MD5 and SHA-1 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include "prov/md5_sha1.h"
#include <openssl/evp.h>

int ossl_md5_sha1_init(MD5_SHA1_CTX *mctx)
{
    if (!MD5_Init(&mctx->md5))
        return 0;
    return SHA1_Init(&mctx->sha1);
}

int ossl_md5_sha1_update(MD5_SHA1_CTX *mctx, const void *data, size_t count)
{
    if (!MD5_Update(&mctx->md5, data, count))
        return 0;
    return SHA1_Update(&mctx->sha1, data, count);
}

int ossl_md5_sha1_final(unsigned char *md, MD5_SHA1_CTX *mctx)
{
    if (!MD5_Final(md, &mctx->md5))
        return 0;
    return SHA1_Final(md + MD5_DIGEST_LENGTH, &mctx->sha1);
}
