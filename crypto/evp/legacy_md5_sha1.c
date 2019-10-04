/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include "prov/md5_sha1.h"   /* diverse MD5_SHA1 macros */

#ifndef OPENSSL_NO_MD5

# include <openssl/obj_mac.h>
# include "crypto/evp.h"

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_SHA1_DIGEST_LENGTH,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    MD5_SHA1_CBLOCK,
};

const EVP_MD *EVP_md5_sha1(void)
{
    return &md5_sha1_md;
}

#endif /* OPENSSL_NO_MD5 */
