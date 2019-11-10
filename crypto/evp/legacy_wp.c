/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/whrlpool.h>
#include "crypto/evp.h"

static const EVP_MD whirlpool_md = {
    NID_whirlpool,
    0,
    WHIRLPOOL_DIGEST_LENGTH,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    WHIRLPOOL_BBLOCK / 8,
};

const EVP_MD *EVP_whirlpool(void)
{
    return &whirlpool_md;
}
