/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/sm3.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

static int ossl_sm3_update_thunk(void *c, const unsigned char *data,
                                 unsigned long len)
{
    return ossl_sm3_update((SM3_CTX *)c, (const void *)data, (size_t)len);
}

/* ossl_sm3_functions */
IMPLEMENT_digest_functions(sm3, SM3_CTX,
                           SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
                           ossl_sm3_init, ossl_sm3_update_thunk, ossl_sm3_final)
