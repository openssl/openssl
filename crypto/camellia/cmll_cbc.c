/*
 * Copyright 2006-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * Camellia low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <opentls/camellia.h>
#include <opentls/modes.h>

void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
                          size_t len, const CAMELLIA_KEY *key,
                          unsigned char *ivec, const int enc)
{

    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f) Camellia_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f) Camellia_decrypt);
}
