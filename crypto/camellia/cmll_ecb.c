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
#include "cmll_local.h"

void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out,
                          const CAMELLIA_KEY *key, const int enc)
{
    if (CAMELLIA_ENCRYPT == enc)
        Camellia_encrypt(in, out, key);
    else
        Camellia_decrypt(in, out, key);
}
