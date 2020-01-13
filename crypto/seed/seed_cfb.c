/*
 * Copyright 2007-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/seed.h>
#include <opentls/modes.h>

void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const SEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[SEED_BLOCK_SIZE], int *num,
                         int enc)
{
    CRYPTO_cfb128_encrypt(in, out, len, ks, ivec, num, enc,
                          (block128_f) SEED_encrypt);
}
