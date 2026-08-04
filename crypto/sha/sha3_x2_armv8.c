/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file is minimal because a generic non interleaved input implementation
 * that handles multiple partial absorbs and partial squeezes is not required
 * at this time. To implement this the partial blocks need to be buffered,
 * The ML_DSA code has been adapted to operate on fully aligned blocks for both
 * the absorb and squeeze.
 * (The buffering would be similar to the approach used by the ossl_sha3_ functions).
 */

#include "arch/arm_arch.h"
#include "internal/sha3.h"
#include <openssl/crypto.h>
#include <string.h>
#include <openssl/byteorder.h>
#include "internal/common.h"
#if defined(__aarch64__) && defined(__AARCH64EL__) && defined(KECCAK1600_ASM) && !defined(OPENSSL_NO_ASM)

int ossl_shakex2_sha3_capable_armv8(void)
{
    return (OPENSSL_armcap_P & ARMV8_SHA3);
}

void ossl_shakex2_cleanup_armv8(KECCAK1600_X2_ARMV8_CTX *ctx)
{
    OPENSSL_cleanse(ctx->A, sizeof(ctx->A));
}

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */
