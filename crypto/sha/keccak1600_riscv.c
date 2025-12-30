/*
 * Copyright 2023-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include "crypto/riscv_arch.h"

#ifdef INCLUDE_C_KECCAK1600
/* The fallback implementation for `SHA3_absorb` and `SHA3_squeeze`. */
size_t SHA3_absorb_c(uint64_t A[5][5], const unsigned char *inp, size_t len,
    size_t r);
void SHA3_squeeze_c(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);
#endif

size_t SHA3_absorb_v_zbb(uint64_t A[5][5], const unsigned char *inp, size_t len,
    size_t r);
void SHA3_squeeze_v_zbb(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
    size_t r)
{
    if (RISCV_HAS_ZBB() && riscv_vlen() >= 128) {
        return SHA3_absorb_v_zbb(A, inp, len, r);
    } else {
        return SHA3_absorb_c(A, inp, len, r);
    }
}

void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next)
{
    if (RISCV_HAS_ZBB() && riscv_vlen() >= 128) {
        SHA3_squeeze_v_zbb(A, out, len, r, next);
    } else {
        SHA3_squeeze_c(A, out, len, r, next);
    }
}
