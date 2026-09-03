/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/types.h>
#include "crypto/poly1305.h"
#include "arch/riscv_arch.h"

void poly1305_init_riscv64(void *ctx, const unsigned char key[16]);
void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
    unsigned int padbit);
void poly1305_emit(void *ctx, unsigned char mac[16],
    const unsigned int nonce[4]);
void poly1305_blocks_vx(void *ctx, const unsigned char *inp, size_t len,
    unsigned int padbit);

int poly1305_init(void *ctx, const unsigned char key[16], void *func[2]);
int poly1305_init(void *ctx, const unsigned char key[16], void *func[2])
{
    poly1305_init_riscv64(ctx, key);

    if (RISCV_HAS_V() && riscv_vlen() >= 128) {
        func[0] = (void *)(uintptr_t)poly1305_blocks_vx;
    } else {
        func[0] = (void *)(uintptr_t)poly1305_blocks;
    }
    func[1] = (void *)(uintptr_t)poly1305_emit;

    return 1;
}
