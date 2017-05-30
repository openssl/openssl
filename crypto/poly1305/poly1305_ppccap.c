/*
 * Copyright 2009-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/opensslconf.h>
#include "../ppc_arch.h"

#ifdef OPENSSL_NO_POLY1305
NON_EMPTY_TRANSLATION_UNIT
#else
void poly1305_init_int(void *ctx, const unsigned char key[16]);
void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void poly1305_emit(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
void poly1305_init_fpu(void *ctx, const unsigned char key[16]);
void poly1305_blocks_fpu(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void poly1305_emit_fpu(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
int poly1305_init(void *ctx, const unsigned char key[16], void *func[2])
{
    if (sizeof(size_t) == 4 && (OPENSSL_ppccap_P & PPC_FPU)) {
        poly1305_init_fpu(ctx, key);
        func[0] = poly1305_blocks_fpu;
        func[1] = poly1305_emit_fpu;
    } else {
        poly1305_init_int(ctx, key);
        func[0] = poly1305_blocks;
        func[1] = poly1305_emit;
    }
    return 1;
}
#endif

