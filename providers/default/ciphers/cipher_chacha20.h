/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "include/crypto/chacha.h"
#include "internal/ciphers/ciphercommon.h"

typedef struct {
    union {
        OSSL_UNION_ALIGN;
        unsigned int d[CHACHA_KEY_SIZE / 4];
    } key;
    unsigned int  counter[CHACHA_CTR_SIZE / 4];
    unsigned char buf[CHACHA_BLK_SIZE];
    unsigned int  partial_len;
} PROV_CHACHA20_CTX;

int CHACHA20_init_key(void *vctx, const unsigned char user_key[CHACHA_KEY_SIZE],
                      const unsigned char iv[CHACHA_CTR_SIZE], int enc);
int CHACHA20_cipher(void *vctx, unsigned char *out, const unsigned char *inp,
                    size_t len);
