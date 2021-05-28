/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MY_DIGEST_H
# define OPENSSL_MY_DIGEST_H
# pragma once

#include <prov/digestcommon.h>
#include <prov/providercommon.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define MY_DIGEST_LENGTH 16

#define MY_DIGEST_LONG unsigned int
#define MY_DIGEST_CBLOCK      64
#define MY_DIGEST_LBLOCK      (MY_DIGEST_CBLOCK/4)

typedef struct MY_DIGEST_state_st {
    long data[MY_DIGEST_LBLOCK];
} MY_DIGEST_CTX;

int my_digest_Init(MY_DIGEST_CTX *c);
int my_digest_Update(MY_DIGEST_CTX *c, const void *data, size_t len);
int my_digest_Final(unsigned char *myd, MY_DIGEST_CTX *c);

IMPLEMENT_digest_functions(my_digest, MY_DIGEST_CTX,
                           MY_DIGEST_CBLOCK, MY_DIGEST_LBLOCK, 0,
                           my_digest_Init, my_digest_Update, my_digest_Final)

#ifdef  __cplusplus
}
#endif
#endif /* OPENSSL_MY_DIGEST_H */
