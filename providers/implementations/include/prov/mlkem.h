/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_MLKEM_H
# define OSSL_INTERNAL_MLKEM_H
# pragma once

# ifndef OPENSSL_NO_MLKEM

#  include <stdint.h>
#  include <crypto/mlkem.h>

#  define MLKEM_KEY_TYPE_512     0
#  define MLKEM_KEY_TYPE_768     1
#  define MLKEY_KEY_TYPE_1024    2

typedef struct mlkem768_key_st {
    int keytype;
    ossl_mlkem768_private_key privkey;
    ossl_mlkem768_public_key pubkey;
    uint8_t *encoded_pubkey;
    uint8_t *encoded_privkey;
    ossl_mlkem_ctx *mlkem_ctx;
    void *provctx;
} MLKEM768_KEY;

# endif /* OPENSSL_NO_MLKEM */

#endif /* OSSL_INTERNAL_MLKEM_H */
