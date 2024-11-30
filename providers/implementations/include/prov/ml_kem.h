/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_ML_KEM_H
# define OSSL_INTERNAL_ML_KEM_H
# pragma once

# ifndef OPENSSL_NO_ML_KEM

#  include <stdint.h>
#  include <crypto/ml_kem.h>

typedef struct {
    void *provctx;
    void *prvkey;
    void *pubkey;
    const ossl_ml_kem_vinfo *vinfo;
    ossl_ml_kem_ctx *ctx;
} ML_KEM_PROVIDER_KEYPAIR;

#  define have_keys(k) (k->pubkey != NULL || k->prvkey != NULL)

# endif /* OPENSSL_NO_ML_KEM */
#endif /* OSSL_INTERNAL_ML_KEM_H */
