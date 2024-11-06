/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "internal/refcount.h"

#define SLH_DSA_MAX_KEYLEN 32 * 2 /* 2 * n */
#define SLH_DSA_SK_SEED(key) (key->priv)
#define SLH_DSA_SK_PRF(key)  (key->priv + key->params->n)
#define SLH_DSA_PK_SEED(key) (key->pub)
#define SLH_DSA_PK_ROOT(key) (key->pub + key->params->n)

struct slh_dsa_key_st {
    uint8_t pub[SLH_DSA_MAX_KEYLEN];
    uint8_t priv[SLH_DSA_MAX_KEYLEN];
    size_t key_len; /* This value is set to 2 * n if there is a public key */
    CRYPTO_REF_COUNT references;
    OSSL_LIB_CTX *libctx;
    char *propq;
    const SLH_DSA_PARAMS *params;
    int has_priv;
};
