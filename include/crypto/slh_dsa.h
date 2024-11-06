/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal SLH_DSA functions for other submodules, not for application use */

#ifndef OSSL_CRYPTO_SLH_DSA_H
# define OSSL_CRYPTO_SLH_DSA_H

# pragma once
# include <openssl/e_os2.h>
# include <openssl/types.h>
# include "crypto/types.h"

# define SLH_DSA_MAX_CONTEXT_STRING_LEN 255

typedef struct slh_dsa_ctx_st SLH_DSA_CTX;

SLH_DSA_KEY *ossl_slh_dsa_key_new(OSSL_LIB_CTX *libctx, const char *alg);
void ossl_slh_dsa_key_free(SLH_DSA_KEY *key);
int ossl_slh_dsa_key_up_ref(SLH_DSA_KEY *key);
int ossl_slh_dsa_key_equal(const SLH_DSA_KEY *key1, const SLH_DSA_KEY *key2,
                           int selection);
int ossl_slh_dsa_key_has(const SLH_DSA_KEY *key, int selection);
int ossl_slh_dsa_key_fromdata(SLH_DSA_KEY *key, const OSSL_PARAM *params);

int ossl_slh_dsa_key_type_matches(SLH_DSA_CTX *ctx, const SLH_DSA_KEY *key);

SLH_DSA_CTX *ossl_slh_dsa_ctx_new(const char *alg,
                                  OSSL_LIB_CTX *lib_ctx, const char *propq);
void ossl_slh_dsa_ctx_free(SLH_DSA_CTX *ctx);

int ossl_slh_dsa_verify(SLH_DSA_CTX *slh_ctx, const SLH_DSA_KEY *pub,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *ctx, size_t ctx_len, int encode,
                        const uint8_t *sig, size_t sig_len);

#endif /* OSSL_CRYPTO_SLH_DSA_H */
