/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal ML_DSA functions for other submodules, not for application use */

#ifndef OSSL_CRYPTO_ML_DSA_H
# define OSSL_CRYPTO_ML_DSA_H

# pragma once
# include <openssl/e_os2.h>
# include <openssl/types.h>
# include "crypto/types.h"

# define ML_DSA_MAX_CONTEXT_STRING_LEN 255

__owur ML_DSA_KEY *ossl_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                                       const char *alg);
__owur int ossl_ml_dsa_key_pub_alloc(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_priv_alloc(ML_DSA_KEY *key);
void ossl_ml_dsa_key_free(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_equal(const ML_DSA_KEY *key1, const ML_DSA_KEY *key2,
                                 int selection);
__owur int ossl_ml_dsa_key_has(const ML_DSA_KEY *key, int selection);
__owur int ossl_ml_dsa_key_pairwise_check(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_fromdata(ML_DSA_KEY *key, const OSSL_PARAM *params,
                                    int include_private);
__owur int ossl_ml_dsa_generate_key(OSSL_LIB_CTX *libctx,
                                    const uint8_t *entropy, size_t entropy_len,
                                    ML_DSA_KEY *out);
__owur const uint8_t *ossl_ml_dsa_key_get_pub(const ML_DSA_KEY *key);
__owur const uint8_t *ossl_ml_dsa_key_get_priv(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_pub_len(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_collision_strength_bits(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_priv_len(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_sig_len(const ML_DSA_KEY *key);
__owur const char *ossl_ml_dsa_key_get_name(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_matches(const ML_DSA_KEY *key, const char *alg);
void ossl_ml_dsa_key_set0_libctx(ML_DSA_KEY *key, OSSL_LIB_CTX *lib_ctx);

__owur int ossl_ml_dsa_key_public_from_private(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_pk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len);
__owur int ossl_ml_dsa_sk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len);

__owur int ossl_ml_dsa_sign(const ML_DSA_KEY *priv,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *context, size_t context_len,
                            const uint8_t *rand, size_t rand_len, int encode,
                            unsigned char *sig, size_t *siglen, size_t sigsize);
__owur int ossl_ml_dsa_verify(const ML_DSA_KEY *pub,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *context, size_t context_len,
                              int encode, const uint8_t *sig, size_t sig_len);

#endif /* OSSL_CRYPTO_SLH_DSA_H */
