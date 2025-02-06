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
# define ML_DSA_SEED_BYTES 32

# define ML_DSA_ENTROPY_LEN 32

/* See FIPS 204 Section 4 Table 1 & Table 2 */
# define ML_DSA_44_PRIV_LEN 2560
# define ML_DSA_44_PUB_LEN 1312
# define ML_DSA_44_SIG_LEN 2420

/* See FIPS 204 Section 4 Table 1 & Table 2 */
# define ML_DSA_65_PRIV_LEN 4032
# define ML_DSA_65_PUB_LEN 1952
# define ML_DSA_65_SIG_LEN 3309

/* See FIPS 204 Section 4 Table 1 & Table 2 */
# define ML_DSA_87_PRIV_LEN 4896
# define ML_DSA_87_PUB_LEN 2592
# define ML_DSA_87_SIG_LEN 4627

/* Key and signature size maxima taken from values above */
# define MAX_ML_DSA_PRIV_LEN ML_DSA_87_PRIV_LEN
# define MAX_ML_DSA_PUB_LEN ML_DSA_87_PUB_LEN
# define MAX_ML_DSA_SIG_LEN ML_DSA_87_SIG_LEN

# ifndef OPENSSL_NO_ML_DSA
__owur ML_DSA_KEY *ossl_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                                       int evp_type);
/* Factory reset for keys that fail initialisation */
void ossl_ml_dsa_key_reset(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_pub_alloc(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_priv_alloc(ML_DSA_KEY *key);
void ossl_ml_dsa_key_free(ML_DSA_KEY *key);
__owur ML_DSA_KEY *ossl_ml_dsa_key_dup(const ML_DSA_KEY *src, int selection);
__owur int ossl_ml_dsa_key_equal(const ML_DSA_KEY *key1, const ML_DSA_KEY *key2,
                                 int selection);
__owur int ossl_ml_dsa_key_has(const ML_DSA_KEY *key, int selection);
__owur int ossl_ml_dsa_key_pairwise_check(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_generate_key(ML_DSA_KEY *out);
__owur const uint8_t *ossl_ml_dsa_key_get_pub(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_pub_len(const ML_DSA_KEY *key);
__owur const uint8_t *ossl_ml_dsa_key_get_priv(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_priv_len(const ML_DSA_KEY *key);
__owur const uint8_t *ossl_ml_dsa_key_get_seed(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_prefer_seed(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_retain_seed(const ML_DSA_KEY *key);
int ossl_ml_dsa_set_prekey(ML_DSA_KEY *key, int prefer_seed, int retain_seed,
                           const uint8_t *seed, size_t seed_len,
                           const uint8_t *sk, size_t sk_len);
__owur size_t ossl_ml_dsa_key_get_collision_strength_bits(const ML_DSA_KEY *key);
__owur size_t ossl_ml_dsa_key_get_sig_len(const ML_DSA_KEY *key);
__owur int ossl_ml_dsa_key_matches(const ML_DSA_KEY *key, int evp_type);
__owur const char *ossl_ml_dsa_key_get_name(const ML_DSA_KEY *key);
OSSL_LIB_CTX *ossl_ml_dsa_key_get0_libctx(const ML_DSA_KEY *key);

__owur int ossl_ml_dsa_key_public_from_private(ML_DSA_KEY *key);
__owur int ossl_ml_dsa_pk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len);
__owur int ossl_ml_dsa_sk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len);

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
# endif /* OPENSSL_NO_ML_DSA */

#endif /* OSSL_CRYPTO_SLH_DSA_H */
