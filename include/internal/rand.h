/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DRBG_RAND_H
# define HEADER_DRBG_RAND_H

/* Flag for CTR mode only: use derivation function ctr_df */
#define RAND_DRBG_FLAG_CTR_USE_DF            0x2

const RAND_METHOD *RAND_drbg(void);

int RAND_DRBG_set(DRBG_CTX *ctx, int type, unsigned int flags);
DRBG_CTX *RAND_DRBG_new(int type, unsigned int flags, DRBG_CTX *parent);
int RAND_DRBG_instantiate(DRBG_CTX *dctx,
                          const unsigned char *pers, size_t perslen);
int RAND_DRBG_uninstantiate(DRBG_CTX *dctx);
int RAND_DRBG_reseed(DRBG_CTX *dctx, const unsigned char *adin, size_t adinlen);
int RAND_DRBG_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen);
void RAND_DRBG_free(DRBG_CTX *dctx);

typedef size_t (*RAND_DRBG_get_entropy_fn)(DRBG_CTX *ctx, unsigned char **pout,
                                           int entropy, size_t min_len,
                                           size_t max_len);
typedef void (*RAND_DRBG_cleanup_entropy_fn)(DRBG_CTX *ctx, unsigned char *out,
                                             size_t olen);
typedef size_t (*RAND_DRBG_get_nonce_fn)(DRBG_CTX *ctx, unsigned char **pout,
                                         int entropy, size_t min_len,
                                         size_t max_len);
typedef void (*RAND_DRBG_cleanup_nonce_fn)(DRBG_CTX *ctx, unsigned char *out,
                                           size_t olen);

int RAND_DRBG_set_callbacks(DRBG_CTX *dctx,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce);

int RAND_DRBG_set_reseed_interval(DRBG_CTX *dctx, int interval);

#define RAND_DRBG_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DRBG, l, p, newf, dupf, freef)
int RAND_DRBG_set_ex_data(DRBG_CTX *dctx, int idx, void *arg);
void *RAND_DRBG_get_ex_data(const DRBG_CTX *dctx, int idx);

DRBG_CTX *RAND_DRBG_get_default(void);


#endif


