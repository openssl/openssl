/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DRBG_RAND_H
# define HEADER_DRBG_RAND_H

/* In CTR mode, disable derivation function ctr_df */
#define RAND_DRBG_FLAG_CTR_NO_DF            0x1

/*
 * Default security strength (in the sense of [NIST SP 800-90Ar1])
 *
 * NIST SP 800-90Ar1 supports the strength of the DRBG being smaller than that
 * of the cipher by collecting less entropy. The current DRBG implemantion does
 * not take RAND_DRBG_STRENGTH into account and sets the strength of the DRBG
 * to that of the cipher.
 *
 * RAND_DRBG_STRENGTH is currently only used for the legacy RAND
 * implementation.
 *
 * Currently supported ciphers are: NID_aes_128_ctr, NID_aes_192_ctr and
 * NID_aes_256_ctr
 *
 * TODO(DRBG): would be nice to have the NID and strength configurable
 */
# define RAND_DRBG_STRENGTH             256
# define RAND_DRBG_NID                  NID_aes_256_ctr

/*
 * Object lifetime functions.
 */
RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent);
RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent);
int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags);
int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen);
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg);
void RAND_DRBG_free(RAND_DRBG *drbg);

/*
 * Object "use" functions.
 */
int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen);
int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen);
int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen);

int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval);
int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval);

int RAND_DRBG_set_reseed_defaults(
                                  unsigned int master_reseed_interval,
                                  unsigned int slave_reseed_interval,
                                  time_t master_reseed_time_interval,
                                  time_t slave_reseed_time_interval
                                  );

RAND_DRBG *RAND_DRBG_get0_master(void);
RAND_DRBG *RAND_DRBG_get0_public(void);
RAND_DRBG *RAND_DRBG_get0_private(void);

/*
 * EXDATA
 */
#define RAND_DRBG_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DRBG, l, p, newf, dupf, freef)
int RAND_DRBG_set_ex_data(RAND_DRBG *dctx, int idx, void *arg);
void *RAND_DRBG_get_ex_data(const RAND_DRBG *dctx, int idx);

/*
 * Callback functions.  See comments in drbg_lib.c
 */
typedef size_t (*RAND_DRBG_get_entropy_fn)(RAND_DRBG *ctx,
                                           unsigned char **pout,
                                           int entropy, size_t min_len,
                                           size_t max_len);
typedef void (*RAND_DRBG_cleanup_entropy_fn)(RAND_DRBG *ctx,
                                             unsigned char *out, size_t outlen);
typedef size_t (*RAND_DRBG_get_nonce_fn)(RAND_DRBG *ctx, unsigned char **pout,
                                         int entropy, size_t min_len,
                                         size_t max_len);
typedef void (*RAND_DRBG_cleanup_nonce_fn)(RAND_DRBG *ctx,
                                           unsigned char *out, size_t outlen);

int RAND_DRBG_set_callbacks(RAND_DRBG *dctx,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce);

/*
 * RAND_POOL functions
 */
RAND_POOL *RAND_POOL_new(int entropy_requested, size_t min_len, size_t max_len);
void RAND_POOL_free(RAND_POOL *pool);

const unsigned char *RAND_POOL_buffer(RAND_POOL *pool);
unsigned char *RAND_POOL_detach(RAND_POOL *pool);

size_t RAND_POOL_entropy(RAND_POOL *pool);
size_t RAND_POOL_length(RAND_POOL *pool);

size_t RAND_POOL_entropy_available(RAND_POOL *pool);
size_t RAND_POOL_entropy_needed(RAND_POOL *pool);
size_t RAND_POOL_bytes_needed(RAND_POOL *pool, unsigned int entropy_per_byte);
size_t RAND_POOL_bytes_remaining(RAND_POOL *pool);

size_t RAND_POOL_add(RAND_POOL *pool,
                     const unsigned char *buffer, size_t len, size_t entropy);
unsigned char *RAND_POOL_add_begin(RAND_POOL *pool, size_t len);
size_t RAND_POOL_add_end(RAND_POOL *pool, size_t len, size_t entropy);


/*
 * Add random bytes to the pool to acquire requested amount of entropy
 *
 * This function is platform specific and tries to acquire the requested
 * amount of entropy by polling platform specific entropy sources.
 *
 * If the function succeeds in acquiring at least |entropy_requested| bits
 * of entropy, the total entropy count is returned. If it fails, it returns
 * an entropy count of 0.
 */
size_t RAND_POOL_acquire_entropy(RAND_POOL *pool);
#endif
