/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/rand_pool.h"

/* Hardware-based seeding functions. */
size_t prov_acquire_entropy_from_tsc(RAND_POOL *pool);
size_t prov_acquire_entropy_from_cpu(RAND_POOL *pool);

/* DRBG entropy callbacks. */
size_t prov_drbg_get_additional_data(RAND_POOL *pool, unsigned char **pout);

void prov_drbg_cleanup_additional_data(RAND_POOL *pool, unsigned char *out);

size_t prov_pool_acquire_entropy(RAND_POOL *pool);
int prov_pool_add_nonce_data(RAND_POOL *pool);

/*
 * Add some platform specific additional data
 *
 * This function is platform specific and adds some random noise to the
 * additional data used for generating random bytes and for reseeding
 * the drbg.
 *
 * Returns 1 on success and 0 on failure.
 */
int rand_pool_add_additional_data(RAND_POOL *pool);

