/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/provider_ctx.h"
#include "crypto/rand_pool.h"

/* Entropy quality for different operating systems */
#if defined(OPENSSL_SYS_VOS)
/*
 * The entropy source repeatedly samples the real-time clock (RTC) to
 * generate a sequence of unpredictable data.  The algorithm relies upon the
 * uneven execution speed of the code (due to factors such as cache misses,
 * interrupts, bus activity, and scheduling) and upon the rather large
 * relative difference between the speed of the clock and the rate at which
 * it can be read.
 *
 * As a precaution, we assume only 2 bits of entropy per byte.
 */
# define OS_ENTROPY_FACTOR  4
#elif defined(__VMS)
/*
 * This number expresses how many bits of data contain 1 bit of entropy.
 *
 * For the moment, we assume about 0.05 entropy bits per data bit, or 1
 * bit of entropy per 20 data bits.
 */
# define OS_ENTROPY_FACTOR  20
#else
/*
 * For other operating systems, it is assumed that the RNG is producing
 * cryptographically "good" output.
 */
# define OS_ENTROPY_FACTOR  1
#endif

/* Entropy quality for different CPU based HRNGs */
#define CPU_ENTROPY_FACTOR  1

/* Hardware-based seeding functions. */
size_t ossl_prov_acquire_entropy_from_tsc(RAND_POOL *pool);
size_t ossl_prov_acquire_entropy_from_cpu(RAND_POOL *pool);

/*
 * External seeding functions from the core dispatch table.
 */
int ossl_prov_seeding_from_dispatch(const OSSL_DISPATCH *fns);

size_t ossl_prov_get_entropy(PROV_CTX *prov_ctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len);
void ossl_prov_cleanup_entropy(PROV_CTX *prov_ctx, unsigned char *buf,
                               size_t len);
size_t ossl_prov_get_nonce(PROV_CTX *prov_ctx, unsigned char **pout,
                           size_t min_len, size_t max_len,
                           const void *salt, size_t salt_len);
void ossl_prov_cleanup_nonce(PROV_CTX *prov_ctx, unsigned char *buf,
                             size_t len);
