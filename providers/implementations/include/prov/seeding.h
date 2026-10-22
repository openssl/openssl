/*
 * Copyright 2020-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_PROVIDERS_IMPLEMENTATIONS_INCLUDE_PROV_SEEDING_H)
#define OSSL_PROVIDERS_IMPLEMENTATIONS_INCLUDE_PROV_SEEDING_H

#include "prov/provider_ctx.h"
#include "crypto/rand_pool.h"

/* Hardware-based seeding functions. */
size_t ossl_prov_acquire_entropy_from_tsc(RAND_POOL *pool);
size_t ossl_prov_acquire_entropy_from_cpu(RAND_POOL *pool);

/*
 * The VMClock generation signal. |*epoch| holds the value the caller last
 * saw. Returns 1 and stores the current value there if the guest has since
 * been restored from a snapshot or migrated; returns 1 without storing if the
 * page could not be read; returns 0 if nothing changed or there is no VMClock
 * device.
 */
int ossl_prov_vmclock_changed(uint64_t *epoch);

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

#endif /* !defined(OSSL_PROVIDERS_IMPLEMENTATIONS_INCLUDE_PROV_SEEDING_H) */
