/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/slh_dsa.h"
#include "slh_hash.h"
#include "slh_params.h"

/*
 * Maximum size of the security parameter |n| in FIPS 205 Section 11. Table 2.
 * This indicates the length in bytes of a message that can be signed.
 * It is the size used by WOTS+ public and private key elements as well as
 * signature elements.
 */
#define SLH_MAX_N                   32
/*
 * For the given standard w=16 for all parameter sets.
 * A n byte message is converted into 2 * n base 16 Integers followed
 * by 3 Integers for the checksum of these values.
 */
#define SLH_WOTS_LEN(n)             (2 * (n) + 3)

/*
 * FIPS 205 SLH_DSA algorithms have many different parameters which includes:
 *   - A set of constants (Section 11. contains 12 parameter sets)
 *     such as tree heights and security parameters associated with a algorithm
 *     name such as SLH-DSA-SHA2-128s.
 *   - ADRS functions (such as set_layer_address() in Section 4.3 & 11.2)
 *   - Hash Functions (such as H_MSG() & PRF()) See Sections 11.1, 11.2.1 & 11.2.2.
 *
 *   - OpenSSL also uses an SLH_HASH_CTX to pass pre-fetched EVP related objects
 *     to the Hash functions.
 *
 * SLH_DSA_CTX is a container to hold all of these objects. This object is
 * resolved early and is then passed to most SLH_DSA related functions.
 */
struct slh_dsa_ctx_st {
    const SLH_DSA_PARAMS *params;
    const SLH_ADRS_FUNC *adrs_func;
    const SLH_HASH_FUNC *hash_func;
    SLH_HASH_CTX hash_ctx;
};

void ossl_slh_wots_pk_from_sig(SLH_DSA_CTX *ctx,
                               const uint8_t *sig, const uint8_t *msg,
                               const uint8_t *pk_seed, uint8_t *adrs,
                               uint8_t *pk_out);

void ossl_slh_xmss_pk_from_sig(SLH_DSA_CTX *ctx, uint32_t node_id,
                               const uint8_t *sig, const uint8_t *msg,
                               const uint8_t *pk_seed, SLH_ADRS adrs,
                               uint8_t *pk_out);

int ossl_slh_ht_verify(SLH_DSA_CTX *ctx, const uint8_t *msg, const uint8_t *sig,
                       const uint8_t *pk_seed, uint64_t tree_id, uint32_t leaf_id,
                       const uint8_t *pk_root);

void ossl_slh_fors_pk_from_sig(SLH_DSA_CTX *ctx, const uint8_t *sig,
                               const uint8_t *md, const uint8_t *pk_seed,
                               SLH_ADRS adrs, uint8_t *pk_out);
