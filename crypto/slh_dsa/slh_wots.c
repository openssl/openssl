/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include "slh_dsa_local.h"

/* For the parameter sets defined there is only one w value */
#define SLH_WOTS_LOGW               4
#define SLH_WOTS_W                  16
#define SLH_WOTS_LEN1(n)            (2 * (n))
#define SLH_WOTS_LEN2                3
#define SLH_WOTS_CHECKSUM_LEN    ((SLH_WOTS_LEN2 + SLH_WOTS_LOGW + 7) / 8)
#define SLH_WOTS_LEN_MAX         SLH_WOTS_LEN(SLH_MAX_N)
#define NIBBLE_MASK                 15
#define NIBBLE_SHIFT                4

/*
 * @brief Convert a byte array to a byte array of (4 bit) nibbles
 * This is a Variant of the FIPS 205 Algorithm 4 base_2^b function.
 * It assumes that |in_len| is an even number and b is 4 bits.
 *
 * @param in A byte message to convert
 * @param in_len The size of |in|.
 * @param out The returned array of nibbles, with a size of 2*|in_len|
 */
static ossl_inline void slh_bytes_to_nibbles(const uint8_t *in, size_t in_len,
                                             uint8_t *out)
{
    size_t consumed = 0;

    assert((in_len & 1) == 0);

    for (consumed = 0; consumed < in_len; consumed++) {
        *out++ = (*in >> NIBBLE_SHIFT);
        *out++ = (*in++ & NIBBLE_MASK);
    }
}

/*
 * With w = 16 the maximum checksum is 0xF * n which fits into 12 bits
 * which is 3 nibbles.
 *
 * This is effectively a cutdown version of Algorithm 7: steps 3 to 6
 * which does a complicated base2^b(tobyte()) operation.
 */
static ossl_inline void compute_checksum_nibbles(const uint8_t *in, size_t in_len,
                                                 uint8_t *out)
{
    size_t i;
    uint16_t csum = 0;

    /* Compute checksum */
    for (i = 0; i < in_len; ++i)
        csum += in[i];
    /*
     * This line is effectively the same as doing csum += NIBBLE_MASK - in[i]
     * in the loop above.
     */
    csum = (uint16_t)(NIBBLE_MASK * in_len) - csum;

    /* output checksum as 3 nibbles */
    out[0] = (csum >> (2 * NIBBLE_SHIFT)) & NIBBLE_MASK;
    out[1] = (csum >> NIBBLE_SHIFT) & NIBBLE_MASK;
    out[2] = csum & NIBBLE_MASK;
}

/**
 * @brief WOTS+ Chaining function
 * See FIPS 205 Section 5 Algorithm 5
 *
 * Iterates using a hash function on the input |steps| times starting at index
 * |start|. (Internally the |adrs| hash address is used to update the chaining
 * index).
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param in An input string of |n| bytes
 * @param n The size of |in| and |pk_seed|_
 * @param start_index The chaining start index
 * @param steps The number of iterations starting from |start_index|
 *              Note |start_index| + |steps| < w
 *              (where w = 16 indicates the length of the hash chains)
 * @param adrs An ADRS object which has a type of WOTS_HASH, and has a layer
 *             address, tree address, key pair address and chain address
 * @param pk_seed A public key seed (which is added to the hash)
 */
static void slh_wots_chain(SLH_DSA_CTX *ctx, const uint8_t *in,
                           uint8_t start_index, uint8_t steps,
                           const uint8_t *pk_seed, uint8_t *adrs, uint8_t *out)
{
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_HASH_FN_DECLARE(hashf, F);
    SLH_ADRS_FN_DECLARE(adrsf, set_hash_address);
    size_t j, end_index = start_index + steps;
    size_t n = ctx->params->n;

    memcpy(out, in, n);

    for (j = start_index; j < end_index; ++j) {
        set_hash_address(adrs, j);
        F(hctx, pk_seed, adrs, out, n, out);
    }
}

/**
 * @brief Compute a candidate WOTS+ public key from a message and signature
 * See FIPS 205 Section 5.2 Algorithm 7
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param sig A WOTS+signature of size len * |n| bytes. (where len = 2 * |n| + 3)
 * @param msg A message of size |n| bytes.
 * @param pk_seed The public key seed of size |n|.
 * @param adrs An ADRS object containing the layer address, tree address and
 *             key pair address that of the WOTS+ key used to sign the message.
 * @param pk_out The returned public key candidate of size |n|
 */
void ossl_slh_wots_pk_from_sig(SLH_DSA_CTX *ctx,
                               const uint8_t *sig, const uint8_t *msg,
                               const uint8_t *pk_seed, uint8_t *adrs,
                               uint8_t *pk_out)
{
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_FN_DECLARE(adrsf, set_chain_address);
    SLH_ADRS_DECLARE(wots_pk_adrs);
    uint8_t msg_and_csum_nibbles[SLH_WOTS_LEN_MAX];
    uint8_t tmp[SLH_WOTS_LEN_MAX * SLH_MAX_N], *ptmp = tmp;
    size_t i, len1, len, n = ctx->params->n;

    len1 = SLH_WOTS_LEN1(n);
    len = len1 + SLH_WOTS_LEN2;

    slh_bytes_to_nibbles(msg, n, msg_and_csum_nibbles);
    compute_checksum_nibbles(msg_and_csum_nibbles, len1, msg_and_csum_nibbles + len1);

    /* Compute the end nodes for each of the chains */
    for (i = 0; i < len; ++i) {
        set_chain_address(adrs, i);
        slh_wots_chain(ctx, sig, msg_and_csum_nibbles[i],
                       NIBBLE_MASK - msg_and_csum_nibbles[i],
                       pk_seed, adrs, ptmp);
        sig += n;
        ptmp += n;
    }
    /* compress the computed public key value */
    adrsf->copy(wots_pk_adrs, adrs);
    adrsf->set_type_and_clear(wots_pk_adrs, SLH_ADRS_TYPE_WOTS_PK);
    adrsf->copy_keypair_address(wots_pk_adrs, adrs);
    hashf->T(hctx, pk_seed, wots_pk_adrs, tmp, ptmp - tmp, pk_out);
}
