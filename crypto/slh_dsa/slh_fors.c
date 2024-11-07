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
#include <openssl/crypto.h>
#include "slh_dsa_local.h"

/* k = 14, 17, 22, 33, 35 (number of trees) */
#define SLH_MAX_K           35
/* a = 6, 8, 9, 12 or 14  - There are (2^a) merkle trees */
#define SLH_MAX_A           9

#define SLH_MAX_K_TIMES_A      (SLH_MAX_A * SLH_MAX_K)
#define SLH_MAX_ROOTS          (SLH_MAX_K_TIMES_A * SLH_MAX_N)

static void slh_base_2b(const uint8_t *in, uint32_t b, uint32_t *out, size_t out_len);

/**
 * @brief Generate FORS secret values
 * See FIPS 205 Section 8.1 Algorithm 14.
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param sk_seed A private key seed of size |n|
 * @param pk_seed A public key seed of size |n|
 * @param adrs An ADRS object containing the layer address of zero, with the
 *             tree address and key pair address set to the index of the WOTS+
 *             key within the XMSS tree that signs the FORS key.
 * @param id The index of the FORS secret value within the sets of FORS trees.
 *               (which must be < 2^(hm - height)
 * @param pk_out The generated FORS secret value of size |n|
 * @returns 1 on success, or 0 on error.
 */
static int slh_fors_sk_gen(SLH_DSA_CTX *ctx, const uint8_t *sk_seed,
                           const uint8_t *pk_seed, SLH_ADRS adrs, uint32_t id,
                           uint8_t *sk_out)
{
    SLH_ADRS_DECLARE(sk_adrs);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);

    adrsf->copy(sk_adrs, adrs);
    adrsf->set_type_and_clear(sk_adrs, SLH_ADRS_TYPE_FORS_PRF);
    adrsf->copy_keypair_address(sk_adrs, adrs);
    adrsf->set_tree_index(sk_adrs, id);
    return ctx->hash_func->PRF(&ctx->hash_ctx, pk_seed, sk_seed, sk_adrs, sk_out);
}

/**
 * @brief Computes the nodes of a Merkle tree.
 * See FIPS 205 Section 8.2 Algorithm 18
 *
 * The leaf nodes are hashes of FORS secret values.
 * Each parent node is a hash of its 2 children.
 * Note this is a recursive function.
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param sk_seed A SLH_DSA private key seed of size |n|
 * @param pk_seed A SLH_DSA public key seed of size |n|
 * @param adrs The ADRS object must have a layer address of zero, and the
 *             tree address set to the XMSS tree that signs the FORS key,
 *             the type set to FORS_TREE, and the keypair address set to the
 *             index of the WOTS+ key that signs the FORS key.
 * @param node_id The target node index
 * @param height The target node height
 * @param node The returned hash for a node of size|n|
 * @returns 1 on success, or 0 on error.
 */
static int slh_fors_node(SLH_DSA_CTX *ctx, const uint8_t *sk_seed,
                         const uint8_t *pk_seed, SLH_ADRS adrs, uint32_t node_id,
                         uint32_t height, uint8_t *node)
{
    int ret = 0;
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    uint8_t sk[SLH_MAX_N], lnode[SLH_MAX_N], rnode[SLH_MAX_N];
    uint32_t n = ctx->params->n;

    if (height == 0) {
        if (!slh_fors_sk_gen(ctx, sk_seed, pk_seed, adrs, node_id, sk))
            return 0;
        adrsf->set_tree_height(adrs, 0);
        adrsf->set_tree_index(adrs, node_id);
        ret = ctx->hash_func->F(&ctx->hash_ctx, pk_seed, adrs, sk, n, node);
        OPENSSL_cleanse(sk, n);
        return ret;
    } else {
        if (!slh_fors_node(ctx, sk_seed, pk_seed, adrs, 2 * node_id, height - 1,
                           lnode)
                || !slh_fors_node(ctx, sk_seed, pk_seed, adrs, 2 * node_id + 1,
                                  height - 1, rnode))
            return 0;
        adrsf->set_tree_height(adrs, height);
        adrsf->set_tree_index(adrs, node_id);
        if (!ctx->hash_func->H(&ctx->hash_ctx, pk_seed, adrs, lnode, rnode, node))
            return 0;
    }
    return 1;
}

/**
 * @brief Generate an FORS signature
 * See FIPS 205 Section 8.3 Algorithm 16
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param md A message digest of size |(k * a + 7) / 8| bytes to sign
 * @param sk_seed A private key seed of size |n|
 * @param pk_seed A public key seed of size |n|
 * @param adrs The ADRS object must have a layer address of zero, and the
 *             tree address set to the XMSS tree that signs the FORS key,
 *             the type set to FORS_TREE, and the keypair address set to the
 *             index of the WOTS+ key that signs the FORS key.
 * @param sig_out The generated XMSS signature which consists of a WOTS+
 *                signature and authentication path
 * @param sig_len  The size of |sig| which is (2 * n + 3) * n + tree_height * n.
 * @returns 1 on success, or 0 on error.
 */
int ossl_slh_fors_sign(SLH_DSA_CTX *ctx, const uint8_t *md,
                       const uint8_t *sk_seed, const uint8_t *pk_seed,
                       SLH_ADRS adrs, uint8_t *sig, size_t sig_len)
{
    uint32_t i, j, s;
    uint32_t ids[SLH_MAX_K];
    const SLH_DSA_PARAMS *params = ctx->params;
    uint32_t n = params->n;
    uint32_t k = params->k;
    uint32_t a = params->a;
    uint32_t t = (1 << a);
    uint32_t t_times_i = 0;
    uint8_t *psig = sig;

    /*
     * Split md into k a-bit values e.g with k = 14, a = 12
     * ids[0..13] = 12 bits each of md
     */
    slh_base_2b(md, a, ids, k);

    for (i = 0; i < k; ++i) {
        uint32_t id = ids[i]; /* |id| = |a| bits */

        if (!slh_fors_sk_gen(ctx, sk_seed, pk_seed, adrs,
                             id + t_times_i, psig))
            return 0;
        psig += n;

        for (j = 0; j < a; ++j) {
            s = id ^ 1;
            if (!slh_fors_node(ctx, sk_seed, pk_seed, adrs, s + i * (1 << (a - j)),
                               j, psig))
                return 0;
            id >>= 1;
            psig += n;
        }
        t_times_i += t;
    }
    assert((size_t)(psig - sig) == sig_len);
    return 1;
}

/**
 * @brief Compute a candidate FORS public key from a message and signature.
 * See FIPS 205 Section 8.4 Algorithm 17.
 *
 * @param ctx Contains SLH_DSA algorithm functions and constants.
 * @param sig A FORS signature of size (k * (a + 1) * n) bytes
 * @param md A message digest of size (k * a / 8) bytes
 * @param pk_seed A public key seed of size |n|
 * @param adrs The ADRS object must have a layer address of zero, and the
 *             tree address set to the XMSS tree that signs the FORS key,
 *             the type set to FORS_TREE, and the keypair address set to the
 *             index of the WOTS+ key that signs the FORS key.
 * @param pk_out The returned candidate FORS public key of size |n|
 * @returns 1 on success, or 0 on error.
 */
int ossl_slh_fors_pk_from_sig(SLH_DSA_CTX *ctx, const uint8_t *sig,
                              const uint8_t *md, const uint8_t *pk_seed,
                              SLH_ADRS adrs, uint8_t *pk_out)
{
    SLH_ADRS_DECLARE(pk_adrs);
    SLH_ADRS_FUNC_DECLARE(ctx, adrsf);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_index);
    SLH_ADRS_FN_DECLARE(adrsf, set_tree_height);
    SLH_HASH_FUNC_DECLARE(ctx, hashf, hctx);
    SLH_HASH_FN_DECLARE(hashf, F);
    SLH_HASH_FN_DECLARE(hashf, H);
    uint32_t i, j, aoff = 0;
    uint32_t ids[SLH_MAX_K];
    uint8_t roots[SLH_MAX_ROOTS], *node = roots;
    const SLH_DSA_PARAMS *params = ctx->params;
    uint32_t a = params->a;
    uint32_t k = params->k;
    uint32_t n = params->n;
    uint32_t two_power_a = (1 << a);

    /* Split md into k a-bit values e.g ids[0..k-1] = 12 bits each of md */
    slh_base_2b(md, a, ids, k);

    /* Compute the roots of k Merkle trees */
    for (i = 0; i < k; ++i) {
        uint32_t id = ids[i];
        uint32_t node_id = id + aoff;

        set_tree_height(adrs, 0);
        set_tree_index(adrs, node_id);
        if (!F(hctx, pk_seed, adrs, sig, n, node))
            return 0;
        sig += n;

        for (j = 0; j < a; ++j) {
            set_tree_height(adrs, j + 1);
            if ((id & 1) == 0) {
                node_id >>= 1;
                set_tree_index(adrs, node_id);
                if (!H(hctx, pk_seed, adrs, node, sig, node))
                    return 0;
            } else {
                node_id = (node_id - 1) >> 1;
                set_tree_index(adrs, node_id);
                if (!H(hctx, pk_seed, adrs, sig, node, node))
                    return 0;
            }
            id >>= 1;
            sig += n;
        }
        aoff += two_power_a;
        node += n;
    }
    assert((size_t)(node - roots) <= sizeof(roots));

    /* The public key is the hash of all the roots of the k trees */
    adrsf->copy(pk_adrs, adrs);
    adrsf->set_type_and_clear(pk_adrs, SLH_ADRS_TYPE_FORS_ROOTS);
    adrsf->copy_keypair_address(pk_adrs, adrs);
    return hashf->T(hctx, pk_seed, pk_adrs, roots, node - roots, pk_out);
}

/**
 * @brief Convert a byte string into a base 2^b representation
 * See FIPS 205 Algorithm 4
 *
 * @param in An input byte stream with a size >= |outlen * b / 8|
 * @param b The bit size to divide |in| into
 *          This is one of 6, 8, 9, 12 or 14 for FORS.
 * @param out The array of returned base 2^b integers that represents the first
 *            |outlen|*|b| bits of |in|
 * @param out_len The size of |out|
 */
static void slh_base_2b(const uint8_t *in, uint32_t b,
                        uint32_t *out, size_t out_len)
{
    size_t consumed = 0;
    uint32_t bits = 0;
    uint32_t total = 0;
    uint32_t mask = (1 << b) - 1;

    for (consumed = 0; consumed < out_len; consumed++) {
        while (bits < b) {
            total <<= 8;
            total += *in++;
            bits += 8;
        }
        bits -= b;
        *out++ = (total >> bits) & mask;
    }
}
