/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Merkle tree implementation with subtree support, implementing the
 * Merkle-tree subtree operations from section 4 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/,
 * built on the RFC 9162 Merkle tree.
 *
 * This is largely a port of BoringSSL's C++ implementation
 * (pki/merkle_tree.cc), with find_subtrees taken from section 4.5 of the
 * same draft.  See include/crypto/mtc.h for the public (internal)
 * interface and for references to the specification.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "crypto/mtc.h"
#include "internal/packet.h"

/**
 * @brief Return the largest power of two strictly smaller than n.
 * @param n a value that must be at least 2
 * @returns the largest power of two less than n.
 */
static uint64_t pow2_smaller(uint64_t n)
{
    /*-
     * The bitwise OR ladder copies the most significant set bit of n - 1
     * down to every lower position, producing 2^(k+1) - 1 where 2^k is the
     * value we want.  Shifting right by one and adding one recovers 2^k.
     * See the equivalent BoringSSL routine for the full derivation.
     */
    assert(n >= 2);
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return (n >> 1) + 1;
}

int ossl_mtc_subtree_is_valid(OSSL_MTC_SUBTREE subtree)
{
    uint64_t size;

    /* A subtree must be a valid interval; it may be empty. */
    if (subtree.start > subtree.end)
        return 0;

    /*
     * The start must be a multiple of the size rounded up to a power of two
     * (section 4.1).  Sizes of 0 and 1 round up to 1, so every start is a
     * multiple.
     */
    size = subtree.end - subtree.start;
    if (size <= 1)
        return 1;
    /* Rounding a larger size up overflows; only 0 is a multiple of 2^64. */
    if (size > (UINT64_C(1) << 63))
        return subtree.start == 0;
    return subtree.start % (2 * pow2_smaller(size)) == 0;
}

uint64_t ossl_mtc_subtree_leaf_count(OSSL_MTC_SUBTREE subtree)
{
    return subtree.end - subtree.start;
}

uint64_t ossl_mtc_subtree_split(OSSL_MTC_SUBTREE subtree)
{
    uint64_t n = ossl_mtc_subtree_leaf_count(subtree);

    if (n < 2)
        return subtree.end;
    return subtree.start + pow2_smaller(n);
}

OSSL_MTC_SUBTREE ossl_mtc_subtree_left(OSSL_MTC_SUBTREE subtree)
{
    OSSL_MTC_SUBTREE left = { subtree.start, ossl_mtc_subtree_split(subtree) };

    return left;
}

OSSL_MTC_SUBTREE ossl_mtc_subtree_right(OSSL_MTC_SUBTREE subtree)
{
    OSSL_MTC_SUBTREE right = { ossl_mtc_subtree_split(subtree), subtree.end };

    return right;
}

int ossl_mtc_subtree_contains_index(OSSL_MTC_SUBTREE subtree, uint64_t index)
{
    return subtree.start <= index && index < subtree.end;
}

int ossl_mtc_subtree_contains_subtree(OSSL_MTC_SUBTREE outer,
    OSSL_MTC_SUBTREE inner)
{
    return outer.start <= inner.start && inner.end <= outer.end;
}

/**
 * @brief Return the number of bits needed to represent n.
 * @returns the position of the most significant set bit plus one, or 0 when n
 * is zero.
 */
static int u64_bit_length(uint64_t n)
{
    int len = 0;

    while (n != 0) {
        n >>= 1;
        len++;
    }
    return len;
}

void ossl_mtc_find_subtrees(OSSL_MTC_SUBTREE interval, OSSL_MTC_SUBTREE out[2])
{
    uint64_t start = interval.start, end = interval.end;
    uint64_t last, mask, mid, left_start;
    int split, left_split;

    assert(start <= end);

    /* An interval of at most one leaf is itself, then [end, end). */
    if (end - start <= 1) {
        out[0] = interval;
        out[1].start = end;
        out[1].end = end;
        return;
    }

    /*
     * split is the height at which the paths to start and to the last leaf
     * (end - 1) diverge; the two subtrees lie on either side of that point.
     * See section 4.5 of
     * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
     * for the derivation of this procedure.
     */
    last = end - 1;
    split = u64_bit_length(start ^ last) - 1;
    mask = (UINT64_C(1) << split) - 1;

    /* mid is the leftmost leaf of the divergence point's right branch. */
    mid = last & ~mask;

    /*
     * Maximise the left subtree: left_split is the height of the lowest
     * common ancestor of [start, mid), found from the most significant zero
     * bit of start within the low split bits.
     */
    left_split = u64_bit_length(~start & mask);
    left_start = start & ~((UINT64_C(1) << left_split) - 1);

    out[0].start = left_start;
    out[0].end = mid;
    out[1].start = mid;
    out[1].end = end;
}

/**
 * @brief Return the node hash length of a digest.
 * @param md the digest to measure
 * @returns the length in bytes, or 0 if md cannot be used here.
 */
static size_t mtc_hash_len(const EVP_MD *md)
{
    int len = EVP_MD_get_size(md);

    if (len <= 0 || len > EVP_MAX_MD_SIZE) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_UNSUPPORTED);
        return 0;
    }
    return (size_t)len;
}

/**
 * @brief Hash the concatenation of a header byte and up to two node hashes.
 *
 * out may alias a or b; the inputs are fully consumed before out is written.
 * A zero-length operand is skipped, so an absent second operand is passed as
 * (NULL, 0); a non-zero length with a NULL pointer is a caller error.
 *
 * @param ctx a digest context to use, reinitialised by this call
 * @param md the digest to hash with
 * @param header the domain-separation prefix (0x00 for leaves, 0x01 nodes)
 * @param a pointer to the first input
 * @param a_len length of the first input
 * @param b pointer to the second input, or NULL when b_len is 0
 * @param b_len length of the second input
 * @param out buffer receiving the node hash
 * @returns 1 on success, 0 on error.
 */
static int mtc_hash(EVP_MD_CTX *ctx, const EVP_MD *md, uint8_t header,
    const uint8_t *a, size_t a_len,
    const uint8_t *b, size_t b_len,
    uint8_t out[EVP_MAX_MD_SIZE])
{
    return EVP_DigestInit_ex(ctx, md, NULL)
        && EVP_DigestUpdate(ctx, &header, 1)
        && (a_len == 0 || EVP_DigestUpdate(ctx, a, a_len))
        && (b_len == 0 || EVP_DigestUpdate(ctx, b, b_len))
        && EVP_DigestFinal_ex(ctx, out, NULL);
}

/**
 * @brief Compute HASH() of the empty string, the hash of an empty subtree.
 * @param ctx a digest context to use, reinitialised by this call
 * @param md the digest to hash with
 * @param out buffer receiving the hash
 * @returns 1 on success, 0 on error.
 */
static int mtc_hash_empty(EVP_MD_CTX *ctx, const EVP_MD *md,
    uint8_t out[EVP_MAX_MD_SIZE])
{
    return EVP_DigestInit_ex(ctx, md, NULL)
        && EVP_DigestFinal_ex(ctx, out, NULL);
}

int ossl_mtc_hash_leaf(const EVP_MD *md, const uint8_t *entry,
    size_t entry_len, uint8_t out[EVP_MAX_MD_SIZE])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    if (ctx == NULL)
        return 0;
    ret = mtc_hash(ctx, md, 0x00, entry, entry_len, NULL, 0, out);
    EVP_MD_CTX_free(ctx);
    return ret;
}

int ossl_mtc_hash_node(const EVP_MD *md, const uint8_t *left,
    const uint8_t *right, uint8_t out[EVP_MAX_MD_SIZE])
{
    EVP_MD_CTX *ctx;
    size_t hash_len = mtc_hash_len(md);
    int ret;

    if (hash_len == 0)
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    ret = mtc_hash(ctx, md, 0x01, left, hash_len, right, hash_len, out);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/**
 * @brief Consume the next node hash from a proof.
 * @param proof pointer to the proof cursor, advanced on success
 * @param remaining pointer to the remaining byte count, decreased on success
 * @param hash_len the node hash length
 * @returns a pointer to the next hash_len bytes, or NULL if fewer than that
 * many bytes remain.
 */
static const uint8_t *next_proof_hash(const uint8_t **proof,
    size_t *remaining, size_t hash_len)
{
    const uint8_t *ret;

    if (*remaining < hash_len)
        return NULL;
    ret = *proof;
    *proof += hash_len;
    *remaining -= hash_len;
    return ret;
}

/**
 * @brief Evaluate a consistency proof for a non-empty subtree with a
 * caller-supplied digest context.
 *
 * This is section 4.4.3 up to the final comparison against the root hash,
 * which is left to the caller: the computed root hash is written to
 * out_root_hash.
 *
 * @param ctx a digest context to use, reinitialised for each hash
 * @param md the digest the tree was built with
 * @param hash_len the node hash length of md
 * @returns 1 on success, 0 on error.
 */
static int eval_consistency_proof(EVP_MD_CTX *ctx, const EVP_MD *md,
    size_t hash_len, uint64_t n, OSSL_MTC_SUBTREE subtree,
    const uint8_t *proof, size_t proof_len, const uint8_t *node_hash,
    uint8_t out_root_hash[EVP_MAX_MD_SIZE])
{
    uint64_t fn, sn, tn;
    uint8_t computed_node_hash[EVP_MAX_MD_SIZE];
    uint8_t computed_root_hash[EVP_MAX_MD_SIZE];
    const uint8_t *p;

    /* Check that inputs are valid.  (Step 1) */
    if (!ossl_mtc_subtree_is_valid(subtree) || n < subtree.end
        || subtree.start == subtree.end)
        return 0;

    /*
     * fn, sn, and tn are the paths from the root of the tree to the leftmost
     * child of the subtree, the rightmost child of the subtree, and the
     * rightmost child of the full tree respectively.  (Step 3)
     */
    fn = subtree.start;
    sn = subtree.end - 1;
    tn = n - 1;

    /*
     * Moving up one level in the tree corresponds to consuming the least
     * significant bit of each cursor.  Skip up to the level where the proof
     * starts.  (Steps 4 and 5)
     */
    if (sn == tn) {
        /*
         * The subtree is directly contained in the full tree; advance until
         * the subtree's left and right edges meet at its root.  (Step 4)
         */
        while (fn != sn) {
            fn >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    } else {
        /*
         * Rise to the largest full subtree whose right edge is still the
         * subtree's right edge, i.e. while the right edge is a right child
         * (its least significant bit is set).  (Step 5)
         */
        while (fn != sn && (sn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    }

    /*
     * computed_node_hash and computed_root_hash are the values fr and sr of
     * the draft.  If the whole subtree is directly contained in the tree its
     * hash is omitted from the proof and node_hash seeds both cursors;
     * otherwise the first proof element seeds them.  (Steps 6 and 7)
     */
    if (fn == sn) {
        memcpy(computed_node_hash, node_hash, hash_len);
        memcpy(computed_root_hash, node_hash, hash_len);
    } else {
        p = next_proof_hash(&proof, &proof_len, hash_len);
        if (p == NULL)
            return 0;
        memcpy(computed_node_hash, p, hash_len);
        memcpy(computed_root_hash, p, hash_len);
    }

    /*
     * Consume the remaining proof elements, moving one level up the tree per
     * element until we reach the root.  (Step 8)
     */
    while (proof_len != 0) {
        p = next_proof_hash(&proof, &proof_len, hash_len);
        if (p == NULL)
            return 0;
        /* We must not have reached the root yet.  (Step 8.1) */
        if (tn == 0)
            return 0;

        if ((sn & 1) == 1 || sn == tn) {
            /*
             * Stop updating computed_node_hash once the subtree root is
             * reached (fn == sn).  (Steps 8.2.1 and 8.2.2)
             */
            if (fn < sn
                && !mtc_hash(ctx, md, 0x01, p, hash_len, computed_node_hash,
                    hash_len, computed_node_hash))
                return 0;
            if (!mtc_hash(ctx, md, 0x01, p, hash_len, computed_root_hash,
                    hash_len, computed_root_hash))
                return 0;
            /* (Step 8.2.3) */
            while ((sn & 1) == 0) {
                fn >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        } else {
            /* (Step 8.3.1) */
            if (!mtc_hash(ctx, md, 0x01, computed_root_hash, hash_len, p,
                    hash_len, computed_root_hash))
                return 0;
        }
        /* Advance the cursors.  (Step 8.4) */
        fn >>= 1;
        sn >>= 1;
        tn >>= 1;
    }

    /* The cursors must have reached the root together.  (Step 9) */
    if (tn != 0)
        return 0;

    /* The recomputed subtree hash must match node_hash.  (Step 9) */
    if (memcmp(computed_node_hash, node_hash, hash_len) != 0)
        return 0;

    /* Return the computed root hash for the caller to compare. */
    memcpy(out_root_hash, computed_root_hash, hash_len);
    return 1;
}

int ossl_mtc_verify_subtree_consistency_proof(
    const EVP_MD *md, uint64_t n, OSSL_MTC_SUBTREE subtree,
    const uint8_t *proof, size_t proof_len, const uint8_t *node_hash,
    const uint8_t *root_hash)
{
    EVP_MD_CTX *ctx;
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hash_len = mtc_hash_len(md);
    int ret = 0;

    if (hash_len == 0)
        return 0;
    if (!ossl_mtc_subtree_is_valid(subtree) || n < subtree.end)
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    if (subtree.start == subtree.end) {
        /* An empty subtree has an empty proof and the hash HASH(). */
        ret = proof_len == 0
            && mtc_hash_empty(ctx, md, hash)
            && memcmp(hash, node_hash, hash_len) == 0;
    } else {
        ret = eval_consistency_proof(ctx, md, hash_len, n, subtree, proof,
                  proof_len, node_hash, hash)
            && memcmp(hash, root_hash, hash_len) == 0;
    }
    EVP_MD_CTX_free(ctx);
    return ret;
}

int ossl_mtc_eval_subtree_inclusion_proof(
    const EVP_MD *md, const uint8_t *inclusion_proof, size_t proof_len,
    uint64_t index, const uint8_t *entry_hash, OSSL_MTC_SUBTREE subtree,
    uint8_t out_root_hash[EVP_MAX_MD_SIZE])
{
    OSSL_MTC_SUBTREE leaf;
    EVP_MD_CTX *ctx;
    size_t hash_len = mtc_hash_len(md);
    int ret;

    if (hash_len == 0)
        return 0;
    if (!ossl_mtc_subtree_is_valid(subtree)
        || !ossl_mtc_subtree_contains_index(subtree, index))
        return 0;

    /* Re-root index inside subtree; an inclusion proof is a consistency
     * proof for the single-leaf range. */
    index -= subtree.start;
    leaf.start = index;
    leaf.end = index + 1;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    ret = eval_consistency_proof(ctx, md, hash_len,
        ossl_mtc_subtree_leaf_count(subtree), leaf, inclusion_proof, proof_len,
        entry_hash, out_root_hash);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * An in-memory Merkle tree stores every node.  level[l] holds the hashes of
 * the full subtrees of size 2^l, so level[0] is the leaves.  Partial
 * subtrees on the right edge are computed on demand.
 */

/**
 * @struct mtc_level
 * One level of an in-memory Merkle tree: a growable array of node hashes.
 */
typedef struct mtc_level_st {
    uint8_t *nodes; /**< count node hashes, hash_len bytes each */
    size_t count; /**< number of node hashes present */
    size_t cap; /**< number of node hashes allocated */
} mtc_level;

struct ossl_mtc_tree_st {
    const EVP_MD *md; /**< the digest every node hash is computed with */
    EVP_MD_CTX *ctx; /**< reinitialised for each hash */
    size_t hash_len; /**< the node hash length of md */
    mtc_level *levels; /**< levels[0] is the leaves */
    size_t num_levels; /**< number of levels in use */
    size_t cap; /**< number of levels allocated */
};

/**
 * @brief Append one node hash to a level, growing it if required.
 * @param level the level to append to
 * @param hash the node hash to append
 * @param hash_len the node hash length
 * @returns 1 on success, 0 on allocation failure.
 */
static int level_push(mtc_level *level, const uint8_t *hash, size_t hash_len)
{
    if (level->count == level->cap) {
        size_t new_cap = level->cap == 0 ? 16 : level->cap * 2;
        uint8_t *tmp = OPENSSL_realloc_array(level->nodes, new_cap, hash_len);

        if (tmp == NULL)
            return 0;
        level->nodes = tmp;
        level->cap = new_cap;
    }
    memcpy(level->nodes + level->count * hash_len, hash, hash_len);
    level->count++;
    return 1;
}

/**
 * @brief Return a pointer to node index at a given level.
 * @param level the level, which must exist
 * @param index the node index, which must be present
 * @returns a pointer to the node's hash.
 */
static const uint8_t *tree_node(const OSSL_MTC_TREE *tree, size_t level,
    uint64_t index)
{
    assert(level < tree->num_levels);
    assert(index < tree->levels[level].count);
    return tree->levels[level].nodes + index * tree->hash_len;
}

/**
 * @brief Discard all but the first n leaves and the interior nodes they
 * support.
 *
 * Level l holds one node per complete subtree of size 2^l, so a tree of n
 * leaves has exactly n / 2^l of them.
 *
 * @param tree the tree to truncate
 * @param n the number of leaves to keep, at most the number present
 */
static void tree_truncate(OSSL_MTC_TREE *tree, uint64_t n)
{
    size_t level;

    tree->levels[0].count = (size_t)n;
    for (level = 1; level < tree->num_levels; level++) {
        n /= 2;
        if (tree->levels[level].count > n)
            tree->levels[level].count = (size_t)n;
    }
}

/**
 * @brief Rebuild the interior levels after leaves are appended.
 * @returns 1 on success, 0 on error.
 */
static int tree_update_levels(OSSL_MTC_TREE *tree)
{
    size_t level;
    uint64_t n;

    for (level = 1, n = ossl_mtc_tree_leaf_count(tree) / 2; n != 0;
        level++, n /= 2) {
        if (level == tree->num_levels) {
            if (tree->num_levels == tree->cap) {
                size_t new_cap = tree->cap == 0 ? 8 : tree->cap * 2;
                mtc_level *tmp = OPENSSL_realloc_array(tree->levels, new_cap,
                    sizeof(*tmp));

                if (tmp == NULL)
                    return 0;
                tree->levels = tmp;
                tree->cap = new_cap;
            }
            memset(&tree->levels[level], 0, sizeof(tree->levels[level]));
            tree->num_levels++;
        }
        while (tree->levels[level].count < n) {
            size_t i = tree->levels[level].count;
            uint8_t h[EVP_MAX_MD_SIZE];

            if (!mtc_hash(tree->ctx, tree->md, 0x01,
                    tree_node(tree, level - 1, 2 * i), tree->hash_len,
                    tree_node(tree, level - 1, 2 * i + 1), tree->hash_len, h))
                return 0;
            if (!level_push(&tree->levels[level], h, tree->hash_len))
                return 0;
        }
    }
    return 1;
}

OSSL_MTC_TREE *ossl_mtc_tree_new(const EVP_MD *md)
{
    OSSL_MTC_TREE *tree;
    size_t hash_len = mtc_hash_len(md);

    if (hash_len == 0)
        return NULL;
    tree = OPENSSL_zalloc(sizeof(*tree));
    if (tree == NULL)
        return NULL;
    tree->md = md;
    tree->hash_len = hash_len;
    tree->ctx = EVP_MD_CTX_new();
    tree->levels = OPENSSL_zalloc(sizeof(*tree->levels));
    if (tree->ctx == NULL || tree->levels == NULL) {
        ossl_mtc_tree_free(tree);
        return NULL;
    }
    tree->num_levels = 1;
    tree->cap = 1;
    return tree;
}

void ossl_mtc_tree_free(OSSL_MTC_TREE *tree)
{
    size_t i;

    if (tree == NULL)
        return;
    for (i = 0; i < tree->num_levels; i++)
        OPENSSL_free(tree->levels[i].nodes);
    OPENSSL_free(tree->levels);
    EVP_MD_CTX_free(tree->ctx);
    OPENSSL_free(tree);
}

uint64_t ossl_mtc_tree_leaf_count(const OSSL_MTC_TREE *tree)
{
    return tree->levels[0].count;
}

int ossl_mtc_tree_append(OSSL_MTC_TREE *tree, const uint8_t *entry,
    size_t entry_len)
{
    uint64_t n = ossl_mtc_tree_leaf_count(tree);
    uint8_t h[EVP_MAX_MD_SIZE];

    if (!mtc_hash(tree->ctx, tree->md, 0x00, entry, entry_len, NULL, 0, h))
        return 0;
    if (!level_push(&tree->levels[0], h, tree->hash_len))
        return 0;
    if (!tree_update_levels(tree)) {
        tree_truncate(tree, n);
        return 0;
    }
    return 1;
}

/**
 * @brief Count the trailing one bits of n.
 * @returns the number of consecutive set bits at the bottom of n.
 */
static size_t trailing_ones(uint64_t n)
{
    size_t count = 0;

    while ((n & 1) != 0) {
        n >>= 1;
        count++;
    }
    return count;
}

int ossl_mtc_tree_subtree_hash(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    uint8_t out[EVP_MAX_MD_SIZE])
{
    uint64_t start, last;
    size_t level;

    assert(ossl_mtc_subtree_is_valid(subtree));
    assert(subtree.end <= ossl_mtc_tree_leaf_count(tree));

    if (subtree.start == subtree.end)
        return mtc_hash_empty(tree->ctx, tree->md, out);

    /* Start from the largest complete subtree on the right edge. */
    start = subtree.start;
    last = subtree.end - 1;
    level = trailing_ones(last - start);
    start >>= level;
    last >>= level;
    memcpy(out, tree_node(tree, level, last), tree->hash_len);

    /*
     * Invariant: out holds the hash of the subtree rooted at
     * (last << level), and start <= last.  Fold in left neighbours while
     * rising to the subtree root.
     */
    while (start < last) {
        if ((last & 1) != 0
            && !mtc_hash(tree->ctx, tree->md, 0x01,
                tree_node(tree, level, last - 1), tree->hash_len, out,
                tree->hash_len, out))
            return 0;
        level++;
        start >>= 1;
        last >>= 1;
    }
    return 1;
}

/**
 * @brief Finish a proof-building WPACKET, transferring the buffer to the
 * caller.
 *
 * On success the accumulated bytes are handed to *out_proof (to be freed with
 * OPENSSL_free()) and their length to *out_proof_len.  On failure the WPACKET
 * is cleaned up and neither output is written.  buf is freed either way; on
 * success its data has already been detached.
 *
 * @param ok 1 if proof construction succeeded so far, 0 otherwise
 * @param out_proof set to the allocated proof buffer on success
 * @param out_proof_len set to the length of the proof buffer on success
 * @returns 1 on success, 0 on error.
 */
static int finish_proof(WPACKET *pkt, BUF_MEM *buf, int ok,
    uint8_t **out_proof, size_t *out_proof_len)
{
    size_t written;

    if (!ok
        || !WPACKET_get_total_written(pkt, &written)
        || !WPACKET_finish(pkt)) {
        WPACKET_cleanup(pkt);
        BUF_MEM_free(buf);
        return 0;
    }
    *out_proof = (uint8_t *)buf->data;
    *out_proof_len = written;
    buf->data = NULL;
    BUF_MEM_free(buf);
    return 1;
}

int ossl_mtc_tree_inclusion_proof(const OSSL_MTC_TREE *tree, uint64_t index,
    OSSL_MTC_SUBTREE subtree,
    uint8_t **out_proof,
    size_t *out_proof_len)
{
    WPACKET pkt;
    BUF_MEM *buf = BUF_MEM_new();
    uint64_t start, last;
    size_t level = 0;
    int ok = 1;

    assert(ossl_mtc_subtree_is_valid(subtree));
    assert(subtree.end <= ossl_mtc_tree_leaf_count(tree));
    assert(ossl_mtc_subtree_contains_index(subtree, index));

    if (buf == NULL)
        return 0;
    if (!WPACKET_init_len(&pkt, buf, 0)) {
        BUF_MEM_free(buf);
        return 0;
    }

    /* The proof is the neighbour of index at each level. */
    start = subtree.start;
    last = subtree.end - 1;
    while (ok && start < last) {
        uint64_t neighbor = index ^ 1;

        if (neighbor < last) {
            /* The neighbour is a complete node; look it up directly. */
            ok = WPACKET_memcpy(&pkt, tree_node(tree, level, neighbor),
                tree->hash_len);
        } else if (neighbor == last) {
            /* The neighbour is on the right edge and may be partial. */
            uint8_t h[EVP_MAX_MD_SIZE];
            OSSL_MTC_SUBTREE edge = { last << level, subtree.end };

            ok = ossl_mtc_tree_subtree_hash(tree, edge, h)
                && WPACKET_memcpy(&pkt, h, tree->hash_len);
        }
        level++;
        start >>= 1;
        index >>= 1;
        last >>= 1;
    }

    return finish_proof(&pkt, buf, ok, out_proof, out_proof_len);
}

/**
 * @brief Recursively accumulate a subtree consistency proof.
 *
 * This mirrors the recursive SUBTREE_PROOF definition in section 4.4.1 of
 * the draft.  known_hash tracks whether the caller already holds the hash of
 * subtree (and so it may be omitted from the proof).
 *
 * @param subtree the subtree the proof is relative to
 * @param range the (sub)tree currently being descended
 * @param known_hash 1 if subtree's hash is already known, 0 otherwise
 * @param pkt the WPACKET accumulating the proof
 * @returns 1 on success, 0 on error.
 */
static int consistency_proof(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree, OSSL_MTC_SUBTREE range,
    int known_hash, WPACKET *pkt)
{
    uint64_t k;
    OSSL_MTC_SUBTREE subproof_range, mth_range;
    uint8_t mth[EVP_MAX_MD_SIZE];

    if (subtree.start == range.start && subtree.end == range.end) {
        if (known_hash)
            return 1;
        if (!ossl_mtc_tree_subtree_hash(tree, subtree, mth))
            return 0;
        return WPACKET_memcpy(pkt, mth, tree->hash_len);
    }

    k = ossl_mtc_subtree_split(range);
    if (subtree.end <= k) {
        subproof_range = ossl_mtc_subtree_left(range);
        mth_range = ossl_mtc_subtree_right(range);
    } else if (subtree.start >= k) {
        mth_range = ossl_mtc_subtree_left(range);
        subproof_range = ossl_mtc_subtree_right(range);
    } else {
        subtree.start = k;
        mth_range = ossl_mtc_subtree_left(range);
        subproof_range = ossl_mtc_subtree_right(range);
        known_hash = 0;
    }

    if (!consistency_proof(tree, subtree, subproof_range, known_hash, pkt))
        return 0;
    if (!ossl_mtc_tree_subtree_hash(tree, mth_range, mth))
        return 0;
    return WPACKET_memcpy(pkt, mth, tree->hash_len);
}

int ossl_mtc_tree_consistency_proof(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    OSSL_MTC_SUBTREE tree_range,
    uint8_t **out_proof,
    size_t *out_proof_len)
{
    WPACKET pkt;
    BUF_MEM *buf = BUF_MEM_new();
    int ok;

    assert(ossl_mtc_subtree_is_valid(subtree));
    assert(ossl_mtc_subtree_is_valid(tree_range));
    assert(ossl_mtc_subtree_contains_subtree(tree_range, subtree));
    assert(tree_range.end <= ossl_mtc_tree_leaf_count(tree));

    if (buf == NULL)
        return 0;
    if (!WPACKET_init_len(&pkt, buf, 0)) {
        BUF_MEM_free(buf);
        return 0;
    }

    /* The proof for an empty subtree is empty. */
    ok = subtree.start == subtree.end
        || consistency_proof(tree, subtree, tree_range, 1, &pkt);
    return finish_proof(&pkt, buf, ok, out_proof, out_proof_len);
}
