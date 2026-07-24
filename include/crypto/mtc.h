/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Internal Merkle Tree Certificate (MTC) subtree support.  Not for
 * application use.
 *
 * This implements the Merkle-tree subtree operations from section 4 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/:
 * the definition of a subtree, the verification of subtree inclusion proofs
 * (section 4.3), and the verification of subtree consistency proofs
 * (section 4.4).  For the whole-tree case these degenerate to the inclusion
 * and consistency proofs of RFC 9162.
 *
 * The digest is a parameter of the certification authority, so every
 * operation that hashes takes one, and an in-memory tree records the digest
 * it was created with.  A node hash is EVP_MD_get_size() bytes long; buffers
 * receiving one are declared EVP_MAX_MD_SIZE so that any digest fits, and a
 * proof is a concatenation of node hashes of that length.
 *
 * An in-memory Merkle tree builder is also provided so that tests and
 * tooling can generate the proofs that the verifiers check.
 *
 * These are internal interfaces: callers are expected to pass valid, non-NULL
 * pointers.  The functions do not check for NULL and are explicitly not
 * NULL-safe, the sole exception being ossl_mtc_tree_free(), which accepts a
 * NULL tree.
 */

#if !defined(OSSL_CRYPTO_MTC_H)
#define OSSL_CRYPTO_MTC_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

/**
 * @brief Encode an ASCII dotted-decimal string as RELATIVE-OID content octets.
 *
 * The result is the binary TrustAnchorID form (section 4 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
 *
 * @param text the dotted-decimal string (e.g. "32473.1")
 * @param len the length of text in bytes
 * @param out set to the newly allocated content octets (caller frees)
 * @param out_len set to the length of the octets
 * @returns 1 on success, 0 on malformed input or allocation failure.
 */
int ossl_mtc_reloid_from_text(const char *text, size_t len, uint8_t **out,
    size_t *out_len);

/**
 * @struct ossl_mtc_subtree_st
 * @brief A range of leaves in a Merkle tree, the half-open interval
 * [start, end).
 *
 * This corresponds to a "subtree" as defined in section 4.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 * A subtree is valid only when start <= end and its left edge is suitably
 * aligned; see ossl_mtc_subtree_is_valid().
 */
typedef struct ossl_mtc_subtree_st {
    uint64_t start; /**< index of the first leaf in the range */
    uint64_t end; /**< index one past the last leaf in the range */
} OSSL_MTC_SUBTREE;

/**
 * @brief Report whether a subtree is well-formed.
 *
 * A subtree is valid when it is an interval (start <= end) whose left edge
 * does not have a "ragged" alignment: writing k for the largest power of two
 * that divides start, the size must not exceed k (this always holds when
 * start is zero).  This is the section 4.1 rule that start be a multiple of
 * the smallest power of two not less than the size.  Every empty subtree
 * [x, x) is valid.
 *
 * @param subtree the subtree to test
 * @returns 1 if subtree is valid, 0 otherwise.
 */
int ossl_mtc_subtree_is_valid(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the number of leaves in a subtree (end - start).
 *
 * This count is what section 4.1 of the draft calls the subtree's "size".
 *
 * @param subtree the subtree to measure
 * @returns the number of leaves in subtree (end - start).
 */
uint64_t ossl_mtc_subtree_leaf_count(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the split point of a subtree.
 *
 * The split point k is the index at which the subtree divides into its left
 * child [start, k) and right child [k, end), sharing no interior nodes.
 * Neither child is empty unless the subtree has fewer than two leaves, in
 * which case end is returned.
 *
 * @param subtree the subtree to split
 * @returns the split index.
 */
uint64_t ossl_mtc_subtree_split(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the left child [start, split) of a subtree, or the subtree
 * itself if it has fewer than two leaves.
 *
 * @param subtree the parent subtree
 * @returns the left child subtree.
 */
OSSL_MTC_SUBTREE ossl_mtc_subtree_left(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the right child [split, end) of a subtree, or the empty
 * subtree [end, end) if it has fewer than two leaves.
 *
 * @param subtree the parent subtree
 * @returns the right child subtree.
 */
OSSL_MTC_SUBTREE ossl_mtc_subtree_right(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Report whether a subtree contains a given leaf index.
 * @param subtree the subtree to test
 * @param index the leaf index to test for
 * @returns 1 if start <= index < end, 0 otherwise.
 */
int ossl_mtc_subtree_contains_index(OSSL_MTC_SUBTREE subtree, uint64_t index);

/**
 * @brief Report whether the outer subtree contains the inner one.
 * @param outer the containing subtree
 * @param inner the subtree tested for containment
 * @returns 1 if inner lies within outer, 0 otherwise.
 */
int ossl_mtc_subtree_contains_subtree(OSSL_MTC_SUBTREE outer,
    OSSL_MTC_SUBTREE inner);

/**
 * @brief Cover an arbitrary interval with two subtrees, per section 4.5
 * of https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 *
 * Given any half-open interval [start, end) with start <= end, this writes
 * two valid subtrees that efficiently cover it.  They are adjacent
 * (out[0].end == out[1].start) and together cover the interval
 * (out[0].start <= start and out[1].end == end, possibly with a few extra
 * leaves before start); out[0] is full and out[1] may be partial.  An
 * interval of at most one leaf is out[0], followed by the empty subtree
 * [end, end).
 *
 * @param interval the interval [start, end) to cover; start must be <= end
 * @param out array of length two receiving the covering subtrees
 */
void ossl_mtc_find_subtrees(OSSL_MTC_SUBTREE interval,
    OSSL_MTC_SUBTREE out[2]);

/**
 * @brief Compute the hash of a Merkle tree leaf, HASH(0x00 || entry).
 * @param md the digest to hash with
 * @param entry pointer to the leaf's bytes
 * @param entry_len the number of bytes in entry
 * @param out buffer receiving the node hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_hash_leaf(const EVP_MD *md, const uint8_t *entry,
    size_t entry_len, uint8_t out[EVP_MAX_MD_SIZE]);

/**
 * @brief Compute the hash of an interior node, HASH(0x01 || left || right).
 *
 * out may alias left or right.
 *
 * @param md the digest to hash with
 * @param left the hash of the left child
 * @param right the hash of the right child
 * @param out buffer receiving the node hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_hash_node(const EVP_MD *md, const uint8_t *left,
    const uint8_t *right, uint8_t out[EVP_MAX_MD_SIZE]);

/**
 * @brief Verify a subtree consistency proof, per section 4.4.3 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 *
 * Given a Merkle tree over n leaves with root hash root_hash, a subtree with
 * hash node_hash, and a consistency proof, this checks that the subtree is
 * consistent with the tree.  An empty subtree is consistent with any tree it
 * fits in: its proof is empty, node_hash must be HASH() of the empty string,
 * and root_hash is not consulted.
 *
 * The internal cursors fn, sn, and tn mirror the "first", "second", and
 * "third" numbers of the draft's procedure.
 *
 * @param md the digest the tree was built with
 * @param n the number of leaves in the full tree
 * @param subtree the subtree the proof is relative to
 * @param proof pointer to the proof bytes
 * @param proof_len the number of proof bytes
 * @param node_hash the hash of subtree
 * @param root_hash the trusted root hash of the full tree
 * @returns 1 if the proof verifies, 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_verify_subtree_consistency_proof(
    const EVP_MD *md, uint64_t n, OSSL_MTC_SUBTREE subtree,
    const uint8_t *proof, size_t proof_len, const uint8_t *node_hash,
    const uint8_t *root_hash);

/**
 * @brief Evaluate a subtree inclusion proof, per section 4.3.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 *
 * Given the hash of the leaf at index and an inclusion proof, this
 * recomputes the hash of subtree, which the caller must compare against the
 * value it trusts.  An inclusion proof is the special case of a consistency
 * proof for the single-leaf range [index, index + 1).
 *
 * @param md the digest the tree was built with
 * @param inclusion_proof pointer to the proof bytes
 * @param proof_len the number of proof bytes
 * @param index the leaf index being proven, in whole-tree coordinates
 * @param entry_hash the hash of the leaf at index
 * @param subtree the subtree the leaf is claimed to belong to
 * @param out_root_hash buffer receiving the computed subtree hash
 * @returns 1 if the proof was well-formed (out_root_hash is then set),
 * 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_eval_subtree_inclusion_proof(
    const EVP_MD *md, const uint8_t *inclusion_proof, size_t proof_len,
    uint64_t index, const uint8_t *entry_hash, OSSL_MTC_SUBTREE subtree,
    uint8_t out_root_hash[EVP_MAX_MD_SIZE]);

/**
 * @struct ossl_mtc_tree_st
 * An in-memory Merkle tree, used to generate proofs for tests and tooling.
 * Opaque; created with ossl_mtc_tree_new().
 */
typedef struct ossl_mtc_tree_st OSSL_MTC_TREE;

/**
 * @brief Allocate a new, empty in-memory Merkle tree.
 *
 * The tree hashes with md throughout its life, and md must outlive it.
 *
 * @param md the digest to build the tree with
 * @returns the new tree, or NULL on error.
 */
OSSL_MTC_TREE *ossl_mtc_tree_new(const EVP_MD *md);

/**
 * @brief Free an in-memory Merkle tree; tree may be NULL.
 * @param tree the tree to free
 */
void ossl_mtc_tree_free(OSSL_MTC_TREE *tree);

/**
 * @brief Append a leaf to an in-memory Merkle tree.
 *
 * On failure the tree is left with the leaves it had before the call.
 *
 * @param tree the tree to append to
 * @param entry pointer to the new leaf's bytes
 * @param entry_len the number of bytes in entry
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_append(OSSL_MTC_TREE *tree, const uint8_t *entry,
    size_t entry_len);

/**
 * @brief Return the number of leaves in an in-memory Merkle tree.
 *
 * The draft refers to this count as the tree's "size" (n).
 *
 * @param tree the tree to measure
 * @returns the number of leaves in tree.
 */
uint64_t ossl_mtc_tree_leaf_count(const OSSL_MTC_TREE *tree);

/**
 * @brief Compute the hash of a subtree of an in-memory Merkle tree.
 *
 * The hash of an empty subtree is HASH() of the empty string.
 *
 * @param tree the tree containing the subtree
 * @param subtree the subtree to hash; must be valid with end <= size
 * @param out buffer receiving the node hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_subtree_hash(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    uint8_t out[EVP_MAX_MD_SIZE]);

/**
 * @brief Generate an inclusion proof for a leaf within a subtree.
 *
 * The returned proof is a heap-allocated concatenation of node hashes,
 * suitable for ossl_mtc_eval_subtree_inclusion_proof().  The caller must
 * free it with OPENSSL_free().  Neither output is written on failure.
 *
 * @param tree the tree to generate the proof from
 * @param index the leaf index to prove; must be contained in subtree
 * @param subtree the subtree to prove membership of; must be valid with
 * end <= size
 * @param out_proof set to the allocated proof buffer on success
 * @param out_proof_len set to the length of the proof buffer on success
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_inclusion_proof(const OSSL_MTC_TREE *tree, uint64_t index,
    OSSL_MTC_SUBTREE subtree,
    uint8_t **out_proof,
    size_t *out_proof_len);

/**
 * @brief Generate a consistency proof for a subtree within a larger tree.
 *
 * The returned proof is a heap-allocated concatenation of node hashes,
 * suitable for ossl_mtc_verify_subtree_consistency_proof(); it is empty for
 * an empty subtree.  The caller must free it with OPENSSL_free().  Neither
 * output is written on failure.
 *
 * @param tree the tree to generate the proof from
 * @param subtree the subtree the proof is relative to; must be valid and
 * contained in tree_range
 * @param tree_range the larger tree the subtree is proven consistent with;
 * must be valid with end <= size
 * @param out_proof set to the allocated proof buffer on success
 * @param out_proof_len set to the length of the proof buffer on success
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_consistency_proof(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    OSSL_MTC_SUBTREE tree_range,
    uint8_t **out_proof,
    size_t *out_proof_len);

#endif /* defined(OSSL_CRYPTO_MTC_H) */
