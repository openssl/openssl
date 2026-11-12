/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "crypto/mtc.h"
#include "internal/nelem.h"
#include "testutil.h"

/* Number of leaves used by the exhaustive round-trip test. */
#define MTC_TEST_LIMIT 65

/* Length of the leaves build_tree() appends. */
#define MTC_TEST_ENTRY_LEN (5 + 8)

/* The digest the tests build their trees with, and its node hash length. */
static const EVP_MD *md;
static size_t hash_len;

/**
 * @brief Fill in the bytes of leaf i.
 *
 * A leaf is the bytes "label" followed by a little-endian 8-byte index,
 * matching the pattern used by the reference implementation's tests.
 *
 * @param i the leaf index
 * @param entry buffer receiving the leaf's bytes
 */
static void make_entry(uint64_t i, uint8_t entry[MTC_TEST_ENTRY_LEN])
{
    size_t j;

    memcpy(entry, "label", 5);
    for (j = 0; j < 8; j++)
        entry[5 + j] = (uint8_t)(i >> (j * 8));
}

/**
 * @brief Build an in-memory tree of n distinct leaves.
 * @param n the number of leaves to append
 * @returns the new tree, or NULL on failure.
 */
static OSSL_MTC_TREE *build_tree(uint64_t n)
{
    OSSL_MTC_TREE *tree = ossl_mtc_tree_new(md);
    uint64_t i;
    uint8_t entry[MTC_TEST_ENTRY_LEN];

    if (tree == NULL)
        return NULL;
    for (i = 0; i < n; i++) {
        make_entry(i, entry);
        if (!ossl_mtc_tree_append(tree, entry, sizeof(entry))) {
            ossl_mtc_tree_free(tree);
            return NULL;
        }
    }
    return tree;
}

static int test_subtree_is_valid(void)
{
    OSSL_MTC_SUBTREE s;

    /* Empty subtrees are valid, at any position. */
    s.start = 0;
    s.end = 0;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    s.start = 5;
    s.end = 5;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* An inverted interval is invalid. */
    s.start = 1;
    s.end = 0;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* The maximum expressible subtree is valid. */
    s.start = 0;
    s.end = UINT64_MAX;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* Test max sizes */
    s.start = 1;
    s.end = (UINT64_C(1) << 63) + 2;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    s.start = UINT64_C(1) << 63;
    s.end = UINT64_MAX;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    s.start = UINT64_C(1) << 62;
    s.end = (UINT64_C(1) << 62) + (UINT64_C(1) << 63);
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* Subtrees need not start at zero. */
    s.start = 4;
    s.end = 8;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* But a non-zero start bounds the size. */
    s.start = 4;
    s.end = 9;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* A ragged right edge is allowed. */
    s.start = 4;
    s.end = 6;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    s.start = 0;
    s.end = 6;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    return 1;
}

static int test_subtree_split(void)
{
    OSSL_MTC_SUBTREE s;

    s.start = 24601;
    s.end = 24601; /* empty */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 24601))
        return 0;
    s.start = 1336;
    s.end = 1337; /* single leaf */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 1337))
        return 0;
    s.start = 42;
    s.end = 44; /* two leaves */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 43))
        return 0;
    s.start = 0;
    s.end = 31; /* one less than a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 16))
        return 0;
    s.start = 64;
    s.end = 128; /* a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 96))
        return 0;
    s.start = 0;
    s.end = 257; /* one more than a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 256))
        return 0;
    s.start = 0;
    s.end = UINT64_MAX;
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), UINT64_C(1) << 63))
        return 0;
    s.start = UINT64_MAX - 3;
    s.end = UINT64_MAX;
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), UINT64_MAX - 1))
        return 0;
    return 1;
}

/* Build the {index, index + 1} single-leaf subtree hash. */
static int leaf_hash(const OSSL_MTC_TREE *tree, uint64_t index,
    uint8_t out[EVP_MAX_MD_SIZE])
{
    OSSL_MTC_SUBTREE leaf;

    leaf.start = index;
    leaf.end = index + 1;
    return ossl_mtc_tree_subtree_hash(tree, leaf, out);
}

static int test_inclusion_roundtrip(void)
{
    OSSL_MTC_TREE *tree = build_tree(847);
    uint8_t node_hash[EVP_MAX_MD_SIZE];
    uint8_t want[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    OSSL_MTC_SUBTREE subtree;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;

    /* A subtree starting at zero. */
    subtree.start = 0;
    subtree.end = 16;
    if (!TEST_true(leaf_hash(tree, 0, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 0, subtree,
            &proof, &proof_len))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            md, proof, proof_len, 0, node_hash, subtree, got))
        || !TEST_mem_eq(got, hash_len, want, hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* A subtree that does not start at zero, with a ragged edge. */
    subtree.start = 840;
    subtree.end = 847;
    if (!TEST_true(leaf_hash(tree, 845, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 845, subtree,
            &proof, &proof_len))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            md, proof, proof_len, 845, node_hash, subtree, got))
        || !TEST_mem_eq(got, hash_len, want, hash_len))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

static int test_inclusion_invalid_args(void)
{
    OSSL_MTC_TREE *tree = build_tree(847);
    uint8_t node_hash[EVP_MAX_MD_SIZE];
    uint8_t wrong_hash[EVP_MAX_MD_SIZE];
    uint8_t want[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    OSSL_MTC_SUBTREE subtree, bad;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;
    subtree.start = 840;
    subtree.end = 847;
    if (!TEST_true(leaf_hash(tree, 845, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 845, subtree,
            &proof, &proof_len)))
        goto err;

    /* A wrong node hash still evaluates, but to the wrong root. */
    if (!TEST_true(leaf_hash(tree, 846, wrong_hash))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            md, proof, proof_len, 845, wrong_hash, subtree, got)))
        goto err;
    if (!TEST_mem_ne(got, hash_len, want, hash_len))
        goto err;

    /* An invalid subtree fails. */
    bad.start = 840;
    bad.end = 849;
    if (!TEST_false(ossl_mtc_eval_subtree_inclusion_proof(
            md, proof, proof_len, 845, node_hash, bad, got)))
        goto err;

    /* An index outside the subtree fails. */
    if (!TEST_false(ossl_mtc_eval_subtree_inclusion_proof(
            md, proof, proof_len, 848, node_hash, subtree, got)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * A tree of one leaf: its root is that leaf's hash, and the proofs for the
 * whole of it are empty.
 */
static int test_one_leaf(void)
{
    OSSL_MTC_TREE *tree = build_tree(1);
    OSSL_MTC_SUBTREE full = { 0, 1 };
    uint8_t entry[MTC_TEST_ENTRY_LEN];
    uint8_t want[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    int ret = 0;

    make_entry(0, entry);
    if (!TEST_ptr(tree)
        || !TEST_uint64_t_eq(ossl_mtc_tree_leaf_count(tree), 1))
        goto err;

    /* The root of the tree is the hash of its only leaf. */
    if (!TEST_true(ossl_mtc_hash_leaf(md, entry, sizeof(entry), want))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, full, got))
        || !TEST_mem_eq(got, hash_len, want, hash_len))
        goto err;

    /* The inclusion proof of the only leaf is empty. */
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 0, full, &proof,
            &proof_len))
        || !TEST_size_t_eq(proof_len, 0)
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(md, proof,
            proof_len, 0, want, full, got))
        || !TEST_mem_eq(got, hash_len, want, hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* So is the consistency proof of the whole tree with itself. */
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, full, full, &proof,
            &proof_len))
        || !TEST_size_t_eq(proof_len, 0)
        || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 1, full,
            proof, proof_len, want, want)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * A subtree spanning the whole tree: its hash is the tree's root, its
 * consistency proof is empty, and inclusion proofs relative to it recompute
 * the root.
 */
static int test_whole_tree_subtree(void)
{
    OSSL_MTC_TREE *tree = build_tree(13);
    OSSL_MTC_SUBTREE full = { 0, 13 };
    uint64_t index;
    uint8_t entry_hash[EVP_MAX_MD_SIZE];
    uint8_t want[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    int ret = 0;

    if (!TEST_ptr(tree)
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, full, want)))
        goto err;

    /* A tree is consistent with itself, with nothing to prove it. */
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, full, full, &proof,
            &proof_len))
        || !TEST_size_t_eq(proof_len, 0)
        || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 13, full,
            proof, proof_len, want, want)))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Every leaf's inclusion proof evaluates to the root. */
    for (index = 0; index < 13; index++) {
        if (!TEST_true(leaf_hash(tree, index, entry_hash))
            || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, index, full,
                &proof, &proof_len))
            || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(md, proof,
                proof_len, index, entry_hash, full, got))
            || !TEST_mem_eq(got, hash_len, want, hash_len))
            goto err;
        OPENSSL_free(proof);
        proof = NULL;
    }

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * An empty subtree hashes to HASH() of the empty string and has an empty
 * consistency proof, which verifies against any tree it fits in without
 * consulting the root hash.
 */
static int test_empty_subtree(void)
{
    OSSL_MTC_TREE *tree = build_tree(13);
    OSSL_MTC_SUBTREE s = { 5, 5 };
    OSSL_MTC_SUBTREE full = { 0, 13 };
    OSSL_MTC_SUBTREE at_end = { 13, 13 };
    OSSL_MTC_SUBTREE beyond = { 14, 14 };
    uint8_t empty_hash[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t root[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    int ret = 0;

    /* root is deliberately not the tree's root hash. */
    memset(root, 0x5a, sizeof(root));
    if (!TEST_ptr(tree)
        || !TEST_true(EVP_Digest(NULL, 0, empty_hash, NULL, md, NULL))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, s, got))
        || !TEST_mem_eq(got, hash_len, empty_hash, hash_len))
        goto err;

    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, s, full, &proof,
            &proof_len))
        || !TEST_size_t_eq(proof_len, 0))
        goto err;

    if (!TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 13, s, NULL,
            0, empty_hash, root))
        /* A non-empty proof is rejected. */
        || !TEST_false(ossl_mtc_verify_subtree_consistency_proof(md, 13, s,
            empty_hash, hash_len, empty_hash, root))
        /* A node hash other than HASH() is rejected. */
        || !TEST_false(ossl_mtc_verify_subtree_consistency_proof(md, 13, s,
            NULL, 0, root, root))
        /* An empty subtree past the end of the tree is rejected. */
        || !TEST_false(ossl_mtc_verify_subtree_consistency_proof(md, 13,
            beyond, NULL, 0, empty_hash, root))
        /* An empty subtree at the end of the tree fits in it. */
        || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 13,
            at_end, NULL, 0, empty_hash, root)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Check that generated proofs match the structural examples in RFC 9162
 * section 2.1.5, computed over this implementation's own tree of 7 leaves.
 */
static int test_rfc9162_structure(void)
{
    OSSL_MTC_TREE *tree = build_tree(7);
    OSSL_MTC_SUBTREE full = { 0, 7 };
    struct {
        uint64_t start, end;
    } parts[] = {
        { 1, 2 }, /* 0: b */
        { 2, 3 }, /* 1: c */
        { 3, 4 }, /* 2: d */
        { 5, 6 }, /* 3: f */
        { 0, 2 }, /* 4: g */
        { 2, 4 }, /* 5: h */
        { 4, 6 }, /* 6: i */
        { 6, 7 }, /* 7: j */
        { 0, 4 }, /* 8: k */
        { 4, 7 } /* 9: l */
    };
    enum { B,
        C,
        D,
        F,
        G,
        H,
        I,
        J,
        K,
        L };
    uint8_t part[10][EVP_MAX_MD_SIZE];
    uint8_t expected[4 * EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0, i;
    OSSL_MTC_SUBTREE sub;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;
    for (i = 0; i < OSSL_NELEM(parts); i++) {
        sub.start = parts[i].start;
        sub.end = parts[i].end;
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, sub, part[i])))
            goto err;
    }

    /* Inclusion proof for d0 is [b, h, l]. */
    memcpy(expected, part[B], hash_len);
    memcpy(expected + hash_len, part[H], hash_len);
    memcpy(expected + 2 * hash_len, part[L], hash_len);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 0, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Inclusion proof for d3 is [c, g, l]. */
    memcpy(expected, part[C], hash_len);
    memcpy(expected + hash_len, part[G], hash_len);
    memcpy(expected + 2 * hash_len, part[L], hash_len);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 3, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Inclusion proof for d6 is [i, k]. */
    memcpy(expected, part[I], hash_len);
    memcpy(expected + hash_len, part[K], hash_len);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 6, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 2 * hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Consistency proof between hash0 [0, 3) and the tree is [c, d, g, l]. */
    memcpy(expected, part[C], hash_len);
    memcpy(expected + hash_len, part[D], hash_len);
    memcpy(expected + 2 * hash_len, part[G], hash_len);
    memcpy(expected + 3 * hash_len, part[L], hash_len);
    sub.start = 0;
    sub.end = 3;
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, sub, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 4 * hash_len))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Consistency proof between hash2 [0, 6) and the tree is [i, j, k]. */
    memcpy(expected, part[I], hash_len);
    memcpy(expected + hash_len, part[J], hash_len);
    memcpy(expected + 2 * hash_len, part[K], hash_len);
    sub.start = 0;
    sub.end = 6;
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, sub, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * hash_len))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Exhaustively generate and verify inclusion and consistency proofs for all
 * valid subtrees of all tree sizes up to MTC_TEST_LIMIT.
 */
static int test_exhaustive(void)
{
    OSSL_MTC_TREE *tree = build_tree(MTC_TEST_LIMIT);
    uint8_t subtree_hash[EVP_MAX_MD_SIZE];
    uint8_t entry_hash[EVP_MAX_MD_SIZE];
    uint8_t tree_hash[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    uint64_t n, start, end, index;
    OSSL_MTC_SUBTREE subtree, full;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;

    /* Consistency proofs against every prefix tree size, empty included. */
    for (n = 0; n < MTC_TEST_LIMIT; n++) {
        full.start = 0;
        full.end = n;
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, full, tree_hash)))
            goto err;
        for (end = 0; end <= n; end++) {
            for (start = 0; start <= end; start++) {
                subtree.start = start;
                subtree.end = end;
                if (!ossl_mtc_subtree_is_valid(subtree))
                    continue;
                if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree,
                        subtree_hash))
                    || !TEST_true(ossl_mtc_tree_consistency_proof(
                        tree, subtree, full, &proof, &proof_len))
                    || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(
                        md, n, subtree, proof, proof_len, subtree_hash,
                        tree_hash)))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }

    /* Inclusion proofs for every leaf of every valid subtree. */
    for (end = 1; end <= MTC_TEST_LIMIT; end++) {
        for (start = 0; start < end; start++) {
            subtree.start = start;
            subtree.end = end;
            if (!ossl_mtc_subtree_is_valid(subtree))
                continue;
            if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree,
                    subtree_hash)))
                goto err;
            for (index = start; index < end; index++) {
                if (!TEST_true(leaf_hash(tree, index, entry_hash))
                    || !TEST_true(ossl_mtc_tree_inclusion_proof(
                        tree, index, subtree, &proof, &proof_len))
                    || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
                        md, proof, proof_len, index, entry_hash, subtree,
                        got))
                    || !TEST_mem_eq(got, hash_len, subtree_hash, hash_len))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Assert that proof equals the concatenation of the hashes of the given
 * subtrees, computed over tree.  Used to check generated proofs against the
 * worked examples in the specification.
 */
static int check_proof_parts(const uint8_t *proof, size_t proof_len,
    const OSSL_MTC_TREE *tree, const OSSL_MTC_SUBTREE *parts, size_t nparts)
{
    uint8_t want[8 * EVP_MAX_MD_SIZE];
    size_t i;

    if (!TEST_size_t_le(nparts, sizeof(want) / hash_len))
        return 0;
    for (i = 0; i < nparts; i++)
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, parts[i],
                want + i * hash_len)))
            return 0;
    return TEST_mem_eq(proof, proof_len, want, nparts * hash_len);
}

/*
 * The specific worked examples from section 4 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 * The subtree [4, 8) is full and
 * [8, 13) is partial (Figures 3-5); both are checked for validity and
 * containment, then the inclusion proof of Figure 6 and the consistency
 * proofs of Figures 7 and 8 are reproduced exactly and verified.
 *
 * The arbitrary-interval covering of section 4.5 (Figures 9 and 10) is
 * exercised separately in test_find_subtrees.
 */
static int test_plants_section4_examples(void)
{
    OSSL_MTC_TREE *t13 = build_tree(13);
    OSSL_MTC_TREE *t14 = build_tree(14);
    OSSL_MTC_SUBTREE full13 = { 0, 13 };
    OSSL_MTC_SUBTREE full14 = { 0, 14 };
    OSSL_MTC_SUBTREE s48 = { 4, 8 }; /* full subtree */
    OSSL_MTC_SUBTREE s813 = { 8, 13 }; /* partial subtree */
    uint8_t node_hash[EVP_MAX_MD_SIZE];
    uint8_t entry_hash[EVP_MAX_MD_SIZE];
    uint8_t want[EVP_MAX_MD_SIZE];
    uint8_t got[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    int ret = 0;

    if (!TEST_ptr(t13) || !TEST_ptr(t14))
        goto err;

    /* Section 4.1/4.2: [4, 8) and [8, 13) are valid, in a size-13 tree. */
    if (!TEST_true(ossl_mtc_subtree_is_valid(s48))
        || !TEST_uint64_t_eq(ossl_mtc_subtree_leaf_count(s48), 4)
        || !TEST_true(ossl_mtc_subtree_is_valid(s813))
        || !TEST_uint64_t_eq(ossl_mtc_subtree_leaf_count(s813), 5)
        || !TEST_true(ossl_mtc_subtree_contains_subtree(full13, s48))
        || !TEST_true(ossl_mtc_subtree_contains_subtree(full13, s813)))
        goto err;

    /*
     * Figure 6: the inclusion proof for entry 10 of subtree [8, 13) is
     * [MTH({d[11]}), MTH(D[8:10]), MTH({d[12]})].
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 11, 12 }, { 8, 10 }, { 12, 13 } };

        if (!TEST_true(ossl_mtc_tree_inclusion_proof(t13, 10, s813, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t13, parts,
                OSSL_NELEM(parts))
            || !TEST_true(leaf_hash(t13, 10, entry_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t13, s813, want))
            || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(md, proof,
                proof_len, 10, entry_hash, s813, got))
            || !TEST_mem_eq(got, hash_len, want, hash_len))
            goto err;
        OPENSSL_free(proof);
        proof = NULL;
    }

    /*
     * Figure 7: the consistency proof for [4, 8) in a size-14 tree is
     * [MTH(D[0:4]), MTH(D[8:14])].
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 0, 4 }, { 8, 14 } };

        if (!TEST_true(ossl_mtc_tree_consistency_proof(t14, s48, full14, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t14, parts,
                OSSL_NELEM(parts))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, s48, node_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, full14, want))
            || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 14,
                s48, proof, proof_len, node_hash, want)))
            goto err;
        OPENSSL_free(proof);
        proof = NULL;
    }

    /*
     * Figure 8: the consistency proof for the partial subtree [8, 13) in a
     * size-14 tree is [MTH({d[12]}), MTH({d[13]}), MTH(D[8:12]), MTH(D[0:8])].
     * [8, 13) is not directly contained in the size-14 tree, yet the proof
     * still verifies against the root, demonstrating the consistent
     * elements.
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 12, 13 }, { 13, 14 }, { 8, 12 },
            { 0, 8 } };

        if (!TEST_true(ossl_mtc_tree_consistency_proof(t14, s813, full14, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t14, parts,
                OSSL_NELEM(parts))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, s813, node_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, full14, want))
            || !TEST_true(ossl_mtc_verify_subtree_consistency_proof(md, 14,
                s813, proof, proof_len, node_hash, want)))
            goto err;
    }

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(t13);
    ossl_mtc_tree_free(t14);
    return ret;
}

/* Report whether x is a power of two. */
static int is_power_of_two(uint64_t x)
{
    return x != 0 && (x & (x - 1)) == 0;
}

/* Check that find_subtrees covers [start, end) with exactly want. */
static int check_find_subtrees(uint64_t start, uint64_t end,
    const OSSL_MTC_SUBTREE want[2])
{
    OSSL_MTC_SUBTREE iv = { start, end };
    OSSL_MTC_SUBTREE out[2];

    ossl_mtc_find_subtrees(iv, out);
    return TEST_uint64_t_eq(out[0].start, want[0].start)
        && TEST_uint64_t_eq(out[0].end, want[0].end)
        && TEST_uint64_t_eq(out[1].start, want[1].start)
        && TEST_uint64_t_eq(out[1].end, want[1].end);
}

/*
 * Section 4.5: covering an arbitrary interval with two subtrees, including
 * the worked examples of Figures 9 ([5, 13)) and 10 ([7, 9)), plus an
 * exhaustive check of the covering properties for all small intervals.
 */
static int test_find_subtrees(void)
{
    static const OSSL_MTC_SUBTREE fig9[2] = { { 4, 8 }, { 8, 13 } };
    static const OSSL_MTC_SUBTREE fig10[2] = { { 7, 8 }, { 8, 9 } };
    static const OSSL_MTC_SUBTREE one[2] = { { 5, 6 }, { 6, 6 } };
    static const OSSL_MTC_SUBTREE none[2] = { { 5, 5 }, { 5, 5 } };
    OSSL_MTC_SUBTREE out[2];
    OSSL_MTC_SUBTREE iv;
    uint64_t start, end;

    /* Figure 9: [5, 13) is covered by [4, 8) and [8, 13). */
    if (!check_find_subtrees(5, 13, fig9)
        /* Figure 10: [7, 9) is covered by [7, 8) and [8, 9). */
        || !check_find_subtrees(7, 9, fig10)
        /* An interval of at most one leaf is itself, then [end, end). */
        || !check_find_subtrees(5, 6, one)
        || !check_find_subtrees(5, 5, none))
        return 0;

    /* Exhaustively check the section 4.5 covering properties. */
    for (end = 0; end <= 64; end++) {
        for (start = 0; start <= end; start++) {
            iv.start = start;
            iv.end = end;
            ossl_mtc_find_subtrees(iv, out);

            if (end - start <= 1) {
                if (!TEST_uint64_t_eq(out[0].start, start)
                    || !TEST_uint64_t_eq(out[0].end, end)
                    || !TEST_uint64_t_eq(out[1].start, end)
                    || !TEST_uint64_t_eq(out[1].end, end))
                    return 0;
                continue;
            }

            if (!TEST_true(ossl_mtc_subtree_is_valid(out[0]))
                || !TEST_true(ossl_mtc_subtree_is_valid(out[1]))
                || !TEST_uint64_t_eq(out[0].end, out[1].start)
                || !TEST_true(out[0].start <= start)
                || !TEST_uint64_t_eq(out[1].end, end)
                || !TEST_true(
                    is_power_of_two(ossl_mtc_subtree_leaf_count(out[0])))
                || !TEST_true(
                    ossl_mtc_subtree_leaf_count(out[0]) < 2 * (end - start))
                || !TEST_true(
                    ossl_mtc_subtree_leaf_count(out[1]) <= end - start))
                return 0;
        }
    }
    return 1;
}

/*
 * The accumulated test vectors of Appendix C.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/:
 * over a tree whose leaf i is the single byte i, every output of each
 * section 4 algorithm for tree sizes up to 130, empty subtrees included, is
 * formatted as a text line and fed to one SHA-256.
 */

#define VECTOR_LEAVES 130

static const char vector_subtree_hashes[] = "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81";
static const char vector_inclusion_proofs[] = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f";
static const char vector_consistency_proofs[] = "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74";
static const char vector_covering_subtrees[] = "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0";

/* Build the Appendix C tree of VECTOR_LEAVES one-byte leaves 0, 1, 2, ... */
static OSSL_MTC_TREE *build_byte_tree(void)
{
    OSSL_MTC_TREE *tree = ossl_mtc_tree_new(md);
    uint8_t leaf;
    unsigned int i;

    if (tree == NULL)
        return NULL;
    for (i = 0; i < VECTOR_LEAVES; i++) {
        leaf = (uint8_t)i;
        if (!ossl_mtc_tree_append(tree, &leaf, 1)) {
            ossl_mtc_tree_free(tree);
            return NULL;
        }
    }
    return tree;
}

/* Format one piece of a vector line and feed it to acc. */
static int accumulate(EVP_MD_CTX *acc, const char *fmt, ...)
{
    char buf[128];
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!TEST_int_ge(len, 0) || !TEST_size_t_lt((size_t)len, sizeof(buf)))
        return 0;
    return TEST_true(EVP_DigestUpdate(acc, buf, (size_t)len));
}

/* Feed " " followed by the hex of each node hash in hashes to acc. */
static int accumulate_hashes(EVP_MD_CTX *acc, const uint8_t *hashes,
    size_t hashes_len)
{
    size_t i, j;

    for (i = 0; i < hashes_len; i += hash_len) {
        if (!accumulate(acc, " "))
            return 0;
        for (j = 0; j < hash_len; j++)
            if (!accumulate(acc, "%02x", hashes[i + j]))
                return 0;
    }
    return 1;
}

/* Finish acc and compare its digest, in hex, against want. */
static int check_vector(EVP_MD_CTX *acc, const char *want)
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    unsigned int digest_len, i;

    if (!TEST_true(EVP_DigestFinal_ex(acc, digest, &digest_len)))
        return 0;
    for (i = 0; i < digest_len; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    return TEST_str_eq(hex, want);
}

static int test_vectors(void)
{
    OSSL_MTC_TREE *tree = build_byte_tree();
    EVP_MD_CTX *acc = EVP_MD_CTX_new();
    OSSL_MTC_SUBTREE s, full, out[2];
    uint8_t hash[EVP_MAX_MD_SIZE];
    uint8_t *proof = NULL;
    size_t proof_len = 0, j;
    uint64_t n, start, end, index;
    int ret = 0;

    if (!TEST_ptr(tree) || !TEST_ptr(acc))
        goto err;

    /* C.1.1: the hash of every valid subtree. */
    if (!TEST_true(EVP_DigestInit_ex(acc, EVP_sha256(), NULL)))
        goto err;
    for (end = 0; end <= VECTOR_LEAVES; end++) {
        for (start = 0; start <= end; start++) {
            s.start = start;
            s.end = end;
            if (!ossl_mtc_subtree_is_valid(s))
                continue;
            if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, s, hash))
                || !accumulate(acc, "[%" PRIu64 ", %" PRIu64 ")", start, end)
                || !accumulate_hashes(acc, hash, hash_len)
                || !accumulate(acc, "\n"))
                goto err;
        }
    }
    if (!check_vector(acc, vector_subtree_hashes))
        goto err;

    /* C.1.2: the inclusion proof of every leaf of every valid subtree. */
    if (!TEST_true(EVP_DigestInit_ex(acc, EVP_sha256(), NULL)))
        goto err;
    for (end = 0; end <= VECTOR_LEAVES; end++) {
        for (start = 0; start <= end; start++) {
            s.start = start;
            s.end = end;
            if (!ossl_mtc_subtree_is_valid(s))
                continue;
            for (index = start; index < end; index++) {
                if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, index, s,
                        &proof, &proof_len))
                    || !accumulate(acc, "%" PRIu64 " [%" PRIu64 ", %" PRIu64 ")",
                        index, start, end)
                    || !accumulate_hashes(acc, proof, proof_len)
                    || !accumulate(acc, "\n"))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }
    if (!check_vector(acc, vector_inclusion_proofs))
        goto err;

    /* C.1.3: the consistency proof of every valid subtree in every tree. */
    if (!TEST_true(EVP_DigestInit_ex(acc, EVP_sha256(), NULL)))
        goto err;
    for (n = 0; n <= VECTOR_LEAVES; n++) {
        full.start = 0;
        full.end = n;
        for (end = 0; end <= n; end++) {
            for (start = 0; start <= end; start++) {
                s.start = start;
                s.end = end;
                if (!ossl_mtc_subtree_is_valid(s))
                    continue;
                if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, s, full,
                        &proof, &proof_len))
                    || !accumulate(acc,
                        "[%" PRIu64 ", %" PRIu64 ") %" PRIu64, start, end, n)
                    || !accumulate_hashes(acc, proof, proof_len)
                    || !accumulate(acc, "\n"))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }
    if (!check_vector(acc, vector_consistency_proofs))
        goto err;

    /* C.1.4: the covering subtrees of every interval. */
    if (!TEST_true(EVP_DigestInit_ex(acc, EVP_sha256(), NULL)))
        goto err;
    for (end = 0; end <= VECTOR_LEAVES; end++) {
        for (start = 0; start <= end; start++) {
            s.start = start;
            s.end = end;
            ossl_mtc_find_subtrees(s, out);
            for (j = 0; j < 2; j++)
                if (!accumulate(acc, "[%" PRIu64 ", %" PRIu64 ")%s",
                        out[j].start, out[j].end, j == 0 ? " " : "\n"))
                    goto err;
        }
    }
    if (!check_vector(acc, vector_covering_subtrees))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    EVP_MD_CTX_free(acc);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * The large subtree test vectors of Appendix C.2.1 (validity) and C.2.4
 * (covering) of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/,
 * for trees bounded by 2^48 - 1, 2^63 - 1 and 2^64 - 1.
 */
static const struct {
    uint64_t start;
    uint64_t end;
    int valid;
} large_validity[] = {
    { 0, (UINT64_C(1) << 47) + 1, 1 },
    { 0, (UINT64_C(1) << 48) - 1, 1 },
    { 0, (UINT64_C(1) << 62) + 1, 1 },
    { 0, (UINT64_C(1) << 63) - 1, 1 },
    { 0, (UINT64_C(1) << 63) + 1, 1 },
    { 0, UINT64_MAX, 1 },
    { UINT64_C(1) << 46, (UINT64_C(1) << 47) + 1, 0 },
    { UINT64_C(1) << 46, (UINT64_C(1) << 48) - 1, 0 },
    { UINT64_C(1) << 61, (UINT64_C(1) << 62) + 1, 0 },
    { UINT64_C(1) << 61, (UINT64_C(1) << 63) - 1, 0 },
    { UINT64_C(1) << 62, (UINT64_C(1) << 63) + 1, 0 },
    { UINT64_C(1) << 62, UINT64_MAX, 0 }
};

static const struct {
    OSSL_MTC_SUBTREE interval;
    OSSL_MTC_SUBTREE want[2];
} large_covering[] = {
    { { UINT64_C(0x0), UINT64_C(0x800000000000) },
        { { UINT64_C(0x0), UINT64_C(0x400000000000) },
            { UINT64_C(0x400000000000), UINT64_C(0x800000000000) } } },
    { { UINT64_C(0x500000000000), UINT64_C(0xd00000000000) },
        { { UINT64_C(0x400000000000), UINT64_C(0x800000000000) },
            { UINT64_C(0x800000000000), UINT64_C(0xd00000000000) } } },
    { { UINT64_C(0x7fffffffffff), UINT64_C(0x800000000001) },
        { { UINT64_C(0x7fffffffffff), UINT64_C(0x800000000000) },
            { UINT64_C(0x800000000000), UINT64_C(0x800000000001) } } },
    { { UINT64_C(0xfffffffffffe), UINT64_C(0xffffffffffff) },
        { { UINT64_C(0xfffffffffffe), UINT64_C(0xffffffffffff) },
            { UINT64_C(0xffffffffffff), UINT64_C(0xffffffffffff) } } },
    { { UINT64_C(0xffffffffffff), UINT64_C(0xffffffffffff) },
        { { UINT64_C(0xffffffffffff), UINT64_C(0xffffffffffff) },
            { UINT64_C(0xffffffffffff), UINT64_C(0xffffffffffff) } } },
    { { UINT64_C(0x0), UINT64_C(0x4000000000000000) },
        { { UINT64_C(0x0), UINT64_C(0x2000000000000000) },
            { UINT64_C(0x2000000000000000), UINT64_C(0x4000000000000000) } } },
    { { UINT64_C(0x2800000000000000), UINT64_C(0x6800000000000000) },
        { { UINT64_C(0x2000000000000000), UINT64_C(0x4000000000000000) },
            { UINT64_C(0x4000000000000000), UINT64_C(0x6800000000000000) } } },
    { { UINT64_C(0x3fffffffffffffff), UINT64_C(0x4000000000000001) },
        { { UINT64_C(0x3fffffffffffffff), UINT64_C(0x4000000000000000) },
            { UINT64_C(0x4000000000000000), UINT64_C(0x4000000000000001) } } },
    { { UINT64_C(0x7ffffffffffffffe), UINT64_C(0x7fffffffffffffff) },
        { { UINT64_C(0x7ffffffffffffffe), UINT64_C(0x7fffffffffffffff) },
            { UINT64_C(0x7fffffffffffffff), UINT64_C(0x7fffffffffffffff) } } },
    { { UINT64_C(0x7fffffffffffffff), UINT64_C(0x7fffffffffffffff) },
        { { UINT64_C(0x7fffffffffffffff), UINT64_C(0x7fffffffffffffff) },
            { UINT64_C(0x7fffffffffffffff), UINT64_C(0x7fffffffffffffff) } } },
    { { UINT64_C(0x0), UINT64_C(0x8000000000000000) },
        { { UINT64_C(0x0), UINT64_C(0x4000000000000000) },
            { UINT64_C(0x4000000000000000), UINT64_C(0x8000000000000000) } } },
    { { UINT64_C(0x5000000000000000), UINT64_C(0xd000000000000000) },
        { { UINT64_C(0x4000000000000000), UINT64_C(0x8000000000000000) },
            { UINT64_C(0x8000000000000000), UINT64_C(0xd000000000000000) } } },
    { { UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000001) },
        { { UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000) },
            { UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000001) } } },
    { { UINT64_C(0xfffffffffffffffe), UINT64_C(0xffffffffffffffff) },
        { { UINT64_C(0xfffffffffffffffe), UINT64_C(0xffffffffffffffff) },
            { UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff) } } },
    { { UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff) },
        { { UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff) },
            { UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff) } } }
};

static int test_large_validity(int i)
{
    OSSL_MTC_SUBTREE s = { large_validity[i].start, large_validity[i].end };

    return TEST_int_eq(ossl_mtc_subtree_is_valid(s), large_validity[i].valid);
}

static int test_large_covering(int i)
{
    return check_find_subtrees(large_covering[i].interval.start,
        large_covering[i].interval.end, large_covering[i].want);
}

int setup_tests(void)
{
    md = EVP_sha256();
    if (!TEST_ptr(md) || !TEST_int_gt(EVP_MD_get_size(md), 0))
        return 0;
    hash_len = (size_t)EVP_MD_get_size(md);

    ADD_TEST(test_subtree_is_valid);
    ADD_TEST(test_subtree_split);
    ADD_TEST(test_one_leaf);
    ADD_TEST(test_whole_tree_subtree);
    ADD_TEST(test_empty_subtree);
    ADD_TEST(test_inclusion_roundtrip);
    ADD_TEST(test_inclusion_invalid_args);
    ADD_TEST(test_rfc9162_structure);
    ADD_TEST(test_plants_section4_examples);
    ADD_TEST(test_find_subtrees);
    ADD_TEST(test_exhaustive);
    ADD_TEST(test_vectors);
    ADD_ALL_TESTS(test_large_validity, OSSL_NELEM(large_validity));
    ADD_ALL_TESTS(test_large_covering, OSSL_NELEM(large_covering));
    return 1;
}
