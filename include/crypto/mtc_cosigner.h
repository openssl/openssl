/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * A Merkle Tree Certificate cosigner a relying party trusts (sections 5.3
 * and 7.3 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 * Not for application use.
 *
 * A cosigner is a (cosigner ID, public key) pair.  The CA cosigner (section
 * 5.4) is part of the OSSL_MTC_CA it belongs to; the cosigners here are the
 * others, which may cosign the logs of any number of CAs and are registered
 * once, in the X509_STORE, for all of them (section 7.3).
 *
 * These are internal interfaces: callers pass valid, non-NULL pointers and the
 * functions are not NULL-safe, except ossl_mtc_cosigner_free(), which accepts
 * NULL.
 */

#if !defined(OSSL_CRYPTO_MTC_COSIGNER_H)
#define OSSL_CRYPTO_MTC_COSIGNER_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/mtc.h>
#include <openssl/safestack.h>
#include <openssl/types.h>

/**
 * @struct ossl_mtc_cosigner_st
 * @brief A trusted cosigner: a (cosigner ID, public key) pair (sections 5.3
 * and 7.1).
 *
 * The public key fixes the signature algorithm (section 5.3.3).  Distinct from
 * an OSSL_MTC_COSIGNATURE, which is a signature parsed from an MTCProof.  Owns
 * its storage: id is a copy and a reference is held on pkey.  Immutable once
 * created, so it needs no lock.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
struct ossl_mtc_cosigner_st {
    uint8_t *id; /**< cosigner ID: a TrustAnchorID, i.e. relative-OID bytes (5.3) */
    size_t id_len;
    EVP_PKEY *pkey; /**< cosigner public key (5.3) */
};
/* STACK_OF(OSSL_MTC_COSIGNER) is declared publicly in <openssl/mtc.h>. */

/**
 * @brief Create a trusted cosigner from its ID and public key.
 *
 * The id bytes are copied and a reference is taken on pkey, released when the
 * cosigner is freed.  The caller retains ownership of its inputs.  id must be
 * non-empty and at most 255 bytes, the bounds of a TrustAnchorID.
 *
 * @param id the cosigner ID (TrustAnchorID relative-OID bytes)
 * @param id_len the length of id
 * @param pkey the cosigner public key
 * @returns the new cosigner, or NULL on error.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
OSSL_MTC_COSIGNER *ossl_mtc_cosigner_new(const uint8_t *id, size_t id_len,
    EVP_PKEY *pkey);

/**
 * @brief Free an OSSL_MTC_COSIGNER; cosigner may be NULL.
 * @param cosigner the cosigner to free
 */
void ossl_mtc_cosigner_free(OSSL_MTC_COSIGNER *cosigner);

/**
 * @brief Return the cosigner's identifier (a TrustAnchorID, i.e. relative-OID
 * bytes).
 * @param cosigner the cosigner
 * @param len set to the length of the returned identifier
 * @returns a pointer to the identifier bytes, owned by cosigner.
 */
const uint8_t *ossl_mtc_cosigner_id(const OSSL_MTC_COSIGNER *cosigner,
    size_t *len);

/**
 * @brief Return the cosigner's public key (section 5.3), non-owning.
 * @param cosigner the cosigner
 * @returns the public key, owned by cosigner.
 */
EVP_PKEY *ossl_mtc_cosigner_pkey(const OSSL_MTC_COSIGNER *cosigner);

/*-
 * A set of trusted cosigners is a STACK_OF(OSSL_MTC_COSIGNER) kept sorted
 * by cosigner ID for binary-search lookup.  The stack holds *borrowed*
 * references: it does not own the cosigners (the application owns them and
 * must keep them alive).  Create it with
 * sk_OSSL_MTC_COSIGNER_new(OSSL_MTC_COSIGNER_cmp) and free it with
 * sk_OSSL_MTC_COSIGNER_free(), which frees the container, not the cosigners.
 */

/**
 * @brief Add a trusted cosigner to a stack, keeping it sorted by ID.
 *
 * The cosigner is stored by reference (not owned, not copied).  Fails if a
 * cosigner with the same ID is already present.
 *
 * @param cosigners the stack of trusted cosigners
 * @param cosigner the cosigner to add (borrowed; caller retains ownership)
 * @returns 1 on success, 0 on error or duplicate ID.
 */
int ossl_mtc_cosigner_stack_add(STACK_OF(OSSL_MTC_COSIGNER) *cosigners,
    OSSL_MTC_COSIGNER *cosigner);

/**
 * @brief Look up a trusted cosigner by its ID (section 5.3).
 *
 * @param cosigners the stack of trusted cosigners, which may be NULL
 * @param id the cosigner ID to find
 * @param id_len the length of id
 * @returns the matching cosigner (borrowed), or NULL if none matches.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
OSSL_MTC_COSIGNER *ossl_mtc_cosigner_stack_lookup(
    const STACK_OF(OSSL_MTC_COSIGNER) *cosigners, const uint8_t *id,
    size_t id_len);

#endif /* defined(OSSL_CRYPTO_MTC_COSIGNER_H) */
