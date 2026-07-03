/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * A trusted Merkle Tree Certification Authority (MTC CA), as configured by a
 * relying party (section 7.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 * Not for application use.
 *
 * This is the identity core of the CA configuration: the CA identifier, its
 * issuance-log hash algorithm, and the CA cosigner (section 5.4).  The wider
 * relying-party configuration -- additional cosigners and cosigner policy
 * (section 7.3), trusted subtrees (section 7.4), and revoked serial ranges
 * (section 7.5) -- is layered onto this object separately.
 *
 * The CA record is built from its configured fields rather than parsed from a
 * section 5.5 CA certificate: section 7.1 makes that certificate only an
 * optional source of this information ("this information MAY be obtained from a
 * CA certificate structure"), and its OIDs are not yet assigned.  Should
 * section 5.5 be standardised, a certificate parser can be layered on top,
 * decoding the extension and calling ossl_mtc_ca_new().
 *
 * These are internal interfaces: callers pass valid, non-NULL pointers and the
 * functions are not NULL-safe, except ossl_mtc_ca_free(), which accepts NULL.
 */

#if !defined(OSSL_CRYPTO_MTC_CA_H)
#define OSSL_CRYPTO_MTC_CA_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/types.h>

/**
 * @struct ossl_mtc_cosigner_st
 * @brief A configured cosigner: a (cosigner ID, public key) pair with its
 * signature algorithm (sections 5.3 and 7.1).
 *
 * This is a cosigner the relying party is configured to recognise, distinct
 * from an OSSL_MTC_COSIGNATURE (a signature parsed from an MTCProof).  Owns its
 * storage: id and sig_name are copies and a reference is held on pkey.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
typedef struct ossl_mtc_cosigner_st {
    uint8_t *id; /**< cosigner ID: a TrustAnchorID, i.e. relative-OID bytes (5.3) */
    size_t id_len;
    char *sig_name; /**< cosigner signature algorithm name (5.3.3) */
    EVP_PKEY *pkey; /**< cosigner public key (5.3) */
} OSSL_MTC_COSIGNER;

/**
 * @struct ossl_mtc_ca_st
 * @brief The identity core of a trusted Merkle Tree CA (section 7.1), plus the
 * additional cosigners the relying party recognises.
 *
 * Owns its storage: ca_id is a copy, a reference is held on cosigner_pkey, and
 * the cosigners list is owned.  The CA cosigner (section 5.4) is the identity
 * core here (its ID is ca_id); cosigners holds the other recognised cosigners.
 *
 * A CRYPTO_RWLOCK (lock) guards concurrent access to the CA's mutable
 * configuration: callers reading the CA take a read lock and callers modifying
 * it take a write lock.  It is created with the CA and lives for its lifetime.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
typedef struct ossl_mtc_ca_st {
    uint8_t *ca_id; /**< CA ID: a TrustAnchorID, i.e. relative-OID bytes (5.1) */
    size_t ca_id_len;
    EVP_MD *hash; /**< issuance-log hash (7.1) */
    uint64_t min_serial; /**< the CA's minimum allowed serial number (5.5) */
    EVP_PKEY *cosigner_pkey; /**< CA cosigner public key (5.4) */
    CRYPTO_RWLOCK *lock; /**< guards concurrent access to the CA's mutable state */
    OSSL_MTC_COSIGNER *cosigners; /**< additional recognised cosigners (7.1) */
    size_t cosigner_count;
} OSSL_MTC_CA;

/**
 * @brief Create a trusted Merkle Tree CA record from its configured fields.
 *
 * The ca_id bytes are copied and a reference is taken on hash and on
 * cosigner_pkey, each released when the CA is freed.  The caller retains
 * ownership of its inputs.
 *
 * @param ca_id the CA identifier (TrustAnchorID relative-OID bytes)
 * @param ca_id_len the length of ca_id
 * @param hash the issuance-log hash
 * @param min_serial the CA's minimum allowed serial number (section 5.5)
 * @param cosigner_pkey the CA cosigner public key
 * @returns the new CA record, or NULL on error.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
OSSL_MTC_CA *ossl_mtc_ca_new(const uint8_t *ca_id, size_t ca_id_len,
    const EVP_MD *hash, uint64_t min_serial, EVP_PKEY *cosigner_pkey);

/**
 * @brief Free an OSSL_MTC_CA; ca may be NULL.
 * @param ca the CA to free
 */
void ossl_mtc_ca_free(OSSL_MTC_CA *ca);

/**
 * @brief Add a recognised cosigner to a CA (sections 5.3, 7.1).
 *
 * The id bytes are copied and a reference is taken on pkey; the caller retains
 * ownership of both inputs.  Cosigner IDs must be distinct (section 5.3), so
 * this fails if id duplicates an already-added cosigner or the CA's own ID (the
 * CA cosigner's ID, section 5.4).
 *
 * @param ca the CA to add to
 * @param id the cosigner ID (TrustAnchorID relative-OID bytes)
 * @param id_len the length of id
 * @param sig_name the cosigner signature algorithm name (for example "ML-DSA-44")
 * @param pkey the cosigner public key
 * @returns 1 on success, 0 on error or duplicate ID.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_add_cosigner(OSSL_MTC_CA *ca, const uint8_t *id, size_t id_len,
    const char *sig_name, EVP_PKEY *pkey);

/**
 * @brief Return the CA's identifier (a TrustAnchorID, i.e. relative-OID bytes).
 * @param ca the CA
 * @param len set to the length of the returned identifier
 * @returns a pointer to the identifier bytes, owned by ca.
 */
const uint8_t *ossl_mtc_ca_id(const OSSL_MTC_CA *ca, size_t *len);

/**
 * @brief Return the CA's issuance-log hash (section 7.1), non-owning.
 * @param ca the CA
 * @returns the issuance-log hash, owned by ca.
 */
const EVP_MD *ossl_mtc_ca_hash(const OSSL_MTC_CA *ca);

/**
 * @brief Return the CA cosigner's public key (section 5.4), non-owning.
 * @param ca the CA
 * @returns the cosigner's public key, owned by ca.
 */
EVP_PKEY *ossl_mtc_ca_cosigner_pkey(const OSSL_MTC_CA *ca);

#endif /* defined(OSSL_CRYPTO_MTC_CA_H) */
