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
 * issuance-log hash algorithm, and the CA cosigner (section 5.4).  Trusted
 * subtrees (section 7.4) and revoked serial ranges (section 7.5) are layered
 * onto this object separately.  The additional cosigners a relying party
 * trusts, and the cosigner policy (section 7.3), are not per CA: they are
 * held by the X509_STORE (see include/crypto/mtc_cosigner.h) and by the
 * X509_VERIFY_PARAM.
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
#include <openssl/mtc.h>
#include <openssl/safestack.h>
#include <openssl/types.h>

#include "internal/packet.h"

/**
 * @struct ossl_mtc_serial_range_st
 * @brief A half-open range [start, end) of revoked serial numbers (section 7.5).
 *
 * A serial number combines a log number and a log index
 * (serial = (log_number << 48) | index), so a range can revoke entries within a
 * log and whole logs alike.
 */
typedef struct ossl_mtc_serial_range_st {
    uint64_t start; /**< first revoked serial (inclusive) */
    uint64_t end; /**< first serial past the range (exclusive) */
} OSSL_MTC_SERIAL_RANGE;

/**
 * @struct ossl_mtc_trusted_subtree_st
 * @brief A subtree of one of the CA's issuance logs, active in that log's
 * landmark window (sections 6.4 and 7.4).
 *
 * A landmark update names the subtrees that cover each active landmark's
 * batch of leaves (section 6.4.3); each is recorded here as a (landmark,
 * subtree) pair, initially without a hash.  The hash is filled in separately,
 * once obtained from a source trusted to have vetted it (section 7.4); a
 * subtree is usable for landmark-relative verification only once it is both
 * active and has a hash.  The containing issuance log is implied by the
 * OSSL_MTC_LOG this belongs to, so it is not stored here.  Owns its hash
 * storage.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
typedef struct ossl_mtc_trusted_subtree_st {
    uint64_t landmark; /**< active landmark this subtree covers (6.4.1) */
    uint64_t start; /**< first leaf index covered, inclusive */
    uint64_t end; /**< one past the last leaf index, exclusive */
    uint8_t *hash; /**< the subtree hash (hash_len bytes), or NULL until vetted */
    size_t hash_len;
} OSSL_MTC_TRUSTED_SUBTREE;
DEFINE_STACK_OF(OSSL_MTC_TRUSTED_SUBTREE)

/**
 * The largest CA ID whose advertised trust anchor IDs always fit their u8
 * length prefix: a landmark group ID appends three relative-OID components of
 * at most ten bytes each to the CA ID (section 8.2.1).
 */
#define OSSL_MTC_CA_ID_MAX (255 - 3 * 10)

/**
 * @struct ossl_mtc_log_st
 * @brief One of a CA's issuance logs (section 5.2) and its active landmark
 * window.
 *
 * subtrees holds the subtrees covering the log's currently active landmarks,
 * kept sorted by (start, end); last_landmark is the newest landmark the log
 * has published.  A landmark update (section 6.4.3) replaces the window
 * wholesale.  Owns its subtrees.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
typedef struct ossl_mtc_log_st {
    uint64_t log_number; /**< the issuance log number (5.2) */
    uint64_t last_landmark; /**< newest published landmark for this log (6.4) */
    STACK_OF(OSSL_MTC_TRUSTED_SUBTREE) *subtrees; /**< active window, sorted */
} OSSL_MTC_LOG;
DEFINE_STACK_OF(OSSL_MTC_LOG)

/**
 * @struct ossl_mtc_ca_st
 * @brief The identity core of a trusted Merkle Tree CA (section 7.1).
 *
 * Owns its storage: ca_id is a copy and a reference is held on cosigner_pkey.
 * The CA cosigner (section 5.4) is the identity core here (its ID is ca_id).
 *
 * A CRYPTO_RWLOCK (lock) guards concurrent access to the CA's mutable
 * configuration: callers reading the CA take a read lock and callers modifying
 * it take a write lock.  It is created with the CA and lives for its lifetime.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
struct ossl_mtc_ca_st {
    uint8_t *ca_id; /**< CA ID: a TrustAnchorID, i.e. relative-OID bytes (5.1) */
    size_t ca_id_len;
    EVP_MD *hash; /**< issuance-log hash (7.1) */
    uint64_t min_serial; /**< the CA's minimum allowed serial number (5.5) */
    uint64_t max_serial; /**< highest accepted serial; implies revoked (max, 2^64) (7.5) */
    EVP_PKEY *cosigner_pkey; /**< CA cosigner public key (5.4) */
    CRYPTO_RWLOCK *lock; /**< guards concurrent access to the CA's mutable state */
    OSSL_MTC_SERIAL_RANGE *revoked; /**< revoked serial ranges (7.5) */
    size_t revoked_count;
    STACK_OF(OSSL_MTC_LOG) *logs; /**< issuance logs, sorted by log number (5.2) */
    uint8_t *advertised_ids; /**< the trust anchor IDs this CA contributes to a
                                  trust_anchors request (8.2.1), precomputed as a
                                  run of u8-length-prefixed IDs.  Sized for one
                                  ID per log: grown only when a log is added,
                                  repacked in place on update */
    size_t advertised_ids_len; /**< bytes used of advertised_ids */
};
/* STACK_OF(OSSL_MTC_CA) is declared publicly in <openssl/mtc.h>. */

/**
 * @brief Create a trusted Merkle Tree CA record from its configured fields.
 *
 * The ca_id bytes are copied and a reference is taken on hash and on
 * cosigner_pkey, each released when the CA is freed.  The caller retains
 * ownership of its inputs.  ca_id must be non-empty and at most
 * OSSL_MTC_CA_ID_MAX bytes, so that the CA's advertised trust anchor IDs
 * always fit their u8 length prefix (see ossl_mtc_ca_put_advertised_ids()).
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
 * @brief Add a revoked range of serial numbers to a CA (section 7.5).
 *
 * The range is half-open, [start, end); it must be non-empty.  The range
 * [0, min_serial) is already implied by the CA and need not be added.
 *
 * Ranges may overlap each other and the implied [0, min_serial) range; they are
 * neither merged nor required to be disjoint, as revocation is a membership test
 * (a serial is revoked if it falls in any range).  The draft places no
 * ordering requirement on revoked ranges nor requires them to be disjoint;
 * revisit this should a later draft impose one.
 *
 * @param ca the CA to add to
 * @param start the first revoked serial (inclusive)
 * @param end the first serial past the range (exclusive)
 * @returns 1 on success, 0 on error or if start >= end.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_add_revoked_range(OSSL_MTC_CA *ca, uint64_t start,
    uint64_t end);

/**
 * @brief Report whether a serial number is revoked for a CA (section 7.5).
 *
 * A serial is revoked if it is below the CA's min_serial or above its
 * max_serial (the implied [0, min_serial) and (max_serial, 2^64) ranges) or
 * falls in any added revoked range.
 *
 * @param ca the CA
 * @param serial the serial number to test
 * @returns 1 if revoked, 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_serial_is_revoked(const OSSL_MTC_CA *ca, uint64_t serial);

/**
 * @brief Set the highest serial number a CA will accept (section 7.5).
 *
 * Implies the revoked range (max_serial, 2^64).  The default is 2^64-1, i.e. no
 * upper revoked range.
 *
 * @param ca the CA
 * @param max_serial the highest accepted serial number
 * @returns 1 on success, 0 on error.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_set_max_serial(OSSL_MTC_CA *ca, uint64_t max_serial);

/**
 * @brief Replace an issuance log's active landmark window from a published
 * landmark description (sections 6.4.3 and 7.4).
 *
 * Reads the log's landmark description in the section 6.4.3 format from in
 * and replaces the log's window with the subtrees covering those landmarks'
 * leaves, leaving out landmarks that expired before cutoff; INT64_MIN leaves
 * out none.  A subtree still present keeps any hash already added to it; one
 * no longer active is dropped; a newly active subtree is recorded without a
 * hash.  The log is created if it does not yet exist.  The CA is left
 * unchanged on any failure.
 *
 * @param ca the CA
 * @param log_number the issuance log to update
 * @param in the landmark description to read
 * @param cutoff the POSIX time before which expired landmarks are not loaded
 * @returns 1 on success, 0 on parse error, inconsistent input, or allocation
 *          failure.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_load_landmarks(OSSL_MTC_CA *ca, uint64_t log_number, BIO *in,
    int64_t cutoff);

/**
 * @brief Record the vetted hash of an active subtree (section 7.4).
 *
 * The subtree with bounds (start, end) must already be in log_number's active
 * window, hash_len must equal the log hash's output length, and the hash bytes
 * are copied.  A subtree's hash is immutable once set: supplying the value it
 * already holds succeeds and changes nothing, a different value fails.
 * Consistency of the hash is assumed to have been established externally: adding
 * it is the act of trusting it (section 7.4).
 *
 * @param ca the CA
 * @param log_number, start, end the active subtree's coordinates
 * @param hash, hash_len the subtree hash (copied in) and its length in bytes
 * @returns 1 on success, 0 if the subtree is not active, hash_len is wrong, a
 *          different hash is already recorded, or on allocation failure.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_add_subtree_hash(OSSL_MTC_CA *ca, uint64_t log_number,
    uint64_t start, uint64_t end, const uint8_t *hash, size_t hash_len);

/**
 * @brief Test whether a subtree is trusted and its hash matches (section 7.4).
 *
 * Looks up the subtree by (log_number, start, end) in the log's active window.
 * A trusted subtree is one that is active and has a hash; if the subtree is
 * trusted, sets *found to 1 and returns whether its hash equals hash.  A
 * subtree that is active but has no hash is not trusted: *found is 0, and the
 * caller falls back to the cosignatures (section 7.2 step 12).  This performs
 * the section 7.2 step 11 check under the read lock without exposing internal
 * storage.
 *
 * @param ca the CA
 * @param log_number, start, end the subtree coordinates to look up
 * @param hash, hash_len the expected subtree hash and its length in bytes
 * @param found set to 1 if a subtree with those coordinates is active and has
 *        a hash, 0 otherwise
 * @returns 1 if such a subtree exists and its hash matches, 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_trusted_subtree_matches(const OSSL_MTC_CA *ca,
    uint64_t log_number, uint64_t start, uint64_t end, const uint8_t *hash,
    size_t hash_len, int *found);

/**
 * @brief Append the trust anchor IDs a relying party advertises for a CA to a
 * packet (section 8.2.1 of the Merkle Tree Certificates draft).
 *
 * The IDs are precomputed: whenever an update changes the CA's landmark
 * state, its advertisement is repacked under the write lock, so a handshake
 * only copies the stored bytes here under the read lock.  The run holds one
 * u8-length-prefixed landmark group ID per issuance log with at least one
 * vetted landmark subtree: the CA ID with the components 2, the log number,
 * and the newest vetted landmark appended.  A group signals support for
 * standalone certificates too (it contains the CA ID itself), so only a CA
 * with no such log falls back to its bare CA ID.  Subtrees added directly
 * (outside the landmark window) carry no landmark number and never
 * contribute a group.
 *
 * @param ca the CA
 * @param pkt the packet the run of u8-length-prefixed IDs is appended to
 * @returns 1 on success, 0 on error.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_ca_put_advertised_ids(const OSSL_MTC_CA *ca, WPACKET *pkt);

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

/**
 * @brief Report whether a certificate represents a Merkle Tree CA (section
 * 5.5): whether it carries the id-pe-mtcCertificationAuthority-SHA256
 * extension.
 *
 * A certificate representing a trusted cosigner has the same trust anchor
 * ID subject and no such extension.
 *
 * @param cert the certificate
 * @returns 1 if the extension is present, 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_cert_is_ca(const X509 *cert);

/**
 * @brief Read PEM certificates from a BIO and hand each to a callback.
 *
 * Reads PEM blocks until the input ends.  Each CERTIFICATE block is decoded
 * with libctx and propq and passed to cb, which owns nothing of it; any other
 * block, an undecodable certificate, or a callback failure stops the read.
 * The caller is responsible for undoing whatever cb did before a failure.
 *
 * @param libctx the library context the certificates are decoded in
 * @param propq the property query used with libctx
 * @param in the PEM input
 * @param cb called with each decoded certificate and arg
 * @param arg passed through to cb
 * @returns 1 when the input is exhausted, 0 on any failure.
 */
int ossl_mtc_parse_pem_certificates(OSSL_LIB_CTX *libctx, const char *propq,
    BIO *in, int (*cb)(OSSL_LIB_CTX *libctx, const char *propq, X509 *cert, void *arg),
    void *arg);

/**
 * @brief Order two trust anchor IDs: shorter first, then lexicographic.
 *
 * This is the order of a sorted stack of trusted CAs and of a sorted stack of
 * trusted cosigners, and the order of cosigner_id values in an MTCProof
 * (section 6.2).
 *
 * @param a the first ID
 * @param alen the length of a
 * @param b the second ID
 * @param blen the length of b
 * @returns a negative value, zero, or a positive value as a sorts before, with,
 *          or after b.
 */
int ossl_mtc_id_order(const uint8_t *a, size_t alen, const uint8_t *b,
    size_t blen);

/*-
 * A set of trusted MTC CAs is a STACK_OF(OSSL_MTC_CA) kept sorted by CA ID for
 * binary-search lookup.  The stack holds *borrowed* references: it does not own
 * the CAs (the application owns them and must keep them alive).  Create it with
 * sk_OSSL_MTC_CA_new(OSSL_MTC_CA_cmp) and free it with sk_OSSL_MTC_CA_free(),
 * which frees the container, not the CAs.
 */

/**
 * @brief Add a trusted CA to a stack, keeping it sorted by CA ID.
 *
 * The CA is stored by reference (not owned, not copied).  Fails if a CA with
 * the same CA ID is already present.
 *
 * @param cas the stack of trusted CAs
 * @param ca the CA to add (borrowed; caller retains ownership)
 * @returns 1 on success, 0 on error or duplicate CA ID.
 */
int ossl_mtc_ca_stack_add(STACK_OF(OSSL_MTC_CA) *cas, OSSL_MTC_CA *ca);

/**
 * @brief Look up a trusted CA by its CA ID (section 5.1).
 *
 * @param cas the stack of trusted CAs
 * @param ca_id the CA identifier to find
 * @param ca_id_len the length of ca_id
 * @returns the matching CA (borrowed), or NULL if none matches.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
OSSL_MTC_CA *ossl_mtc_ca_stack_lookup(const STACK_OF(OSSL_MTC_CA) *cas,
    const uint8_t *ca_id, size_t ca_id_len);

#endif /* defined(OSSL_CRYPTO_MTC_CA_H) */
