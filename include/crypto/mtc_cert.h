/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Internal parsing of the Merkle Tree Certificate (MTC) MTCProof from section 6
 * of https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 * Not for application use.
 *
 * An MTC certificate is an ordinary X.509 certificate whose signatureAlgorithm
 * is id-alg-mtcProof and whose signatureValue carries a TLS-presentation-
 * language MTCProof (section 6.2).  The X.509 shell is parsed by the existing
 * OpenSSL machinery; this module decodes the MTCProof blob.
 *
 * Only the wire formats from
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 * are handled.
 *
 * These are internal interfaces: callers pass valid, non-NULL pointers and the
 * functions are not NULL-safe.  The byte spans in OSSL_MTC_PROOF and
 * OSSL_MTC_COSIGNATURE reference the caller-provided input buffer, which MUST
 * outlive them; parsing performs no copying.
 */

#if !defined(OSSL_CRYPTO_MTC_CERT_H)
#define OSSL_CRYPTO_MTC_CERT_H

#include <stddef.h>
#include <stdint.h>

/**
 * @struct ossl_mtc_cosignature_st
 * @brief One cosigner's signature within an MTCProof (section 6.2).
 *
 * Both spans reference the input buffer.
 */
typedef struct ossl_mtc_cosignature_st {
    const uint8_t *cosigner_id; /**< TrustAnchorID, a relative OID */
    size_t cosigner_id_len;
    const uint8_t *signature; /**< raw cosignature bytes */
    size_t signature_len;
} OSSL_MTC_COSIGNATURE;

/**
 * @struct ossl_mtc_proof_st
 * @brief A decoded MTCProof (section 6.2), carried in the signatureValue of an
 * MTC certificate.
 *
 * start and end define the subtree the inclusion proof is relative to; both are
 * carried as uint48 on the wire.  All byte spans reference the input buffer.
 */
typedef struct ossl_mtc_proof_st {
    const uint8_t *extensions; /**< opaque extensions<0..2^16-1> */
    size_t extensions_len;
    uint64_t start; /**< subtree start (uint48 on wire) */
    uint64_t end; /**< subtree end (uint48 on wire) */
    const uint8_t *inclusion_proof; /**< opaque inclusion_proof<> */
    size_t inclusion_proof_len;
    const uint8_t *signatures; /**< raw SubtreeSignature<> list body */
    size_t signatures_len;
} OSSL_MTC_PROOF;

/**
 * @brief Decode an MTCProof from the bytes of a certificate's signatureValue.
 *
 * Checks the outer framing, that no trailing bytes remain, that the subtree is
 * a non-empty range, and that the cosignature list is well-formed with unique,
 * correctly ordered cosigner_ids, which section 6.2 requires of a parser.  The
 * cosignatures themselves are read with ossl_mtc_proof_get_cosignatures().
 *
 * The length of inclusion_proof is not checked against the hash size, which is
 * a parameter of the issuing CA and is applied when the proof is evaluated.
 *
 * @param in pointer to the MTCProof bytes (the signatureValue contents)
 * @param in_len number of bytes at in
 * @param proof structure populated with spans into in on success, untouched on
 * failure
 * @returns 1 on success, 0 on malformed input.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_proof_parse(const uint8_t *in, size_t in_len,
    OSSL_MTC_PROOF *proof);

/**
 * @brief Extract the cosignatures from a parsed MTCProof.
 *
 * Validates that each entry is well-formed and that the list is strictly
 * ascending by cosigner_id with no duplicates (section 6.2), as
 * ossl_mtc_proof_parse() has already done.
 *
 * Callers use two passes: out NULL yields the count, and a second call with an
 * array of that size fills it.  A call with fewer than count entries fails, and
 * a failing call writes nothing, so the count is unavailable from it.
 *
 * @param proof the parsed proof
 * @param out array receiving the cosignatures, or NULL to count only
 * @param max number of entries out can hold (ignored when out is NULL)
 * @param count set to the number of cosignatures present, untouched on failure
 * @returns 1 on success, 0 on malformed input or if the count exceeds max.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_proof_get_cosignatures(const OSSL_MTC_PROOF *proof,
    OSSL_MTC_COSIGNATURE *out, size_t max,
    size_t *count);

#endif /* defined(OSSL_CRYPTO_MTC_CERT_H) */
