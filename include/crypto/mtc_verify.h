/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Internal verification of a Merkle Tree Certificate proof, per section 7.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 */

#if !defined(OSSL_CRYPTO_MTC_VERIFY_H)
#define OSSL_CRYPTO_MTC_VERIFY_H

#include <openssl/types.h>
#include <crypto/mtc_ca.h>
#include <crypto/mtc_cosigner.h>

/**
 * @brief Extract a Merkle Tree CA ID from a distinguished name (section 5.1).
 *
 * The name must be a single RDN with a single trustAnchorID attribute whose
 * value is a RELATIVE-OID holding a valid trust anchor ID; its content octets
 * are the CA ID.  This is the issuer of a Merkle Tree Certificate and the
 * subject of a certificate representing its CA.
 *
 * @param name the distinguished name
 * @param out set to the newly allocated CA ID octets (caller frees)
 * @param out_len set to the length of the CA ID
 * @returns 1 on success, 0 if name is not a trustAnchorID name or on error.
 */
int ossl_mtc_ca_id_from_name(const X509_NAME *name, uint8_t **out,
    size_t *out_len);

/**
 * @brief Resolve the Merkle Tree Certificate CA that issued a certificate.
 *
 * Reads the trust anchor ID from cert's issuer (section 5.1) and looks it up
 * among the trusted MTC CAs in cas.  The returned CA is borrowed from cas; a
 * caller synchronising access to cas need hold its lock only for this call, as
 * the resolved CA is stable and self-locking thereafter.
 *
 * @param cas the trusted MTC CAs to search
 * @param cert the certificate whose issuing CA is sought
 * @param error set to an X509_V_ERR_* value when no CA is returned
 * @returns the issuing CA, or NULL if the issuer names none or none is trusted.
 */
OSSL_MTC_CA *ossl_mtc_ca_for_cert(const STACK_OF(OSSL_MTC_CA) *cas,
    const X509 *cert, int *error);

/**
 * @brief Look up a trusted cosigner by ID for ossl_mtc_verify().
 *
 * Called once per cosignature whose cosigner is not the CA cosigner.  The
 * returned cosigner is borrowed and must stay valid until ossl_mtc_verify()
 * returns.
 *
 * @param id the cosigner ID (TrustAnchorID relative-OID bytes)
 * @param id_len the length of id
 * @param arg the caller's argument to ossl_mtc_verify()
 * @returns the trusted cosigner with that ID, or NULL if there is none.
 */
typedef OSSL_MTC_COSIGNER *(*ossl_mtc_cosigner_lookup_fn)(const uint8_t *id,
    size_t id_len, void *arg);

/**
 * @brief Verify a Merkle Tree Certificate proof (section 7.2).
 *
 * Verifies a proof against its already-resolved issuing CA (see
 * ossl_mtc_ca_for_cert()): decodes the MTCProof, derives the serial from the
 * TBS, checks revocation, reconstructs and hashes the log entry from the TBS,
 * evaluates the inclusion proof, and confirms a trusted subtree or sufficient
 * cosignatures.  Sufficient cosignatures (section 7.3) are a valid one from
 * the CA cosigner plus valid ones from at least quorum of the trusted
 * cosigners, which lookup resolves by ID.  It works purely from the supplied
 * encodings, taking no
 * certificate object, and does not perform the generic X.509 leaf checks
 * (validity, identity, purpose).  The caller supplies whole-octet proof bytes
 * (the signatureValue) and confirms the certificate is a Merkle Tree
 * Certificate (see ossl_mtc_is_mtc()) beforehand.
 *
 * @param ca the issuing CA to verify against
 * @param lookup resolves a cosigner ID to a trusted cosigner, or NULL when
 *        no cosigner other than the CA cosigner is trusted
 * @param lookup_arg passed through to lookup
 * @param quorum the number of trusted cosigners whose signatures a standalone
 *        certificate must carry
 * @param tbs the DER-encoded TBSCertificate
 * @param tbs_len the length of tbs
 * @param proof the MTCProof bytes (the certificate's signatureValue)
 * @param proof_len the length of proof
 * @param error set to an X509_V_ERR_* value describing the outcome
 * @returns 1 if the proof is valid, 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/
 */
int ossl_mtc_verify(OSSL_MTC_CA *ca, ossl_mtc_cosigner_lookup_fn lookup,
    void *lookup_arg, size_t quorum, const uint8_t *tbs, size_t tbs_len,
    const uint8_t *proof, size_t proof_len, int *error);

/**
 * @brief Report whether a certificate is a Merkle Tree Certificate.
 *
 * A certificate is a Merkle Tree Certificate when its signatureAlgorithm is
 * id-alg-mtcProof.  A caller confirms this before verifying the proof with
 * ossl_mtc_verify().
 *
 * @param cert the certificate to inspect, which may be NULL
 * @returns 1 if cert is a Merkle Tree Certificate, 0 otherwise.
 */
int ossl_mtc_is_mtc(const X509 *cert);

#endif /* defined(OSSL_CRYPTO_MTC_VERIFY_H) */
