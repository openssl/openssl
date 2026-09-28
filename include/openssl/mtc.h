/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_MTC_H)
#define OPENSSL_MTC_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*-
 * Provisional public API to configure a trusted Merkle Tree Certificate CA
 * (sections 5 and 7.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 */

DEFINE_STACK_OF(OSSL_MTC_CA)

/**
 * @brief Create a trusted Merkle Tree Certificate CA from configured fields.
 * @see OSSL_MTC_CA_new(3), OSSL_MTC_CA_free(3)
 */
OSSL_MTC_CA *OSSL_MTC_CA_new(const uint8_t *ca_id, size_t ca_id_len,
    const EVP_MD *hash, uint64_t min_serial, EVP_PKEY *cosigner_pkey);

/**
 * @brief Parse PEM certificates representing Merkle Tree Certificate CAs into
 * trusted CA objects.
 * @see OSSL_MTC_CA_parse_certificates(3)
 */
int OSSL_MTC_CA_parse_certificates(OSSL_LIB_CTX *libctx, const char *propq,
    BIO *in, STACK_OF(OSSL_MTC_CA) *out_cas);

/**
 * @brief Free a trusted Merkle Tree Certificate CA.
 * @see OSSL_MTC_CA_free(3), OSSL_MTC_CA_new(3)
 */
void OSSL_MTC_CA_free(OSSL_MTC_CA *ca);

/**
 * @brief Add a revoked serial-number range to a trusted MTC CA.
 * @see OSSL_MTC_CA_add_revoked_range(3)
 */
int OSSL_MTC_CA_add_revoked_range(OSSL_MTC_CA *ca, uint64_t start, uint64_t end);

/**
 * @brief Order two trusted MTC CAs by CA ID; the comparison function for a
 * sorted stack of them.
 * @see OSSL_MTC_CA_cmp(3)
 */
int OSSL_MTC_CA_cmp(const OSSL_MTC_CA *const *a, const OSSL_MTC_CA *const *b);

/**
 * @brief Find a trusted MTC CA in a stack by its CA ID.
 * @see OSSL_MTC_CA_find(3)
 */
OSSL_MTC_CA *OSSL_MTC_CA_find(STACK_OF(OSSL_MTC_CA) *cas, const uint8_t *ca_id,
    size_t ca_id_len, const char *ca_id_str);

/**
 * @brief Replace an issuance log's active landmark window from a published
 * landmark description.
 * @see OSSL_MTC_CA_load_landmarks(3)
 */
int OSSL_MTC_CA_load_landmarks(OSSL_MTC_CA *ca, uint64_t log_number, BIO *in,
    int64_t cutoff);

/**
 * @brief Record the vetted hash of an active subtree of a trusted MTC CA.
 * @see OSSL_MTC_CA_add_subtree_hash(3)
 */
int OSSL_MTC_CA_add_subtree_hash(OSSL_MTC_CA *ca, uint64_t log_number,
    uint64_t start, uint64_t end, const uint8_t *hash, size_t hash_len);

/**
 * @brief Set the highest serial number a trusted MTC CA will accept.
 * @see OSSL_MTC_CA_set_max_serial(3)
 */
int OSSL_MTC_CA_set_max_serial(OSSL_MTC_CA *ca, uint64_t max_serial);

/**
 * @brief Get a trusted MTC CA's identifier (a TrustAnchorID).
 * @see OSSL_MTC_CA_get0_id(3)
 */
int OSSL_MTC_CA_get0_id(const OSSL_MTC_CA *ca, const uint8_t **out_id,
    size_t *out_id_len);

/**
 * @brief Compute an MTC serial number from a log number and log index.
 * @see OSSL_MTC_serial(3)
 */
uint64_t OSSL_MTC_serial(uint16_t log_number, uint64_t index);

/*-
 * A Merkle Tree Certificate cosigner a relying party trusts in addition to the
 * CA cosigner (sections 5.3 and 7.3 of the draft).  Cosigners are trusted in
 * an X509_STORE; see X509_STORE_trust_mtc_cosigner(3).
 */

DEFINE_STACK_OF(OSSL_MTC_COSIGNER)

/**
 * @brief Create a trusted Merkle Tree Certificate cosigner from its cosigner
 * ID and public key.
 * @see OSSL_MTC_COSIGNER_new(3), OSSL_MTC_COSIGNER_free(3)
 */
OSSL_MTC_COSIGNER *OSSL_MTC_COSIGNER_new(const uint8_t *id, size_t id_len,
    EVP_PKEY *pkey);

/**
 * @brief Parse PEM certificates representing Merkle Tree Certificate cosigners
 * into cosigner objects.
 * @see OSSL_MTC_COSIGNER_parse_certificates(3)
 */
int OSSL_MTC_COSIGNER_parse_certificates(OSSL_LIB_CTX *libctx,
    const char *propq, BIO *in, STACK_OF(OSSL_MTC_COSIGNER) *out_cosigners);

/**
 * @brief Free a trusted Merkle Tree Certificate cosigner.
 * @see OSSL_MTC_COSIGNER_free(3), OSSL_MTC_COSIGNER_new(3)
 */
void OSSL_MTC_COSIGNER_free(OSSL_MTC_COSIGNER *cosigner);

/**
 * @brief Get a cosigner's identifier (a TrustAnchorID).
 * @see OSSL_MTC_COSIGNER_get0_id(3)
 */
int OSSL_MTC_COSIGNER_get0_id(const OSSL_MTC_COSIGNER *cosigner,
    const uint8_t **out_id, size_t *out_id_len);

/**
 * @brief Order two cosigners by cosigner ID; the comparison function for a
 * sorted stack of them.
 * @see OSSL_MTC_COSIGNER_cmp(3)
 */
int OSSL_MTC_COSIGNER_cmp(const OSSL_MTC_COSIGNER *const *a,
    const OSSL_MTC_COSIGNER *const *b);

#if defined(__cplusplus)
}
#endif
#endif /* defined(OPENSSL_MTC_H) */
