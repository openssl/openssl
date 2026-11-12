/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_PROOF_H)
#define OPENSSL_PROOF_H

#include <openssl/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*-
 * Verify a proof against configured trust. The only proof form
 * supported at present is a Merkle Tree Certificate, per section 7.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 */

/**
 * @brief Create a proof from a Merkle Tree Certificate.  The proof
 *        takes a reference on cert and only reads it thereafter.
 * @see OSSL_PROOF_new_mtc(3), OSSL_PROOF_free(3)
 */
OSSL_PROOF *OSSL_PROOF_new_mtc(const X509 *cert);

/**
 * @brief Free a proof.
 * @see OSSL_PROOF_free(3), OSSL_PROOF_new_mtc(3)
 */
void OSSL_PROOF_free(OSSL_PROOF *proof);

/**
 * @brief Create a proof trust configuration whose verifications run in the
 *        given library context with the given property query.
 * @see OSSL_PROOF_TRUST_new(3), OSSL_PROOF_TRUST_free(3)
 */
OSSL_PROOF_TRUST *OSSL_PROOF_TRUST_new(OSSL_LIB_CTX *libctx, const char *propq);

/**
 * @brief Free a proof trust configuration.
 * @see OSSL_PROOF_TRUST_free(3), OSSL_PROOF_TRUST_new(3)
 */
void OSSL_PROOF_TRUST_free(OSSL_PROOF_TRUST *trust);

/**
 * @brief Set the X.509 trust store used when verifying X.509-based proofs.
 * @see OSSL_PROOF_TRUST_set1_x509_store(3), OSSL_PROOF_verify(3)
 */
int OSSL_PROOF_TRUST_set1_x509_store(OSSL_PROOF_TRUST *trust, X509_STORE *store);

/**
 * @brief Get the X.509 trust store used when verifying X.509-based proofs.
 * @see OSSL_PROOF_TRUST_get0_x509_store(3), OSSL_PROOF_TRUST_set1_x509_store(3)
 */
X509_STORE *OSSL_PROOF_TRUST_get0_x509_store(const OSSL_PROOF_TRUST *trust);

/**
 * @brief Create per-verification parameters.
 * @see OSSL_PROOF_PARAMS_new(3), OSSL_PROOF_PARAMS_free(3)
 */
OSSL_PROOF_PARAMS *OSSL_PROOF_PARAMS_new(void);

/**
 * @brief Free per-verification parameters.
 * @see OSSL_PROOF_PARAMS_free(3), OSSL_PROOF_PARAMS_new(3)
 */
void OSSL_PROOF_PARAMS_free(OSSL_PROOF_PARAMS *params);

/**
 * @brief Get the X.509 verification parameters applied to X.509-based
 *        proofs.
 * @see OSSL_PROOF_PARAMS_get0_x509_param(3), X509_VERIFY_PARAM_set1_host(3)
 */
X509_VERIFY_PARAM *OSSL_PROOF_PARAMS_get0_x509_param(const OSSL_PROOF_PARAMS *params);

/**
 * @brief Set the X.509 verification parameters applied to X.509-based
 *        proofs.
 * @see OSSL_PROOF_PARAMS_set1_x509_param(3), OSSL_PROOF_PARAMS_get0_x509_param(3)
 */
int OSSL_PROOF_PARAMS_set1_x509_param(OSSL_PROOF_PARAMS *params,
    const X509_VERIFY_PARAM *param);

/**
 * @brief Set how many trusted cosigners, besides the CA cosigner, must have
 *        cosigned a standalone Merkle Tree Certificate's subtree.
 * @see OSSL_PROOF_PARAMS_set_mtc_cosigner_quorum(3), X509_STORE_trust_mtc_cosigner(3)
 */
int OSSL_PROOF_PARAMS_set_mtc_cosigner_quorum(OSSL_PROOF_PARAMS *params,
    size_t quorum);

/**
 * @brief Get the cosigner quorum a standalone Merkle Tree Certificate must
 *        meet.
 * @see OSSL_PROOF_PARAMS_get_mtc_cosigner_quorum(3), OSSL_PROOF_PARAMS_set_mtc_cosigner_quorum(3)
 */
size_t OSSL_PROOF_PARAMS_get_mtc_cosigner_quorum(const OSSL_PROOF_PARAMS *params);

/**
 * @brief Verify a proof against the trust configuration and parameters; the
 *        outcome is returned through out_output unless it is NULL.
 * @see OSSL_PROOF_verify(3), OSSL_PROOF_new_mtc(3), OSSL_PROOF_OUTPUT_free(3)
 */
int OSSL_PROOF_verify(OSSL_PROOF_TRUST *trust, OSSL_PROOF *proof,
    const OSSL_PROOF_PARAMS *params, OSSL_PROOF_OUTPUT **out_output);

/**
 * @brief Free a verification output; output may be NULL.
 * @see OSSL_PROOF_OUTPUT_free(3), OSSL_PROOF_verify(3)
 */
void OSSL_PROOF_OUTPUT_free(OSSL_PROOF_OUTPUT *output);

/**
 * @brief Get the X.509 error code of a verification output; fails if the
 *        output is not from an X.509-based proof.
 * @see OSSL_PROOF_OUTPUT_get_x509_error(3), OSSL_PROOF_verify(3)
 */
int OSSL_PROOF_OUTPUT_get_x509_error(const OSSL_PROOF_OUTPUT *output,
    int *out_code);

/**
 * @brief Get the depth of the certificate at fault from a verification
 *        output; fails if the output is not from an X.509-based proof.
 * @see OSSL_PROOF_OUTPUT_get_x509_error_depth(3), OSSL_PROOF_OUTPUT_get_x509_error(3)
 */
int OSSL_PROOF_OUTPUT_get_x509_error_depth(const OSSL_PROOF_OUTPUT *output,
    int *out_depth);

/**
 * @brief Get the certificate at fault from a verification output.
 * @see OSSL_PROOF_OUTPUT_get0_x509_error_cert(3), OSSL_PROOF_OUTPUT_get_x509_error(3)
 */
X509 *OSSL_PROOF_OUTPUT_get0_x509_error_cert(const OSSL_PROOF_OUTPUT *output);

/**
 * @brief Get the verified chain from a successful verification output.
 * @see OSSL_PROOF_OUTPUT_get0_x509_chain(3), OSSL_PROOF_verify(3)
 */
STACK_OF(X509) *OSSL_PROOF_OUTPUT_get0_x509_chain(const OSSL_PROOF_OUTPUT *output);

/**
 * @brief Get the peer name the host check matched from a successful
 *        verification output.
 * @see OSSL_PROOF_OUTPUT_get0_x509_peername(3), X509_VERIFY_PARAM_set1_host(3)
 */
const char *OSSL_PROOF_OUTPUT_get0_x509_peername(const OSSL_PROOF_OUTPUT *output);

/**
 * @brief Get the policy tree from a successful verification output.
 * @see OSSL_PROOF_OUTPUT_get0_x509_policy_tree(3), X509_STORE_CTX_get0_policy_tree(3)
 */
X509_POLICY_TREE *OSSL_PROOF_OUTPUT_get0_x509_policy_tree(const OSSL_PROOF_OUTPUT *output);

#if defined(__cplusplus)
}
#endif

#endif /* defined(OPENSSL_PROOF_H) */
