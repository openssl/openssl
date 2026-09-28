/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_PROOF_H)
#define OSSL_CRYPTO_PROOF_H

#include <openssl/x509_vfy.h>

/**
 * @brief The revocation stage of a proof verification for one certificate,
 *        whose issuer signs CRLs with key: the CRL check selected by
 *        X509_V_FLAG_CRL_CHECK, against a complete CRL under x's issuer name
 *        held by the store.
 * @param ctx the verification context (its store and parameters)
 * @param x the certificate to check
 * @param key the public key x's issuer signs CRLs with
 * @returns 1 if x is not revoked (or the check is not enabled), 0 otherwise
 *          with the reason in ctx->error.
 */
int ossl_proof_check_revocation(X509_STORE_CTX *ctx, X509 *x, EVP_PKEY *key);

#endif /* defined(OSSL_CRYPTO_PROOF_H) */
