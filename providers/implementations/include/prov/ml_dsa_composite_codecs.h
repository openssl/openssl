/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PROV_ML_DSA_COMPOSITE_CODECS_H
#define PROV_ML_DSA_COMPOSITE_CODECS_H
#pragma once

#ifndef OPENSSL_NO_ML_DSA_COMPOSITE
#include <openssl/bio.h>
#include <openssl/e_os2.h>
#include "prov/ml_dsa_composite.h"
#include "prov/provider_ctx.h"

/*
 * Encode the ml dsa composite public key (mldsaPK || tradPK) into *out.
 * Returns the total byte length on success, 0 on error.
 * If out is NULL, only the length is returned (no allocation).
 */
__owur int ossl_ml_dsa_composite_i2d_pubkey(const ML_DSA_COMPOSITE_KEY *key,
    unsigned char **out);

/*
 * Encode the ml dsa composite private key (mldsaSeed[32] || tradSK) into *out.
 * Returns the total byte length on success, 0 on error.
 * If out is NULL, only the length is returned (no allocation).
 */
__owur int ossl_ml_dsa_composite_i2d_prvkey(const ML_DSA_COMPOSITE_KEY *key,
    unsigned char **out);

/*
 * Print a human-readable description of the ml dsa composite key to |out|.
 * |selection| is an OSSL_KEYMGMT_SELECT_* mask.
 */
__owur int ossl_ml_dsa_composite_key_to_text(BIO *out, const ML_DSA_COMPOSITE_KEY *key,
    int selection);

/*
 * Decode a ml dsa composite public key from its wire format (mldsaPK || tradPK).
 * |pk|/|pk_len|: raw concatenated public key bytes (BIT STRING content
 *   from SubjectPublicKeyInfo).
 * |ml_dsa_evp_type|: EVP_PKEY_ML_DSA_44/65/87 selecting the ML-DSA variant.
 * |classic_alg|: "RSA", "EC", "ED25519", or "ED448".
 * |classic_bits|: expected classic key size in bits, checked for RSA only.
 * |ec_curve|: curve name for EC (e.g. "P-256"), NULL for non-EC.
 * |provctx|: provider context for library context and propq.
 * |propq|: property query string (may be NULL).
 * Returns a newly allocated ML_DSA_COMPOSITE_KEY on success, NULL on failure.
 */
__owur ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_pubkey(const unsigned char *pk,
    int pk_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq);

/*
 * Decode a ml dsa composite private key from its wire format (mldsaSeed[32] || tradSK).
 * |priv|/|priv_len|: raw concatenated private key bytes.
 * Other params: same as ossl_ml_dsa_composite_d2i_pubkey.
 * Returns a newly allocated ML_DSA_COMPOSITE_KEY on success, NULL on failure.
 */
__owur ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_prvkey(const unsigned char *priv,
    int priv_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq);

#endif /* OPENSSL_NO_ML_DSA_COMPOSITE */
#endif /* PROV_ML_DSA_COMPOSITE_CODECS_H */
