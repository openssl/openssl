/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_DETERMINISTIC_NONCE_H
#define OSSL_INTERNAL_DETERMINISTIC_NONCE_H
#pragma once

#include <openssl/bn.h>
#include "crypto/types.h"

int ossl_gen_deterministic_nonce_rfc6979(BIGNUM *out, const BIGNUM *q,
    const BIGNUM *priv,
    const unsigned char *message,
    size_t message_len,
    const char *digestname,
    OSSL_LIB_CTX *libctx,
    const char *propq);

/**
 * @brief Generate a deterministic DSA/ECDSA nonce per RFC 6979, in OSSL_FN
 * form.
 *
 * The OSSL_FN counterpart of ossl_gen_deterministic_nonce_rfc6979(): the
 * nonce and the private key it is derived from are never held in a BIGNUM.
 *
 * @param out receives the nonce; must hold at least num_bits(q) bits
 * @param q the public group order
 * @param priv the private key
 * @param hm the message digest
 * @param hmlen the length of hm in bytes
 * @param digestname the name of the digest for the HMAC-DRBG
 * @param libctx the library context to fetch the KDF and digest from
 * @param propq the property query for fetching, or NULL
 * @returns 1 on success, 0 on error
 */
int ossl_fn_gen_deterministic_nonce_rfc6979(OSSL_FN *out, const BIGNUM *q,
    const OSSL_FN *priv,
    const unsigned char *hm, size_t hmlen,
    const char *digestname,
    OSSL_LIB_CTX *libctx,
    const char *propq);

#endif /*OSSL_INTERNAL_DETERMINISTIC_NONCE_H */
