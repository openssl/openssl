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

int ossl_fn_gen_deterministic_nonce_rfc6979(OSSL_FN *out, const BIGNUM *q,
    const OSSL_FN *priv,
    const unsigned char *hm, size_t hmlen,
    const char *digestname,
    OSSL_LIB_CTX *libctx,
    const char *propq);

#endif /*OSSL_INTERNAL_DETERMINISTIC_NONCE_H */
