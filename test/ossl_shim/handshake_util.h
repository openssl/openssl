/*
* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_SHIM_HANDSHAKE_UTIL_H
#define OSSL_TEST_SHIM_HANDSHAKE_UTIL_H

#include <functional>

#include <openssl/types.h>

// RetryAsync is called after a failed operation on |ssl| with return code
// |ret|. If the operation should be retried, it simulates one asynchronous
// event and returns true. Otherwise it returns false.
bool RetryAsync(SSL *ssl, int ret);

// CheckIdempotentError runs |func|, an operation on |ssl|, ensuring that
// errors are idempotent.
int CheckIdempotentError(const char *name, SSL *ssl, std::function<int()> func);

#endif  // OSSL_TEST_SHIM_HANDSHAKE_UTIL_H
