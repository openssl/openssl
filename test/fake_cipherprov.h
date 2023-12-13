/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>

/* Fake Cipher provider implementation */
OSSL_PROVIDER *fake_cipher_start(OSSL_LIB_CTX *libctx);
void fake_cipher_finish(OSSL_PROVIDER *p);
