/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_INTERNAL_THREAD_COMMON_H
# define OPENSSL_INTERNAL_THREAD_COMMON_H

# include <openssl/crypto.h>

typedef enum {
   CRYPTO_THREAD_DEF_CTX_KEY_ID = 0,
   CRYPTO_THREAD_KEY_ID_MAX
} CRYPTO_THREAD_KEY_ENTRY_ID;

typedef struct crypto_local_key_entry {
    CRYPTO_THREAD_LOCAL key;
    void (*cleanup)(void *);
} CRYPTO_LOCAL_KEY_ENTRY;

CRYPTO_THREAD_LOCAL*
CRYPTO_THREAD_get_key_entry(CRYPTO_THREAD_KEY_ENTRY_ID id);

#endif /* OPENSSL_INTERNAL_THREAD_COMMON_H */
