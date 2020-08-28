/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_INTERNAL_WORKER_H
# define OPENSSL_INTERNAL_WORKER_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)

#  include <openssl/types.h>
#  include <openssl/crypto.h>
#  include <internal/list.h>
#  include <internal/cryptlib.h>
#  include <internal/thread.h>

size_t crypto_thread_get_available_threads(OPENSSL_CTX *ctx);
void *crypto_thread_start(OPENSSL_CTX *ctx,  CRYPTO_THREAD_ROUTINE start,
                          void *data, int options);
int crypto_thread_join(OPENSSL_CTX *ctx, void* task,
                       CRYPTO_THREAD_RETVAL *retval);
int crypto_thread_clean(OPENSSL_CTX *ctx, void *task);

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_INTERNAL_WORKER_H */
