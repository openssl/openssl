/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTO_WORKER_H
# define OPENSSL_CRYPTO_WORKER_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)

#  include <openssl/crypto.h>
#  include <internal/worker.h>
#  include <internal/thread.h>
#  include "openssl_threads.h"

typedef enum {
    CRYPTO_WORKER_INTERNAL,
    CRYPTO_WORKER_EXTERNAL
} CRYPTO_WORKER_TYPE;

typedef struct crypto_worker_st {
    CRYPTO_THREAD *handle;
    CRYPTO_TASK *task;
    CRYPTO_WORKER_TYPE type;
    OPENSSL_CTX *ctx;
    struct list list;
    CRYPTO_WORKER_CALLBACK cb;
    CRYPTO_MUTEX lock;
    CRYPTO_CONDVAR cond;
    int initialized;
} CRYPTO_WORKER;

CRYPTO_THREAD_RETVAL worker_main(void *data);
CRYPTO_WORKER_CMD worker_internal_cb(OPENSSL_CTX *ctx, size_t queued_tasks);

CRYPTO_WORKER * CRYPTO_WORKER_new(OPENSSL_CTX *ctx, CRYPTO_WORKER_CALLBACK cb,
                                void *vtask);
void CRYPTO_WORKER_free(CRYPTO_WORKER *worker);

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_CRYPTO_WORKER_H */
