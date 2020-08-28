/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTO_TASK_H
# define OPENSSL_CRYPTO_TASK_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)

#  include <openssl/crypto.h>
#  include <internal/thread.h>
#  include "openssl_threads.h"

enum crypto_task_state {
    CRYPTO_TASK_NO_STATE = 0,
    CRYPTO_TASK_CREATED  = 1 << 0,
    CRYPTO_TASK_STARTED  = 1 << 1,
    CRYPTO_TASK_FINISHED = 1 << 2
};

typedef struct crypto_task_st {
    uint32_t id;
    void *data;
    struct list list;

    enum crypto_task_state state;

    CRYPTO_THREAD_RETVAL retval;
    CRYPTO_THREAD_ROUTINE routine;

    CRYPTO_MUTEX lock;
    CRYPTO_CONDVAR cond;
} CRYPTO_TASK;

int task_list_cmp(struct list *l, void *data);
CRYPTO_TASK * crypto_task_new(CRYPTO_THREAD_ROUTINE start, void *data);
void crypto_task_free(CRYPTO_TASK *t);

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_CRYPTO_TASK_H */
