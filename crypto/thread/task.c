/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#if defined(OPENSSL_THREADS)

# include "task.h"

int task_list_cmp(struct list *l, void *data)
{
    return container_of(l, struct crypto_task_st, list)->id == *(uint32_t*)data;
}

CRYPTO_TASK *crypto_task_new(CRYPTO_THREAD_ROUTINE start, void *data)
{
    struct crypto_task_st *t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->state = CRYPTO_TASK_NO_STATE;

    t->lock = CRYPTO_MUTEX_create();
    t->cond = CRYPTO_CONDVAR_create();

    if (t->lock == NULL || t->cond == NULL)
        goto fail;

    if (CRYPTO_MUTEX_init(t->lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(t->cond) == 0)
        goto fail;

    t->data = data;
    t->routine = start;
    return t;

fail:
    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->cond);
    OPENSSL_free(t);
    return NULL;
}

void crypto_task_free(CRYPTO_TASK *t)
{
    if (t == NULL)
        return;
    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->cond);
    OPENSSL_free(t);
}

#endif /* defined(OPENSSL_THREADS) */
