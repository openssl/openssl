/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#if defined(OPENSSL_THREADS)
# include <internal/thread.h>

CRYPTO_THREAD * crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine,
                                           void *data, int joinable)
{
    struct crypto_thread_st *handle;

    if (routine == NULL)
        return NULL;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        return NULL;

    handle->lock = CRYPTO_MUTEX_create();
    if (handle->lock == NULL)
        goto fail;

    if (CRYPTO_MUTEX_init(handle->lock) == 0)
        goto fail;

    handle->joinable = joinable;
    handle->data = data;
    handle->routine = routine;

    if (crypto_thread_native_spawn(handle) != 1)
        goto fail;

    return handle;

 fail:
    CRYPTO_MUTEX_destroy(&handle->lock);
    OPENSSL_free(handle);
    return NULL;
}

int crypto_thread_native_clean(CRYPTO_THREAD *handle)
{
    uint64_t req_state_mask;

    if (handle == NULL)
        return 0;

    req_state_mask = 0;
    req_state_mask |= CRYPTO_THREAD_FINISHED;
    req_state_mask |= CRYPTO_THREAD_TERMINATED;
    req_state_mask |= CRYPTO_THREAD_JOINED;

    if (CRYPTO_THREAD_GET_STATE(handle, req_state_mask) == 0)
        return 0;

    CRYPTO_MUTEX_destroy(&handle->lock);
    OPENSSL_free(handle->handle);
    OPENSSL_free(handle);

    return 1;
}

#endif
