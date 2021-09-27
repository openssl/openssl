/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#include <internal/thread_arch.h>

#if defined(OPENSSL_THREADS)

CRYPTO_THREAD *ossl_crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine,
                                               void *data, int joinable)
{
    CRYPTO_THREAD *handle;

    if (routine == NULL)
        return NULL;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        return NULL;

    if ((handle->lock = ossl_crypto_mutex_new()) == NULL)
        goto fail;
    if ((handle->statelock = ossl_crypto_mutex_new()) == NULL)
        goto fail;
    if ((handle->condvar = ossl_crypto_condvar_new()) == NULL)
        goto fail;

    handle->data = data;
    handle->routine = routine;
    handle->joinable = joinable;

    if (ossl_crypto_thread_native_spawn(handle) == 1)
        return handle;

fail:
    ossl_crypto_condvar_free(&handle->condvar);
    ossl_crypto_mutex_free(&handle->statelock);
    ossl_crypto_mutex_free(&handle->lock);
    OPENSSL_free(handle);
    return NULL;
}

int ossl_crypto_thread_native_clean(CRYPTO_THREAD *handle)
{
    uint64_t req_state_mask;

    if (handle == NULL)
        return 0;

    req_state_mask = 0;
    req_state_mask |= CRYPTO_THREAD_FINISHED;
    req_state_mask |= CRYPTO_THREAD_TERMINATED;
    req_state_mask |= CRYPTO_THREAD_JOINED;

    ossl_crypto_mutex_lock(handle->statelock);
    if (CRYPTO_THREAD_GET_STATE(handle, req_state_mask) == 0) {
        ossl_crypto_mutex_unlock(handle->statelock);
        return 0;
    }
    ossl_crypto_mutex_unlock(handle->statelock);

    ossl_crypto_mutex_free(&handle->lock);
    ossl_crypto_mutex_free(&handle->statelock);
    ossl_crypto_condvar_free(&handle->condvar);

    OPENSSL_free(handle->handle);
    OPENSSL_free(handle);

    return 1;
}

#else

CRYPTO_THREAD *ossl_crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine,
                                           void *data, int joinable)
{
    return NULL;
}

int ossl_crypto_thread_native_clean(CRYPTO_THREAD *handle)
{
    return 0;
}

#endif
