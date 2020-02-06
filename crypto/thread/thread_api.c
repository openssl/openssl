/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/async.h>
#include "thread_external.h"
#include "thread_internal.h"

#if defined(OPENSSL_THREADS)

CRYPTO_THREAD CRYPTO_THREAD_new(CRYPTO_THREAD_ROUTINE start,
                                CRYPTO_THREAD_DATA data)
{
    CRYPTO_THREAD thread = NULL;
    if (CRYPTO_THREAD_EXTERN_enabled == 1)
        thread = CRYPTO_THREAD_EXTERN_add_job(start, data);
    else if (CRYPTO_THREAD_INTERN_enabled == 1)
        thread = CRYPTO_THREAD_INTERN_new(start, data);
    return thread;
}

int CRYPTO_THREAD_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval)
{
    if (thread == NULL)
        return 0;
    if (thread->handle == NULL)
        return CRYPTO_THREAD_EXTERN_join(thread, retval);
    else
        return CRYPTO_THREAD_INTERN_join(thread, retval);
    return 0;
}

int CRYPTO_THREAD_exit(CRYPTO_THREAD_RETVAL retval)
{
    if (CRYPTO_THREAD_EXTERN_enabled == 1 && ASYNC_is_capable()) {
        CRYPTO_THREAD_INTERN_exit(retval);
        return 1;
    }
    else if (CRYPTO_THREAD_INTERN_enabled == 1) {
        CRYPTO_THREAD_INTERN_exit(retval);
        return 1;
    }
    return 0;
}

CRYPTO_THREAD CRYPTO_THREAD_provide(CRYPTO_THREAD_CALLBACK cb)
{
    return CRYPTO_THREAD_EXTERN_provide(cb);
}

CRYPTO_THREAD_STATE CRYPTO_THREAD_state(CRYPTO_THREAD thread)
{
    return thread->state;
}

int CRYPTO_THREAD_clean(CRYPTO_THREAD* thread)
{
    if (thread == NULL || *thread == NULL)
        return 0;
    if ((*thread)->handle != NULL)
        return CRYPTO_THREAD_INTERN_clean(thread);
    else
        return CRYPTO_THREAD_EXTERN_clean(thread);
}

#endif
