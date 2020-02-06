/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_UNIX)
# include "openssl/crypto.h"
# include "thread_posix.h"
# include "../thread.h"

static void* thread_call_routine(void* param)
{
    CRYPTO_THREAD_POSIX* thread = (CRYPTO_THREAD_POSIX*)param;
    thread->state = CRYPTO_THREAD_RUNNING;
    thread->retval = thread->routine(thread->data);
    thread->state = CRYPTO_THREAD_STOPPED;
    return NULL;
}

CRYPTO_THREAD CRYPTO_THREAD_arch_create(CRYPTO_THREAD_ROUTINE routine,
                                        CRYPTO_THREAD_DATA data)
{
    int retval;
    CRYPTO_THREAD_POSIX* thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1 && CRYPTO_THREAD_INTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    thread->routine = routine;
    thread->data = data;

    retval = pthread_create(thread->handle, NULL, thread_call_routine, thread);

    if (retval != 0 || thread->handle == NULL) {
        thread->state = CRYPTO_THREAD_FAILED;
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (CRYPTO_THREAD) thread;
}

int CRYPTO_THREAD_arch_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval)
{
    void* retval_intern;
    CRYPTO_THREAD_POSIX* thread_p;

    if (thread == NULL)
        return 0;

    thread_p = (CRYPTO_THREAD_POSIX*)thread;

    if (thread_p->handle == NULL)
        return 0;

    if (pthread_join(*thread_p->handle, &retval_intern) != 0)
        return 0;

    if (retval)
        *retval = thread_p->retval;

    return (retval_intern == NULL);
}

int CRYPTO_THREAD_arch_exit(CRYPTO_THREAD_RETVAL retval)
{
    /* @TODO */
    pthread_exit((void*)retval);
    return 1;
}

CRYPTO_MUTEX CRYPTO_MUTEX_create(void)
{
    CRYPTO_MUTEX_POSIX* mutex;
    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX) mutex;
}

int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    if (pthread_mutex_init(mutex_p, NULL) != 0)
        return 0;
    return 1;
}

void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_lock(mutex_p);
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_unlock(mutex_p);
}

void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX* mutex)
{
    CRYPTO_MUTEX_POSIX** mutex_p = (CRYPTO_MUTEX_POSIX**)mutex;
    pthread_mutex_destroy(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void)
{
    CRYPTO_CONDVAR_POSIX* cv;
    if ((cv = OPENSSL_zalloc(sizeof(*cv))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR) cv;
}

void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_cond_wait(cv_p, mutex_p);
}

int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    if (pthread_cond_init(cv_p, NULL) != 0)
        return 0;
    return 1;
}

void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    pthread_cond_broadcast(cv_p);
}

void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR* cv)
{
    CRYPTO_CONDVAR_POSIX** cv_p = (CRYPTO_CONDVAR_POSIX**)cv;
    pthread_cond_destroy(*cv_p);
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void CRYPTO_mem_barrier()
{
    __asm__ volatile ("" : : : "memory");
}

#endif
