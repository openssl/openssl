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

#if defined(_WIN32)
# include <windows.h>
#endif

#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_WINDOWS) && \
    defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
# include "thread_win.h"
# include "process.h"

static DWORD WINAPI thread_call_routine(LPVOID param)
{
    CRYPTO_THREAD_WIN* thread = (CRYPTO_THREAD_WIN*) param;
    thread->state = CRYPTO_THREAD_RUNNING;
    thread->retval = thread->routine(thread->data);
    thread->state = CRYPTO_THREAD_STOPPED;
    return 0L;
}

CRYPTO_THREAD CRYPTO_THREAD_arch_create(CRYPTO_THREAD_ROUTINE routine,
                                        CRYPTO_THREAD_DATA data)
{
    CRYPTO_THREAD_WIN * thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1 && CRYPTO_THREAD_INTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    thread->routine = routine;
    thread->data = data;

#ifndef __MINGW32__
    *thread->handle = CreateThread(NULL, 0, thread_call_routine,
                                   (LPVOID)thread, 0, NULL);
#else
    *thread->handle = (HANDLE*)_beginthreadex(NULL, 0, &thread_call_routine,
                                              NULL, 0, NULL);
#endif

    if (thread->handle == NULL) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (CRYPTO_THREAD) thread;
}

int CRYPTO_THREAD_arch_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval)
{
    DWORD retval_intern;

    if (thread == NULL)
        return 0;

    CRYPTO_THREAD_WIN* thread_w = (CRYPTO_THREAD_WIN*)thread;

    if (thread_w->handle == NULL)
        return 0;

    if (WaitForSingleObject(*thread_w->handle, INFINITE) != WAIT_OBJECT_0)
        return 0;

    if (GetExitCodeThread(*thread_w->handle, &retval_intern) == 0)
        return 0;

    if (CloseHandle(*thread_w->handle) == 0)
        return 0;

    if (retval)
        *retval = thread_w->retval;

    return (retval_intern == 0);
}

int CRYPTO_THREAD_arch_exit(CRYPTO_THREAD_RETVAL retval)
{
    /* @TODO */
    ExitThread((DWORD)retval);
    return 1;
}

CRYPTO_MUTEX CRYPTO_MUTEX_create(void)
{
    CRYPTO_MUTEX_WIN* mutex;
    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX)mutex;
}

int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_WIN*)mutex;
    InitializeCriticalSection(mutex_p);
    return 1;
}

void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_WIN*)mutex;
    EnterCriticalSection(mutex_p);
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_WIN*)mutex;
    LeaveCriticalSection(mutex_p);
}

void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX* mutex)
{
    CRYPTO_MUTEX_WIN** mutex_p = (CRYPTO_MUTEX_WIN**)mutex;
    DeleteCriticalSection(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void)
{
    CRYPTO_CONDVAR_WIN* cv_p;
    if ((cv_p = OPENSSL_zalloc(sizeof(*cv_p))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR)cv_p;
}

void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_WIN*)mutex;
    SleepConditionVariableCS(cv_p, mutex_p, INFINITE);
}

int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    InitializeConditionVariable(cv_p);
    return 1;
}

void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    WakeAllConditionVariable(cv_p);
}

void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR* cv)
{
    CRYPTO_CONDVAR_WIN** cv_p = (CRYPTO_CONDVAR_WIN**)cv;
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void CRYPTO_mem_barrier()
{
    MemoryBarrier();
}

#endif
