/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "common.h"

#if defined(OPENSSL_THREADS_WINNT)
# include <process.h>
# include <internal/thread.h>

static DWORD __stdcall thread_start_thunk(LPVOID vthread)
{
    CRYPTO_THREAD *thread;

    thread = (CRYPTO_THREAD*) vthread;
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_RUNNING);
    thread->thread_id = GetCurrentThreadId();
    thread->retval = thread->routine(thread->data);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_FINISHED);
    return 0;
}

int crypto_thread_native_spawn(CRYPTO_THREAD *t)
{
    HANDLE *handle;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        goto fail;

    *handle = (HANDLE)_beginthreadex(NULL, 0, &thread_start_thunk, t, 0, NULL);
    if (*handle == NULL)
        goto fail;

    CRYPTO_THREAD_SET_STATE(t, CRYPTO_THREAD_CREATED);
    t->handle = handle;
    return 1;

fail:
    CRYPTO_THREAD_SET_ERROR(t, CRYPTO_THREAD_CREATED);
    OPENSSL_free(handle);
    return 0;
}

int crypto_thread_native_join(CRYPTO_THREAD *thread, CRYPTO_THREAD_RETVAL *retval)
{
    DWORD thread_retval;
    HANDLE *handle;

    if (thread == NULL)
        return 0;

    CRYPTO_MUTEX_lock(thread->lock);

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_JOINED))
        goto pass;

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_FINISHED))
        goto pass;

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_TERMINATED))
        goto fail;

    handle = (HANDLE*) thread->handle;

    if (handle == NULL)
        goto fail;

    if (WaitForSingleObject(*handle, INFINITE) != WAIT_OBJECT_0)
        goto fail;

    if (GetExitCodeThread(*handle, &thread_retval) == 0)
        goto fail;

    /*
     * GetExitCodeThread call followed by this check is to make sure that
     * the thread exitted properly. In particular, thread_retval may be
     * non-zero when exitted via explicit ExitThread/TerminateThread or
     * if the thread is still active (returns STILL_ACTIVE (259)).
     */
    if (thread_retval != 0)
        goto fail;

    if (CloseHandle(*handle) == 0)
        goto fail;

    thread->handle = NULL;
    OPENSSL_free(handle);

pass:
    if (retval != NULL)
        *retval = thread->retval;

    CRYPTO_THREAD_UNSET_ERROR(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_MUTEX_unlock(thread->lock);
    return 1;

fail:
    CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_MUTEX_unlock(thread->lock);
    return 0;
}

int crypto_thread_native_terminate(CRYPTO_THREAD *thread)
{
    uint64_t mask;
    HANDLE *handle;

    mask = CRYPTO_THREAD_FINISHED;
    mask |= CRYPTO_THREAD_TERMINATED;
    mask |= CRYPTO_THREAD_JOINED;

    if (thread == NULL)
        return 1;

    if (thread->handle == NULL || CRYPTO_THREAD_GET_STATE(thread, mask))
        goto terminated;

    handle = thread->handle;
    if (WaitForSingleObject(*handle, 0) != WAIT_OBJECT_0) {
        if (TerminateThread(*handle, STILL_ACTIVE) == 0) {
            CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_TERMINATED);
            return 0;
        }
    }

    if (CloseHandle(*handle) == 0) {
        CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_TERMINATED);
        return 0;
    }

    thread->handle = NULL;
    OPENSSL_free(handle);

terminated:
    CRYPTO_THREAD_UNSET_ERROR(thread, CRYPTO_THREAD_TERMINATED);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_TERMINATED);
    return 1;
}

int crypto_thread_native_exit(void)
{
    _endthreadex(0);
    return 1;
}

int crypto_thread_native_is_self(CRYPTO_THREAD *thread)
{
    return thread->thread_id == GetCurrentThreadId();
}

CRYPTO_MUTEX CRYPTO_MUTEX_create(void)
{
    CRITICAL_SECTION *mutex;

    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX)mutex;
}

int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION*)mutex;
    InitializeCriticalSection(mutex_p);
    return 1;
}

void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION*)mutex;
    EnterCriticalSection(mutex_p);
}

int CRYPTO_MUTEX_try_lock(CRYPTO_MUTEX mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION*)mutex;
    if (TryEnterCriticalSection(mutex_p))
        return 1;

    return 0;
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION*)mutex;
    LeaveCriticalSection(mutex_p);
}

void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX *mutex)
{
    CRITICAL_SECTION **mutex_p;

    mutex_p = (CRITICAL_SECTION**)mutex;
    if (*mutex_p != NULL)
        DeleteCriticalSection(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void)
{
    CONDITION_VARIABLE *cv_p;

    if ((cv_p = OPENSSL_zalloc(sizeof(*cv_p))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR)cv_p;
}

void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CONDITION_VARIABLE *cv_p;
    CRITICAL_SECTION *mutex_p;

    cv_p = (CONDITION_VARIABLE*)cv;
    mutex_p = (CRITICAL_SECTION*)mutex;
    SleepConditionVariableCS(cv_p, mutex_p, INFINITE);
}

int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv)
{
    CONDITION_VARIABLE *cv_p;

    cv_p = (CONDITION_VARIABLE*)cv;
    InitializeConditionVariable(cv_p);
    return 1;
}

void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv)
{
    CONDITION_VARIABLE *cv_p;

    cv_p = (CONDITION_VARIABLE*)cv;
    WakeAllConditionVariable(cv_p);
}

void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR *cv)
{
    CONDITION_VARIABLE **cv_p;

    cv_p = (CONDITION_VARIABLE**)cv;
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void CRYPTO_mem_barrier(void)
{
    MemoryBarrier();
}

#endif
