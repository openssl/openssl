/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <internal/thread_arch.h>

#if defined(OPENSSL_THREADS_POSIX)
# define _GNU_SOURCE
# include <errno.h>
# include <sys/types.h>
# include <unistd.h>

static void *thread_start_thunk(void *vthread)
{
    CRYPTO_THREAD *thread;
    CRYPTO_THREAD_RETVAL ret;

    thread = (CRYPTO_THREAD *)vthread;

    ret = thread->routine(thread->data);
    ossl_crypto_mutex_lock(thread->statelock);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_FINISHED);
    thread->retval = ret;
    ossl_crypto_condvar_broadcast(thread->condvar);
    ossl_crypto_mutex_unlock(thread->statelock);

    return NULL;
}

int ossl_crypto_thread_native_spawn(CRYPTO_THREAD *thread)
{
    int ret;
    pthread_attr_t attr;
    pthread_t *handle;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        goto fail;

    pthread_attr_init(&attr);
    if (!thread->joinable)
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(handle, &attr, thread_start_thunk, thread);
    pthread_attr_destroy(&attr);

    if (ret != 0)
        goto fail;

    thread->handle = handle;
    return 1;

fail:
    thread->handle = NULL;
    OPENSSL_free(handle);
    return 0;
}

int ossl_crypto_thread_native_perform_join(CRYPTO_THREAD *thread, CRYPTO_THREAD_RETVAL *retval)
{
    void *thread_retval;
    pthread_t *handle;

    if (thread == NULL || thread->handle == NULL)
        return 0;

    handle = (pthread_t *) thread->handle;
    if (pthread_join(*handle, &thread_retval) != 0)
        return 0;

    /*
     * Join return value may be non-NULL when the thread has been cancelled,
     * as indicated by thread_retval set to PTHREAD_CANCELLED.
     */
    if (thread_retval != NULL)
        return 0;

    return 1;
}

int ossl_crypto_thread_native_exit(void)
{
    pthread_exit(NULL);
    return 1;
}

int ossl_crypto_thread_native_is_self(CRYPTO_THREAD *thread)
{
    return pthread_equal(*(pthread_t *)thread->handle, pthread_self());
}

CRYPTO_MUTEX *ossl_crypto_mutex_new(void)
{
    pthread_mutex_t *mutex;

    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    if (pthread_mutex_init(mutex, NULL) != 0) {
        OPENSSL_free(mutex);
        return NULL;
    }
    return (CRYPTO_MUTEX *)mutex;
}

int ossl_crypto_mutex_try_lock(CRYPTO_MUTEX *mutex)
{
    pthread_mutex_t *mutex_p;

    mutex_p = (pthread_mutex_t *)mutex;

    if (pthread_mutex_trylock(mutex_p) == EBUSY)
        return 0;

    return 1;
}

void ossl_crypto_mutex_lock(CRYPTO_MUTEX *mutex)
{
    pthread_mutex_t *mutex_p;

    mutex_p = (pthread_mutex_t *)mutex;
    pthread_mutex_lock(mutex_p);
}

void ossl_crypto_mutex_unlock(CRYPTO_MUTEX *mutex)
{
    pthread_mutex_t *mutex_p;

    mutex_p = (pthread_mutex_t *)mutex;
    pthread_mutex_unlock(mutex_p);
}

void ossl_crypto_mutex_free(CRYPTO_MUTEX **mutex)
{
    pthread_mutex_t **mutex_p;

    if (mutex == NULL)
        return;

    mutex_p = (pthread_mutex_t **)mutex;
    if (*mutex_p != NULL)
        pthread_mutex_destroy(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR *ossl_crypto_condvar_new(void)
{
    pthread_cond_t *cv_p;

    if ((cv_p = OPENSSL_zalloc(sizeof(*cv_p))) == NULL)
        return NULL;
    if (pthread_cond_init(cv_p, NULL) != 0) {
        OPENSSL_free(cv_p);
        return NULL;
    }
    return (CRYPTO_CONDVAR *) cv_p;
}

void ossl_crypto_condvar_wait(CRYPTO_CONDVAR *cv, CRYPTO_MUTEX *mutex)
{
    pthread_cond_t *cv_p;
    pthread_mutex_t *mutex_p;

    cv_p = (pthread_cond_t *)cv;
    mutex_p = (pthread_mutex_t *)mutex;
    pthread_cond_wait(cv_p, mutex_p);
}

void ossl_crypto_condvar_broadcast(CRYPTO_CONDVAR *cv)
{
    pthread_cond_t *cv_p;

    cv_p = (pthread_cond_t *)cv;
    pthread_cond_broadcast(cv_p);
}

void ossl_crypto_condvar_free(CRYPTO_CONDVAR **cv)
{
    pthread_cond_t **cv_p;

    if (cv == NULL)
        return;

    cv_p = (pthread_cond_t **)cv;
    if (*cv_p != NULL)
        pthread_cond_destroy(*cv_p);
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void ossl_crypto_mem_barrier(void)
{
# if defined(__clang__) || defined(__GNUC__)
    __sync_synchronize();
# elif !defined(OPENSSL_NO_ASM)
#  if defined(__alpha__) /* Alpha */
    __asm__ volatile("mb" : : : "memory");
#  elif defined(__amd64__) || defined(__i386__) || defined(__i486__) \
    || defined(__i586__)  || defined(__i686__) || defined(__i386) /* x86 */
    __asm__ volatile("mfence" : : : "memory");
#  elif defined(__arm__) || defined(__aarch64__) /* ARMv7, ARMv8 */
    __asm__ volatile("dmb ish" : : : "memory");
#  elif defined(__hppa__) /* PARISC */
    __asm__ volatile("" : : : "memory");
#  elif defined(__mips__) /* MIPS */
    __asm__ volatile("sync" : : : "memory");
#  elif defined(__powerpc__) || defined(__powerpc64__) /* power, ppc64, ppc64le */
    __asm__ volatile("sync" : : : "memory");
#  elif defined(__sparc__)
    __asm__ volatile("ba,pt	%%xcc, 1f\n\t" \
                     " membar	#Sync\n"   \
                     "1:\n"                \
                     : : : "memory");
#  elif defined(__s390__) || defined(__s390x__) /* z */
    __asm__ volatile("bcr 15,0" : : : "memory");
#  elif defined(__riscv) || defined(__riscv__) /* riscv */
    __asm__ volatile("fence iorw,iorw" : : : "memory");
#  else /* others, compiler only */
    __asm__ volatile("" : : : "memory");
#  endif
# else
    /* compiler only barrier */
    __asm__ volatile("" : : : "memory");
# endif
}

#endif
