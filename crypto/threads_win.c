/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/crypto.h>
#include "internal/threads.h"

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && defined(OPENSSL_SYS_WINDOWS)

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
    CRYPTO_RWLOCK *lock = OPENSSL_zalloc(sizeof(CRITICAL_SECTION));
    if (lock == NULL)
        return NULL;

    /* 0x400 is the spin count value suggested in the documentation */
    if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
        OPENSSL_free(lock);
        return NULL;
    }

    return lock;
}

int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
    EnterCriticalSection(lock);
    return 1;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
    EnterCriticalSection(lock);
    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
    LeaveCriticalSection(lock);
    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

    DeleteCriticalSection(lock);
    OPENSSL_free(lock);

    return;
}

# if _WIN32_WINNT < 0x0600

#  define ONCE_UNINITED     0
#  define ONCE_ININIT       1
#  define ONCE_DONE         2

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    LONG volatile *lock = (LONG *)once;
    LONG result;

    if (*lock == ONCE_DONE)
        return 1;

    do {
        result = InterlockedCompareExchange(lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init();
            *lock = ONCE_DONE;
            return 1;
        }
    } while (result == ONCE_ININIT);

    return (*lock == ONCE_DONE);
}

# else

BOOL CALLBACK once_cb(PINIT_ONCE once, PVOID p, PVOID *pp)
{
    void (*init)(void) = p;

    init();

    return TRUE;
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (InitOnceExecuteOnce(once, once_cb, init, NULL))
        return 1;

    return 0;
}

# endif

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    *key = TlsAlloc();
    if (*key == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return TlsGetValue(*key);
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (TlsSetValue(*key, val) == 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (TlsFree(*key) == 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return GetCurrentThreadId();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
    *ret = InterlockedExchangeAdd(val, amount) + amount;
    return 1;
}

#endif
