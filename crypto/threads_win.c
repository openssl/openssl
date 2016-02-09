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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/crypto.h>

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && defined(OPENSSL_SYS_WINDOWS)

int CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock)
{
    if (InitializeCriticalSectionAndSpinCount((CRITICAL_SECTION *) lock, 0x400)
          != 0)
        return 0;

    return 1;
}

int CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock)
{
    EnterCriticalSection((CRITICAL_SECTION *) lock);
    return 1;
}

int CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock)
{
    EnterCriticalSection((CRITICAL_SECTION *) lock);
    return 1;
}

int CRYPTO_MUTEX_unlock(CRYPTO_MUTEX *lock)
{
    LeaveCriticalSection((CRITICAL_SECTION *) lock);
    return 1;
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock)
{
    DeleteCriticalSection((CRITICAL_SECTION *) lock);
}

BOOL CALLBACK once_cb(PINIT_ONCE once, PVOID p, PVOID *pp)
{
    void (*init)(void) = p;

    init();

    return TRUE;
}

void CRYPTO_ONCE_run(CRYPTO_ONCE *once, void (*init)(void))
{
    InitOnceExecuteOnce((INIT_ONCE *) once, once_cb, init, NULL);
}

int CRYPTO_THREAD_LOCAL_init(CRTPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    *key = TlsAlloc();
    if (*key == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_LOCAL_get(CRYPTO_THREAD_LOCAL *key)
{
    return TlsGetValue(key);
}

int CRYPTO_THREAD_LOCAL_set(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (TlsSetValue(key, val) == 0)
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

#endif
