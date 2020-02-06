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

#if defined(OPENSSL_THREADS)
# ifndef OPENSSL_THREAD_H
#  define OPENSSL_THREAD_H
#  pragma once

CRYPTO_THREAD CRYPTO_THREAD_arch_create(CRYPTO_THREAD_ROUTINE routine,
                                        CRYPTO_THREAD_DATA data);
int CRYPTO_THREAD_arch_join(CRYPTO_THREAD thread,
                            CRYPTO_THREAD_RETVAL* retval);
int CRYPTO_THREAD_arch_exit(CRYPTO_THREAD_RETVAL retval);

CRYPTO_MUTEX CRYPTO_MUTEX_create(void);
int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex);
void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex);
void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex);
void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX* mutex);

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void);
void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex);
int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv);
void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv);
void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR* cv);

void CRYPTO_mem_barrier(void);

# endif
#endif
