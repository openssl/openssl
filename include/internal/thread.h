/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_INTERNAL_THREAD_H
# define HEADER_INTERNAL_THREAD_H

# if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
#  if defined(_WIN32)
#   if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> in order to use this */
typedef DWORD CRYPTO_THREAD_LOCAL;
typedef DWORD CRYPTO_THREAD_ID;
typedef LONG CRYPTO_ONCE;
#    define CRYPTO_ONCE_STATIC_INIT 0
#   endif
#  else
#   include <pthread.h>
typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;
#   define CRYPTO_ONCE_STATIC_INIT PTHREAD_ONCE_INIT
#  endif
# endif

# if !defined(CRYPTO_ONCE_STATIC_INIT)
typedef unsigned int CRYPTO_ONCE;
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
#  define CRYPTO_ONCE_STATIC_INIT 0
# endif

void OPENSSL_thread_stop(void);

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void);
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);
#endif
