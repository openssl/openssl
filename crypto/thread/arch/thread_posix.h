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
# ifndef OPENSSL_CRYPTO_THREAD_POSIX
#  define OPENSSL_CRYPTO_THREAD_POSIX
#  pragma once

#  include <sys/types.h>
#  include <unistd.h>

typedef struct {
    CRYPTO_THREAD_STATE   state;
    pthread_t*            handle;
    CRYPTO_THREAD_ROUTINE routine;
    CRYPTO_THREAD_DATA    data;
    CRYPTO_THREAD_RETVAL  retval;
} CRYPTO_THREAD_POSIX;

typedef pthread_mutex_t CRYPTO_MUTEX_POSIX;
typedef pthread_cond_t CRYPTO_CONDVAR_POSIX;

# endif
#endif
