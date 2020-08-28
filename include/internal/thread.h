/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTO_THREAD_H
# define OPENSSL_CRYPTO_THREAD_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)

#  include <internal/list.h>
#  include <openssl/crypto.h>

typedef uint32_t CRYPTO_THREAD_RETVAL;
typedef CRYPTO_THREAD_RETVAL (*CRYPTO_THREAD_ROUTINE)(void *);

typedef struct crypto_thread_st {
    uint32_t state;
    void *data;
    CRYPTO_THREAD_ROUTINE routine;
    CRYPTO_THREAD_RETVAL retval;
    void *handle;
    CRYPTO_MUTEX lock;
    unsigned long thread_id;
    int joinable;
} CRYPTO_THREAD;

CRYPTO_THREAD * crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine,
                                           void *data, int joinable);
int crypto_thread_native_spawn(CRYPTO_THREAD *thread);
int crypto_thread_native_join(CRYPTO_THREAD *thread,
                              CRYPTO_THREAD_RETVAL *retval);
int crypto_thread_native_terminate(CRYPTO_THREAD *thread);
int crypto_thread_native_exit(void);
int crypto_thread_native_is_self(CRYPTO_THREAD *thread);
int crypto_thread_native_clean(CRYPTO_THREAD *thread);

# define CRYPTO_THREAD_NO_STATE   0UL
# define CRYPTO_THREAD_AWAITING   1UL << 0
# define CRYPTO_THREAD_CREATED    1UL << 1
# define CRYPTO_THREAD_RUNNING    1UL << 2
# define CRYPTO_THREAD_FINISHED   1UL << 3
# define CRYPTO_THREAD_JOINED     1UL << 4
# define CRYPTO_THREAD_TERMINATED 1UL << 5

# define CRYPTO_THREAD_GET_STATE(THREAD, FLAG) ((THREAD)->state & FLAG)
# define CRYPTO_THREAD_GET_ERROR(THREAD, FLAG) (((THREAD)->state >> 16) & FLAG)

# define CRYPTO_THREAD_UNSET_STATE(THREAD, FLAG)                        \
    do {                                                                \
        (THREAD)->state &= ~(FLAG);                                     \
    } while ((void)0, 0)

# define CRYPTO_THREAD_SET_STATE(THREAD, FLAG)                          \
    do {                                                                \
        (THREAD)->state |= FLAG;                                        \
    } while ((void)0, 0)

# define CRYPTO_THREAD_SET_ERROR(THREAD, FLAG)                          \
    do {                                                                \
        (THREAD)->state |= (FLAG << 16);                                \
    } while ((void)0, 0)

# define CRYPTO_THREAD_UNSET_ERROR(THREAD, FLAG)                        \
    do {                                                                \
        (THREAD)->state &= ~(FLAG << 16);                               \
    } while ((void)0, 0)

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_CRYPTO_THREAD_H */
