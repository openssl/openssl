/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0

void OPENSSL_fork_prepare(void)
{
}

void OPENSSL_fork_parent(void)
{
}

void OPENSSL_fork_child(void)
{
}

#endif

static ossl_inline int lock(CRYPTO_RWLOCK *l, int wr)
{
    if (wr)
        return CRYPTO_THREAD_write_lock(l);
    else
        return CRYPTO_THREAD_read_lock(l);
}

static ossl_inline int try_lock(CRYPTO_RWLOCK *l, int wr)
{
    if (wr)
        return CRYPTO_THREAD_try_write_lock(l);
    else
        return CRYPTO_THREAD_try_read_lock(l);
}

/*
 * Lock two locks using a deadlock avoidance algorithm.
 */
int CRYPTO_THREAD_lock_dual(CRYPTO_RWLOCK *lock1, int lock1_write, CRYPTO_RWLOCK *lock2, int lock2_write)
{
    for (;;) {
        if (lock(lock1, lock1_write) == 0)
            return 0;
        if (try_lock(lock2, lock2_write) != 0)
            return 1;

        CRYPTO_THREAD_unlock(lock1);

        if (lock(lock2, lock2_write) == 0)
            return 0;
        if (try_lock(lock1, lock1_write) != 0)
            return 1;

        CRYPTO_THREAD_unlock(lock2);
    }
}
