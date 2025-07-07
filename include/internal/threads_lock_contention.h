/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _CRYPTO_THREADS_LOCK_CONTENTION_H_
# define _CRYPTO_THREADS_LOCK_CONTENTION_H_

# include <openssl/configuration.h>

# if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && !defined(OPENSSL_SYS_WINDOWS)

#  include "internal/threads_common.h"

#  if defined(OPENSSL_NO_STDIO)
#   ifdef REPORT_RWLOCK_CONTENTION
#    warning "RWLOCK CONTENTION REPORTING NOT SUPPORTED, Disabling"
#    undef REPORT_RWLOCK_CONTENTION
#   endif
#  endif

#  include <pthread.h>

#  ifdef REPORT_RWLOCK_CONTENTION

void ossl_init_rwlock_contention_data(void);
void ossl_free_rwlock_contention_data(void);
int ossl_rwlock_rdlock(pthread_rwlock_t *);
int ossl_rwlock_wrlock(pthread_rwlock_t *);
int ossl_rwlock_unlock(pthread_rwlock_t *);

#  else /* !REPORT_RWLOCK_CONTENTION */

static inline void ossl_init_rwlock_contention_data(void)
{
}

static inline void ossl_free_rwlock_contention_data(void)
{
}

static inline int ossl_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
    return pthread_rwlock_rdlock(rwlock);
}

static inline int ossl_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
    return pthread_rwlock_wrlock(rwlock);
}

static inline int ossl_rwlock_unlock(pthread_rwlock_t *rwlock)
{
    return pthread_rwlock_unlock(rwlock);
}

#  endif /* REPORT_RWLOCK_CONTENTION */

# endif /* OPENSSL_THREADS && !CRYPTO_TDEBUG && !OPENSSL_SYS_WINDOWS */

#endif /* _CRYPTO_THREADS_LOCK_CONTENTION_H_ */
