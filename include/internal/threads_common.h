/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _CRYPTO_THREADS_COMMON_H_
# define _CRYPTO_THREADS_COMMON_H_

# if defined(__apple_build_version__) && __apple_build_version__ < 6000000
/*
 * OS/X 10.7 and 10.8 had a weird version of clang which has __ATOMIC_ACQUIRE and
 * __ATOMIC_ACQ_REL but which expects only one parameter for __atomic_is_lock_free()
 * rather than two which has signature __atomic_is_lock_free(sizeof(_Atomic(T))).
 * All of this makes impossible to use __atomic_is_lock_free here.
 *
 * See: https://github.com/llvm/llvm-project/commit/a4c2602b714e6c6edb98164550a5ae829b2de760
 */
#  define BROKEN_CLANG_ATOMICS
# endif

typedef enum {
    CRYPTO_THREAD_LOCAL_RCU_KEY = 0,
    CRYPTO_THREAD_LOCAL_DRBG_PRIV_KEY,
    CRYPTO_THREAD_LOCAL_DRBG_PUB_KEY,
    CRYPTO_THREAD_LOCAL_ERR_KEY,
    CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
    CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY,
    CRYPTO_THREAD_LOCAL_TEVENT_KEY,
    CRYPTO_THREAD_LOCAL_KEY_MAX
} CRYPTO_THREAD_LOCAL_KEY_ID;

#define CRYPTO_THREAD_NO_CONTEXT (void *)1

void *CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id,
                                 OSSL_LIB_CTX *ctx);
int CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id,
                               OSSL_LIB_CTX *ctx, void *data);

# ifdef FIPS_MODULE
void CRYPTO_THREAD_clean_local_for_fips(void);
# endif

#endif
