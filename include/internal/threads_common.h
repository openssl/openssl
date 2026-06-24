/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _CRYPTO_THREADS_COMMON_H_
#define _CRYPTO_THREADS_COMMON_H_

#include <openssl/types.h>

#if defined(__clang__) && defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__
#endif
#endif

#if defined(__SANITIZE_THREAD__)
#include <sanitizer/tsan_interface.h>
extern void AnnotateBenignRaceSized(const char *f, int l,
    const volatile void *mem, unsigned int size, const char *desc);
#define TSAN_BENIGN(x, desc) \
    AnnotateBenignRaceSized(__FILE__, __LINE__, (x), sizeof(*(x)), desc);
#else
#define TSAN_BENIGN(x, desc)
#endif

typedef enum {
    CRYPTO_THREAD_LOCAL_RCU_KEY = 0,
    CRYPTO_THREAD_LOCAL_DRBG_PRIV_KEY,
    CRYPTO_THREAD_LOCAL_DRBG_PUB_KEY,
    CRYPTO_THREAD_LOCAL_ERR_KEY,
    CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
    CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY,
    CRYPTO_THREAD_LOCAL_TEVENT_KEY,
    CRYPTO_THREAD_LOCAL_TANDEM_ID_KEY,
    CRYPTO_THREAD_LOCAL_FIPS_DEFERRED_KEY,
    CRYPTO_THREAD_LOCAL_KEY_MAX
} CRYPTO_THREAD_LOCAL_KEY_ID;

#define CRYPTO_THREAD_NO_CONTEXT (void *)1

void *CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id,
    OSSL_LIB_CTX *ctx);
int CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id,
    OSSL_LIB_CTX *ctx, void *data);

void CRYPTO_THREAD_clean_local(void);

/* Do atomics work? */

#if defined(__apple_build_version__) && __apple_build_version__ < 6000000
/*
 * OS/X 10.7 and 10.8 had a weird version of clang which has __ATOMIC_ACQUIRE and
 * __ATOMIC_ACQ_REL but which expects only one parameter for __atomic_is_lock_free()
 * rather than two which has signature __atomic_is_lock_free(sizeof(_Atomic(T))).
 * All of this makes impossible to use __atomic_is_lock_free here.
 *
 * See: https://github.com/llvm/llvm-project/commit/a4c2602b714e6c6edb98164550a5ae829b2de760
 */
#define BROKEN_CLANG_ATOMICS
#endif

/*
 * Define OSSL_USE_INTERLOCKEDOR64 on Windows toolchains that expose
 * InterlockedOr64 in a form usable as a compiler intrinsic.  Today this
 * means MSVC and 64-bit MinGW (mingw-w64 x86_64).  32-bit MinGW does not
 * expose an intrinsic form, so OSSL_USE_INTERLOCKEDOR64 is left undefined
 * there and crypto/threads_win.c falls back to a manual locking mechanism.
 * The fallback path can be removed when 32-bit MinGW is no longer a
 * supported build target.
 */
#if defined(_MSC_VER) || defined(__MINGW64__)
#define OSSL_USE_INTERLOCKEDOR64
#endif

#if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS) \
    && !defined(USE_ATOMIC_FALLBACKS)
#define OSSL_USE_GCC_ATOMICS
#elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
#define OSSL_USE_SOLARIS_ATOMICS
#endif

/* Allow us to know if atomics will be implemented with a fallback lock or not. */
#if defined(OSSL_USE_GCC_ATOMICS) || defined(OSSL_USE_SOLARIS_ATOMICS) || defined(OSSL_USE_INTERLOCKEDOR64)
#define OSSL_ATOMICS_LOCKLESS
#endif

#endif
