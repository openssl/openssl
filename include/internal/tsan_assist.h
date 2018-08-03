/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
/*
 * Goal here is to facilitate writing "thread-opportunistic" code that
 * withstands Thread Sanitizer's scrutiny. "Thread-opportunistic" is when
 * exact result is not required, e.g. some statistics, or execution flow
 * doesn't have to be unambiguous. Simplest example is lazy "constant"
 * initialization when one can synchronize on variable itself, e.g.
 *
 * if (var == NOT_YET_INITIALIZED)
 *     var = function_returning_same_value();
 *
 * This does work provided that loads and stores are single-instuction
 * operations (and integer ones are on *all* supported platforms), but
 * it upsets Thread Sanitizer. Suggested solution is
 *
 * if (tsan_load(&var) == NOT_YET_INITIALIZED)
 *     tsan_store(&var, function_returning_same_value());
 *
 * Production machine code would be the same, so one can wonder why
 * bother. Having Thread Sanitizer accept "thread-opportunistic" code
 * allows to move on trouble-shooting real bugs.
 *
 * We utilize the fact that compilers that implement Thread Sanitizer
 * implement even atomic operations. Then it's assumed that
 * ATOMIC_{LONG|INT}_LOCK_FREE are assigned same value as
 * ATOMIC_POINTER_LOCK_FREE. And check for >= 2 ensures that correspodning
 * code is inlined. It should be noted that statistics counters become
 * accurate in such case.
 */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
    && !defined(__STDC_NO_ATOMICS__)
# include <stdatomic.h>

# if defined(ATOMIC_POINTER_LOCK_FREE) \
          && ATOMIC_POINTER_LOCK_FREE >= 2
#  define TSAN_QUALIFIER _Atomic
#  define tsan_load(ptr) atomic_load_explicit((ptr), memory_order_relaxed)
#  define tsan_store(ptr, val) atomic_store_explicit((ptr), (val), memory_order_relaxed)
#  define tsan_counter(ptr) atomic_fetch_add_explicit((ptr), 1, memory_order_relaxed)
# endif

#elif defined(__GNUC__) && defined(__ATOMIC_RELAXED)

# if defined(__GCC_ATOMIC_POINTER_LOCK_FREE) \
          && __GCC_ATOMIC_POINTER_LOCK_FREE >= 2
#  define TSAN_QUALIFIER volatile
#  define tsan_load(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#  define tsan_store(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)
#  define tsan_counter(ptr) __atomic_fetch_add((ptr), 1, __ATOMIC_RELAXED)
# endif

#elif defined(_MSC_VER) && _MSC_VER>=1200

# define TSAN_QUALIFIER volatile
# define tsan_load(ptr) (*(ptr))
# define tsan_store(ptr, val) (*(ptr) = (val))
# pragma intrinsic(_InterlockedExchangeAdd)
# ifdef _WIN64
#  pragma intrinsic(_InterlockedExchangeAdd64)
#  define tsan_counter(ptr) (sizeof(*ptr) == 8 ? _InterlockedExchangeAdd64((ptr), 1) \
                                               : _InterlockedExchangeAdd((ptr), 1))
# else
#  define tsan_counter(ptr) _InterlockedExchangeAdd((ptr), 1)
# endif

#endif

#ifndef TSAN_QUALIFIER

# define TSAN_QUALIFIER volatile
# define tsan_load(ptr) (*(ptr))
# define tsan_store(ptr, val) (*(ptr) = (val))
# define tsan_counter(ptr) ((*(ptr))++)

#endif
