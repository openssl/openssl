/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "compat.h"

#if !defined(HAVE_ALIGNED_ALLOC)

#include <errno.h>
#include <stdlib.h>
#if !defined(HAVE_POSIX_MEMALIGN) || defined(__MING32__) || defined(__MING64__) || defined(_MSC_VER)
#include <malloc.h>
#endif

void* aligned_alloc(size_t alignment, size_t size) {
  /* check alignment (power of 2) and size (multiple of alignment) */
  if (alignment & (alignment - 1) || size & (alignment - 1)) {
    errno = EINVAL;
    return NULL;
  }

#if defined(HAVE_POSIX_MEMALIGN)
  /* check alignment (needs to be >= sizeof(void*)) */
  if (alignment < sizeof(void*)) {
    alignment = sizeof(void*);
  }

  void* ptr     = NULL;
  const int err = posix_memalign(&ptr, alignment, size);
  if (err) {
    errno = err;
  }
  return ptr;
#elif defined(HAVE_MEMALIGN)
  return memalign(alignment, size);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  return __mingw_aligned_malloc(size, alignment);
#elif defined(_MSC_VER)
  return _aligned_malloc(size, alignment);
#else
  if (size > 0) {
    errno = ENOMEM;
  }
  return NULL;
#endif
}

void aligned_free(void* ptr) {
#if defined(HAVE_POSIX_MEMALIGN) || defined(HAVE_MEMALIGN)
  free(ptr);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  __mingw_aligned_free(ptr);
#elif defined(_MSC_VER)
  _aligned_free(ptr);
#endif
}

#endif
