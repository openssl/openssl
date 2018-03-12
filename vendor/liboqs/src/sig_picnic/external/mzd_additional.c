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
#include "mzd_additional.h"

#if !defined(_MSC_VER)
#include <stdalign.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_MSC_VER) && !defined(static_assert)
#define static_assert _Static_assert
#endif

static const size_t mzd_local_t_size = (sizeof(mzd_local_t) + 0x1f) & ~0x1f;
static_assert(((sizeof(mzd_local_t) + 0x1f) & ~0x1f) == 32, "sizeof mzd_local_t not supported");

#ifdef WITH_OPT
#include "simd.h"

#if defined(WITH_SSE2) || defined(WITH_AVX2) || defined(WITH_NEON)
static const unsigned int word_size_bits = 8 * sizeof(word);
#endif
#endif
static const unsigned int align_bound = 128 / (8 * sizeof(word));

static uint32_t calculate_rowstride(uint32_t width) {
  // As soon as we hit the AVX bound, use 32 byte alignment. Otherwise use 16
  // byte alignment for SSE2 and 128 bit vectors.
  if (width > align_bound) {
    return ((width * sizeof(word) + 31) & ~31) / sizeof(word);
  } else {
    return ((width * sizeof(word) + 15) & ~15) / sizeof(word);
  }
}

// Notes on the memory layout: mzd_init allocates multiple memory blocks (one
// for mzd_local_t, one for rows and multiple for the buffers). We use one memory
// block for mzd_local_t, rows and the buffer. This improves memory locality and
// requires less calls to malloc.
//
// In mzd_local_init_multiple we do the same, but store n mzd_local_t instances in one
// memory block.

mzd_local_t* oqs_sig_picnic_mzd_local_init_ex(uint32_t r, uint32_t c, bool clear) {
  const uint32_t width     = (c + 64 - 1) / 64;
  const uint32_t rowstride = calculate_rowstride(width);

  const size_t buffer_size = r * rowstride * sizeof(word);

  unsigned char* buffer = aligned_alloc(32, (mzd_local_t_size + buffer_size + 31) & ~31);

  mzd_local_t* A = (mzd_local_t*)buffer;
  buffer += mzd_local_t_size;

  if (clear) {
    memset(buffer, 0, buffer_size);
  }

  // assign in order
  A->nrows     = r;
  A->ncols     = c;
  A->width     = width;
  A->rowstride = rowstride;

  return A;
}

void oqs_sig_picnic_mzd_local_free(mzd_local_t* v) {
  aligned_free(v);
}

void oqs_sig_picnic_mzd_local_init_multiple_ex(mzd_local_t** dst, size_t n, uint32_t r, uint32_t c, bool clear) {
  const uint32_t width     = (c + 64 - 1) / 64;
  const uint32_t rowstride = calculate_rowstride(width);

  const size_t buffer_size   = r * rowstride * sizeof(word);
  const size_t size_per_elem = (mzd_local_t_size + buffer_size + 31) & ~31;

  unsigned char* full_buffer = aligned_alloc(32, size_per_elem * n);

  for (size_t s = 0; s < n; ++s, full_buffer += size_per_elem) {
    unsigned char* buffer = full_buffer;
    mzd_local_t* A        = (mzd_local_t*)buffer;
    dst[s]                = A;

    buffer += mzd_local_t_size;

    if (clear) {
      memset(buffer, 0, buffer_size);
    }

    // assign in order
    A->nrows     = r;
    A->ncols     = c;
    A->width     = width;
    A->rowstride = rowstride;
  }
}

void oqs_sig_picnic_mzd_local_free_multiple(mzd_local_t** vs) {
  if (vs) {
    aligned_free(vs[0]);
  }
}

mzd_local_t* oqs_sig_picnic_mzd_local_copy(mzd_local_t* dst, mzd_local_t const* src) {
  if (dst == src) {
    return dst;
  }

  if (!dst) {
    dst = oqs_sig_picnic_mzd_local_init(src->nrows, src->ncols);
  }

  memcpy(ASSUME_ALIGNED(FIRST_ROW(dst), 32), ASSUME_ALIGNED(CONST_FIRST_ROW(src), 32),
         src->nrows * sizeof(word) * src->rowstride);
  return dst;
}

void oqs_sig_picnic_mzd_local_clear(mzd_local_t* c) {
  memset(ASSUME_ALIGNED(FIRST_ROW(c), 32), 0, c->nrows * sizeof(word) * c->rowstride);
}

void oqs_sig_picnic_mzd_shift_right(mzd_local_t* res, mzd_local_t const* val, unsigned count) {
  if (!count) {
    oqs_sig_picnic_mzd_local_copy(res, val);
    return;
  }

  const unsigned int nwords     = val->width;
  const unsigned int left_count = 8 * sizeof(word) - count;

  word* resptr       = FIRST_ROW(res);
  word const* valptr = CONST_FIRST_ROW(val);

  for (unsigned int i = nwords - 1; i; --i, ++resptr) {
    const word tmp = *valptr >> count;
    *resptr        = tmp | (*++valptr << left_count);
  }
  *resptr = *valptr >> count;
}

void oqs_sig_picnic_mzd_shift_left(mzd_local_t* res, mzd_local_t const* val, unsigned count) {
  if (!count) {
    oqs_sig_picnic_mzd_local_copy(res, val);
    return;
  }

  const unsigned int nwords      = val->width;
  const unsigned int right_count = 8 * sizeof(word) - count;

  word* resptr       = FIRST_ROW(res) + nwords - 1;
  word const* valptr = CONST_FIRST_ROW(val) + nwords - 1;

  for (unsigned int i = nwords - 1; i; --i, --resptr) {
    const word tmp = *valptr << count;
    *resptr        = tmp | (*--valptr >> right_count);
  }
  *resptr = *valptr << count;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
ATTR_TARGET("sse2")
static inline mzd_local_t* mzd_and_sse(mzd_local_t* res, mzd_local_t const* first,
                                       mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  __m128i* mresptr          = (__m128i*)ASSUME_ALIGNED(resptr, alignof(__m128i));
  __m128i const* mfirstptr  = (__m128i*)ASSUME_ALIGNED(firstptr, alignof(__m128i));
  __m128i const* msecondptr = (__m128i*)ASSUME_ALIGNED(secondptr, alignof(__m128i));

  do {
    *mresptr++ = _mm_and_si128(*mfirstptr++, *msecondptr++);
    width -= sizeof(__m128i) / sizeof(word);
  } while (width);

  return res;
}
#endif

#ifdef WITH_AVX2
ATTR_TARGET("avx2")
static inline mzd_local_t* mzd_and_avx(mzd_local_t* res, mzd_local_t const* first,
                                       mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  __m256i* mresptr          = (__m256i*)ASSUME_ALIGNED(resptr, alignof(__m256i));
  __m256i const* mfirstptr  = (__m256i*)ASSUME_ALIGNED(firstptr, alignof(__m256i));
  __m256i const* msecondptr = (__m256i*)ASSUME_ALIGNED(secondptr, alignof(__m256i));

  do {
    *mresptr++ = _mm256_and_si256(*mfirstptr++, *msecondptr++);
    width -= sizeof(__m256i) / sizeof(word);
  } while (width);

  return res;
}
#endif

#ifdef WITH_NEON
static inline mzd_local_t* mzd_and_neon(mzd_local_t* res, mzd_local_t const* first,
                                        mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  uint32x4_t* mresptr          = (uint32x4_t*)ASSUME_ALIGNED(resptr, alignof(uint32x4_t));
  uint32x4_t const* mfirstptr  = (uint32x4_t*)ASSUME_ALIGNED(firstptr, alignof(uint32x4_t));
  uint32x4_t const* msecondptr = (uint32x4_t*)ASSUME_ALIGNED(secondptr, alignof(uint32x4_t));

  do {
    *mresptr++ = vandq_u32(*mfirstptr++, *msecondptr++);
    width -= sizeof(uint32x4_t) / sizeof(word);
  } while (width);

  return res;
}
#endif
#endif

mzd_local_t* oqs_sig_picnic_mzd_and(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && ((first->ncols & (word_size_bits - 1)) == 0)) {
    return mzd_and_avx(res, first, second);
  }
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && ((first->ncols & (word_size_bits - 1)) == 0)) {
    return mzd_and_sse(res, first, second);
  }
#endif
#ifdef WITH_NEON
  if (CPU_SUPPORTS_NEON && first->ncols % ((first->ncols & (word_size_bits - 1)) == 0)) {
    return mzd_and_neon(res, first, second);
  }
#endif
#endif

  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  while (width--) {
    *resptr++ = *firstptr++ & *secondptr++;
  }

  return res;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_xor_sse(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  __m128i* mresptr          = (__m128i*)ASSUME_ALIGNED(resptr, alignof(__m128i));
  __m128i const* mfirstptr  = (__m128i*)ASSUME_ALIGNED(firstptr, alignof(__m128i));
  __m128i const* msecondptr = (__m128i*)ASSUME_ALIGNED(secondptr, alignof(__m128i));

  do {
    *mresptr++ = _mm_xor_si128(*mfirstptr++, *msecondptr++);
    width -= sizeof(__m128i) / sizeof(word);
  } while (width);

  return res;
}
#endif

#ifdef WITH_AVX2
ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_xor_avx(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  __m256i* mresptr          = (__m256i*)ASSUME_ALIGNED(resptr, alignof(__m256i));
  __m256i const* mfirstptr  = (__m256i*)ASSUME_ALIGNED(firstptr, alignof(__m256i));
  __m256i const* msecondptr = (__m256i*)ASSUME_ALIGNED(secondptr, alignof(__m256i));

  do {
    *mresptr++ = _mm256_xor_si256(*mfirstptr++, *msecondptr++);
    width -= sizeof(__m256i) / sizeof(word);
  } while (width);

  return res;
}
#endif

#ifdef WITH_NEON
inline mzd_local_t* oqs_sig_picnic_mzd_xor_neon(mzd_local_t* res, mzd_local_t const* first,
                                 mzd_local_t const* second) {
  unsigned int width    = first->rowstride;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  uint32x4_t* mresptr          = (uint32x4_t*)ASSUME_ALIGNED(resptr, alignof(uint32x4_t));
  uint32x4_t const* mfirstptr  = (uint32x4_t*)ASSUME_ALIGNED(firstptr, alignof(uint32x4_t));
  uint32x4_t const* msecondptr = (uint32x4_t*)ASSUME_ALIGNED(secondptr, alignof(uint32x4_t));

  do {
    *mresptr++ = veorq_u32(*mfirstptr++, *msecondptr++);
    width -= sizeof(uint32x4_t) / sizeof(word);
  } while (width);

  return res;
}
#endif
#endif

mzd_local_t* oqs_sig_picnic_mzd_xor(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && ((first->ncols & (word_size_bits - 1)) == 0)) {
    return oqs_sig_picnic_mzd_xor_avx(res, first, second);
  }
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && ((first->ncols & (word_size_bits - 1)) == 0)) {
    return oqs_sig_picnic_mzd_xor_sse(res, first, second);
  }
#endif
#ifdef WITH_NEON
  if (CPU_SUPPORTS_NEON && ((first->ncols & (word_size_bits - 1)) == 0)) {
    return oqs_sig_picnic_mzd_xor_neon(res, first, second);
  }
#endif
#endif
  return oqs_sig_picnic_mzd_xor_general(res, first, second);
}

mzd_local_t* oqs_sig_picnic_mzd_xor_general(mzd_local_t* res, mzd_local_t const* first,
                             mzd_local_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  while (width--) {
    *resptr++ = *firstptr++ ^ *secondptr++;
  }

  return res;
}

mzd_local_t* oqs_sig_picnic_mzd_mul_v(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* At) {
  if (At->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_v(c, v, At);
}

mzd_local_t* oqs_sig_picnic_mzd_mul_v_general(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* At) {

  if (At->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_v_general(c, v, At);
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_mul_v_sse(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_v_sse(c, v, A);
}

ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_v_sse(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word* cptr                    = FIRST_ROW(c);
  word const* vptr              = CONST_FIRST_ROW(v);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m128i);
  const unsigned int len        = mrowstride;

  __m128i* mcptr = (__m128i*)ASSUME_ALIGNED(cptr, alignof(__m128i));

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx             = *vptr;
    word const* Aptr     = CONST_ROW(A, w * sizeof(word) * 8);
    __m128i const* mAptr = (__m128i const*)ASSUME_ALIGNED(Aptr, alignof(__m128i));

    for (unsigned int i = 0; i < sizeof(word) * 8; ++i, idx >>= 1, mAptr += mrowstride) {
      const __m128i mask = _mm_set1_epi64x(-(idx & 1));
      mm128_xor_mask_region(mcptr, mAptr, mask, len);
    }
  }

  return c;
}
#endif

#ifdef WITH_AVX2
ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_mul_v_avx(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_v_avx(c, v, A);
}

ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_v_avx(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word* cptr                    = FIRST_ROW(c);
  word const* vptr              = CONST_FIRST_ROW(v);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m256i);
  const unsigned int len        = mrowstride;

  __m256i* mcptr = (__m256i*)ASSUME_ALIGNED(cptr, alignof(__m256i));

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx             = *vptr;
    word const* Aptr     = CONST_ROW(A, w * sizeof(word) * 8);
    __m256i const* mAptr = (__m256i const*)ASSUME_ALIGNED(Aptr, alignof(__m256i));

    for (unsigned int i = 0; i < sizeof(word) * 8; ++i, idx >>= 1, mAptr += mrowstride) {
      const __m256i mask = _mm256_set1_epi64x(-(idx & 1));
      mm256_xor_mask_region(mcptr, mAptr, mask, len);
    }
  }

  return c;
}
#endif

#ifdef WITH_NEON
mzd_local_t* oqs_sig_picnic_mzd_mul_v_neon(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_v_neon(c, v, A);
}

inline mzd_local_t* oqs_sig_picnic_mzd_addmul_v_neon(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word* cptr                    = FIRST_ROW(c);
  word const* vptr              = CONST_FIRST_ROW(v);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(uint32x4_t);
  const unsigned int len        = mrowstride;
  uint32x4_t* mcptr             = ASSUME_ALIGNED(cptr, alignof(uint32x4_t));

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx         = *vptr;
    word const* Aptr = CONST_ROW(A, w * sizeof(word) * 8);

    uint32x4_t const* mAptr = ASSUME_ALIGNED(Aptr, alignof(uint32x4_t));

    for (unsigned int i = 0; i < sizeof(word) * 8; ++i, idx >>= 1, mAptr += mrowstride) {
      const uint32x4_t mask = vreinterpretq_u32_u64(vdupq_n_u64(-(idx & 1)));
      mm128_xor_mask_region(mcptr, mAptr, mask, len);
    }
  }

  return c;
}
#endif
#endif

mzd_local_t* oqs_sig_picnic_mzd_addmul_v(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  if (A->ncols != c->ncols || A->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2 && (A->ncols & 0xff) == 0) {
      return oqs_sig_picnic_mzd_addmul_v_avx(c, v, A);
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2 && (A->ncols & 0x7f) == 0) {
      return oqs_sig_picnic_mzd_addmul_v_sse(c, v, A);
    }
#endif
#ifdef WITH_NEON
    if (CPU_SUPPORTS_NEON && (A->ncols & 0x7f) == 0) {
      return oqs_sig_picnic_mzd_addmul_v_neon(c, v, A);
    }
#endif
  }
#endif

  return oqs_sig_picnic_mzd_addmul_v_general(c, v, A);
}

mzd_local_t* oqs_sig_picnic_mzd_addmul_v_general(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {

  const unsigned int len       = A->width;
  const unsigned int rowstride = A->rowstride;
  word* cptr                   = FIRST_ROW(c);
  word const* vptr             = CONST_FIRST_ROW(v);
  const unsigned int width     = v->width;

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx = *vptr;

    word const* Aptr = CONST_ROW(A, w * sizeof(word) * 8);
    while (idx) {
      if (idx & 0x1) {
        for (unsigned int i = 0; i < len; ++i) {
          cptr[i] ^= Aptr[i];
        }
      }

      Aptr += rowstride;
      idx >>= 1;
    }
  }

  return c;
}

bool oqs_sig_picnic_mzd_local_equal(mzd_local_t const* first, mzd_local_t const* second) {
  if (first == second) {
    return true;
  }
  if (first->ncols != second->ncols || first->nrows != second->nrows) {
    return false;
  }

  const unsigned int rows  = first->nrows;
  const unsigned int width = first->width;

  for (unsigned int r = 0; r < rows; ++r) {
    if (memcmp(ASSUME_ALIGNED(CONST_ROW(first, r), 32), ASSUME_ALIGNED(CONST_ROW(second, r), 32),
               sizeof(word) * width) != 0) {
      return false;
    }
  }

  return true;
}

static void xor_comb(const unsigned int len, word* Brow, mzd_local_t const* A,
                     unsigned int r_offset, unsigned comb) {
  while (comb) {
    const word* Arow = CONST_ROW(A, r_offset);
    if (comb & 0x1) {
      for (unsigned int i = 0; i < len; ++i) {
        Brow[i] ^= Arow[i];
      }
    }

    comb >>= 1;
    ++r_offset;
  }
}

/**
 * Pre-compute matrices for faster mzd_addmul_v computions.
 *
 */
mzd_local_t* oqs_sig_picnic_mzd_precompute_matrix_lookup(mzd_local_t const* A) {
  mzd_local_t* B = oqs_sig_picnic_mzd_local_init_ex(32 * A->nrows, A->ncols, true);

  const unsigned int len = A->width;

  for (unsigned int r = 0; r < B->nrows; ++r) {
    const unsigned int comb     = r & 0xff;
    const unsigned int r_offset = (r >> 8) << 3;
    if (!comb) {
      continue;
    }

    xor_comb(len, ROW(B, r), A, r_offset, comb);
  }

  return B;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_mul_vl_sse_128(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff2 = 256;

  __m128i mc           = _mm_setzero_si128();
  __m128i const* mAptr = (__m128i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m128i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm_xor_si128(mc, mAptr[comb]);
    }
  }

  __m128i* mcptr = (__m128i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m128i));
  *mcptr         = mc;
  return c;
}

ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_mul_vl_sse(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_vl_sse(c, v, A);
}

ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_sse_128(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff2 = 256;

  __m128i* mcptr       = (__m128i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m128i));
  __m128i mc           = *mcptr;
  __m128i const* mAptr = (__m128i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m128i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm_xor_si128(mc, mAptr[comb]);
    }
  }

  *mcptr = mc;
  return c;
}

ATTR_TARGET("sse2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_sse(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr              = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m128i);
  const unsigned int len        = mrowstride;
  const unsigned int moff2      = 256 * mrowstride;

  __m128i* mcptr       = (__m128i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m128i));
  __m128i const* mAptr = (__m128i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m128i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mm128_xor_region(mcptr, mAptr + comb * mrowstride, len);
    }
  }

  return c;
}
#endif

#ifdef WITH_AVX2
ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_mul_vl_avx_256(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff2 = 256;

  __m256i mc           = _mm256_setzero_si256();
  __m256i const* mAptr = (__m256i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m256i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm256_xor_si256(mc, mAptr[comb]);
    }
  }

  __m256i* mcptr = (__m256i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m256i));
  *mcptr         = mc;
  return c;
}

ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_avx_256(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff2 = 256;

  __m256i* mcptr       = (__m256i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m256i));
  __m256i mc           = *mcptr;
  __m256i const* mAptr = (__m256i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m256i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm256_xor_si256(mc, mAptr[comb]);
    }
  }

  *mcptr = mc;
  return c;
}

ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_mul_vl_avx(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_vl_avx(c, v, A);
}

ATTR_TARGET("avx2")
mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_avx(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr              = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m256i);
  const unsigned int moff2      = 256 * mrowstride;
  const unsigned int len        = mrowstride;

  __m256i* mcptr       = (__m256i*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(__m256i));
  __m256i const* mAptr = (__m256i const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(__m256i));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mm256_xor_region(mcptr, mAptr + comb * mrowstride, len);
    }
  }

  return c;
}
#endif

#ifdef WITH_NEON
mzd_local_t* oqs_sig_picnic_mzd_mul_vl_neon_128(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {

  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff2 = 256;

  uint32x4_t mc = vmovq_n_u32(0);
  uint32x4_t const* mAptr =
      (uint32x4_t const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(uint32x4_t));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mc              = veorq_u32(mc, mAptr[comb]);
    }
  }

  uint32x4_t* mcptr = (uint32x4_t*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(uint32x4_t));
  *mcptr            = mc;
  return c;
}

mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_neon_128(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr                = ASSUME_ALIGNED(CONST_FIRST_ROW(v), 16);
  static const unsigned int moff2 = 256;

  uint32x4_t* mcptr = (uint32x4_t*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(uint32x4_t));
  uint32x4_t mc     = *mcptr;
  uint32x4_t const* mAptr =
      (uint32x4_t const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(uint32x4_t));

  word idx = *vptr;
  for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
    const word comb = idx & 0xff;
    mc              = veorq_u32(mc, mAptr[comb]);
  }
  vptr++;
  idx = *vptr;
  for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
    const word comb = idx & 0xff;
    mc              = veorq_u32(mc, mAptr[comb]);
  }
  *mcptr = mc;
  return c;
}

mzd_local_t* oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128(mzd_local_t* c, mzd_local_t const* v,
                                             mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_vl_neon(c, v, A);
}

mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_neon(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  word const* vptr              = ASSUME_ALIGNED(CONST_FIRST_ROW(v), alignof(uint32x4_t));
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(uint32x4_t);
  const unsigned int len        = mrowstride;
  const unsigned int moff2      = 256 * mrowstride;

  uint32x4_t* mcptr = (uint32x4_t*)ASSUME_ALIGNED(FIRST_ROW(c), alignof(uint32x4_t));
  uint32x4_t const* mAptr =
      (uint32x4_t const*)ASSUME_ALIGNED(CONST_FIRST_ROW(A), alignof(uint32x4_t));

  for (unsigned int w = width; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptr += moff2) {
      const word comb = idx & 0xff;
      mm128_xor_region(mcptr, mAptr + comb * mrowstride, len);
    }
  }

  return c;
}
#endif
#endif

mzd_local_t* oqs_sig_picnic_mzd_mul_vl(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  if (A->nrows != 32 * v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2) {
      if (A->ncols == 256) {
        return oqs_sig_picnic_mzd_mul_vl_avx_256(c, v, A);
      }
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2) {
      if (A->ncols == 128) {
        return oqs_sig_picnic_mzd_mul_vl_sse_128(c, v, A);
      }
    }
#endif
#ifdef WITH_NEON
    if (CPU_SUPPORTS_NEON) {
      if (A->ncols == 128) {
        return oqs_sig_picnic_mzd_mul_vl_neon_128(c, v, A);
      }
    }
#endif
  }
#endif
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_vl(c, v, A);
}

mzd_local_t* oqs_sig_picnic_mzd_mul_vl_general(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  oqs_sig_picnic_mzd_local_clear(c);
  return oqs_sig_picnic_mzd_addmul_vl_general(c, v, A);
}

mzd_local_t* oqs_sig_picnic_mzd_addmul_vl(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  if (A->ncols != c->ncols || A->nrows != 32 * v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2) {
      if (A->ncols == 256) {
        return oqs_sig_picnic_mzd_addmul_vl_avx_256(c, v, A);
      }
      if ((A->ncols & 0xff) == 0) {
        return oqs_sig_picnic_mzd_addmul_vl_avx(c, v, A);
      }
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2) {
      if (A->ncols == 128) {
        return oqs_sig_picnic_mzd_addmul_vl_sse_128(c, v, A);
      }
      if ((A->ncols & 0x7f) == 0) {
        return oqs_sig_picnic_mzd_addmul_vl_sse(c, v, A);
      }
    }
#endif
#ifdef WITH_NEON
    if (CPU_SUPPORTS_NEON) {
      if (A->ncols == 128) {
        return oqs_sig_picnic_mzd_addmul_vl_neon_128(c, v, A);
      }
      if ((A->ncols & 0x7f) == 0) {
        return oqs_sig_picnic_mzd_addmul_vl_neon(c, v, A);
      }
    }
#endif
  }
#endif
  return oqs_sig_picnic_mzd_addmul_vl_general(c, v, A);
}

mzd_local_t* oqs_sig_picnic_mzd_addmul_vl_general(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  const unsigned int len   = A->width;
  word* cptr               = FIRST_ROW(c);
  word const* vptr         = CONST_FIRST_ROW(v);
  const unsigned int width = v->width;

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx         = *vptr;
    unsigned int add = 0;

    while (idx) {
      const word comb = idx & 0xff;

      word const* Aptr = CONST_ROW(A, w * sizeof(word) * 8 * 32 + add + comb);
      for (unsigned int i = 0; i < len; ++i) {
        cptr[i] ^= Aptr[i];
      }

      idx >>= 8;
      add += 256;
    }
  }

  return c;
}
