/*
  aesenc-int.c version $Date: 2014/08/22 16:49:12 $
  AES-CTR
  Romain Dolbeau
  Public Domain
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "crypto_stream_aes256ctr.h"

#ifdef __INTEL_COMPILER
#define ALIGN16 __declspec(align(16))
#define ALIGN32 __declspec(align(32))
#define ALIGN64 __declspec(align(64))
#else // assume GCC
#define ALIGN16  __attribute__((aligned(16)))
#define ALIGN32  __attribute__((aligned(32)))
#define ALIGN64  __attribute__((aligned(64)))
#define _bswap64(a) __builtin_bswap64(a)
#define _bswap(a) __builtin_bswap(a)
#endif

static inline void aesni_key256_expand(const unsigned char* key, __m128 rkeys[16]) {
  __m128 key0 = _mm_loadu_ps((const float *)(key+0));
  __m128 key1 = _mm_loadu_ps((const float *)(key+16));
  __m128 temp0, temp1, temp2, temp4;
  int idx = 0;

  rkeys[idx++] = key0;
  temp0 = key0;
  temp2 = key1;
  temp4 = _mm_setzero_ps();

  /* why single precision floating-point rather than integer instructions ?
     because _mm_shuffle_ps takes two inputs, while _mm_shuffle_epi32 only
     takes one - it doesn't perform the same computation...
     _mm_shuffle_ps takes the lower 64 bits of the result from the first
     operand, and the higher 64 bits of the result from the second operand
     (in both cases, all four input floats are accessible).
     I don't like the non-orthogonal naming scheme :-(
     
     This is all strongly inspired by the openssl assembly code.
  */
#define BLOCK1(IMM)                                                     \
  temp1 = (__m128)_mm_aeskeygenassist_si128((__m128i)temp2, IMM);       \
  rkeys[idx++] = temp2;                                                 \
  temp4 = _mm_shuffle_ps(temp4, temp0, 0x10);                           \
  temp0 = _mm_xor_ps(temp0, temp4);                                     \
  temp4 = _mm_shuffle_ps(temp4, temp0, 0x8c);                           \
  temp0 = _mm_xor_ps(temp0, temp4);                                     \
  temp1 = _mm_shuffle_ps(temp1, temp1, 0xff);                           \
  temp0 = _mm_xor_ps(temp0, temp1)
  
#define BLOCK2(IMM)                                                     \
  temp1 = (__m128)_mm_aeskeygenassist_si128((__m128i)temp0, IMM);       \
  rkeys[idx++] = temp0;                                                 \
  temp4 = _mm_shuffle_ps(temp4, temp2, 0x10);                           \
  temp2 = _mm_xor_ps(temp2, temp4);                                     \
  temp4 = _mm_shuffle_ps(temp4, temp2, 0x8c);                           \
  temp2 = _mm_xor_ps(temp2, temp4);                                     \
  temp1 = _mm_shuffle_ps(temp1, temp1, 0xaa);                           \
  temp2 = _mm_xor_ps(temp2, temp1)
  
  BLOCK1(0x01);
  BLOCK2(0x01);

  BLOCK1(0x02);
  BLOCK2(0x02);

  BLOCK1(0x04);
  BLOCK2(0x04);

  BLOCK1(0x08);
  BLOCK2(0x08);

  BLOCK1(0x10);
  BLOCK2(0x10);

  BLOCK1(0x20);
  BLOCK2(0x20);

  BLOCK1(0x40);
  rkeys[idx++] = temp0;
}

/** single, by-the-book AES encryption with AES-NI */
static inline void aesni_encrypt1(unsigned char *out, unsigned char *n, __m128i rkeys[16]) {
  __m128i nv = _mm_load_si128((const __m128i *)n);
  int i;
  __m128i temp = _mm_xor_si128(nv, rkeys[0]);
#pragma unroll(13)
  for (i = 1 ; i < 14 ; i++) {
    temp = _mm_aesenc_si128(temp, rkeys[i]);
  }
  temp = _mm_aesenclast_si128(temp, rkeys[14]);
  _mm_store_si128((__m128i*)(out), temp);
}

/** increment the 16-bytes nonce ;
    this really should be improved somehow...
    but it's not yet time-critical, because we
    use the vector variant anyway  */
static inline void incle(unsigned char n[16]) {
/*   unsigned long long out; */
/*   unsigned char carry; */
  unsigned long long *n_ = (unsigned long long*)n;
  n_[1]++;
  if (n_[1] == 0)
    n_[0] ++;
  /* perhaps this will be efficient on broadwell ? */
  /*   carry = _addcarry_u64(0, n_[1], 1ULL, &out); */
  /*   carry = _addcarry_u64(carry, n_[0], 0ULL, &out); */
}

/** multiple-blocks-at-once AES encryption with AES-NI ;
    on Haswell, aesenc as a latency of 7 and a througput of 1
    so the sequence of aesenc should be bubble-free, if you
    have at least 8 blocks. Let's build an arbitratry-sized
    function */
/* Step 1 : loading the nonce */
/* load & increment the n vector (non-vectorized, unused for now) */
#define NVx(a)                                                  \
  __m128i nv##a = _mm_shuffle_epi8(_mm_load_si128((const __m128i *)n), _mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7)); incle(n)
/* load the incremented n vector (vectorized, probably buggy) */
#define NVxV_DEC(a)                                                     \
  __m128i nv##a;
#define NVxV_NOWRAP(a)                                                  \
  nv##a = _mm_shuffle_epi8(_mm_add_epi64(nv0i, _mm_set_epi64x(a,0)), _mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7))
#define NVxV_WRAP(a)                                                    \
  __m128i ad##a = _mm_add_epi64(nv0i, _mm_set_epi64x(a,a>=wrapnumber?1:0)); \
  nv##a = _mm_shuffle_epi8(ad##a, _mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7))

/* Step 2 : define value in round one (xor with subkey #0, aka key) */
#define TEMPx(a)                                        \
  __m128i temp##a = _mm_xor_si128(nv##a, rkeys[0])

/* Step 3: one round of AES */
#define AESENCx(a)                                      \
  temp##a =  _mm_aesenc_si128(temp##a, rkeys[i]);

/* Step 4: last round of AES */
#define AESENCLASTx(a)                                  \
  temp##a = _mm_aesenclast_si128(temp##a, rkeys[14]);

/* Step 5: store result */
#define STOREx(a)                                       \
  _mm_store_si128((__m128i*)(out+(a*16)), temp##a);

/* all the MAKE* macros are for automatic explicit unrolling */
#define MAKE4(X)                                \
  X(0);X(1);X(2);X(3)

#define MAKE6(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5)

#define MAKE7(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6)

#define MAKE8(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7)

#define MAKE10(X)                               \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7);                          \
  X(8);X(9)

#define MAKE12(X)                               \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7);                          \
  X(8);X(9);X(10);X(11)

/* create a function of unrolling N ; the MAKEN is the unrolling
   macro, defined above. The N in MAKEN must match N, obviously. */
#define FUNC(N, MAKEN)                          \
  static inline void aesni_encrypt##N(unsigned char *out, unsigned char *n, __m128i rkeys[16]) { \
    __m128i nv0i = _mm_load_si128((const __m128i *)n);                  \
    long long nl = *(long long*)&n[8];                                  \
    MAKEN(NVxV_DEC);                                                    \
    /* check for nonce wraparound */                                    \
    if ((nl < 0) && (nl + (N-1)) >= 0) {                                \
      int wrapnumber = (int)(N - (nl+N));                               \
      MAKEN(NVxV_WRAP);                                                 \
      _mm_storeu_si128((__m128i*)n, _mm_add_epi64(nv0i, _mm_set_epi64x(N,1))); \
    } else {                                                            \
      MAKEN(NVxV_NOWRAP);                                               \
      _mm_storeu_si128((__m128i*)n, _mm_add_epi64(nv0i, _mm_set_epi64x(N,0))); \
    }                                                                   \
    int i;                                                              \
    MAKEN(TEMPx);                                                       \
    for (i = 1 ; i < 14 ; i++) {                                        \
      MAKEN(AESENCx);                                                   \
    }                                                                   \
    MAKEN(AESENCLASTx);                                                 \
    MAKEN(STOREx);                                                      \
  }

/* and now building our unrolled function is trivial */
FUNC(4, MAKE4)
FUNC(6, MAKE6)
FUNC(7, MAKE7)
FUNC(8, MAKE8)
FUNC(10, MAKE10)
FUNC(12, MAKE12)

int crypto_stream_aes256ctr(
unsigned char *out,
unsigned long long outlen,
const unsigned char *n,
const unsigned char *k
)
{
  __m128 rkeys[16];
  ALIGN16 unsigned char n2[16];
  unsigned long long i, j;
  aesni_key256_expand(k, rkeys);
  /* n2 is in byte-reversed (i.e., native little endian)
     order to make increment/testing easier */
  (*(unsigned long long*)&n2[8]) = _bswap64((*(unsigned long long*)&n[8]));
  (*(unsigned long long*)&n2[0]) = _bswap64((*(unsigned long long*)&n[0]));
  
#define LOOP(iter)                                       \
  int lb = iter * 16;                                    \
  for (i = 0 ; i < outlen ; i+= lb) {                    \
    ALIGN16 unsigned char outni[lb];       \
    aesni_encrypt##iter(outni, n2, (__m128i*)rkeys);     \
    unsigned long long mj = lb;                          \
    if ((i+mj)>=outlen)                                  \
      mj = outlen-i;                                     \
    for (j = 0 ; j < mj ; j++)                           \
      out[i+j] = outni[j];                               \
  }
  
  LOOP(8);

  return 0;
}
