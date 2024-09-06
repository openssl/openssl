#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>
#include "verify.h"

/*************************************************
* Name:        verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len: length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint64_t r;
  __m256i f, g, h;

  h = _mm256_setzero_si256();
  for(i=0;i<len/32;i++) {
    f = _mm256_loadu_si256((__m256i *)&a[32*i]);
    g = _mm256_loadu_si256((__m256i *)&b[32*i]);
    f = _mm256_xor_si256(f,g);
    h = _mm256_or_si256(h,f);
  }
  r = 1 - _mm256_testz_si256(h,h);

  a += 32*i;
  b += 32*i;
  len -= 32*i;
  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  r = (-r) >> 63;
  return r;
}

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *r: pointer to output byte array
*              const uint8_t *x: pointer to input byte array
*              size_t len: Amount of bytes to be copied
*              uint8_t b: Condition bit; has to be in {0,1}
**************************************************/
void cmov(uint8_t * restrict r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;
  __m256i xvec, rvec, bvec;

  bvec = _mm256_set1_epi64x(-(uint64_t)b);
  for(i=0;i<len/32;i++) {
    rvec = _mm256_loadu_si256((__m256i *)&r[32*i]);
    xvec = _mm256_loadu_si256((__m256i *)&x[32*i]);
    rvec = _mm256_blendv_epi8(rvec,xvec,bvec);
    _mm256_storeu_si256((__m256i *)&r[32*i],rvec);
  }

  r += 32*i;
  x += 32*i;
  len -= 32*i;
  for(i=0;i<len;i++)
    r[i] ^= -b & (x[i] ^ r[i]);
}
