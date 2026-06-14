#include <stdint.h>
#include "params.h"
#include "rounding.h"

/*************************************************
* Name:        power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t power2round(int32_t *a0, int32_t a)  {
  int32_t a1;

  a1 = (a + (1 << (D-1)) - 1) >> D;
  *a0 = a - (a1 << D);
  return a1;
}

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t decompose(int32_t *a0, int32_t a) {
  int32_t a1;

  a1  = (a + 127) >> 7;
#if GAMMA2 == (Q-1)/32
  a1  = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif GAMMA2 == (Q-1)/88
  a1  = (a1*11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif

  *a0  = a - a1*2*GAMMA2;
  *a0 -= (((Q-1)/2 - *a0) >> 31) & Q;
  return a1;
}

/*************************************************
* Name:        make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits. Inputs assumed
*              to be standard representatives.
*
* Arguments:   - int32_t a0: low bits of input element
*              - int32_t a1: high bits of input element
*
* Returns 1 if overflow.
**************************************************/
unsigned int make_hint(int32_t a0, int32_t a1) {
  if(a0 <= GAMMA2 || a0 > Q - GAMMA2 || (a0 == Q - GAMMA2 && a1 == 0))
    return 0;

  return 1;
}

/*************************************************
* Name:        use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - int32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
int32_t use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;

  a1 = decompose(&a0, a);
  if(hint == 0)
    return a1;

#if GAMMA2 == (Q-1)/32
  if(a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
#elif GAMMA2 == (Q-1)/88
  if(a0 > 0)
    return (a1 == 43) ?  0 : a1 + 1;
  else
    return (a1 ==  0) ? 43 : a1 - 1;
#endif
}
