/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: modular arithmetic optimized for x64 platforms for P751
*********************************************************************************************/

/* OQS note: not needed since this file is #included in another source file
#include "../P751_internal.h"


// Global constants
extern const uint64_t p751[NWORDS_FIELD];
extern const uint64_t p751p1[NWORDS_FIELD]; 
extern const uint64_t p751x2[NWORDS_FIELD]; 
*/

__inline void fpadd751(const digit_t* a, const digit_t* b, digit_t* c)
{ // Modular addition, c = a+b mod p751.
  // Inputs: a, b in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
    
#if (OS_TARGET == OS_WIN)
    unsigned int i, carry = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], b[i], carry, c[i]); 
    }

    carry = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(carry, c[i], ((digit_t*)p751x2)[i], carry, c[i]); 
    }
    mask = 0 - (digit_t)carry;

    carry = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, c[i], ((digit_t*)p751x2)[i] & mask, carry, c[i]); 
    } 
    
#elif (OS_TARGET == OS_LINUX)                 
    
    fpadd751_asm(a, b, c);    

#endif
} 


__inline void fpsub751(const digit_t* a, const digit_t* b, digit_t* c)
{ // Modular subtraction, c = a-b mod p751.
  // Inputs: a, b in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
    
#if (OS_TARGET == OS_WIN)
    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]); 
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, c[i], ((digit_t*)p751x2)[i] & mask, borrow, c[i]); 
    }
    
#elif (OS_TARGET == OS_LINUX)                 
    
    fpsub751_asm(a, b, c);    

#endif
}


__inline void fpneg751(digit_t* a)
{ // Modular negation, a = -a mod p751.
  // Input/output: a in [0, 2*p751-1] 
    unsigned int i, borrow = 0;
    
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, ((digit_t*)p751x2)[i], a[i], borrow, a[i]); 
    }
}


void fpdiv2_751(const digit_t* a, digit_t* c)
{ // Modular division by two, c = a/2 mod p751.
  // Input : a in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
    unsigned int i, carry = 0;
    digit_t mask;
        
    mask = 0 - (digit_t)(a[0] & 1);    // If a is odd compute a+p751
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], ((digit_t*)p751)[i] & mask, carry, c[i]); 
    }

    mp_shiftr1(c, NWORDS_FIELD);
}  


void fpcorrection751(digit_t* a)
{ // Modular correction to reduce field element a in [0, 2*p751-1] to [0, p751-1].
    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], ((digit_t*)p751)[i], borrow, a[i]); 
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, a[i], ((digit_t*)p751)[i] & mask, borrow, a[i]); 
    }
}


void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords.
        
    UNREFERENCED_PARAMETER(nwords);

#if (OS_TARGET == OS_WIN)
    digit_t t = 0;
    uint128_t uv = {0};
    unsigned int carry = 0;
        
    MULADD128(a[0], b[0], uv, carry, uv);
    t += carry;
    c[0] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[0], uv, carry, uv);
    t += carry;
    c[1] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[0], uv, carry, uv);
    t += carry;
    c[2] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[0], uv, carry, uv);
    t += carry;
    c[3] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[0], uv, carry, uv);
    t += carry;
    c[4] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[0], uv, carry, uv);
    t += carry;
    c[5] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[0], uv, carry, uv);
    t += carry;
    c[6] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[0], uv, carry, uv);
    t += carry;
    c[7] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[0], uv, carry, uv);
    t += carry;
    c[8] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[0], uv, carry, uv);
    t += carry;
    c[9] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[0], uv, carry, uv);
    t += carry;
    c[10] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[11], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[11], b[0], uv, carry, uv);
    t += carry;
    c[11] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;    
    
    MULADD128(a[1], b[11], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[11], b[1], uv, carry, uv);
    t += carry;
    c[12] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[11], uv, carry, uv);
    t += carry;
    c[13] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[11], uv, carry, uv);
    t += carry;
    c[14] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[11], uv, carry, uv);
    t += carry;
    c[15] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[11], uv, carry, uv);
    t += carry;
    c[16] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[11], uv, carry, uv);
    t += carry;
    c[17] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[7], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[7], b[11], uv, carry, uv);
    t += carry;
    c[18] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[8], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[8], b[11], uv, carry, uv);
    t += carry;
    c[19] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[9], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[9], b[11], uv, carry, uv);
    t += carry;
    c[20] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[11], b[10], uv, carry, uv);
    t += carry;
    MULADD128(a[10], b[11], uv, carry, uv);
    t += carry;
    c[21] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    
    MULADD128(a[11], b[11], uv, carry, uv);
    c[22] = uv[0];
    c[23] = uv[1];

#elif (OS_TARGET == OS_LINUX)
    
    mul751_asm(a, b, c);

#endif
}


void rdc_mont(const digit_t* ma, digit_t* mc)
{ // Efficient Montgomery reduction using comba and exploiting the special form of the prime p751.
  // mc = ma*R^-1 mod p751x2, where R = 2^768.
  // If ma < 2^768*p751, the output mc is in the range [0, 2*p751-1].
  // ma is assumed to be in Montgomery representation.
        
#if (OS_TARGET == OS_WIN)
    unsigned int carry;
    digit_t t = 0;
    uint128_t uv = {0};
    
    mc[0] = ma[0];
    mc[1] = ma[1];
    mc[2] = ma[2];
    mc[3] = ma[3];
    mc[4] = ma[4];
    MUL128(mc[0], ((digit_t*)p751p1)[5], uv);
    ADDC(0, uv[0], ma[5], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    mc[5] = uv[0];
    uv[0] = uv[1];
    uv[1] = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[6], uv, carry, uv);
    MULADD128(mc[1], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[6], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[6] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[7], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[7] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[8], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[8] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[9], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[9] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[10], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[10] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[11], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[11] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[1], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[12], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[0] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[2], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[13], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[1] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[3], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[14], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[2] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[4], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[15], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[3] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[5], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[16], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[4] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[6], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[7], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[6], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[17], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[5] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[7], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[8], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[7], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[18], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[6] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[8], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[9], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[8], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[19], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[7] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[9], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[10], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[9], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[20], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[8] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[10], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    MULADD128(mc[11], ((digit_t*)p751p1)[10], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[21], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[9] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[11], ((digit_t*)p751p1)[11], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[22], carry, mc[10]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    ADDC(0, uv[1], ma[23], carry, mc[11]); 
    
#elif (OS_TARGET == OS_LINUX)                 
    
    rdc751_asm(ma, mc);    

#endif
}
