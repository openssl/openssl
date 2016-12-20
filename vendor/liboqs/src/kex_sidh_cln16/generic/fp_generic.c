/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: portable modular arithmetic
*
*********************************************************************************************/

#include "../SIDH_internal.h"


// Global constants
extern const uint64_t p751[NWORDS_FIELD];
extern const uint64_t p751p1[NWORDS_FIELD]; 
extern const uint64_t p751x2[NWORDS_FIELD]; 


__inline void oqs_sidh_cln16_fpadd751(digit_t* a, digit_t* b, digit_t* c)
{ // Modular addition, c = a+b mod p751.
  // Inputs: a, b in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
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
} 


__inline void oqs_sidh_cln16_fpsub751(digit_t* a, digit_t* b, digit_t* c)
{ // Modular subtraction, c = a-b mod p751.
  // Inputs: a, b in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
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
}


__inline void oqs_sidh_cln16_fpneg751(digit_t* a)
{ // Modular negation, a = -a mod p751.
  // Input/output: a in [0, 2*p751-1] 
    unsigned int i, borrow = 0;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, ((digit_t*)p751x2)[i], a[i], borrow, a[i]); 
    }
}


void oqs_sidh_cln16_fpdiv2_751(digit_t* a, digit_t* c)
{ // Modular division by two, c = a/2 mod p751.
  // Input : a in [0, 2*p751-1] 
  // Output: c in [0, 2*p751-1] 
    unsigned int i, carry = 0;
    digit_t mask;
        
    mask = 0 - (digit_t)(a[0] & 1);    // If a is odd compute a+p521
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], ((digit_t*)p751)[i] & mask, carry, c[i]); 
    }

    oqs_sidh_cln16_mp_shiftr1(c, NWORDS_FIELD);
} 


void oqs_sidh_cln16_fpcorrection751(digit_t* a)
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


void oqs_sidh_cln16_digit_x_digit(digit_t a, digit_t b, digit_t* c)
{ // Digit multiplication, digit * digit -> 2-digit result    
    register digit_t al, ah, bl, bh, temp;
    digit_t albl, albh, ahbl, ahbh, res1, res2, res3, carry;
    digit_t mask_low = (digit_t)(-1) >> (sizeof(digit_t)*4), mask_high = (digit_t)(-1) << (sizeof(digit_t)*4);

    al = a & mask_low;                        // Low part
    ah = a >> (sizeof(digit_t) * 4);          // High part
    bl = b & mask_low;
    bh = b >> (sizeof(digit_t) * 4);

    albl = al*bl;
    albh = al*bh;
    ahbl = ah*bl;
    ahbh = ah*bh;
    c[0] = albl & mask_low;                   // C00

    res1 = albl >> (sizeof(digit_t) * 4);
    res2 = ahbl & mask_low;
    res3 = albh & mask_low;  
    temp = res1 + res2 + res3;
    carry = temp >> (sizeof(digit_t) * 4);
    c[0] ^= temp << (sizeof(digit_t) * 4);    // C01   

    res1 = ahbl >> (sizeof(digit_t) * 4);
    res2 = albh >> (sizeof(digit_t) * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    c[1] = temp & mask_low;                   // C10 
    carry = temp & mask_high; 
    c[1] ^= (ahbh & mask_high) + carry;       // C11
}

 
void oqs_sidh_cln16_mp_mul_schoolbook(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision schoolbook multiply, c = a*b, where lng(a) = lng(b) = nwords.   
    unsigned int i, j;
    digit_t u, v, UV[2];
    unsigned int carry = 0;

     for (i = 0; i < (2*nwords); i++) c[i] = 0;

     for (i = 0; i < nwords; i++) {
          u = 0;
          for (j = 0; j < nwords; j++) {
               MUL(a[i], b[j], UV+1, UV[0]); 
               ADDC(0, UV[0], u, carry, v); 
               u = UV[1] + carry;
               ADDC(0, c[i+j], v, carry, v); 
               u = u + carry;
               c[i+j] = v;
          }
          c[nwords+i] = u;
     }
}


void oqs_sidh_cln16_mp_mul_comba(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.   
    unsigned int i, j;
    digit_t t = 0, u = 0, v = 0, UV[2];
    unsigned int carry = 0;
    
    for (i = 0; i < nwords; i++) {
        for (j = 0; j <= i; j++) {
            MUL(a[j], b[i-j], UV+1, UV[0]); 
            ADDC(0, UV[0], v, carry, v); 
            ADDC(carry, UV[1], u, carry, u); 
            t += carry;
        }
        c[i] = v;
        v = u; 
        u = t;
        t = 0;
    }

    for (i = nwords; i < 2*nwords-1; i++) {
        for (j = i-nwords+1; j < nwords; j++) {
            MUL(a[j], b[i-j], UV+1, UV[0]); 
            ADDC(0, UV[0], v, carry, v); 
            ADDC(carry, UV[1], u, carry, u); 
            t += carry;
        }
        c[i] = v;
        v = u; 
        u = t;
        t = 0;
    }
    c[2*nwords-1] = v; 
}


void oqs_sidh_cln16_rdc_mont(oqs_sidh_cln16_dfelm_t ma, oqs_sidh_cln16_felm_t mc)
{ // Optimized Montgomery reduction using comba and exploiting the special form of the prime p751.
  // mc = ma*mb*R^-1 mod p751, where ma,mb,mc in [0, p751-1] and R = 2^768.
  // ma and mb are assumed to be in Montgomery representation.
    unsigned int i, j, carry, count = p751_ZERO_WORDS;
    digit_t UV[2], t = 0, u = 0, v = 0;

    for (i = 0; i < NWORDS_FIELD; i++) {
        mc[i] = 0;
    }

    for (i = 0; i < NWORDS_FIELD; i++) {
        for (j = 0; j < i; j++) {
            if (j < (i-p751_ZERO_WORDS+1)) { 
                MUL(mc[j], ((digit_t*)p751p1)[i-j], UV+1, UV[0]);
                ADDC(0, UV[0], v, carry, v); 
                ADDC(carry, UV[1], u, carry, u); 
                t += carry; 
            }
        }
        ADDC(0, v, ma[i], carry, v); 
        ADDC(carry, u, 0, carry, u); 
        t += carry; 
        mc[i] = v;
        v = u;
        u = t;
        t = 0;
    }    

    for (i = NWORDS_FIELD; i < 2*NWORDS_FIELD-1; i++) {
        if (count > 0) {
            count -= 1;
        }
        for (j = i-NWORDS_FIELD+1; j < NWORDS_FIELD; j++) {
            if (j < (NWORDS_FIELD-count)) { 
                MUL(mc[j], ((digit_t*)p751p1)[i-j], UV+1, UV[0]);
                ADDC(0, UV[0], v, carry, v); 
                ADDC(carry, UV[1], u, carry, u); 
                t += carry;
            }
        }
        ADDC(0, v, ma[i], carry, v); 
        ADDC(carry, u, 0, carry, u); 
        t += carry; 
        mc[i-NWORDS_FIELD] = v;
        v = u;
        u = t;
        t = 0;
    }
    ADDC(0, v, ma[2*NWORDS_FIELD-1], carry, v); 
    mc[NWORDS_FIELD-1] = v;
}
