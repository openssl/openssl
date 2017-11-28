/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__) && !I_HATE_UNROLLED_LOOPS) \
     || defined(DECAF_FORCE_UNROLL)
#define REPEAT8(_x) _x _x _x _x _x _x _x _x
#define FOR_LIMB(_i,_start,_end,_x) do { _i=_start; REPEAT8( if (_i<_end) { _x; } _i++;) } while (0)
#else
#define FOR_LIMB(_i,_start,_end,_x) do { for (_i=_start; _i<_end; _i++) _x; } while (0)
#endif

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) { 
    const uint32_t *a = as->limb, *b = bs->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0 = 0, accum1 = 0, accum2 = 0;
    uint32_t mask = (1<<28) - 1;  

    uint32_t aa[8], bb[8];
    
    int i,j;
    for (i=0; i<8; i++) {
        aa[i] = a[i] + a[i+8];
        bb[i] = b[i] + b[i+8];
    }
    
    FOR_LIMB(j,0,8,{
        accum2 = 0;
    
        FOR_LIMB (i,0,j+1,{
            accum2 += widemul(a[j-i],b[i]);
            accum1 += widemul(aa[j-i],bb[i]);
            accum0 += widemul(a[8+j-i], b[8+i]);
        });
        
        accum1 -= accum2;
        accum0 += accum2;
        accum2 = 0;
    
        FOR_LIMB (i,j+1,8,{
            accum0 -= widemul(a[8+j-i], b[i]);
            accum2 += widemul(aa[8+j-i], bb[i]);
            accum1 += widemul(a[16+j-i], b[8+i]);
        });

        accum1 += accum2;
        accum0 += accum2;

        c[j] = ((uint32_t)(accum0)) & mask;
        c[j+8] = ((uint32_t)(accum1)) & mask;

        accum0 >>= 28;
        accum1 >>= 28;
    });
    
    accum0 += accum1;
    accum0 += c[8];
    accum1 += c[0];
    c[8] = ((uint32_t)(accum0)) & mask;
    c[0] = ((uint32_t)(accum1)) & mask;
    
    accum0 >>= 28;
    accum1 >>= 28;
    c[9] += ((uint32_t)(accum0));
    c[1] += ((uint32_t)(accum1));
}

void gf_mulw_unsigned (gf_s *__restrict__ cs, const gf as, uint32_t b) {
    const uint32_t *a = as->limb;
    uint32_t *c = cs->limb;
    uint64_t accum0 = 0, accum8 = 0;
    uint32_t mask = (1<<28)-1;  
    int i;

    assert(b<1<<28);

    FOR_LIMB(i,0,8,{
        accum0 += widemul(b, a[i]);
        accum8 += widemul(b, a[i+8]);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
    });

    accum0 += accum8 + c[8];
    c[8] = accum0 & mask;
    c[9] += accum0 >> 28;

    accum8 += c[0];
    c[0] = accum8 & mask;
    c[1] += accum8 >> 28;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    gf_mul(cs,as,as); /* Performs better with a dedicated square */
}

