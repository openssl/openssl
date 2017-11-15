/* Copyright (c) 2014-2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#define GF_HEADROOM 2
#define LIMBPERM(x) (((x)<<1 | (x)>>3) & 15)
#define USE_NEON_PERM 1
#define LIMBHI(x) ((x##ull)>>28)
#define LIMBLO(x) ((x##ull)&((1ull<<28)-1))
#  define FIELD_LITERAL(a,b,c,d,e,f,g,h) \
    {{LIMBLO(a),LIMBLO(e), LIMBHI(a),LIMBHI(e), \
      LIMBLO(b),LIMBLO(f), LIMBHI(b),LIMBHI(f), \
      LIMBLO(c),LIMBLO(g), LIMBHI(c),LIMBHI(g), \
      LIMBLO(d),LIMBLO(h), LIMBHI(d),LIMBHI(h)}}
    
#define LIMB_PLACE_VALUE(i) 28

void gf_add_RAW (gf out, const gf a, const gf b) {
    for (unsigned int i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] + ((const uint32xn_t*)b)[i];
    }
}

void gf_sub_RAW (gf out, const gf a, const gf b) {
    for (unsigned int i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] - ((const uint32xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void gf_bias (gf a, int amt) {
    uint32_t co1 = ((1ull<<28)-1)*amt, co2 = co1-amt;
    uint32x4_t lo = {co1,co2,co1,co1}, hi = {co1,co1,co1,co1};
    uint32x4_t *aa = (uint32x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
    aa[2] += hi;
    aa[3] += hi;
}

void gf_weak_reduce (gf a) {

    uint32x2_t *aa = (uint32x2_t*) a, vmask = {(1ull<<28)-1, (1ull<<28)-1}, vm2 = {0,-1},
       tmp = vshr_n_u32(aa[7],28);
       
    for (unsigned int i=7; i>=1; i--) {
        aa[i] = vsra_n_u32(aa[i] & vmask, aa[i-1], 28);
    }
    aa[0] = (aa[0] & vmask) + vrev64_u32(tmp) + (tmp&vm2);
}

