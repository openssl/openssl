/* Copyright (c) 2014-2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#define GF_HEADROOM 2
#define LIMB(x) (x)&((1<<28)-1), (x)>>28
#define FIELD_LITERAL(a,b,c,d,e,f,g,h) \
    {{LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e),LIMB(f),LIMB(g),LIMB(h)}}
    
#define LIMB_PLACE_VALUE(i) 28

void gf_add_RAW (gf out, const gf a, const gf b) {
    unsigned int i;

    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
}

void gf_sub_RAW (gf out, const gf a, const gf b) {
    unsigned int i;

    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
}

void gf_bias (gf a, int amt) {
    unsigned int i;
    uint32_t co1 = ((1<<28)-1)*amt, co2 = co1-amt;

    for (i=0; i<sizeof(*a)/sizeof(a->limb[0]); i++) {
        a->limb[i] += (i==sizeof(*a)/sizeof(a->limb[0])/2) ? co2 : co1;
    }
}

void gf_weak_reduce (gf a) {
    uint32_t mask = (1<<28) - 1;
    uint32_t tmp = a->limb[15] >> 28;
    unsigned int i;

    a->limb[8] += tmp;
    for (i=15; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>28);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

