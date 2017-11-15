/**
 * @file ed448goldilocks/scalar.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Decaf high-level functions.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include "word.h"
#include "constant_time.h"
#include "point_448.h"

/* Template stuff */
#define API_NS(_id) decaf_448_##_id
#define SCALAR_BITS DECAF_448_SCALAR_BITS
#define SCALAR_SER_BYTES DECAF_448_SCALAR_BYTES
#define SCALAR_LIMBS DECAF_448_SCALAR_LIMBS
#define scalar_t API_NS(scalar_t)

static const decaf_word_t MONTGOMERY_FACTOR = (decaf_word_t)0x3bd440fae918bc5ull;
static const scalar_t sc_p = {{{
    SC_LIMB(0x2378c292ab5844f3), SC_LIMB(0x216cc2728dc58f55), SC_LIMB(0xc44edb49aed63690), SC_LIMB(0xffffffff7cca23e9), SC_LIMB(0xffffffffffffffff), SC_LIMB(0xffffffffffffffff), SC_LIMB(0x3fffffffffffffff)
}}}, sc_r2 = {{{
    SC_LIMB(0xe3539257049b9b60), SC_LIMB(0x7af32c4bc1b195d9), SC_LIMB(0x0d66de2388ea1859), SC_LIMB(0xae17cf725ee4d838), SC_LIMB(0x1a9cc14ba3c47c44), SC_LIMB(0x2052bcb7e4d070af), SC_LIMB(0x3402a939f823b729)
}}};
/* End of template stuff */

#define WBITS DECAF_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

const scalar_t API_NS(scalar_one) = {{{1}}}, API_NS(scalar_zero) = {{{0}}};

/** {extra,accum} - sub +? p
 * Must have extra <= 1
 */
static DECAF_NOINLINE void sc_subx(
    scalar_t out,
    const decaf_word_t accum[SCALAR_LIMBS],
    const scalar_t sub,
    const scalar_t p,
    decaf_word_t extra
) {
    decaf_dsword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + accum[i]) - sub->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_word_t borrow = chain+extra; /* = 0 or -1 */
    
    chain = 0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
}

static DECAF_NOINLINE void sc_montmul (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    unsigned int i,j;
    decaf_word_t accum[SCALAR_LIMBS+1] = {0};
    decaf_word_t hi_carry = 0;
    
    for (i=0; i<SCALAR_LIMBS; i++) {
        decaf_word_t mand = a->limb[i];
        const decaf_word_t *mier = b->limb;
        
        decaf_dword_t chain = 0;
        for (j=0; j<SCALAR_LIMBS; j++) {
            chain += ((decaf_dword_t)mand)*mier[j] + accum[j];
            accum[j] = chain;
            chain >>= WBITS;
        }
        accum[j] = chain;
        
        mand = accum[0] * MONTGOMERY_FACTOR;
        chain = 0;
        mier = sc_p->limb;
        for (j=0; j<SCALAR_LIMBS; j++) {
            chain += (decaf_dword_t)mand*mier[j] + accum[j];
            if (j) accum[j-1] = chain;
            chain >>= WBITS;
        }
        chain += accum[j];
        chain += hi_carry;
        accum[j-1] = chain;
        hi_carry = chain >> WBITS;
    }
    
    sc_subx(out, accum, sc_p, sc_p, hi_carry);
}

void API_NS(scalar_mul) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    sc_montmul(out,a,b);
    sc_montmul(out,out,sc_r2);
}

/* PERF: could implement this */
static DECAF_INLINE void sc_montsqr (scalar_t out, const scalar_t a) {
    sc_montmul(out,a,a);
}

decaf_error_t API_NS(scalar_invert) (
    scalar_t out,
    const scalar_t a
) {
    /* Fermat's little theorem, sliding window.
     * Sliding window is fine here because the modulus isn't secret.
     */
    const int SCALAR_WINDOW_BITS = 3;
    scalar_t precmp[1<<SCALAR_WINDOW_BITS];
    const int LAST = (1<<SCALAR_WINDOW_BITS)-1;

    /* Precompute precmp = [a^1,a^3,...] */
    sc_montmul(precmp[0],a,sc_r2);
    if (LAST > 0) sc_montmul(precmp[LAST],precmp[0],precmp[0]);

    int i;
    for (i=1; i<=LAST; i++) {
        sc_montmul(precmp[i],precmp[i-1],precmp[LAST]);
    }
    
    /* Sliding window */
    unsigned residue = 0, trailing = 0, started = 0;
    for (i=SCALAR_BITS-1; i>=-SCALAR_WINDOW_BITS; i--) {
        
        if (started) sc_montsqr(out,out);
        
        decaf_word_t w = (i>=0) ? sc_p->limb[i/WBITS] : 0;
        if (i >= 0 && i<WBITS) {
            assert(w >= 2);
            w-=2;
        }
        
        residue = (residue<<1) | ((w>>(i%WBITS))&1);
        if (residue>>SCALAR_WINDOW_BITS != 0) {
            assert(trailing == 0);
            trailing = residue;
            residue = 0;
        }
        
        if (trailing > 0 && (trailing & ((1<<SCALAR_WINDOW_BITS)-1)) == 0) {
            if (started) {
                sc_montmul(out,out,precmp[trailing>>(SCALAR_WINDOW_BITS+1)]);
            } else {
                API_NS(scalar_copy)(out,precmp[trailing>>(SCALAR_WINDOW_BITS+1)]);
                started = 1;
            }
            trailing = 0;
        }
        trailing <<= 1;
        
    }
    assert(residue==0);
    assert(trailing==0);
    
    /* Demontgomerize */
    sc_montmul(out,out,API_NS(scalar_one));
    decaf_bzero(precmp, sizeof(precmp));
    return decaf_succeed_if(~API_NS(scalar_eq)(out,API_NS(scalar_zero)));
}

void API_NS(scalar_sub) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    sc_subx(out, a->limb, b, sc_p, 0);
}

void API_NS(scalar_add) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + b->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    sc_subx(out, out->limb, sc_p, sc_p, chain);
}

void
API_NS(scalar_set_unsigned) (
    scalar_t out,
    uint64_t w
) {
    memset(out,0,sizeof(scalar_t));
    unsigned int i = 0;
    for (; i<sizeof(uint64_t)/sizeof(decaf_word_t); i++) {
        out->limb[i] = w;
#if DECAF_WORD_BITS < 64
        w >>= 8*sizeof(decaf_word_t);
#endif
    }
}

decaf_bool_t
API_NS(scalar_eq) (
    const scalar_t a,
    const scalar_t b
) {
    decaf_word_t diff = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        diff |= a->limb[i] ^ b->limb[i];
    }
    return mask_to_bool(word_is_zero(diff));
}

static DECAF_INLINE void scalar_decode_short (
    scalar_t s,
    const unsigned char *ser,
    unsigned int nbytes
) {
    unsigned int i,j,k=0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t) && k<nbytes; j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
}

decaf_error_t API_NS(scalar_decode)(
    scalar_t s,
    const unsigned char ser[SCALAR_SER_BYTES]
) {
    unsigned int i;
    scalar_decode_short(s, ser, SCALAR_SER_BYTES);
    decaf_dsword_t accum = 0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - sc_p->limb[i]) >> WBITS;
    }
    /* Here accum == 0 or -1 */
    
    API_NS(scalar_mul)(s,s,API_NS(scalar_one)); /* ham-handed reduce */
    
    return decaf_succeed_if(~word_is_zero(accum));
}

void API_NS(scalar_destroy) (
    scalar_t scalar
) {
    decaf_bzero(scalar, sizeof(scalar_t));
}

void API_NS(scalar_decode_long)(
    scalar_t s,
    const unsigned char *ser,
    size_t ser_len
) {
    if (ser_len == 0) {
        API_NS(scalar_copy)(s, API_NS(scalar_zero));
        return;
    }
    
    size_t i;
    scalar_t t1, t2;

    i = ser_len - (ser_len%SCALAR_SER_BYTES);
    if (i==ser_len) i -= SCALAR_SER_BYTES;
    
    scalar_decode_short(t1, &ser[i], ser_len-i);

    if (ser_len == sizeof(scalar_t)) {
        assert(i==0);
        /* ham-handed reduce */
        API_NS(scalar_mul)(s,t1,API_NS(scalar_one));
        API_NS(scalar_destroy)(t1);
        return;
    }

    while (i) {
        i -= SCALAR_SER_BYTES;
        sc_montmul(t1,t1,sc_r2);
        ignore_result( API_NS(scalar_decode)(t2, ser+i) );
        API_NS(scalar_add)(t1, t1, t2);
    }

    API_NS(scalar_copy)(s, t1);
    API_NS(scalar_destroy)(t1);
    API_NS(scalar_destroy)(t2);
}

void API_NS(scalar_encode)(
    unsigned char ser[SCALAR_SER_BYTES],
    const scalar_t s
) {
    unsigned int i,j,k=0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            ser[k] = s->limb[i] >> (8*j);
        }
    }
}

void API_NS(scalar_cond_sel) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b,
    decaf_bool_t pick_b
) {
    constant_time_select(out,a,b,sizeof(scalar_t),bool_to_mask(pick_b),sizeof(out->limb[0]));
}

void API_NS(scalar_halve) (
    scalar_t out,
    const scalar_t a
) {
    decaf_word_t mask = -(a->limb[0] & 1);
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + (sc_p->limb[i] & mask);
        out->limb[i] = chain;
        chain >>= DECAF_WORD_BITS;
    }
    for (i=0; i<SCALAR_LIMBS-1; i++) {
        out->limb[i] = out->limb[i]>>1 | out->limb[i+1]<<(WBITS-1);
    }
    out->limb[i] = out->limb[i]>>1 | chain<<(WBITS-1);
}

