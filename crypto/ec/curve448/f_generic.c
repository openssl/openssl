/**
 * @file p448/f_generic.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Generic arithmetic which has to be compiled per field.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include "field.h"

static const gf MODULUS = {FIELD_LITERAL(
    0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff, 0xfffffffffffffe, 0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff
)};
    
#if P_MOD_8 == 5
    const gf SQRT_MINUS_ONE = {FIELD_LITERAL(
        /* NOPE */
    )};
#endif

/** Serialize to wire format. */
void gf_serialize (uint8_t serial[SER_BYTES], const gf x, int with_hibit) {
    gf red;
    gf_copy(red, x);
    gf_strong_reduce(red);
    if (!with_hibit) { assert(gf_hibit(red) == 0); }
    
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    UNROLL for (unsigned int i=0; i<(with_hibit ? X_SER_BYTES : SER_BYTES); i++) {
        if (fill < 8 && j < NLIMBS) {
            buffer |= ((dword_t)red->limb[LIMBPERM(j)]) << fill;
            fill += LIMB_PLACE_VALUE(LIMBPERM(j));
            j++;
        }
        serial[i] = buffer;
        fill -= 8;
        buffer >>= 8;
    }
}

/** Return high bit of x = low bit of 2x mod p */
mask_t gf_hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_strong_reduce(y);
    return -(y->limb[0]&1);
}

/** Return high bit of x = low bit of 2x mod p */
mask_t gf_lobit(const gf x) {
    gf y;
    gf_copy(y,x);
    gf_strong_reduce(y);
    return -(y->limb[0]&1);
}

/** Deserialize from wire format; return -1 on success and 0 on failure. */
mask_t gf_deserialize (gf x, const uint8_t serial[SER_BYTES], int with_hibit, uint8_t hi_nmask) {
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    dsword_t scarry = 0;
    const unsigned nbytes = with_hibit ? X_SER_BYTES : SER_BYTES;
    UNROLL for (unsigned int i=0; i<NLIMBS; i++) {
        UNROLL while (fill < LIMB_PLACE_VALUE(LIMBPERM(i)) && j < nbytes) {
            uint8_t sj = serial[j];
            if (j==nbytes-1) sj &= ~hi_nmask;
            buffer |= ((dword_t)sj) << fill;
            fill += 8;
            j++;
        }
        x->limb[LIMBPERM(i)] = (i<NLIMBS-1) ? buffer & LIMB_MASK(LIMBPERM(i)) : buffer;
        fill -= LIMB_PLACE_VALUE(LIMBPERM(i));
        buffer >>= LIMB_PLACE_VALUE(LIMBPERM(i));
        scarry = (scarry + x->limb[LIMBPERM(i)] - MODULUS->limb[LIMBPERM(i)]) >> (8*sizeof(word_t));
    }
    mask_t succ = with_hibit ? -(mask_t)1 : ~gf_hibit(x);
    return succ & word_is_zero(buffer) & ~word_is_zero(scarry);
}

/** Reduce to canonical form. */
void gf_strong_reduce (gf a) {
    /* first, clear high */
    gf_weak_reduce(a); /* Determined to have negligible perf impact. */

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */
    dsword_t scarry = 0;
    for (unsigned int i=0; i<NLIMBS; i++) {
        scarry = scarry + a->limb[LIMBPERM(i)] - MODULUS->limb[LIMBPERM(i)];
        a->limb[LIMBPERM(i)] = scarry & LIMB_MASK(LIMBPERM(i));
        scarry >>= LIMB_PLACE_VALUE(LIMBPERM(i));
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
     * common case: it was < p, so now scarry = -1 and this = x - p + 2^255
     * so let's add back in p.  will carry back off the top for 2^255.
     */
    assert(word_is_zero(scarry) | word_is_zero(scarry+1));

    word_t scarry_0 = scarry;
    dword_t carry = 0;

    /* add it back */
    for (unsigned int i=0; i<NLIMBS; i++) {
        carry = carry + a->limb[LIMBPERM(i)] + (scarry_0 & MODULUS->limb[LIMBPERM(i)]);
        a->limb[LIMBPERM(i)] = carry & LIMB_MASK(LIMBPERM(i));
        carry >>= LIMB_PLACE_VALUE(LIMBPERM(i));
    }

    assert(word_is_zero(carry + scarry_0));
}

/** Subtract two gf elements d=a-b */
void gf_sub (gf d, const gf a, const gf b) {
    gf_sub_RAW ( d, a, b );
    gf_bias( d, 2 );
    gf_weak_reduce ( d );
}

/** Add two field elements d = a+b */
void gf_add (gf d, const gf a, const gf b) {
    gf_add_RAW ( d, a, b );
    gf_weak_reduce ( d );
}

/** Compare a==b */
mask_t gf_eq(const gf a, const gf b) {
    gf c;
    gf_sub(c,a,b);
    gf_strong_reduce(c);
    mask_t ret=0;
    for (unsigned int i=0; i<NLIMBS; i++) {
        ret |= c->limb[LIMBPERM(i)];
    }

    return word_is_zero(ret);
}
