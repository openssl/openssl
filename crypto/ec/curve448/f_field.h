/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef __P448_F_FIELD_H__
# define __P448_F_FIELD_H__ 1

# include "constant_time.h"
# include <string.h>
# include <assert.h>

# include "word.h"

# define NLIMBS (64/sizeof(word_t))
# define X_SER_BYTES 56
# define SER_BYTES 56
typedef struct gf_s {
    word_t limb[NLIMBS];
} __attribute__ ((aligned(32))) gf_s, gf[1];

/* RFC 7748 support */
# define X_PUBLIC_BYTES  X_SER_BYTES
# define X_PRIVATE_BYTES X_PUBLIC_BYTES
# define X_PRIVATE_BITS  448

# define INLINE_UNUSED __inline__ __attribute__((unused,always_inline))

#ifdef __cplusplus
extern "C" {
#endif

/* Defined below in f_impl.h */
static INLINE_UNUSED void gf_copy(gf out, const gf a)
{
    *out = *a;
}

static INLINE_UNUSED void gf_add_RAW(gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_sub_RAW(gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_bias(gf inout, int amount);
static INLINE_UNUSED void gf_weak_reduce(gf inout);

void gf_strong_reduce(gf inout);
void gf_add(gf out, const gf a, const gf b);
void gf_sub(gf out, const gf a, const gf b);
void gf_mul(gf_s * __restrict__ out, const gf a, const gf b);
void gf_mulw_unsigned(gf_s * __restrict__ out, const gf a, uint32_t b);
void gf_sqr(gf_s * __restrict__ out, const gf a);
mask_t gf_isr(gf a, const gf x); /** a^2 x = 1, QNR, or 0 if x=0.  Return true if successful */
mask_t gf_eq(const gf x, const gf y);
mask_t gf_lobit(const gf x);
mask_t gf_hibit(const gf x);

void gf_serialize(uint8_t *serial, const gf x, int with_highbit);
mask_t gf_deserialize(gf x, const uint8_t serial[SER_BYTES], int with_hibit,
                      uint8_t hi_nmask);


#ifdef __cplusplus
} /* extern "C" */
#endif

# include "f_impl.h"            /* Bring in the inline implementations */

# ifndef LIMBPERM
#  define LIMBPERM(i) (i)
# endif
# define LIMB_MASK(i) (((1)<<LIMB_PLACE_VALUE(i))-1)

static const gf ZERO = {{{0}}}, ONE = {{{1}}};

#endif                          /* __P448_F_FIELD_H__ */
