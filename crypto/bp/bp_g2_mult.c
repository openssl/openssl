/*
 * Written by Diego F. Aranha (d@miracl.com) and contributed to the
 * the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */

#include <string.h>
#include <openssl/err.h>

#include "bp_lcl.h"
#include "internal/bn_int.h"

/*
 * Largely based on ec_mult.c
 *
 * This file implements the wNAF-based interleaving multi-exponentiation method
 * (<URL:http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp>);
 * for multiplication with precomputation, we use wNAF splitting
 * (<URL:http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#fastexp>).
 */

/* structure for precomputed multiples of the generator */
struct g2_pre_comp_st {
    const BP_GROUP *group;      /* parent BP_GROUP object */
    size_t blocksize;           /* block size for wNAF splitting */
    size_t numblocks;           /* max. number of blocks for which we have
                                 * precomputation */
    size_t w;                   /* window size */
    G2_ELEM **points;           /* array with pre-calculated multiples of
                                 * generator: 'num' pointers to G2_ELEM
                                 * objects followed by a NULL */
    size_t num;                 /* numblocks * 2^(w-1) */
    int references;
};

static G2_PRE_COMP *g2_pre_comp_new(const BP_GROUP *group)
{
    G2_PRE_COMP *ret = NULL;

    if (group == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return ret;
    ret->group = group;
    ret->blocksize = 8;         /* default */
    ret->w = 4;                 /* default */
    ret->references = 1;
    return ret;
}

G2_PRE_COMP *g2_pre_comp_dup(G2_PRE_COMP *pre)
{
    if (pre != NULL)
        CRYPTO_add(&pre->references, 1, CRYPTO_LOCK_EC_PRE_COMP);
    return pre;
}

void g2_pre_comp_free(G2_PRE_COMP *pre)
{
    if (pre == NULL
        || CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP) > 0)
        return;

    if (pre->points != NULL) {
        G2_ELEM **pts;

        for (pts = pre->points; *pts != NULL; pts++)
            G2_ELEM_free(*pts);
        OPENSSL_free(pre->points);
    }
    OPENSSL_free(pre);
}

/*
 * Table should be optimised for the wNAF-based implementation,
 * sometimes smaller windows will give better performance (thus the
 * boundaries should be increased)
 */
#define G2_window_bits_for_scalar_size(b) \
                ((size_t) \
                 ((b) >= 2000 ? 6 : \
                  (b) >=  800 ? 5 : \
                  (b) >=  300 ? 4 : \
                  (b) >=   70 ? 3 : \
                  (b) >=   20 ? 2 : \
                  1))

int G2_ELEM_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *g_scalar,
                const G2_ELEM *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    const G2_ELEM *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;
    return G2_ELEMs_mul(group, r, g_scalar,
                        (point != NULL
                         && p_scalar != NULL), points, scalars, ctx);

}

/*-
 * Compute
 *      \sum scalars[i]*points[i],
 * also including
 *      scalar*generator
 * in the addition if scalar != NULL
 */
int G2_ELEMs_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G2_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    const G2_ELEM *generator = NULL;
    G2_ELEM *tmp = NULL;
    size_t totalnum;
    size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int r_is_inverted = 0;
    int r_is_at_infinity = 1;
    size_t *wsize = NULL;       /* individual window sizes */
    signed char **wNAF = NULL;  /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;
    size_t num_val;
    G2_ELEM **val = NULL;       /* precomputation */
    G2_ELEM **v;
    G2_ELEM ***val_sub = NULL;  /* pointers to sub-arrays of 'val' or
                                 * 'pre_comp->points' */
    const G2_PRE_COMP *pre_comp = NULL;
    int num_scalar = 0;         /* flag: will be set to 1 if 'scalar' must be
                                 * treated like other scalars, i.e.
                                 * precomputation is not available */
    int ret = 0;

    if (scalar == NULL && num == 0)
        return G2_ELEM_set_to_infinity(group, r);

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    if (scalar != NULL) {
        generator = group->gen2;
        if (generator == NULL) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }

        /* look if we can use precomputed multiples of generator */

        pre_comp = group->g2_pre_comp;
        if (pre_comp && pre_comp->numblocks
            && G2_ELEM_cmp(group, generator, pre_comp->points[0], ctx) == 0) {
            blocksize = pre_comp->blocksize;

            /*
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             */
            numblocks = (BN_num_bits(scalar) / blocksize) + 1;

            /*
             * we cannot use more blocks than we have precomputation for
             */
            if (numblocks > pre_comp->numblocks)
                numblocks = pre_comp->numblocks;

            pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

            /* check that pre_comp looks sane */
            if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* can't use precomputation */
            pre_comp = NULL;
            numblocks = 1;
            num_scalar = 1;     /* treat 'scalar' like 'num'-th element of
                                 * 'scalars' */
        }
    }

    totalnum = num + numblocks;

    wsize = OPENSSL_malloc(totalnum * sizeof wsize[0]);
    wNAF_len = OPENSSL_malloc(totalnum * sizeof wNAF_len[0]);
    wNAF = OPENSSL_malloc((totalnum + 1) * sizeof wNAF[0]); /* includes space
                                                             * for pivot */
    val_sub = OPENSSL_malloc(totalnum * sizeof val_sub[0]);

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF != NULL)
        wNAF[0] = NULL;         /* preliminary pivot */

    if (wsize == NULL || wNAF_len == NULL || wNAF == NULL || val_sub == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    num_val = 0;

    for (i = 0; i < num + num_scalar; i++) {
        size_t bits;

        bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
        wsize[i] = G2_window_bits_for_scalar_size(bits);
        num_val += (size_t)1 << (wsize[i] - 1);
        wNAF[i + 1] = NULL;     /* make sure we always have a pivot */
        wNAF[i] =
            bn_compute_wNAF((i < num ? scalars[i] : scalar), wsize[i],
                            &wNAF_len[i]);
        if (wNAF[i] == NULL)
            goto err;
        if (wNAF_len[i] > max_len)
            max_len = wNAF_len[i];
    }

    if (numblocks) {
        /* we go here iff scalar != NULL */

        if (pre_comp == NULL) {
            if (num_scalar != 1) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* we have already generated a wNAF for 'scalar' */
        } else {
            signed char *tmp_wNAF = NULL;
            size_t tmp_len = 0;

            if (num_scalar != 0) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /*
             * use the window size for which we have precomputation
             */
            wsize[num] = pre_comp->w;
            tmp_wNAF = bn_compute_wNAF(scalar, wsize[num], &tmp_len);
            if (!tmp_wNAF)
                goto err;

            if (tmp_len <= max_len) {
                /*
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 */

                numblocks = 1;
                totalnum = num + 1; /* don't use wNAF splitting */
                wNAF[num] = tmp_wNAF;
                wNAF[num + 1] = NULL;
                wNAF_len[num] = tmp_len;
                if (tmp_len > max_len)
                    max_len = tmp_len;
                /*
                 * pre_comp->points starts with the points that we need here:
                 */
                val_sub[num] = pre_comp->points;
            } else {
                /*
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 */

                signed char *pp;
                G2_ELEM **tmp_points;

                if (tmp_len < numblocks * blocksize) {
                    /*
                     * possibly we can do with fewer blocks than estimated
                     */
                    numblocks = (tmp_len + blocksize - 1) / blocksize;
                    if (numblocks > pre_comp->numblocks) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    totalnum = num + numblocks;
                }

                /* split wNAF in 'numblocks' parts */
                pp = tmp_wNAF;
                tmp_points = pre_comp->points;

                for (i = num; i < totalnum; i++) {
                    if (i < totalnum - 1) {
                        wNAF_len[i] = blocksize;
                        if (tmp_len < blocksize) {
                            ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                            goto err;
                        }
                        tmp_len -= blocksize;
                    } else
                        /*
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         */
                        wNAF_len[i] = tmp_len;

                    wNAF[i + 1] = NULL;
                    wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                    if (wNAF[i] == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if (wNAF_len[i] > max_len)
                        max_len = wNAF_len[i];

                    if (*tmp_points == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    val_sub[i] = tmp_points;
                    tmp_points += pre_points_per_block;
                    pp += blocksize;
                }
                OPENSSL_free(tmp_wNAF);
            }
        }
    }

    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
    if (val == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    val[num_val] = NULL;        /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = G2_ELEM_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((tmp = G2_ELEM_new(group)) == NULL)
        goto err;

    /*-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     */
    for (i = 0; i < num + num_scalar; i++) {
        if (i < num) {
            if (!G2_ELEM_copy(val_sub[i][0], points[i]))
                goto err;
        } else {
            if (!G2_ELEM_copy(val_sub[i][0], generator))
                goto err;
        }

        if (wsize[i] > 1) {
            if (!G2_ELEM_dbl(group, tmp, val_sub[i][0], ctx))
                goto err;
            for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
                if (!G2_ELEM_add
                    (group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
                    goto err;
            }
        }
    }

    if (!G2_ELEMs_make_affine(group, num_val, val, ctx))
        goto err;

    r_is_at_infinity = 1;

    for (k = max_len - 1; k >= 0; k--) {
        if (!r_is_at_infinity) {
            if (!G2_ELEM_dbl(group, r, r, ctx))
                goto err;
        }

        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;

                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != r_is_inverted) {
                        if (!r_is_at_infinity) {
                            if (!G2_ELEM_invert(group, r, ctx))
                                goto err;
                        }
                        r_is_inverted = !r_is_inverted;
                    }

                    /* digit > 0 */

                    if (r_is_at_infinity) {
                        if (!G2_ELEM_copy(r, val_sub[i][digit >> 1]))
                            goto err;
                        r_is_at_infinity = 0;
                    } else {
                        if (!G2_ELEM_add
                            (group, r, r, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }
                }
            }
        }
    }

    if (r_is_at_infinity) {
        if (!G2_ELEM_set_to_infinity(group, r))
            goto err;
    } else {
        if (r_is_inverted)
            if (!G2_ELEM_invert(group, r, ctx))
                goto err;
    }

    ret = 1;
 err:
    BN_CTX_free(new_ctx);
    G2_ELEM_free(tmp);
    OPENSSL_free(wsize);
    OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            G2_ELEM_clear_free(*v);

        OPENSSL_free(val);
    }
    OPENSSL_free(val_sub);
    return ret;
}

/*-
 * g2_wNAF_precompute_mult()
 * creates an G2_PRE_COMP object with preprecomputed multiples of the generator
 * for use with wNAF splitting as implemented in G2_ELEMs_mul().
 *
 * 'pre_comp->points' is an array of multiples of the generator
 * of the following form:
 * points[0] =     generator;
 * points[1] = 3 * generator;
 * ...
 * points[2^(w-1)-1] =     (2^(w-1)-1) * generator;
 * points[2^(w-1)]   =     2^blocksize * generator;
 * points[2^(w-1)+1] = 3 * 2^blocksize * generator;
 * ...
 * points[2^(w-1)*(numblocks-1)-1] = (2^(w-1)) *  2^(blocksize*(numblocks-2)) * generator
 * points[2^(w-1)*(numblocks-1)]   =              2^(blocksize*(numblocks-1)) * generator
 * ...
 * points[2^(w-1)*numblocks-1]     = (2^(w-1)) *  2^(blocksize*(numblocks-1)) * generator
 * points[2^(w-1)*numblocks]       = NULL
 */
int g2_wNAF_precompute_mult(BP_GROUP *group, BN_CTX *ctx)
{
    const G2_ELEM *generator;
    G2_ELEM *tmp_point = NULL, *base = NULL, **var;
    BN_CTX *new_ctx = NULL;
    BIGNUM *order;
    size_t i, bits, w, pre_points_per_block, blocksize, numblocks, num;
    G2_ELEM **points = NULL;
    G2_PRE_COMP *pre_comp;
    int ret = 0;

    /* if there is an old G2_PRE_COMP object, throw it away */
    g2_pre_comp_free(group->g2_pre_comp);
    if ((pre_comp = g2_pre_comp_new(group)) == NULL)
        return 0;

    generator = group->gen2;
    if (generator == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);
    if ((order = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!BP_GROUP_get_order(group, order, ctx))
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * The following parameters mean we precompute (approximately) one point
     * per bit. TBD: The combination 8, 4 is perfect for 160 bits; for other
     * bit lengths, other parameter combinations might provide better
     * efficiency.
     */
    blocksize = 8;
    w = 4;
    if (G2_window_bits_for_scalar_size(bits) > w)
        /* let's not make the window too small ... */
        w = G2_window_bits_for_scalar_size(bits);

    numblocks = (bits + blocksize - 1) / blocksize; /* max. number of blocks
                                                     * to use for wNAF
                                                     * splitting */

    pre_points_per_block = (size_t)1 << (w - 1);
    num = pre_points_per_block * numblocks; /* number of points to compute
                                             * and store */

    points = OPENSSL_malloc(sizeof(*points) * (num + 1));
    if (points == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    var = points;
    var[num] = NULL;            /* pivot */
    for (i = 0; i < num; i++) {
        if ((var[i] = G2_ELEM_new(group)) == NULL) {
            ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if ((tmp_point = G2_ELEM_new(group)) == NULL
        || (base = G2_ELEM_new(group)) == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!G2_ELEM_copy(base, generator))
        goto err;

    /* do the precomputation */
    for (i = 0; i < numblocks; i++) {
        size_t j;

        if (!G2_ELEM_dbl(group, tmp_point, base, ctx))
            goto err;

        if (!G2_ELEM_copy(*var++, base))
            goto err;

        for (j = 1; j < pre_points_per_block; j++, var++) {
            /*
             * calculate odd multiples of the current base point
             */
            if (!G2_ELEM_add(group, *var, tmp_point, *(var - 1), ctx))
                goto err;
        }

        if (i < numblocks - 1) {
            /*
             * get the next base (multiply current one by 2^blocksize)
             */
            size_t k;

            if (blocksize <= 2) {
                ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!G2_ELEM_dbl(group, base, tmp_point, ctx))
                goto err;
            for (k = 2; k < blocksize; k++)
                if (!G2_ELEM_dbl(group, base, base, ctx))
                    goto err;
        }
    }

    if (!G2_ELEMs_make_affine(group, num, points, ctx))
        goto err;

    pre_comp->group = group;
    pre_comp->blocksize = blocksize;
    pre_comp->numblocks = numblocks;
    pre_comp->w = w;
    pre_comp->points = points;
    points = NULL;
    group->g2_pre_comp = pre_comp;
    pre_comp->num = num;
    pre_comp = NULL;

    ret = 1;
 err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    g2_pre_comp_free(pre_comp);
    if (points) {
        G2_ELEM **p;

        for (p = points; *p != NULL; p++)
            G2_ELEM_free(*p);
        OPENSSL_free(points);
    }
    G2_ELEM_free(tmp_point);
    G2_ELEM_free(base);
    return ret;
}
