/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Copyright IBM Corp. 2025, 2026
 *
 * ===================================================================================
 * Written by Danny Tsen <dtsen@us.ibm.com>
 */

#define ML_DSA_Q 8380417   /* The modulus is 23 bits (2^23 - 2^13 + 1) */

#define V_Q     0

.machine "any"
.text

/*
 * Load polynominals
 */
.macro Load_poly
        lxvd2x  32+1, 0, 3
        lxvd2x  32+2, 6, 3
        lxvd2x  32+3, 7, 3
        lxvd2x  32+4, 8, 3
        lxvd2x  32+5, 0, 4
        lxvd2x  32+6, 6, 4
        lxvd2x  32+7, 7, 4
        lxvd2x  32+8, 8, 4
        addi  3, 3, 64
        addi  4, 4, 64
.endm

/*
 * Reduces x mod q in constant time
 * i.e. return x < q ? x : x - q;
 */
.macro reduce_once_1x _vt
        vsubuwm  19, \_vt, V_Q
        vcmpgtsw 18, V_Q, \_vt
        xxsel   32+\_vt, 32+19, 32+\_vt, 32+18
.endm

/*
 * Calculate The positive value of (a-b) mod q in constant time.
 *
 * a - b mod q gives a value in the range -(q-1)..(q-1)
 * By adding q we get a range of 1..(2q-1).
 * Reducing this once then gives the range 0..q-1
 *
 * returns The value (q + a - b) mod q
 */
.macro mod_sub _x _a _b
        vadduwm 18, \_a, V_Q
        vsubuwm \_x, 18, \_b
        reduce_once_1x \_x
.endm

.macro Write_out
        stxvd2x 32+9, 0, 5
        stxvd2x 32+10, 6, 5
        stxvd2x 32+11, 7, 5
        stxvd2x 32+12, 8, 5
        addi  5, 5, 64
.endm

/*
 * Returns: The returned addition result with the coefficients all in the
 *          range 0..q-1
 */
.macro poly_add
        Load_poly
        vaddudm 9, 1, 5
        vaddudm 10, 2, 6
        vaddudm 11, 3, 7
        vaddudm 12, 4, 8

        reduce_once_1x 9
        reduce_once_1x 10
        reduce_once_1x 11
        reduce_once_1x 12
        Write_out
.endm

.macro poly_add_4x
        poly_add
        poly_add
        poly_add
        poly_add
.endm

/*
 * Returns: The returned subtraction result with the coefficients all in the
 *          range 0..q-1
 */
.macro poly_sub
        Load_poly
        mod_sub 9, 1, 5
        mod_sub 10, 2, 6
        mod_sub 11, 3, 7
        mod_sub 12, 4, 8
        Write_out
.endm

.macro poly_sub_4x
        poly_sub
        poly_sub
        poly_sub
        poly_sub
.endm

/*
 * mldsa_poly_add(const POLY *lhs, const POLY *rhs, POLY *out)
 *   Polynomial addition.
 */
.global mldsa_poly_add
.align 4
mldsa_poly_add:
.localentry     mldsa_poly_add,.-mldsa_poly_add

        stdu    1, -16(1)
        mflr    0

        /* load Q and Q_NEG_INV */
        addis   8,2,.mldsa_consts@toc@ha
        addi    8,8,.mldsa_consts@toc@l
        lvx     V_Q, 0, 8

        li  6, 16
        li  7, 32
        li  8, 48

        poly_add_4x
        poly_add_4x
        poly_add_4x
        poly_add_4x

        mtlr    0
        addi    1, 1, 16
        blr
.size     mldsa_poly_add,.-mldsa_poly_add

/*
 * mldsa_poly_sub(const POLY *lhs, const POLY *rhs, POLY *out)
 *   Polynomial subtraction.
 */
.global mldsa_poly_sub
.align 4
mldsa_poly_sub:
.localentry     mldsa_poly_sub,.-mldsa_poly_sub

        stdu    1, -16(1)
        mflr    0

        /* load Q and Q_NEG_INV */
        addis   8,2,.mldsa_consts@toc@ha
        addi    8,8,.mldsa_consts@toc@l
        lvx     V_Q, 0, 8

        li  6, 16
        li  7, 32
        li  8, 48

        poly_sub_4x
        poly_sub_4x
        poly_sub_4x
        poly_sub_4x

        mtlr    0
        addi    1, 1, 16
        blr
.size     mldsa_poly_sub,.-mldsa_poly_sub

.rodata
.align 4
.mldsa_consts:
.long ML_DSA_Q, ML_DSA_Q, ML_DSA_Q, ML_DSA_Q
