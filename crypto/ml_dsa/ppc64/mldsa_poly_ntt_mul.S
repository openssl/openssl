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

#define Q_NEG_INV	0
#define V_Q	1
#define ML_DSA_Q_NEG_INV 4236238847

.machine "any"
.text

.macro SAVE_REGS
        stdu    1, -256(1)
        mflr    0
        li      9, 128
        li      10, 144
        li      11, 160
        li      12, 176
        stxvx   32+20, 9, 1
        stxvx   32+21, 10, 1
        stxvx   32+22, 11, 1
        stxvx   32+23, 12, 1
        li      9, 192
        li      10, 208
        li      11, 224
        stxvx   32+24, 9, 1
        stxvx   32+25, 10, 1
        stxvx   32+30, 11, 1
.endm

.macro RESTORE_REGS
        li      9, 128
        li      10, 144
        li      11, 160
        li      12, 176
        lxvx    32+20, 9, 1
        lxvx    32+21, 10, 1
        lxvx    32+22, 11, 1
        lxvx    32+23, 12, 1
        li      9, 192
        li      10, 208
        li      11, 224
        lxvx    32+24, 9, 1
        lxvx    32+25, 10, 1
        lxvx    32+30, 11, 1

        mtlr    0
        addi    1, 1, 256
.endm

.macro Load_poly_points_vectors
	lxvd2x     32+2, 0, 4
	lxvd2x     32+3, 10, 4
	lxvd2x     32+4, 11, 4
	lxvd2x     32+5, 12, 4

	lxvd2x     32+6, 0, 5
	lxvd2x     32+7, 10, 5
	lxvd2x     32+8, 11, 5
	lxvd2x     32+9, 12, 5
	addi    4, 4, 64
	addi    5, 5, 64
.endm

.macro Write_Poly
	stxvd2x     32+10, 0, 3
	stxvd2x     32+11, 10, 3
	stxvd2x     32+12, 11, 3
	stxvd2x     32+13, 12, 3
	addi    3, 3, 64
.endm

/*
 * Reduces x mod q in constant time
 * i.e. return x < q ? x : x - q;
 */
.macro reduce_once_1x _vt
        vsubuwm  16, \_vt, V_Q
        vcmpgtsw 17, V_Q, \_vt
        xxsel   32+\_vt, 32+16, 32+\_vt, 32+17
.endm

/*
 * Montgomery multiply:
 *   Multiply of 2 numbers in montgomery form, in the range 0...(2^32)*q
 */
.macro Mont_point_mul
        vmuleuw 10, 6, 2
        vmulouw 11, 6, 2
        vmuleuw 12, 7, 3
        vmulouw 13, 7, 3
        vmuleuw 14, 8, 4
        vmulouw 15, 8, 4
        vmuleuw 16, 9, 5
        vmulouw 17, 9, 5
.endm

/*
 * Returns:
 *   The Montgomery form of input 'a' with multiplier 2^32 in the range 0..q-1
 *   The result is congruent to x * 2^-32 mod q
 */
.macro Mont_reduce
        vmulouw 18, 10, Q_NEG_INV
        vmulouw 19, 11, Q_NEG_INV
        vmulouw 20, 12, Q_NEG_INV
        vmulouw 21, 13, Q_NEG_INV
        vmulouw 22, 14, Q_NEG_INV
        vmulouw 23, 15, Q_NEG_INV
        vmulouw 24, 16, Q_NEG_INV
        vmulouw 25, 17, Q_NEG_INV

        vmulouw 18, 18, V_Q
        vmulouw 19, 19, V_Q
        vmulouw 20, 20, V_Q
        vmulouw 21, 21, V_Q
        vmulouw 22, 22, V_Q
        vmulouw 23, 23, V_Q
        vmulouw 24, 24, V_Q
        vmulouw 25, 25, V_Q

        vaddudm 18, 18, 10
        vaddudm 19, 19, 11
        vaddudm 20, 20, 12
        vaddudm 21, 21, 13
        vaddudm 22, 22, 14
        vaddudm 23, 23, 15
        vaddudm 24, 24, 16
        vaddudm 25, 25, 17

        vmrgew  10, 18, 19
        vmrgew  11, 20, 21
        vmrgew  12, 22, 23
        vmrgew  13, 24, 25

        reduce_once_1x 10
        reduce_once_1x 11
        reduce_once_1x 12
        reduce_once_1x 13
.endm

/*
 * -----------------------------------
 * Mont_reduce_4x
 */
.macro Mont_reduce_4x
	Load_poly_points_vectors
        Mont_point_mul
        Mont_reduce
	Write_Poly
.endm

/*
 * mldsa_poly_ntt_mult(poly *c, const poly *a, const poly *b)
 */
.global mldsa_poly_ntt_mult
.align 4
mldsa_poly_ntt_mult:
.localentry     mldsa_poly_ntt_mult,.-mldsa_poly_ntt_mult

	SAVE_REGS

	/* load Q and Q_NEG_INV */
	addis   8,2,.mldsa_consts@toc@ha
	addi    8,8,.mldsa_consts@toc@l
	lvx     V_Q, 0, 8
        li      10, 16
	lvx     Q_NEG_INV, 10, 8

	/*
	 * Montgomery reduce loops for a * b
	 *
	 *  c[j] = montgomery_reduce(a[j] * b[j])
	 */
        li       10, 16
        li       11, 32
        li       12, 48

	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x
	Mont_reduce_4x

	RESTORE_REGS
	blr
.size     mldsa_poly_ntt_mult,.-mldsa_poly_ntt_mult

.data
.align 4
.mldsa_consts:
# Q = 8380417
.long  8380417, 8380417, 8380417, 8380417
.long  ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV
