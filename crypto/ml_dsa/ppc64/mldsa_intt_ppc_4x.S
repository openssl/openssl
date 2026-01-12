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
 *
 * Optimized inverse NTT implementation for ppc64le.
 */

#define Q_NEG_INV_OFFSET 16
#define FCONST_OFFSET 32
#define ZETA_INTT_OFFSET 48

#define ML_DSA_Q 8380417   /* The modulus is 23 bits (2^23 - 2^13 + 1) */
#define ML_DSA_Q_NEG_INV 4236238847 /* Inverse of -q modulo 2^32 */

#define Q_NEG_INV    0
#define V_Q     1
#define V_F     2
#define V_ZETA  2
#define V_Z0    2
#define V_Z1    3
#define V_Z2    4
#define V_Z3    5

.machine "any"
.text

.macro SAVE_REGS
        stdu    1, -352(1)
        mflr    0
        std     14, 56(1)
        std     15, 64(1)
        std     16, 72(1)
        std     17, 80(1)
        std     18, 88(1)
        std     19, 96(1)
        std     20, 104(1)
        std     21, 112(1)
        li      10, 128
        li      11, 144
        li      12, 160
        li      14, 176
        li      15, 192
        li      16, 208
        stxvx   32+20, 10, 1
        stxvx   32+21, 11, 1
        stxvx   32+22, 12, 1
        stxvx   32+23, 14, 1
        stxvx   32+24, 15, 1
        stxvx   32+25, 16, 1
        li      10, 224
        li      11, 240
        li      12, 256
        li      14, 272
        li      15, 288
        li      16, 304
        stxvx   32+26, 10, 1
        stxvx   32+27, 11, 1
        stxvx   32+28, 12, 1
        stxvx   32+29, 14, 1
        stxvx   32+30, 15, 1
        stxvx   32+31, 16, 1
.endm

.macro RESTORE_REGS
        li      10, 128
        li      11, 144
        li      12, 160
        li      14, 176
        li      15, 192
        li      16, 208
        lxvx    32+20, 10, 1
        lxvx    32+21, 11, 1
        lxvx    32+22, 12, 1
        lxvx    32+23, 14, 1
        lxvx    32+24, 15, 1
        lxvx    32+25, 16, 1
        li      10, 224
        li      11, 240
        li      12, 256
        li      14, 272
        li      15, 288
        li      16, 304
        lxvx    32+26, 10, 1
        lxvx    32+27, 11, 1
        lxvx    32+28, 12, 1
        lxvx    32+29, 14, 1
        lxvx    32+30, 15, 1
        lxvx    32+31, 16, 1
        ld      14, 56(1)
        ld      15, 64(1)
        ld      16, 72(1)
        ld      17, 80(1)
        ld      18, 88(1)
        ld      19, 96(1)
        ld      20, 104(1)
        ld      21, 112(1)

        mtlr    0
        addi    1, 1, 352
.endm

/*
 * Init_Coeffs_offset: initial offset setup for the coeeficient array.
 *
 * start: beginning of the offset to the coefficient array.
 * next: Next offset.
 * len: Index difference between coefficients.
 *
 * r7: len * 2, each coefficient component is 32 bits.
 *
 * registers used for offset to coefficients, r[j] and r[j+len]
 * R9: offset to r0 = j
 * R16: offset to r1 = r0 + next
 * R18: offset to r2 = r1 + next
 * R20: offset to r3 = r2 + next
 *
 * R10: offset to r'0 = r0 + len*2
 * R17: offset to r'1 = r'0 + next
 * R19: offset to r'2 = r'1 + next
 * R21: offset to r'3 = r'2 + next
 *
 */
.macro Init_Coeffs_offset start next
        li      9, \start       /* first offset to j */
        add     10, 7, 9        /* J + len*2 */
        addi    16, 9, \next
        addi    17, 10, \next
        addi    18, 16, \next
        addi    19, 17, \next
        addi    20, 18, \next
        addi    21, 19, \next
.endm

/*
 * For Len=1, load 1-1-1-1 layout
 *
 * Load Coeffients and setup vectors
 *    rj0, rjlen1, rj2, rjlen3
 *    rj4, rjlen5, rj6, rjlen7
 *
 *  Each vmrgew and vmrgow will transpose vectors as,
 *
 *   rj vector = (rj0, rj4, rj2, rj6)
 *   rjlen vector = (rjlen1, rjlen5, rjlen3, rjlen7)
 *
 *  r' =r[j+len]: V18, V19, V20, V21
 *  r = r[j]: V14, V15, V16, V17
 *
 * In order to do the coefficients computation, zeta vector will arrange
 * in the proper order to match the multiplication.
 */
.macro Load_41Coeffs
        lxvd2x     32+10, 0, 5
        lxvd2x     32+11, 10, 5
        vmrgew 18, 10, 11
        vmrgow 14, 10, 11
        lxvd2x     32+12, 11, 5
        lxvd2x     32+13, 12, 5
        vmrgew 19, 12, 13
        vmrgow 15, 12, 13
        lxvd2x     32+10, 15, 5
        lxvd2x     32+11, 16, 5
        vmrgew 20, 10, 11
        vmrgow 16, 10, 11
        lxvd2x     32+12, 17, 5
        lxvd2x     32+13, 18, 5
        vmrgew 21, 12, 13
        vmrgow 17, 12, 13
.endm

/*
 * For Len=2, Load 2 - 2 - 2 - 2 layout
 *
 * Load Coefficients and setup vectors for 8 coefficients in the
 * following order,
 *    rj0, rj1, rjlen2, rjlen3,
 *    rj4, rj5, rjlen6, arlen7
 *  Each xxpermdi will transpose vectors as,
 *  r[j]=      rj0, rj1, rj4, rj5
 *  r[j+len]=  rjlen2, rjlen3, rjlen6, arlen7
 *
 *  r' =r[j+len]: V18, V19, V20, V21
 *  r = r[j]: V14, V15, V16, V17
 *
 * In order to do the coefficients computation, zeta vector will arrange
 * in the proper order to match the multiplication.
 */
.macro Load_42Coeffs
        lxvd2x     1, 0, 5
        lxvd2x     2, 10, 5
        xxpermdi 32+18, 1, 2, 3
        xxpermdi 32+14, 1, 2, 0
        lxvd2x     3, 11, 5
        lxvd2x     4, 12, 5
        xxpermdi 32+19, 3, 4, 3
        xxpermdi 32+15, 3, 4, 0
        lxvd2x     1, 15, 5
        lxvd2x     2, 16, 5
        xxpermdi 32+20, 1, 2, 3
        xxpermdi 32+16, 1, 2, 0
        lxvd2x     3, 17, 5
        lxvd2x     4, 18, 5
        xxpermdi 32+21, 3, 4, 3
        xxpermdi 32+17, 3, 4, 0
.endm

/*
 * For Len=8,
 * Load coefficient with 2 legs with 64  bytes apart in
 *  r[j+len] (r') vectors from offset, R10, R17, R19 and R21
 *  r[j] (r) vectors from offset, R9, R16, R18 and R20
 *  r[j+len]: V18, V19, V20, V21
 *  r = r[j]: V14, V15, V16, V17
 */
.macro Load_22Coeffs start next
        li      9, \start
        add     10, 7, 9
        addi    16, 9, \next
        addi    17, 10, \next
        li      18, \start+64
        add     19, 7, 18
        addi    20, 18, \next
        addi    21, 19, \next
        lxvd2x  32+18, 3, 10
        lxvd2x  32+19, 3, 17
        lxvd2x  32+20, 3, 19
        lxvd2x  32+21, 3, 21

        lxvd2x  32+14, 3, 9
        lxvd2x  32+15, 3, 16
        lxvd2x  32+16, 3, 18
        lxvd2x  32+17, 3, 20
.endm

/*
 * Load coefficient with 2 legs with len*2 bytes apart in
 *  r[j+len] (r') vectors from offset, R10, R17, R19 and R21
 *  r[j] (r) vectors from offset, R9, R16, R18 and R20
 *  r[j+len]: V18, V19, V20, V21
 *  r = r[j]: V14, V15, V16, V17
 */
.macro Load_4Coeffs start next
        Init_Coeffs_offset \start, \next

        lxvd2x  32+18, 3, 10
        lxvd2x  32+19, 3, 17
        lxvd2x  32+20, 3, 19
        lxvd2x  32+21, 3, 21

        lxvd2x  32+14, 3, 9
        lxvd2x  32+15, 3, 16
        lxvd2x  32+16, 3, 18
        lxvd2x  32+17, 3, 20
.endm

/*
 * Reduces x mod q in constant time
 * i.e. return x < q ? x : x - q;
 */
.macro reduce_once_1x _vt
        vsubuwm  30, \_vt, V_Q
        vcmpgtsw 31, V_Q, \_vt
        xxsel   32+\_vt, 32+30, 32+\_vt, 32+31
.endm

/*
 * Compute final final r[j] and r[j+len]
 *  final r[j]: V26, V27, V28, V29
 *  final r[j+len]: V6, V7, V8, V9
 */
.macro Compute_4Coeff
        vadduwm 26, 14, 18
        reduce_once_1x 26
        vsubuwm 6, 14, 18
        vadduwm 6, 6, V_Q

        vadduwm 27, 15, 19
        reduce_once_1x 27
        vsubuwm 7, 15, 19
        vadduwm 7, 7, V_Q

        vadduwm 28, 16, 20
        reduce_once_1x 28
        vsubuwm 8, 16, 20
        vadduwm 8, 8, V_Q

        vadduwm 29, 17, 21
        reduce_once_1x 29
        vsubuwm 9, 17, 21
        vadduwm 9, 9, V_Q
.endm

.macro Write_One
        stxvd2x 32+26, 3, 9
        stxvd2x 32+10, 3, 10
        stxvd2x 32+27, 3, 16
        stxvd2x 32+11, 3, 17
        stxvd2x 32+28, 3, 18
        stxvd2x 32+12, 3, 19
        stxvd2x 32+29, 3, 20
        stxvd2x 32+13, 3, 21
.endm

/*
 * For Len=2
 * Transpose the final coefficients of 2-2-2-2 layout to the orginal
 * coefficient array order.
 */
.macro PermWrite42
        xxpermdi 32+14, 32+26, 32+10, 0
        xxpermdi 32+15, 32+26, 32+10, 3
        xxpermdi 32+16, 32+27, 32+11, 0
        xxpermdi 32+17, 32+27, 32+11, 3
        xxpermdi 32+18, 32+28, 32+12, 0
        xxpermdi 32+19, 32+28, 32+12, 3
        xxpermdi 32+20, 32+29, 32+13, 0
        xxpermdi 32+21, 32+29, 32+13, 3
        stxvd2x    32+14, 0, 5
        stxvd2x    32+15, 10, 5
        stxvd2x    32+16, 11, 5
        stxvd2x    32+17, 12, 5
        stxvd2x    32+18, 15, 5
        stxvd2x    32+19, 16, 5
        stxvd2x    32+20, 17, 5
        stxvd2x    32+21, 18, 5
.endm

/*
 * For Len=1
 * Transpose the final coefficients of 1-1-1-1 layout to the orginal
 * coefficient array order.
 */
.macro PermWrite41
        vmrgew 14, 10, 26
        vmrgow 15, 10, 26
        vmrgew 16, 11, 27
        vmrgow 17, 11, 27
        vmrgew 18, 12, 28
        vmrgow 19, 12, 28
        vmrgew 20, 13, 29
        vmrgow 21, 13, 29
        stxvd2x    32+14, 0, 5
        stxvd2x    32+15, 10, 5
        stxvd2x    32+16, 11, 5
        stxvd2x    32+17, 12, 5
        stxvd2x    32+18, 15, 5
        stxvd2x    32+19, 16, 5
        stxvd2x    32+20, 17, 5
        stxvd2x    32+21, 18, 5
.endm

.macro Load_next_4zetas
        li      10, 16
        li      11, 32
        li      12, 48
        lxvd2x  32+V_Z0, 0, 14
        lxvd2x  32+V_Z1, 10, 14
        lxvd2x  32+V_Z2, 11, 14
        lxvd2x  32+V_Z3, 12, 14
        addi    14, 14, 64
.endm

/*
 * Montgomery multiply:
 *   Multiply of 2 numbers in montgomery form, in the range 0...(2^32)*q
 */
.macro Mont_point_mul  _vz0 _vz1 _vz2 _vz3
        vmuleuw 10, 6, \_vz0
        vmulouw 11, 6, \_vz0
        vmuleuw 12, 7, \_vz1
        vmulouw 13, 7, \_vz1
        vmuleuw 14, 8, \_vz2
        vmulouw 15, 8, \_vz2
        vmuleuw 16, 9, \_vz3
        vmulouw 17, 9, \_vz3
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
 * montgomery_reduce
 *  montgomery_reduce((int64_t)zeta * a[j + len])
 *    a = zeta * a[j+len]
 *    t = (int64_t)(int32_t)a*QINV;
 *    t = (a - (int64_t)t*Q) >> 32;
 *
 * Or
 *  montgomery_reduce((int64_t)f * a[j])
 *
 * -----------------------------------
 * MREDUCE_4X(_vz0, _vz1, _vz2, _vz3)
 */
.macro MREDUCE_4x  _vz0 _vz1 _vz2 _vz3
        Mont_point_mul \_vz0, \_vz1, \_vz2, \_vz3
        Mont_reduce
.endm

/*
 * For Len=1, layer with 1-1-1-1 layout.
 */
.macro iNTT_MREDUCE_41x
        Load_next_4zetas
        Load_41Coeffs
        Compute_4Coeff
        MREDUCE_4x V_Z0, V_Z1, V_Z2, V_Z3
        PermWrite41
        addi    5, 5, 128
.endm

/*
 * For Len=2, layer with 2-2-2-2 layout.
 */
.macro iNTT_MREDUCE_42x
        Load_next_4zetas
        Load_42Coeffs
        Compute_4Coeff
        MREDUCE_4x V_Z0, V_Z1, V_Z2, V_Z3
        PermWrite42
        addi    5, 5, 128
.endm

/*
 * For Len=8
 */
.macro iNTT_MREDUCE_22x  start next _vz0 _vz1 _vz2 _vz3
        Load_22Coeffs \start, \next
        Compute_4Coeff
        MREDUCE_4x \_vz0, \_vz1, \_vz2, \_vz3
        Write_One
.endm

/*
 * For Len=128, 64, 32, 16 and 4.
 */
.macro iNTT_MREDUCE_4x  start next _vz0 _vz1 _vz2 _vz3
        Load_4Coeffs \start, \next
        Compute_4Coeff
        MREDUCE_4x \_vz0, \_vz1, \_vz2, \_vz3
        Write_One
.endm

.macro Reload_4coeffs
        lxvd2x  32+6, 0, 6
        lxvd2x  32+7, 10, 6
        lxvd2x  32+8, 11, 6
        lxvd2x  32+9, 12, 6
.endm

.macro Write_F
        stxvd2x 32+10, 0, 6
        stxvd2x 32+11, 10, 6
        stxvd2x 32+12, 11, 6
        stxvd2x 32+13, 12, 6
        addi    6, 6, 64
.endm

.macro POLY_Mont_Reduce_4x
        Reload_4coeffs
        MREDUCE_4x V_F, V_F, V_F, V_F
        Write_F

        Reload_4coeffs
        MREDUCE_4x V_F, V_F, V_F, V_F
        Write_F

        Reload_4coeffs
        MREDUCE_4x V_F, V_F, V_F, V_F
        Write_F

        Reload_4coeffs
        MREDUCE_4x V_F, V_F, V_F, V_F
        Write_F
.endm

/*
 * mldsa_poly_ntt_inverse(int32_t *r)
 *
 *   Compute Inverse NTT based on the following 8 layers -
 *     len = 1, 2, 4, 8, 16, 32, 64, 128.
 *
 *   Each layer compute the coeffients on 2 legs, start and start + len*2 offsets.
 *
 *   leg 1                        leg 2
 *   -----                        -----
 *   start                        start+len*2
 *   start+next                   start+len*2+next
 *   start+next+next              start+len*2+next+next
 *   start+next+next+next         start+len*2+next+next+next
 *
 *   Each computation loads 8 vectors, 4 for each leg.
 *   The final coefficient (t) from each vector of leg1 and leg2 then do the
 *   add/sub operations to obtain the final results.
 *
 *   -> leg1 = leg1 + t, leg2 = leg1 - t
 *
 *   The resulting coeffients then store back to each leg's offset.
 *
 *   Each vector has the same corresponding zeta except len=2.
 *
 *   len=2 has 2-2-2-2 layout which means every 2 32-bit coeffients has the same zeta.
 *   e.g.
 *         coeff vector    a1   a2   a3  a4  a5  a6  a7  a8
 *         zeta  vector    z1   z1   z2  z2  z3  z3  z4  z4
 *
 *   For len=2, each vector will get permuted to leg1 and leg2. Zeta is
 *   pre-arranged for the leg1 and leg2.  After the computation, each vector needs
 *   to transpose back to its original 2-2-2-2 layout.       
 *
 */
.global mldsa_poly_ntt_inverse
.align 4
mldsa_poly_ntt_inverse:
.localentry     mldsa_poly_ntt_inverse,.-mldsa_poly_ntt_inverse

        SAVE_REGS

        /* load Q and Q_NEG_INV */
        addis   8,2,.mldsa_consts@toc@ha
        addi    8,8,.mldsa_consts@toc@l
        lvx     V_Q, 0, 8
        li      10, Q_NEG_INV_OFFSET
        lvx     Q_NEG_INV, 10, 8

        /* set zetas array */
	addi    14, 8, ZETA_INTT_OFFSET

.align 4
        /*
         * 1. len = 1, start = 0, 2, 4, 6, 8, 10, 12,...254
         *
         *    Compute coefficients of the inverse NTT based on the following sequences,
         *      0, 1, 2, 3
         *      4, 5, 6, 7
         *      8, 9, 10, 11
         *      12, 13, 14, 15
         *            ...
         *      240, 241, 242, 243
         *      244, 245, 246, 247
         *      248, 249, 250, 251
         *      252, 253, 254, 255
         *
         *     These are indexes to the 32 bits array.  Each loads 4 vectors.
         */
        mr      5, 3
        li      7, 4

        li      10, 16
        li      11, 32
        li      12, 48
        li      15, 64
        li      16, 80
        li      17, 96
        li      18, 112

        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x
        iNTT_MREDUCE_41x

.align 4
        /*
         * 2. len = 2, start = 0, 4, 8, 12,...244, 248, 252 
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        4
         *        8        -        12
         *          16        -        20
         *                    ...
         *            240        -        244
         *              248        -        252
         *
         *     These are indexes to the 32 bits array
         */
        mr      5, 3
        li      7, 8

        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x
        iNTT_MREDUCE_42x

.align 4
        /*
         * 3. len = 4, start = 0, 32, 64, 96, 128, 160, 192, 224
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        4
         *        32        -        36
         *          64        -        68
         *                    ...
         *            192        -        196
         *              224        -        228
         *
         *     These are indexes to the 32 bits array
         */

        li      7, 16

        Load_next_4zetas
        iNTT_MREDUCE_4x 0, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*2, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*3, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*4, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*5, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*6, 32, V_Z0, V_Z1, V_Z2, V_Z3
        Load_next_4zetas
        iNTT_MREDUCE_4x 128*7, 32, V_Z0, V_Z1, V_Z2, V_Z3

.align 4
        /*
         * 4. len = 8, start = 0, 32, 64, 96, 128, 160, 192, 224
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        8
         *        32        -        40
         *          64        -        72
         *                    ...
         *            192        -        200
         *              224        -        232
         *
         *     These are indexes to the 32 bits array
         */

        li      7, 32
        Load_next_4zetas
        iNTT_MREDUCE_22x 0, 16, V_Z0, V_Z0, V_Z1, V_Z1
        iNTT_MREDUCE_22x 128, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        iNTT_MREDUCE_22x 128*2, 16, V_Z0, V_Z0, V_Z1, V_Z1
        iNTT_MREDUCE_22x 128*3, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        iNTT_MREDUCE_22x 128*4, 16, V_Z0, V_Z0, V_Z1, V_Z1
        iNTT_MREDUCE_22x 128*5, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        iNTT_MREDUCE_22x 128*6, 16, V_Z0, V_Z0, V_Z1, V_Z1
        iNTT_MREDUCE_22x 128*7, 16, V_Z2, V_Z2, V_Z3, V_Z3

.align 4
        /*
         * 5. len = 16, start = 0, 32, 64, 96, 128, 160, 192, 224
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        16
         *        32        -        48
         *          64        -        80
         *                    ...
         *            192        -        208
         *              224        -        240
         *
         *     These are indexes to the 32 bits array
         */
        li      7, 64
        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*2, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*3, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*4, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*5, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*6, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 128*7, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 6. len = 32, start = 0, 64, 128, 192
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        32
         *               ...
         *      64        -        96
         *               ...
         *      128        -        160
         *                ...
         *      192        -        224
         *                ...
         *
         *     These are indexes to the 32 bits array
         */
        li      7, 128
        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 256, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 256+64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 512, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 512+64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 768, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 768+64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 7. len = 64, start = 0, 128
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        64
         *        16        -        80
         *          32        -        96
         *                    ...
         *      128        -        192
         *        144        -        208
         *          160        -        224
         *            176        -        240
         *     These are indexes to the 32 bits array
         */
        li      7, 256
        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 192, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        iNTT_MREDUCE_4x 512, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 512+64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 512+128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 512+192, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        /*
         * 8. len = 128, start = 0
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        128
         *        16        -        144
         *          32        -        160
         *                    ...
         *            112        -        240
         *     These are indexes to the 32 bits array
         */
        li      7, 512
        lvx     V_ZETA, 0, 14
        addi    14, 14, 16

        iNTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*2, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*3, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*4, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*5, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*6, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        iNTT_MREDUCE_4x 64*7, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        /*
         * Montgomery reduce loops with constant f=41978 (mont^2/256)
         *
         *  a[j] = montgomery_reduce((int64_t)f * a[j])
         */
	addi    10, 8, FCONST_OFFSET
        lvx     V_F, 0, 10

        li      10, 16
        li      11, 32
        li      12, 48

	mr      6, 3

        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x

        RESTORE_REGS
        blr
.size     mldsa_poly_ntt_inverse,.-mldsa_poly_ntt_inverse

.data
.align 4
.mldsa_consts:
.long ML_DSA_Q, ML_DSA_Q, ML_DSA_Q, ML_DSA_Q
.long ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV
/* Constant for INTT, f=mont^2/256 */
.long 41978, 41978, 41978, 41978

.mldsa_izetas:
/* Zetas for Lane=1: setup as (3, 2, 1, 4) order */
.long 6979993, 6403635, 4442679, 846154, 4460757, 1362209, 554416, 48306
.long 976891, 3545687, 8196974, 6767575, 2235985, 2286327, 2939036, 420899
.long 1104333, 3833893, 1667432, 260646, 6656817, 6470041, 426683, 1803090
.long 975884, 7908339, 6167306, 6662682, 4856520, 8110657, 3038916, 4513516
.long 6727783, 1799107, 7570268, 3694233, 8217573, 5366416, 3183426, 6764025
.long 5011305, 1207385, 6423145, 8194886, 5948022, 164721, 2013608, 5925962
.long 3724270, 3776993, 2584293, 7786281, 2831860, 1846953, 542412, 1671176
.long 7603226, 4974386, 6880252, 6144537, 6463336, 1374803, 1279661, 2546312
.long 7067962, 1962642, 451100, 5074302, 7143142, 1430225, 1333058, 3318210
.long 6511298, 1050970, 2994039, 6476982, 7129923, 3548272, 3767016, 5744496
.long 7132797, 6784443, 4325093, 5894064, 5688936, 7115408, 5538076, 2590150
.long 3342277, 8177373, 4943130, 6644538, 8093429, 4272102, 8038120, 2437823
.long 525098, 3595838, 3556995, 768622, 3122442, 5173371, 655327, 6348669
.long 1613174, 522500, 7884926, 43260, 6521319, 7561383, 7479715, 7470875
.long 3759364, 3193378, 3520352, 1197226, 5945978, 4867236, 8113420, 1235728
.long 6136326, 3562462, 3342478, 2446433, 4972711, 4562441, 6288750, 6063917
/* For Len=2 */
.long 4540456, 4540456, 3628969, 3628969, 3881060, 3881060, 3019102, 3019102
.long 1439742, 1439742, 812732, 812732, 1584928, 1584928, 7094748, 7094748
.long 7039087, 7039087, 7064828, 7064828, 177440, 177440, 2409325, 2409325
.long 1851402, 1851402, 5220671, 5220671, 3553272, 3553272, 8190869, 8190869
.long 1316856, 1316856, 7620448, 7620448, 210977, 210977, 5991061, 5991061
.long 3249728, 3249728, 6727353, 6727353, 8578, 8578, 3724342, 3724342
.long 4421799, 4421799, 7475901, 7475901, 1100098, 1100098, 8336129, 8336129
.long 5282425, 5282425, 7871466, 7871466, 8115473, 8115473, 3343383, 3343383
.long 1430430, 1430430, 6527646, 6527646, 7031341, 7031341, 381987, 381987
.long 1308169, 1308169, 22981, 22981, 1228525, 1228525, 671102, 671102
.long 2477047, 2477047, 411027, 411027, 3693493, 3693493, 2967645, 2967645
.long 5665122, 5665122, 6232521, 6232521, 983419, 983419, 4968207, 4968207
.long 8253495, 8253495, 3632928, 3632928, 3157330, 3157330, 3190144, 3190144
.long 1000202, 1000202, 4083598, 4083598, 6441103, 6441103, 1257611, 1257611
.long 1585221, 1585221, 6203962, 6203962, 4904467, 4904467, 1452451, 1452451
.long 3041255, 3041255, 3677745, 3677745, 1528703, 1528703, 3930395, 3930395
/*  For Lane=4 */
.long 2797779, 2797779, 2797779, 2797779, 6308525, 6308525, 6308525, 6308525
.long 2556880, 2556880, 2556880, 2556880, 4479693, 4479693, 4479693, 4479693
.long 4499374, 4499374, 4499374, 4499374, 7426187, 7426187, 7426187, 7426187
.long 7849063, 7849063, 7849063, 7849063, 7568473, 7568473, 7568473, 7568473
.long 4680821, 4680821, 4680821, 4680821, 1600420, 1600420, 1600420, 1600420
.long 2140649, 2140649, 2140649, 2140649, 4873154, 4873154, 4873154, 4873154
.long 3821735, 3821735, 3821735, 3821735, 4874723, 4874723, 4874723, 4874723
.long 1643818, 1643818, 1643818, 1643818, 1699267, 1699267, 1699267, 1699267
.long 539299, 539299, 539299, 539299, 6031717, 6031717, 6031717, 6031717
.long 300467, 300467, 300467, 300467, 4840449, 4840449, 4840449, 4840449
.long 2867647, 2867647, 2867647, 2867647, 4805995, 4805995, 4805995, 4805995
.long 3043716, 3043716, 3043716, 3043716, 3861115, 3861115, 3861115, 3861115
.long 4464978, 4464978, 4464978, 4464978, 2537516, 2537516, 2537516, 2537516
.long 3592148, 3592148, 3592148, 3592148, 1661693, 1661693, 1661693, 1661693
.long 4849980, 4849980, 4849980, 4849980, 5303092, 5303092, 5303092, 5303092
.long 8284641, 8284641, 8284641, 8284641, 5674394, 5674394, 5674394, 5674394
/* zetas for other len */
.long 8100412, 8100412, 8100412, 8100412, 4369920, 4369920, 4369920, 4369920
.long 19422, 19422, 19422, 19422, 6623180, 6623180, 6623180, 6623180
.long 3277672, 3277672, 3277672, 3277672, 1399561, 1399561, 1399561, 1399561
.long 3859737, 3859737, 3859737, 3859737, 2118186, 2118186, 2118186, 2118186
.long 2108549, 2108549, 2108549, 2108549, 5760665, 5760665, 5760665, 5760665
.long 1119584, 1119584, 1119584, 1119584, 549488, 549488, 549488, 549488
.long 4794489, 4794489, 4794489, 4794489, 1079900, 1079900, 1079900, 1079900
.long 7356305, 7356305, 7356305, 7356305, 5654953, 5654953, 5654953, 5654953
.long 5700314, 5700314, 5700314, 5700314, 5268920, 5268920, 5268920, 5268920
.long 2884855, 2884855, 2884855, 2884855, 5260684, 5260684, 5260684, 5260684
.long 2091905, 2091905, 2091905, 2091905, 359251, 359251, 359251, 359251
.long 6026966, 6026966, 6026966, 6026966, 6554070, 6554070, 6554070, 6554070
.long 7913949, 7913949, 7913949, 7913949, 876248, 876248, 876248, 876248
.long 777960, 777960, 777960, 777960, 8143293, 8143293, 8143293, 8143293
.long 518909, 518909, 518909, 518909, 2608894, 2608894, 2608894, 2608894
.long 8354570, 8354570, 8354570, 8354570
