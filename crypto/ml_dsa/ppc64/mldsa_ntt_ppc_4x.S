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
 * Optimized NTT implementation for ppc64le.
 */

#define Q_NEG_INV_OFFSET 16
#define ZETA_NTT_OFFSET 32

#define ML_DSA_Q 8380417   /* The modulus is 23 bits (2^23 - 2^13 + 1) */
#define ML_DSA_Q_NEG_INV 4236238847 /* Inverse of -q modulo 2^32 */

#define Q_NEG_INV    0
#define V_Q     1
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
 * Load Coefficients and setup vectors
 *    rj0, rjlen1, rj2, rjlen3
 *    rj4, rjlen5, rj6, rjlen7
 *
 *  Each vmrgew and vmrgow will transpose vectors as,
 *
 *   rj vector = (rj0, rj4, rj2, rj6)
 *   rjlen vector = (rjlen1, rjlen5, rjlen3, rjlen7)
 *
 *  r' =r[j+len]: V6, V7, V8, V9
 *  r = r[j]: V26, V27, V28, V29
 *
 * In order to do the coefficients computation, zeta vector will arrange
 * in the proper order to match the multiplication.
 */
.macro Load_41Coeffs
        lxvd2x     32+10, 0, 5
        lxvd2x     32+11, 10, 5
        vmrgew 6, 10, 11
        vmrgow 26, 10, 11
        lxvd2x     32+12, 11, 5
        lxvd2x     32+13, 12, 5
        vmrgew 7, 12, 13
        vmrgow 27, 12, 13
        lxvd2x     32+10, 15, 5
        lxvd2x     32+11, 16, 5
        vmrgew 8, 10, 11
        vmrgow 28, 10, 11
        lxvd2x     32+12, 17, 5
        lxvd2x     32+13, 18, 5
        vmrgew 9, 12, 13
        vmrgow 29, 12, 13
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
 *  r' = r[j+len]: V6, V7, V8, V9
 *  r = r[j]: V26, V27, V28, V29
 *
 * In order to do the coefficients computation, zeta vector will arrange
 * in the proper order to match the multiplication.
 */
.macro Load_42Coeffs
        lxvd2x     1, 0, 5
        lxvd2x     2, 10, 5
        xxpermdi 32+6, 1, 2, 3
        xxpermdi 32+26, 1, 2, 0
        lxvd2x     3, 11, 5
        lxvd2x     4, 12, 5
        xxpermdi 32+7, 3, 4, 3
        xxpermdi 32+27, 3, 4, 0
        lxvd2x     1, 15, 5
        lxvd2x     2, 16, 5
        xxpermdi 32+8, 1, 2, 3
        xxpermdi 32+28, 1, 2, 0
        lxvd2x     3, 17, 5
        lxvd2x     4, 18, 5
        xxpermdi 32+9, 3, 4, 3
        xxpermdi 32+29, 3, 4, 0
.endm

/*
 * For Len=8,
 * Load coefficient with 2 legs with 64  bytes apart in
 *  r[j+len] (r') vectors from offset, R10, R17, R19 and R21
 *  r[j+len]: V6, V7, V8, V9
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
        lxvd2x  32+6, 3, 10
        lxvd2x  32+7, 3, 17
        lxvd2x  32+8, 3, 19
        lxvd2x  32+9, 3, 21
.endm

/*
 * Load coefficient with 2 legs with len*2 bytes apart in
 *  r[j+len] (r') vectors from offset, R10, R17, R19 and R21
 *  r[j+len]: V6, V7, V8, V9
 */
.macro Load_4Coeffs start next
        Init_Coeffs_offset \start, \next

        lxvd2x  32+6, 3, 10
        lxvd2x  32+7, 3, 17
        lxvd2x  32+8, 3, 19
        lxvd2x  32+9, 3, 21
.endm

/*
 * Load 4 r[j] (r) coefficient vectors:
 *   Load coefficient in vectors from offset, R9, R16, R18 and R20
 *  r[j]: V26, V27, V28, V29
 */
.macro Load_4Rj
        lxvd2x  32+26, 3, 9
        lxvd2x  32+27, 3, 16
        lxvd2x  32+28, 3, 18
        lxvd2x  32+29, 3, 20
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
 * Calculate The positive value of (a-b) mod q in constant time.
 *
 * a - b mod q gives a value in the range -(q-1)..(q-1)
 * By adding q we get a range of 1..(2q-1).
 * Reducing this once then gives the range 0..q-1
 *
 * returns The value (q + a - b) mod q
 */
.macro mod_sub _x _a _b
        vadduwm 14, \_a, V_Q
        vsubuwm \_x, 14, \_b
        reduce_once_1x \_x
.endm

/*
 * Compute final final r[j] and r[j+len]
 *  final r[j+len]: V18, V19, V20, V21
 *  final r[j]: V22, V23, V24, V25
 */
.macro Compute_4Coeff
        vadduwm 22, 26, 10
        mod_sub 18, 26, 10
        reduce_once_1x 22

        vadduwm 23, 27, 11
        mod_sub 19, 27, 11
        reduce_once_1x 23

        vadduwm 24, 28, 12
        mod_sub 20, 28, 12
        reduce_once_1x 24

        vadduwm 25, 29, 13
        mod_sub 21, 29, 13
        reduce_once_1x 25
.endm

.macro Write_One
        stxvd2x 32+22, 3, 9
        stxvd2x 32+18, 3, 10
        stxvd2x 32+23, 3, 16
        stxvd2x 32+19, 3, 17
        stxvd2x 32+24, 3, 18
        stxvd2x 32+20, 3, 19
        stxvd2x 32+25, 3, 20
        stxvd2x 32+21, 3, 21
.endm

/*
 * Transpose the final coefficients of 2-2-2-2 layout to the original
 * coefficient array order.
 */
.macro PermWrite42
        xxpermdi 32+10, 32+22, 32+18, 0
        xxpermdi 32+14, 32+22, 32+18, 3
        xxpermdi 32+11, 32+23, 32+19, 0
        xxpermdi 32+15, 32+23, 32+19, 3
        xxpermdi 32+12, 32+24, 32+20, 0
        xxpermdi 32+16, 32+24, 32+20, 3
        xxpermdi 32+13, 32+25, 32+21, 0
        xxpermdi 32+17, 32+25, 32+21, 3
        stxvd2x    32+10, 0, 5
        stxvd2x    32+14, 10, 5
        stxvd2x    32+11, 11, 5
        stxvd2x    32+15, 12, 5
        stxvd2x    32+12, 15, 5
        stxvd2x    32+16, 16, 5
        stxvd2x    32+13, 17, 5
        stxvd2x    32+17, 18, 5
.endm

/*
 * Transpose the final coefficients of 1-1-1-1 layout to the original
 * coefficient array order.
 */
.macro PermWrite41
        vmrgew 10, 18, 22
        vmrgow 11, 18, 22
        vmrgew 12, 19, 23
        vmrgow 13, 19, 23
        vmrgew 14, 20, 24
        vmrgow 15, 20, 24
        vmrgew 16, 21, 25
        vmrgow 17, 21, 25
        stxvd2x 32+10, 0, 5
        stxvd2x 32+11, 10, 5
        stxvd2x 32+12, 11, 5
        stxvd2x 32+13, 12, 5
        stxvd2x 32+14, 15, 5
        stxvd2x 32+15, 16, 5
        stxvd2x 32+16, 17, 5
        stxvd2x 32+17, 18, 5
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
 *  a = zeta * a[j+len]
 *  t = (int64_t)(int32_t)a*QINV;
 *  t = (a - (int64_t)t*Q) >> 32;
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
.macro NTT_MREDUCE_41x
        Load_next_4zetas
        Load_41Coeffs
        MREDUCE_4x V_Z0, V_Z1, V_Z2, V_Z3
        Compute_4Coeff
        PermWrite41
        addi    5, 5, 128
.endm

/*
 * For Len=2, layer with 2-2-2-2 layout.
 */
.macro NTT_MREDUCE_42x
        Load_next_4zetas
        Load_42Coeffs
        MREDUCE_4x V_Z0, V_Z1, V_Z2, V_Z3
        Compute_4Coeff
        PermWrite42
        addi    5, 5, 128
.endm

/*
 * For Len=8
 */
.macro NTT_MREDUCE_22x  start next _vz0 _vz1 _vz2 _vz3
        Load_22Coeffs \start, \next
        MREDUCE_4x \_vz0, \_vz1, \_vz2, \_vz3
        Load_4Rj
        Compute_4Coeff
        Write_One
.endm

/*
 * For Len=128, 64, 32, 16 and 4.
 */
.macro NTT_MREDUCE_4x  start next _vz0 _vz1 _vz2 _vz3
        Load_4Coeffs \start, \next
        MREDUCE_4x \_vz0, \_vz1, \_vz2, \_vz3
        Load_4Rj
        Compute_4Coeff
        Write_One
.endm

/*
 * mldsa_poly_ntt(int32_t *r)
 *   Compute forward NTT based on the following 8 layers -
 *     len = 128, 64, 32, 16, 8, 4, 2, 1.
 *
 *   Each layer compute the coefficients on 2 legs, start and start + len*2 offsets.
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
 *   The resulting coefficients then store back to each leg's offset.
 *
 *   Each vector has the same corresponding zeta except len=2.
 *
 *   len=2 has 2-2-2-2 layout which means every 2 32-bit coefficients has the same zeta.
 *   e.g.
 *         coeff vector    a1   a2   a3  a4  a5  a6  a7  a8
 *         zeta  vector    z1   z1   z2  z2  z3  z3  z4  z4
 *
 *   For len=2, each vector will get permuted to leg1 and leg2. Zeta is
 *   pre-arranged for the leg1 and leg2.  After the computation, each vector needs
 *   to transpose back to its original 2-2-2-2 layout. 
 *
 */
.global mldsa_poly_ntt
.align 4
mldsa_poly_ntt:
.localentry     mldsa_poly_ntt,.-mldsa_poly_ntt

        SAVE_REGS

        /* load Q and Q_NEG_INV */
        addis   8,2,.mldsa_consts@toc@ha
        addi    8,8,.mldsa_consts@toc@l
        lvx     V_Q, 0, 8
        li      10, Q_NEG_INV_OFFSET
        lvx     Q_NEG_INV, 10, 8

        /* set zetas array */
        addi      14, 8, ZETA_NTT_OFFSET

        /*
         * 1. len = 128, start = 0
         *
         *    Compute coefficients of the NTT based on 2 legs,
         *      0        -        128
         *        16        -        144
         *          32        -        160
         *                    ...
         *            112        -        240
         *     These are indexes to the 32 bits array
         *
         * r7 is len * 4
         */
        li      7, 512
        lvx     V_ZETA, 0, 14
        addi    14, 14, 16

        NTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 192, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 256, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 320, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 384, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 448, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 2. len = 64, start = 0, 128
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
        NTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 192, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 512, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 576, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 640, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 704, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 3. len = 32, start = 0, 64, 128, 192
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
        NTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 64, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 256, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 320, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 512, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 576, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 768, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA
        NTT_MREDUCE_4x 832, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 4. len = 16, start = 0, 32, 64, 96, 128, 160, 192, 224
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
        NTT_MREDUCE_4x 0, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 128, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 256, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 384, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 512, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 640, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 768, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

        lvx     V_ZETA, 0, 14
        addi    14, 14, 16
        NTT_MREDUCE_4x 896, 16, V_ZETA, V_ZETA, V_ZETA, V_ZETA

.align 4
        /*
         * 5. len = 8, start = 0, 32, 64, 96, 128, 160, 192, 224
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
        NTT_MREDUCE_22x 0, 16, V_Z0, V_Z0, V_Z1, V_Z1
        NTT_MREDUCE_22x 128, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_22x 256, 16, V_Z0, V_Z0, V_Z1, V_Z1
        NTT_MREDUCE_22x 384, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_22x 512, 16, V_Z0, V_Z0, V_Z1, V_Z1
        NTT_MREDUCE_22x 640, 16, V_Z2, V_Z2, V_Z3, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_22x 768, 16, V_Z0, V_Z0, V_Z1, V_Z1
        NTT_MREDUCE_22x 896, 16, V_Z2, V_Z2, V_Z3, V_Z3

.align 4
        /*
         * 6. len = 4, start = 0, 32, 64, 96, 128, 160, 192, 224
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
        NTT_MREDUCE_4x 0, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 128, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 256, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 384, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 512, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 640, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 768, 32, V_Z0, V_Z1, V_Z2, V_Z3

        Load_next_4zetas
        NTT_MREDUCE_4x 896, 32, V_Z0, V_Z1, V_Z2, V_Z3

.align 4
        /*
         * 7. len = 2, start = 0, 4, 8, 12,...244, 248, 252
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

        li      10, 16
        li      11, 32
        li      12, 48
        li      15, 64
        li      16, 80
        li      17, 96
        li      18, 112

        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x
        NTT_MREDUCE_42x

.align 4
        /*
         * 8. len = 1, start = 0, 2, 4, 6, 8, 10, 12,...254
         *
         *    Compute coefficients of the NTT based on the following sequences,
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

        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x
        NTT_MREDUCE_41x

        RESTORE_REGS
        blr
.size     mldsa_poly_ntt,.-mldsa_poly_ntt

.rodata
.align 4
.mldsa_consts:
.long ML_DSA_Q, ML_DSA_Q, ML_DSA_Q, ML_DSA_Q
.long ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV

/* zetas */
.mldsa_zetas:
/* For Len=128, 64, 32, 16, 8 */
.long 25847, 25847, 25847, 25847, 5771523, 5771523, 5771523, 5771523
.long 7861508, 7861508, 7861508, 7861508, 237124, 237124, 237124, 237124
.long 7602457, 7602457, 7602457, 7602457, 7504169, 7504169, 7504169, 7504169
.long 466468, 466468, 466468, 466468, 1826347, 1826347, 1826347, 1826347
.long 2353451, 2353451, 2353451, 2353451, 8021166, 8021166, 8021166, 8021166
.long 6288512, 6288512, 6288512, 6288512, 3119733, 3119733, 3119733, 3119733
.long 5495562, 5495562, 5495562, 5495562, 3111497, 3111497, 3111497, 3111497
.long 2680103, 2680103, 2680103, 2680103, 2725464, 2725464, 2725464, 2725464
.long 1024112, 1024112, 1024112, 1024112, 7300517, 7300517, 7300517, 7300517
.long 3585928, 3585928, 3585928, 3585928, 7830929, 7830929, 7830929, 7830929
.long 7260833, 7260833, 7260833, 7260833, 2619752, 2619752, 2619752, 2619752
.long 6271868, 6271868, 6271868, 6271868, 6262231, 6262231, 6262231, 6262231
.long 4520680, 4520680, 4520680, 4520680, 6980856, 6980856, 6980856, 6980856
.long 5102745, 5102745, 5102745, 5102745, 1757237, 1757237, 1757237, 1757237
.long 8360995, 8360995, 8360995, 8360995, 4010497, 4010497, 4010497, 4010497
.long 280005, 280005, 280005, 280005
/*For Len=4 */
.long 2706023, 2706023, 2706023, 2706023, 95776, 95776, 95776, 95776
.long 3077325, 3077325, 3077325, 3077325, 3530437, 3530437, 3530437, 3530437
.long 6718724, 6718724, 6718724, 6718724, 4788269, 4788269, 4788269, 4788269
.long 5842901, 5842901, 5842901, 5842901, 3915439, 3915439, 3915439, 3915439
.long 4519302, 4519302, 4519302, 4519302, 5336701, 5336701, 5336701, 5336701
.long 3574422, 3574422, 3574422, 3574422, 5512770, 5512770, 5512770, 5512770
.long 3539968, 3539968, 3539968, 3539968, 8079950, 8079950, 8079950, 8079950
.long 2348700, 2348700, 2348700, 2348700, 7841118, 7841118, 7841118, 7841118
.long 6681150, 6681150, 6681150, 6681150, 6736599, 6736599, 6736599, 6736599
.long 3505694, 3505694, 3505694, 3505694, 4558682, 4558682, 4558682, 4558682
.long 3507263, 3507263, 3507263, 3507263, 6239768, 6239768, 6239768, 6239768
.long 6779997, 6779997, 6779997, 6779997, 3699596, 3699596, 3699596, 3699596
.long 811944, 811944, 811944, 811944, 531354, 531354, 531354, 531354
.long 954230, 954230, 954230, 954230, 3881043, 3881043, 3881043, 3881043
.long 3900724, 3900724, 3900724, 3900724, 5823537, 5823537, 5823537, 5823537
.long 2071892, 2071892, 2071892, 2071892, 5582638, 5582638, 5582638, 5582638
/* For Len=2 */
.long 4450022, 4450022, 6851714, 6851714, 4702672, 4702672, 5339162, 5339162
.long 6927966, 6927966, 3475950, 3475950, 2176455, 2176455, 6795196, 6795196
.long 7122806, 7122806, 1939314, 1939314, 4296819, 4296819, 7380215, 7380215
.long 5190273, 5190273, 5223087, 5223087, 4747489, 4747489, 126922, 126922
.long 3412210, 3412210, 7396998, 7396998, 2147896, 2147896, 2715295, 2715295
.long 5412772, 5412772, 4686924, 4686924, 7969390, 7969390, 5903370, 5903370
.long 7709315, 7709315, 7151892, 7151892, 8357436, 8357436, 7072248, 7072248
.long 7998430, 7998430, 1349076, 1349076, 1852771, 1852771, 6949987, 6949987
.long 5037034, 5037034, 264944, 264944, 508951, 508951, 3097992, 3097992
.long 44288, 44288, 7280319, 7280319, 904516, 904516, 3958618, 3958618
.long 4656075, 4656075, 8371839, 8371839, 1653064, 1653064, 5130689, 5130689
.long 2389356, 2389356, 8169440, 8169440, 759969, 759969, 7063561, 7063561
.long 189548, 189548, 4827145, 4827145, 3159746, 3159746, 6529015, 6529015
.long 5971092, 5971092, 8202977, 8202977, 1315589, 1315589, 1341330, 1341330
.long 1285669, 1285669, 6795489, 6795489, 7567685, 7567685, 6940675, 6940675
.long 5361315, 5361315, 4499357, 4499357, 4751448, 4751448, 3839961, 3839961
/* Setup zetas for Len=1 as (3, 2, 1, 4) order */
.long 2316500, 2091667, 3817976, 3407706, 5933984, 5037939, 4817955, 2244091
.long 7144689, 266997, 3513181, 2434439, 7183191, 4860065, 5187039, 4621053
.long 909542, 900702, 819034, 1859098, 8337157, 495491, 7857917, 6767243
.long 2031748, 7725090, 3207046, 5257975, 7611795, 4823422, 4784579, 7855319
.long 5942594, 342297, 4108315, 286988, 1735879, 3437287, 203044, 5038140
.long 5790267, 2842341, 1265009, 2691481, 2486353, 4055324, 1595974, 1247620
.long 2635921, 4613401, 4832145, 1250494, 1903435, 5386378, 7329447, 1869119
.long 5062207, 7047359, 6950192, 1237275, 3306115, 7929317, 6417775, 1312455
.long 5834105, 7100756, 7005614, 1917081, 2235880, 1500165, 3406031, 777191
.long 6709241, 7838005, 6533464, 5548557, 594136, 5796124, 4603424, 4656147
.long 2454455, 6366809, 8215696, 2432395, 185531, 1957272, 7173032, 3369112
.long 1616392, 5196991, 3014001, 162844, 4686184, 810149, 6581310, 1652634
.long 3866901, 5341501, 269760, 3523897, 1717735, 2213111, 472078, 7404533
.long 6577327, 7953734, 1910376, 1723600, 8119771, 6712985, 4546524, 7276084
.long 7959518, 5441381, 6094090, 6144432, 1612842, 183443, 4834730, 7403526
.long 8332111, 7826001, 7018208, 3919660, 7534263, 3937738, 1976782, 1400424
