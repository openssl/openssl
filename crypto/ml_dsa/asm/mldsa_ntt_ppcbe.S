/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
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
 * Optimized NTT implementation for ppc64be.
 *
 * Enable optimized NTT implementation for PPC Big Endian by
 * Sandeep Umesh <sanumesh@in.ibm.com> assisted by Bob.
 */

#define ML_DSA_Q 8380417
#define ML_DSA_Q_NEG_INV 4236238847

#define Q_NEG_INV_OFFSET 16
#define ZETA_NTT_OFFSET 32

#define Q_NEG_INV    0
#define V_Q          1

#define V_ZETA       2
#define V_Z0         2
#define V_Z1         3
#define V_Z2         4
#define V_Z3         5

#define GPR_OFFSET_C0 9
#define GPR_OFFSET_C1 11
#define GPR_OFFSET_C2 15
#define GPR_OFFSET_C3 17

#define GPR_OFFSET_P0 10
#define GPR_OFFSET_P1 12
#define GPR_OFFSET_P2 16
#define GPR_OFFSET_P3 18

/*
 * Word-size dependent definitions: the same source is used for 32-bit and
 * 64-bit AIX builds.
 */
#if defined(__64BIT__) || defined(_LP64) || defined(__LP64__) || defined(__powerpc64__)
#define STD       std
#define STDU      stdu
#define LD        ld
#define ADDR_WORD .llong
#else
#define STD       stw
#define STDU      stwu
#define LD        lwz
#define ADDR_WORD .long
#endif

.machine "any"
.csect .text[PR]

/*
 * SAVE_REGS / RESTORE_REGS for mldsa_poly_ntt_ppcbe
 * Saves GPRs 14-21 and VSX registers 52-61 (VRs 20-29).
 */
#define SAVE_REGS \
        STDU    1, -352(1); \
        mflr    0; \
        STD     14, 56(1); \
        STD     15, 64(1); \
        STD     16, 72(1); \
        STD     17, 80(1); \
        STD     18, 88(1); \
        STD     19, 96(1); \
        STD     20, 104(1); \
        STD     21, 112(1); \
        li      10, 128; \
        li      11, 144; \
        li      12, 160; \
        li      14, 176; \
        li      15, 192; \
        li      16, 208; \
        stxvx   52, 10, 1; \
        stxvx   53, 11, 1; \
        stxvx   54, 12, 1; \
        stxvx   55, 14, 1; \
        stxvx   56, 15, 1; \
        stxvx   57, 16, 1; \
        li      10, 224; \
        li      11, 240; \
        li      12, 256; \
        li      14, 272; \
        stxvx   58, 10, 1; \
        stxvx   59, 11, 1; \
        stxvx   60, 12, 1; \
        stxvx   61, 14, 1

#define RESTORE_REGS \
        li      10, 128; \
        li      11, 144; \
        li      12, 160; \
        li      14, 176; \
        li      15, 192; \
        li      16, 208; \
        lxvx    52, 10, 1; \
        lxvx    53, 11, 1; \
        lxvx    54, 12, 1; \
        lxvx    55, 14, 1; \
        lxvx    56, 15, 1; \
        lxvx    57, 16, 1; \
        li      10, 224; \
        li      11, 240; \
        li      12, 256; \
        li      14, 272; \
        lxvx    58, 10, 1; \
        lxvx    59, 11, 1; \
        lxvx    60, 12, 1; \
        lxvx    61, 14, 1; \
        LD      14, 56(1); \
        LD      15, 64(1); \
        LD      16, 72(1); \
        LD      17, 80(1); \
        LD      18, 88(1); \
        LD      19, 96(1); \
        LD      20, 104(1); \
        LD      21, 112(1); \
        mtlr    0; \
        addi    1, 1, 352

/*
 * Constant-time reduction and modular arithmetic primitives.
 */
#define reduce_once_1x(vt, vsx_vt) \
        vsubuwm  16, vt, V_Q; \
        vcmpgtsw 17, V_Q, vt; \
        xxsel    vsx_vt, 48, vsx_vt, 49

#define mod_sub(x, vsx_x, a, b) \
        vadduwm 14, a, V_Q; \
        vsubuwm x, 14, b; \
        reduce_once_1x(x, vsx_x)

#define Load_4zetas(vz0, vz1, vz2, vz3) \
        lxvw4x  34, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  35, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  36, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  37, 0, 14; \
        addi    14, 14, 16

#define Mont_scalar_mul_4x(vz0, vz1, vz2, vz3) \
        vmuleuw 10, 6, vz0; \
        vmulouw 11, 6, vz0; \
        vmuleuw 12, 7, vz1; \
        vmulouw 13, 7, vz1; \
        vmuleuw 14, 8, vz2; \
        vmulouw 15, 8, vz2; \
        vmuleuw 16, 9, vz3; \
        vmulouw 17, 9, vz3

#define Mont_reduce_4x \
        vmulouw 18, 10, Q_NEG_INV; \
        vmulouw 19, 11, Q_NEG_INV; \
        vmulouw 20, 12, Q_NEG_INV; \
        vmulouw 21, 13, Q_NEG_INV; \
        vmulouw 22, 14, Q_NEG_INV; \
        vmulouw 23, 15, Q_NEG_INV; \
        vmulouw 24, 16, Q_NEG_INV; \
        vmulouw 25, 17, Q_NEG_INV; \
        vmulouw 18, 18, V_Q; \
        vmulouw 19, 19, V_Q; \
        vmulouw 20, 20, V_Q; \
        vmulouw 21, 21, V_Q; \
        vmulouw 22, 22, V_Q; \
        vmulouw 23, 23, V_Q; \
        vmulouw 24, 24, V_Q; \
        vmulouw 25, 25, V_Q; \
        vaddudm 18, 18, 10; \
        vaddudm 19, 19, 11; \
        vaddudm 20, 20, 12; \
        vaddudm 21, 21, 13; \
        vaddudm 22, 22, 14; \
        vaddudm 23, 23, 15; \
        vaddudm 24, 24, 16; \
        vaddudm 25, 25, 17; \
        vmrgew  10, 18, 19; \
        vmrgew  11, 20, 21; \
        vmrgew  12, 22, 23; \
        vmrgew  13, 24, 25; \
        reduce_once_1x(10, 42); \
        reduce_once_1x(11, 43); \
        reduce_once_1x(12, 44); \
        reduce_once_1x(13, 45)

#define mont_mul_reduce_4x(vz0, vz1, vz2, vz3) \
        Mont_scalar_mul_4x(vz0, vz1, vz2, vz3); \
        Mont_reduce_4x

#define Load_vmrg_coeffs_be(c1, c2, c3, c4, p1, p2, p3, p4) \
        lxvw4x  42, GPR_OFFSET_C0, 5; \
        lxvw4x  43, GPR_OFFSET_P0, 5; \
        vmrgew  c1, 10, 11; \
        vmrgow  p1, 10, 11; \
        lxvw4x  44, GPR_OFFSET_C1, 5; \
        lxvw4x  45, GPR_OFFSET_P1, 5; \
        vmrgew  c2, 12, 13; \
        vmrgow  p2, 12, 13; \
        lxvw4x  42, GPR_OFFSET_C2, 5; \
        lxvw4x  43, GPR_OFFSET_P2, 5; \
        vmrgew  c3, 10, 11; \
        vmrgow  p3, 10, 11; \
        lxvw4x  44, GPR_OFFSET_C3, 5; \
        lxvw4x  45, GPR_OFFSET_P3, 5; \
        vmrgew  c4, 12, 13; \
        vmrgow  p4, 12, 13

#define Load_xxperm_coeffs_be(c1_vsx, c2_vsx, c3_vsx, c4_vsx, p1_vsx, p2_vsx, p3_vsx, p4_vsx) \
        lxvw4x   1, GPR_OFFSET_C0, 5; \
        lxvw4x   2, GPR_OFFSET_P0, 5; \
        xxpermdi c1_vsx, 1, 2, 0; \
        xxpermdi p1_vsx, 1, 2, 3; \
        lxvw4x   3, GPR_OFFSET_C1, 5; \
        lxvw4x   4, GPR_OFFSET_P1, 5; \
        xxpermdi c2_vsx, 3, 4, 0; \
        xxpermdi p2_vsx, 3, 4, 3; \
        lxvw4x   1, GPR_OFFSET_C2, 5; \
        lxvw4x   2, GPR_OFFSET_P2, 5; \
        xxpermdi c3_vsx, 1, 2, 0; \
        xxpermdi p3_vsx, 1, 2, 3; \
        lxvw4x   3, GPR_OFFSET_C3, 5; \
        lxvw4x   4, GPR_OFFSET_P3, 5; \
        xxpermdi c4_vsx, 3, 4, 0; \
        xxpermdi p4_vsx, 3, 4, 3

#define delayed_writes_curr_peer_be(c1_vsx, p1_vsx, c2_vsx, p2_vsx, c3_vsx, p3_vsx, c4_vsx, p4_vsx) \
        stxvw4x c1_vsx, GPR_OFFSET_C0, 5; \
        stxvw4x p1_vsx, GPR_OFFSET_P0, 5; \
        stxvw4x c2_vsx, GPR_OFFSET_C1, 5; \
        stxvw4x p2_vsx, GPR_OFFSET_P1, 5; \
        stxvw4x c3_vsx, GPR_OFFSET_C2, 5; \
        stxvw4x p3_vsx, GPR_OFFSET_P2, 5; \
        stxvw4x c4_vsx, GPR_OFFSET_C3, 5; \
        stxvw4x p4_vsx, GPR_OFFSET_P3, 5

#define _update_curr_peer_coeffs \
        vadduwm 22, 26, 10; \
        mod_sub(18, 50, 26, 10); \
        vadduwm 23, 27, 11; \
        mod_sub(19, 51, 27, 11); \
        vadduwm 24, 28, 12; \
        mod_sub(20, 52, 28, 12); \
        vadduwm 25, 29, 13; \
        mod_sub(21, 53, 29, 13); \
        reduce_once_1x(22, 54); \
        reduce_once_1x(23, 55); \
        reduce_once_1x(24, 56); \
        reduce_once_1x(25, 57)

#define _delayed_writes_xxperm \
        xxpermdi 42, 54, 50, 0; \
        xxpermdi 46, 54, 50, 3; \
        xxpermdi 43, 55, 51, 0; \
        xxpermdi 47, 55, 51, 3; \
        xxpermdi 44, 56, 52, 0; \
        xxpermdi 48, 56, 52, 3; \
        xxpermdi 45, 57, 53, 0; \
        xxpermdi 49, 57, 53, 3; \
        delayed_writes_curr_peer_be(42, 46, 43, 47, 44, 48, 45, 49)

#define _delayed_writes_vmrg \
        vmrgew 10, 22, 18; \
        vmrgow 11, 22, 18; \
        vmrgew 12, 23, 19; \
        vmrgow 13, 23, 19; \
        vmrgew 14, 24, 20; \
        vmrgow 15, 24, 20; \
        vmrgew 16, 25, 21; \
        vmrgow 17, 25, 21; \
        delayed_writes_curr_peer_be(42, 43, 44, 45, 46, 47, 48, 49)

#define _ntt_body(vz0, vz1, vz2, vz3) \
        lxvw4x  38, 5, GPR_OFFSET_P0; \
        lxvw4x  39, 5, GPR_OFFSET_P1; \
        lxvw4x  40, 5, GPR_OFFSET_P2; \
        lxvw4x  41, 5, GPR_OFFSET_P3; \
        mont_mul_reduce_4x(vz0, vz1, vz2, vz3); \
        lxvw4x  58, 5, GPR_OFFSET_C0; \
        lxvw4x  59, 5, GPR_OFFSET_C1; \
        lxvw4x  60, 5, GPR_OFFSET_C2; \
        lxvw4x  61, 5, GPR_OFFSET_C3; \
        _update_curr_peer_coeffs

#define NTT_Layer123_4x(vz0, vz1, vz2, vz3) \
        _ntt_body(vz0, vz1, vz2, vz3); \
        delayed_writes_curr_peer_be(54, 50, 55, 51, 56, 52, 57, 53); \
        addi    5, 5, 64

#define NTT_Layer456_4x(vz0, vz1, vz2, vz3) \
        _ntt_body(vz0, vz1, vz2, vz3); \
        delayed_writes_curr_peer_be(54, 50, 55, 51, 56, 52, 57, 53); \
        addi    5, 5, 128

#define NTT_Layer7_4x \
        lxvw4x  34, 0, 14; \
        lxvw4x  35, 10, 14; \
        lxvw4x  36, 11, 14; \
        lxvw4x  37, 12, 14; \
        addi    14, 14, 64; \
        Load_xxperm_coeffs_be(58, 59, 60, 61, 38, 39, 40, 41); \
        mont_mul_reduce_4x(V_Z0, V_Z1, V_Z2, V_Z3); \
        _update_curr_peer_coeffs; \
        _delayed_writes_xxperm; \
        addi    5, 5, 128

#define NTT_Layer8_4x \
        lxvw4x  34, 0, 14; \
        lxvw4x  35, 10, 14; \
        lxvw4x  36, 11, 14; \
        lxvw4x  37, 12, 14; \
        addi    14, 14, 64; \
        Load_vmrg_coeffs_be(26, 27, 28, 29, 6, 7, 8, 9); \
        mont_mul_reduce_4x(V_Z0, V_Z1, V_Z2, V_Z3); \
        _update_curr_peer_coeffs; \
        _delayed_writes_vmrg; \
        addi    5, 5, 128

/*
 * POLY_SAVE_REGS / POLY_RESTORE_REGS for mldsa_poly_ntt_mult_ppcbe
 */
#define POLY_SAVE_REGS \
        STDU    1, -256(1); \
        mflr    0; \
        li      9, 128; \
        li      10, 144; \
        li      11, 160; \
        li      12, 176; \
        stxvx   52, 9, 1; \
        stxvx   53, 10, 1; \
        stxvx   54, 11, 1; \
        stxvx   55, 12, 1; \
        li      9, 192; \
        li      10, 208; \
        stxvx   56, 9, 1; \
        stxvx   57, 10, 1

#define POLY_RESTORE_REGS \
        li      9, 128; \
        li      10, 144; \
        li      11, 160; \
        li      12, 176; \
        lxvx    52, 9, 1; \
        lxvx    53, 10, 1; \
        lxvx    54, 11, 1; \
        lxvx    55, 12, 1; \
        li      9, 192; \
        li      10, 208; \
        lxvx    56, 9, 1; \
        lxvx    57, 10, 1; \
        mtlr    0; \
        addi    1, 1, 256

#define _Load_poly_points_vectors \
        lxvw4x  34, 0, 4; \
        lxvw4x  35, 10, 4; \
        lxvw4x  36, 11, 4; \
        lxvw4x  37, 12, 4; \
        lxvw4x  38, 0, 5; \
        lxvw4x  39, 10, 5; \
        lxvw4x  40, 11, 5; \
        lxvw4x  41, 12, 5; \
        addi    4, 4, 64; \
        addi    5, 5, 64

#define _update_poly_coeffs \
        stxvw4x 42, 0, 3; \
        stxvw4x 43, 10, 3; \
        stxvw4x 44, 11, 3; \
        stxvw4x 45, 12, 3; \
        addi    3, 3, 64

#define _poly_ntt_mul_4x \
        _Load_poly_points_vectors; \
        Mont_scalar_mul_4x(2, 3, 4, 5); \
        Mont_reduce_4x; \
        _update_poly_coeffs

/* ===================================================================== */
/*
 * mldsa_poly_ntt_ppcbe(int32_t *r)
 *   Compute forward NTT based on the 8 layers:
 *     len = 128, 64, 32, 16, 8, 4, 2, 1.
 */
.globl  .mldsa_poly_ntt_ppcbe
.globl  mldsa_poly_ntt_ppcbe
.csect  mldsa_poly_ntt_ppcbe[DS]
mldsa_poly_ntt_ppcbe:
        ADDR_WORD  .mldsa_poly_ntt_ppcbe, TOC[TC0], 0

.csect  .text[PR]
.align  4
.mldsa_poly_ntt_ppcbe:

        SAVE_REGS

        /* load Q and Q_NEG_INV */
        LD      8, .Lmldsa_consts(2)
        lxvw4x  33, 0, 8
        li      10, Q_NEG_INV_OFFSET
        lxvw4x  32, 10, 8

        /* set zetas array */
        addi    14, 8, ZETA_NTT_OFFSET

        /*
         * Layer 1, len = 128
         */
        mr      5, 3

        li      GPR_OFFSET_C0, 0
        li      GPR_OFFSET_C1, 0x10
        li      GPR_OFFSET_C2, 0x20
        li      GPR_OFFSET_C3, 0x30

        li      GPR_OFFSET_P0, 0x200
        li      GPR_OFFSET_P1, 0x210
        li      GPR_OFFSET_P2, 0x220
        li      GPR_OFFSET_P3, 0x230

        lxvw4x  34, 0, 14
        addi    14, 14, 16

        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)

.align 4
        /*
         * Layer 2, len = 64
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x100
        li      GPR_OFFSET_P1, 0x110
        li      GPR_OFFSET_P2, 0x120
        li      GPR_OFFSET_P3, 0x130

        lxvw4x  34, 0, 14
        addi    14, 14, 16
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        addi    5, 5, 0x100

        lxvw4x  34, 0, 14
        addi    14, 14, 16
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        NTT_Layer123_4x(V_ZETA, V_ZETA, V_ZETA, V_ZETA)

.align 4
        /*
         * Layer 3, len = 32
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x80
        li      GPR_OFFSET_P1, 0x90
        li      GPR_OFFSET_P2, 0xa0
        li      GPR_OFFSET_P3, 0xb0

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer123_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        NTT_Layer123_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        addi    5, 5, 0x80

        NTT_Layer123_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        NTT_Layer123_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        addi    5, 5, 0x80

        NTT_Layer123_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        NTT_Layer123_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        addi    5, 5, 0x80

        NTT_Layer123_4x(V_Z3, V_Z3, V_Z3, V_Z3)
        NTT_Layer123_4x(V_Z3, V_Z3, V_Z3, V_Z3)

.align 4
        /*
         * Layer 4, len = 16
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x40
        li      GPR_OFFSET_P1, 0x50
        li      GPR_OFFSET_P2, 0x60
        li      GPR_OFFSET_P3, 0x70

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        NTT_Layer456_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        NTT_Layer456_4x(V_Z3, V_Z3, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        NTT_Layer456_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        NTT_Layer456_4x(V_Z3, V_Z3, V_Z3, V_Z3)

.align 4
        /*
         * Layer 5, len = 8
         */
        mr      5, 3

        li      GPR_OFFSET_C1, 0x10
        li      GPR_OFFSET_C2, 0x40
        li      GPR_OFFSET_C3, 0x50

        li      GPR_OFFSET_P0, 0x20
        li      GPR_OFFSET_P1, 0x30
        li      GPR_OFFSET_P2, 0x60
        li      GPR_OFFSET_P3, 0x70

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        NTT_Layer456_4x(V_Z2, V_Z2, V_Z3, V_Z3)

.align 4
        /*
         * Layer 6, len = 4
         */
        mr      5, 3

        li      GPR_OFFSET_C1, 0x20
        li      GPR_OFFSET_C2, 0x40
        li      GPR_OFFSET_C3, 0x60

        li      GPR_OFFSET_P0, 0x10
        li      GPR_OFFSET_P1, 0x30
        li      GPR_OFFSET_P2, 0x50
        li      GPR_OFFSET_P3, 0x70

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        NTT_Layer456_4x(V_Z0, V_Z1, V_Z2, V_Z3)

.align 4
        /*
         * Layer 7, len = 2
         */
        mr      5, 3

        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x
        NTT_Layer7_4x

.align 4
        /*
         * Layer 8, len = 1
         */
        mr      5, 3

        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x
        NTT_Layer8_4x

        RESTORE_REGS
        blr
.long 0
.byte 0,12,0x14,0,0,0,0,0

/* ===================================================================== */
/*
 * mldsa_poly_ntt_mult(poly *c, const poly *a, const poly *b)
 */
.globl  .mldsa_poly_ntt_mult_ppcbe
.globl  mldsa_poly_ntt_mult_ppcbe
.csect  mldsa_poly_ntt_mult_ppcbe[DS]
mldsa_poly_ntt_mult_ppcbe:
        ADDR_WORD  .mldsa_poly_ntt_mult_ppcbe, TOC[TC0], 0

.csect  .text[PR]
.align  4
.mldsa_poly_ntt_mult_ppcbe:

        POLY_SAVE_REGS

        /* load Q and Q_NEG_INV */
        LD      8, .Lmldsa_consts(2)
        lxvw4x  33, 0, 8
        li      10, 16
        lxvw4x  32, 10, 8

        /*
         * Montgomery reduce loops for a * b
         *  c[j] = montgomery_reduce(a[j] * b[j])
         */
        li       10, 16
        li       11, 32
        li       12, 48

        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x
        _poly_ntt_mul_4x

        POLY_RESTORE_REGS
        blr
.long 0
.byte 0,12,0x14,0,0,0,0,0

/* ===================================================================== */

.toc
.Lmldsa_consts:
        .tc .mldsa_consts[TC],.mldsa_consts[RO]

.csect .mldsa_consts[RO], 4
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
/* For Len=4 */
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
/* Zetas for Len=1 */
.long 2091667, 2316500, 3407706, 3817976, 5037939, 5933984, 2244091, 4817955
.long 266997, 7144689, 2434439, 3513181, 4860065, 7183191, 4621053, 5187039
.long 900702, 909542, 1859098, 819034, 495491, 8337157, 6767243, 7857917
.long 7725090, 2031748, 5257975, 3207046, 4823422, 7611795, 7855319, 4784579
.long 342297, 5942594, 286988, 4108315, 3437287, 1735879, 5038140, 203044
.long 2842341, 5790267, 2691481, 1265009, 4055324, 2486353, 1247620, 1595974
.long 4613401, 2635921, 1250494, 4832145, 5386378, 1903435, 1869119, 7329447
.long 7047359, 5062207, 1237275, 6950192, 7929317, 3306115, 1312455, 6417775
.long 7100756, 5834105, 1917081, 7005614, 1500165, 2235880, 777191, 3406031
.long 7838005, 6709241, 5548557, 6533464, 5796124, 594136, 4656147, 4603424
.long 6366809, 2454455, 2432395, 8215696, 1957272, 185531, 3369112, 7173032
.long 5196991, 1616392, 162844, 3014001, 810149, 4686184, 1652634, 6581310
.long 5341501, 3866901, 3523897, 269760, 2213111, 1717735, 7404533, 472078
.long 7953734, 6577327, 1723600, 1910376, 6712985, 8119771, 7276084, 4546524
.long 5441381, 7959518, 6144432, 6094090, 183443, 1612842, 7403526, 4834730
.long 7826001, 8332111, 3919660, 7018208, 3937738, 7534263, 1400424, 1976782
